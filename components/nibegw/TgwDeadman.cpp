#include "TgwDeadman.h"

#include <algorithm>
#include <cstring>

namespace esphome {
namespace nibegw {
namespace tgw {

namespace {

const char *outcome_name(FiredOutcome outcome) {
  switch (outcome) {
    case FiredOutcome::PUT_BACK:
      return "PUT_BACK";
    case FiredOutcome::REFUSED:
      return "REFUSED";
    case FiredOutcome::SKIPPED:
      return "SKIPPED";
    case FiredOutcome::NO_ANSWER:
      return "NO_ANSWER";
  }
  return "?";
}

uint32_t mask(uint8_t width) {
  return width >= 4 ? 0xFFFFFFFF : (uint32_t(1) << (8 * width)) - 1;
}

uint32_t le(const uint8_t *data, size_t len) {
  uint32_t value = 0;
  for (size_t i = 0; i < len; i++)
    value |= uint32_t(data[i]) << (8 * i);
  return value;
}

// The value the entry's write puts back, at its width: the write's four value bytes.
uint32_t restores(const DeadmanEntry &entry) {
  return le(entry.frame.data() + 5, 4) & mask(entry.width);
}

// The register's value in a 0x6A answer: two 16-bit words after the register, the first
// the low half.
std::optional<uint32_t> value_of(const std::vector<uint8_t> &payload, uint8_t width) {
  if (payload.size() < 2u + width)
    return std::nullopt;
  return le(payload.data() + 2, width);
}

std::vector<uint8_t> read_request(uint16_t reg) {
  std::vector<uint8_t> frame{bus::START_REPLY, bus::READ_TOKEN_CMD, 2, uint8_t(reg & 0xFF), uint8_t(reg >> 8)};
  frame.push_back(bus_checksum(frame.data(), frame.size()));
  return frame;
}

Message report(const DeadmanOutcome &o, uint64_t now_us) {
  Message m;
  m.type = MessageType::FIRED;
  m.gw_time_us = now_us;
  m.entry = o.entry;
  m.outcome = static_cast<uint8_t>(o.outcome);
  m.reg = o.reg;
  m.read = o.read;
  m.fired_us = o.fired_us;
  return m;
}

}  // namespace

Deadman::Deadman(Engine &engine, uint64_t now_us, DeadmanHooks hooks)
    : engine_(engine), hooks_(std::move(hooks)), heard_us_(now_us), saved_us_(now_us) {
  load_();
}

// --- the client ---------------------------------------------------------------------------

std::pair<uint16_t, uint8_t> Deadman::grant(uint32_t asked_s, uint32_t asked_entries) {
  uint16_t seconds = std::min<uint32_t>(std::max<uint32_t>(asked_s, SILENCE_MIN_S), SILENCE_MAX_S);
  if (uint64_t(seconds) * 1000000 != silence_us_) {
    silence_us_ = uint64_t(seconds) * 1000000;
    dirty_ = true;
  }
  return {seconds, std::min<uint32_t>(asked_entries, ENTRIES)};
}

void Deadman::heard(uint64_t now_us) {
  heard_us_ = now_us;
  if (firing_) {
    log_("dead-man: the client is back, " + std::to_string(queue_.size()) + " entries left armed");
    firing_ = false;
    queue_.clear();
  }
}

Message Deadman::arm(const Message &msg, uint8_t entries) {
  ArmRefusal refusal = refusal_(msg, entries);
  if (refusal == ArmRefusal::NONE)
    refusal = fired_refusal_(msg.entry);
  if (refusal != ArmRefusal::NONE)
    return armed_answer_(msg.entry, ArmResult::REFUSED, msg.id, refusal);
  armed_[msg.entry] = DeadmanEntry{msg.entry, msg.width, msg.reg, msg.expected, msg.frame};
  dirty_ = true;
  return armed_answer_(msg.entry, ArmResult::ARMED, msg.id);
}

Message Deadman::disarm(uint8_t entry, uint32_t id) {
  ArmRefusal refusal = fired_refusal_(entry);
  if (refusal != ArmRefusal::NONE)
    return armed_answer_(entry, ArmResult::REFUSED, id, refusal);
  if (armed_.erase(entry) != 0)
    dirty_ = true;
  return armed_answer_(entry, ArmResult::DISARMED, id);
}

// An entry being fired, or whose outcome isn't acknowledged, keeps its number: a report for
// it is then always for what the client armed last.
ArmRefusal Deadman::fired_refusal_(uint8_t entry) const {
  if (fired_.count(entry) != 0 || (current_ && current_->number == entry))
    return ArmRefusal::FIRED;
  return ArmRefusal::NONE;
}

Message Deadman::ack_fired(uint8_t entry, uint32_t id) {
  if (fired_.erase(entry) != 0)
    dirty_ = true;
  return armed_answer_(entry, ArmResult::DISARMED, id);
}

void Deadman::stop(uint64_t now_us) {
  if (current_ && armed_.count(current_->number) == 0)
    armed_[current_->number] = *current_;
  current_.reset();
  pending_.reset();
  firing_ = false;
  queue_.clear();
  save(now_us);
}

std::vector<Message> Deadman::reports(uint64_t now_us) const {
  std::vector<Message> out;
  for (const auto &[entry, outcome] : fired_)
    out.push_back(report(outcome, now_us));
  return out;
}

std::vector<Message> Deadman::just_fired(uint64_t now_us) {
  std::vector<Message> out;
  for (const auto &outcome : just_fired_)
    out.push_back(report(outcome, now_us));
  just_fired_.clear();
  return out;
}

ArmRefusal Deadman::refusal_(const Message &msg, uint8_t entries) {
  if (msg.entry >= entries)
    return ArmRefusal::NO_SUCH_ENTRY;
  if (msg.width != 2 && msg.width != 4)
    return ArmRefusal::BAD_WIDTH;
  if (!valid_reply(msg.frame) || msg.frame[1] != bus::WRITE_TOKEN_CMD || msg.frame[2] != 6)
    return ArmRefusal::INVALID_FRAME;
  if (le(msg.frame.data() + 3, 2) != msg.reg)
    return ArmRefusal::REGISTER_MISMATCH;
  return ArmRefusal::NONE;
}

Message Deadman::armed_answer_(uint8_t entry, ArmResult result, uint32_t id, ArmRefusal detail) {
  Message m;
  m.type = MessageType::ARMED;
  m.id = id;
  m.entry = entry;
  m.result = static_cast<uint8_t>(result);
  m.detail = static_cast<uint16_t>(detail);
  return m;
}

// --- firing -------------------------------------------------------------------------------

void Deadman::tick(uint64_t now_us) {
  if (!firing_ && !armed_.empty() && now_us - heard_us_ >= silence_us_) {
    log_("dead-man: silent for " + std::to_string(silence_us_ / 1000000) + " s, putting " +
         std::to_string(armed_.size()) + " back");
    firing_ = true;
    queue_.clear();
    for (const auto &[number, entry] : armed_)
      queue_.push_back(entry);
  }
  if (firing_ && !current_)
    next_(now_us);
  if (dirty_ && now_us - saved_us_ >= SAVE_EVERY_US)
    save(now_us);
}

void Deadman::on_message(const Message &message, uint64_t now_us) {
  if (!pending_ || message.id != pending_->first || !current_)
    return;
  DeadmanEntry entry = *current_;
  Step step = pending_->second;
  DeadmanOutcome no_answer{entry.number, FiredOutcome::NO_ANSWER, entry.reg, 0, 0};
  if (message.type == MessageType::FATE) {
    auto stage = static_cast<Stage>(message.stage);
    if (stage == Stage::DROPPED || stage == Stage::PUMP_NAK)
      done_(no_answer, now_us);
    return;
  }
  if (message.type != MessageType::ANSWER)
    return;
  if (message.status != static_cast<uint8_t>(AnswerStatus::OK)) {
    done_(no_answer, now_us);
    return;
  }
  Exchange telegram =
      make_exchange(message.frame.data(), message.frame.size(), false, Exchange::Reply::NONE, 0, now_us, 0);
  if (!telegram.parsed) {
    done_(no_answer, now_us);
    return;
  }
  const auto &payload = telegram.payload;
  if (step == Step::READ) {
    auto value = value_of(payload, entry.width);
    if (!value || le(payload.data(), 2) != entry.reg) {
      done_(no_answer, now_us);
    } else if (*value == restores(entry)) {
      // Already back: a firing before a restart wrote it, or someone put it back.
      done_({entry.number, FiredOutcome::PUT_BACK, entry.reg, *value, 0}, now_us);
    } else if (*value != (entry.expected & mask(entry.width))) {
      // Someone changed it while the client was silent: theirs stands.
      done_({entry.number, FiredOutcome::SKIPPED, entry.reg, *value, 0}, now_us);
    } else {
      request_(bus::WRITE_TOKEN_CMD, entry.frame, Step::WRITE, now_us);
    }
  } else {
    bool taken = !payload.empty() && payload[0] == 1;
    done_({entry.number, taken ? FiredOutcome::PUT_BACK : FiredOutcome::REFUSED, entry.reg, entry.expected, 0}, now_us);
  }
}

void Deadman::next_(uint64_t now_us) {
  if (queue_.empty()) {
    firing_ = false;
    return;
  }
  DeadmanEntry entry = queue_.front();
  queue_.pop_front();
  auto found = armed_.find(entry.number);
  if (found == armed_.end() || found->second != entry)
    return;  // disarmed or armed anew since the firing began: the client knows best
  armed_.erase(found);
  current_ = entry;
  dirty_ = true;
  request_(bus::READ_TOKEN_CMD, read_request(entry.reg), Step::READ, now_us);
}

void Deadman::request_(uint8_t token, std::vector<uint8_t> frame, Step step, uint64_t now_us) {
  next_id_++;
  pending_ = std::make_pair(next_id_, step);
  Message request;
  request.type = MessageType::REQUEST;
  request.id = next_id_;
  request.address = bus::MODBUS40_ADDR;
  request.token = token;
  request.request_flags = request_flag::EXPECT_ANSWER;
  request.ttl_ms = REQUEST_TTL_MS;
  request.frame = std::move(frame);
  engine_.submit(this, request, now_us);
}

void Deadman::done_(const DeadmanOutcome &outcome, uint64_t now_us) {
  log_("dead-man: entry " + std::to_string(outcome.entry) + " (" + std::to_string(outcome.reg) +
       "): " + outcome_name(outcome.outcome));
  DeadmanOutcome kept = outcome;
  kept.fired_us = now_us;
  fired_[kept.entry] = kept;
  just_fired_.push_back(kept);
  current_.reset();
  pending_.reset();
  dirty_ = true;
  save(now_us);  // a firing is kept at once: a reboot must not fire it again
  if (firing_)
    next_(now_us);
}

// --- kept through a reboot ----------------------------------------------------------------

void Deadman::save(uint64_t now_us) {
  saved_us_ = now_us;
  dirty_ = false;
  if (!hooks_.save)
    return;
  // The entry being fired is still to be put back until its outcome is kept: a restart
  // fires it again, and its read then shows whether this firing already did.
  std::map<uint8_t, DeadmanEntry> armed = armed_;
  if (current_)
    armed.emplace(current_->number, *current_);
  DeadmanSaved saved{};
  saved.magic = DeadmanSaved::MAGIC;
  saved.silence_s = silence_s();
  for (const auto &[number, entry] : armed) {
    if (saved.armed_count == DeadmanSaved::ENTRIES || entry.frame.size() != DeadmanSaved::FRAME_LEN)
      continue;
    auto &a = saved.armed[saved.armed_count++];
    a.number = entry.number;
    a.width = entry.width;
    a.reg = entry.reg;
    a.expected = entry.expected;
    std::memcpy(a.frame, entry.frame.data(), DeadmanSaved::FRAME_LEN);
  }
  for (const auto &[number, outcome] : fired_) {
    if (saved.fired_count == DeadmanSaved::ENTRIES)
      break;
    auto &f = saved.fired[saved.fired_count++];
    f.entry = outcome.entry;
    f.outcome = static_cast<uint8_t>(outcome.outcome);
    f.reg = outcome.reg;
    f.read = outcome.read;
  }
  hooks_.save(saved);
}

void Deadman::load_() {
  if (!hooks_.load)
    return;
  DeadmanSaved saved{};
  if (!hooks_.load(saved))
    return;
  if (saved.magic != DeadmanSaved::MAGIC || saved.armed_count > DeadmanSaved::ENTRIES ||
      saved.fired_count > DeadmanSaved::ENTRIES) {
    log_("dead-man: what was saved couldn't be read");
    return;
  }
  silence_us_ =
      uint64_t(std::min<uint32_t>(std::max<uint32_t>(saved.silence_s, SILENCE_MIN_S), SILENCE_MAX_S)) * 1000000;
  for (size_t i = 0; i < saved.armed_count; i++) {
    const auto &a = saved.armed[i];
    armed_[a.number] = DeadmanEntry{a.number, a.width, a.reg, a.expected,
                                    std::vector<uint8_t>(a.frame, a.frame + DeadmanSaved::FRAME_LEN)};
  }
  for (size_t i = 0; i < saved.fired_count; i++) {
    const auto &f = saved.fired[i];
    fired_[f.entry] = DeadmanOutcome{f.entry, static_cast<FiredOutcome>(f.outcome), f.reg, f.read, 0};
  }
  log_("dead-man: " + std::to_string(armed_.size()) + " entries armed from what was saved");
}

void Deadman::log_(const std::string &text) const {
  if (hooks_.log)
    hooks_.log(text);
}

}  // namespace tgw
}  // namespace nibegw
}  // namespace esphome
