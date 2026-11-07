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

uint16_t clamp_silence(uint32_t seconds) {
  return std::min<uint32_t>(std::max<uint32_t>(seconds, Deadman::SILENCE_MIN_S), Deadman::SILENCE_MAX_S);
}

}  // namespace

Deadman::Deadman(Engine &engine, uint64_t now_us, DeadmanHooks hooks)
    : engine_(engine), hooks_(std::move(hooks)), saved_us_(now_us) {
  load_(now_us);
}

// --- the client ---------------------------------------------------------------------------

std::optional<std::pair<uint16_t, uint8_t>> Deadman::grant(const ClientId &client, uint32_t asked_s,
                                                           uint32_t asked_entries, uint64_t now_us) {
  uint16_t seconds = clamp_silence(asked_s);
  auto known = clients_.find(client);
  if (known == clients_.end()) {
    auto unowned = clients_.find(ClientId());
    if (unowned != clients_.end()) {
      log_("dead-man: the entries kept before clients were known are this one's");
      Client adopted = std::move(unowned->second);
      clients_.erase(unowned);
      known = clients_.emplace(client, std::move(adopted)).first;
      if (firing_.erase(ClientId()) != 0)
        firing_.insert(client);
      for (auto &[c, entry] : queue_) {
        if (c.empty())
          c = client;
      }
      if (current_ && current_->first.empty())
        current_->first = client;
      dirty_ = true;
    } else if (holding_(client) >= MAX_CLIENTS) {
      log_("dead-man: entries are held for " + std::to_string(MAX_CLIENTS) + " other clients");
      return std::nullopt;
    } else {
      Client fresh;
      fresh.silence_us = uint64_t(seconds) * 1000000;
      fresh.heard_us = now_us;
      known = clients_.emplace(client, std::move(fresh)).first;
    }
  }
  if (uint64_t(seconds) * 1000000 != known->second.silence_us) {
    known->second.silence_us = uint64_t(seconds) * 1000000;
    dirty_ = true;
  }
  return std::make_pair(seconds, uint8_t(std::min<uint32_t>(asked_entries, ENTRIES)));
}

std::pair<size_t, size_t> Deadman::counts(const ClientId &client) const {
  auto known = clients_.find(client);
  if (known == clients_.end())
    return {0, 0};
  return {known->second.armed.size(), known->second.fired.size()};
}

void Deadman::heard(const ClientId &client, uint64_t now_us) {
  auto known = clients_.find(client);
  if (known == clients_.end())
    return;
  known->second.heard_us = now_us;
  if (firing_.erase(client) != 0) {
    size_t left = 0;
    std::deque<std::pair<ClientId, DeadmanEntry>> others;
    for (auto &queued : queue_) {
      if (queued.first == client)
        left++;
      else
        others.push_back(std::move(queued));
    }
    queue_ = std::move(others);
    log_("dead-man: the client is back, " + std::to_string(left) + " entries left armed");
  }
}

std::optional<Message> Deadman::arm(const ClientId &client, const Message &msg, uint8_t entries, uint16_t silence_s,
                                    uint64_t asker, uint64_t now_us) {
  ArmRefusal refusal = refusal_(msg, entries);
  if (refusal == ArmRefusal::NONE)
    refusal = fired_refusal_(client, msg.entry);
  auto known = clients_.find(client);
  if (refusal == ArmRefusal::NONE && (known == clients_.end() || !known->second.holds()) &&
      holding_(client) >= MAX_CLIENTS)
    refusal = ArmRefusal::NO_ROOM;
  if (refusal != ArmRefusal::NONE)
    return armed_answer_(msg.entry, ArmResult::REFUSED, msg.id, refusal);
  if (known == clients_.end()) {  // it held nothing, and was forgotten while its session lasted
    Client fresh;
    fresh.silence_us = uint64_t(clamp_silence(silence_s)) * 1000000;
    fresh.heard_us = now_us;
    known = clients_.emplace(client, std::move(fresh)).first;
  }
  auto &armed = known->second.armed;
  std::optional<DeadmanEntry> before;
  auto found = armed.find(msg.entry);
  if (found != armed.end())
    before = found->second;
  armed[msg.entry] = DeadmanEntry{msg.entry, msg.width, msg.reg, msg.expected, msg.frame};
  Message answer = armed_answer_(msg.entry, ArmResult::ARMED, msg.id);
  // Kept before it is confirmed: a client told "armed" may stop, and a reboot of the
  // gateway after that must still fire it.
  save(now_us);
  if (!hooks_.save)
    return answer;  // nothing is kept through a reboot anyway
  awaiting_.push_back(Awaiting{asker, client, answer, before});
  return std::nullopt;
}

std::vector<Deadman::Awaiting> Deadman::saved(bool ok) {
  std::vector<Awaiting> done = std::move(awaiting_);
  awaiting_.clear();
  if (ok)
    return done;
  // Not kept, so not armed: each entry goes back to what it held, newest first.
  for (auto it = done.rbegin(); it != done.rend(); ++it) {
    auto known = clients_.find(it->client);
    if (known != clients_.end()) {
      if (it->before)
        known->second.armed[it->answer.entry] = *it->before;
      else
        known->second.armed.erase(it->answer.entry);
    }
    it->answer.result = static_cast<uint8_t>(ArmResult::REFUSED);
    it->answer.detail = static_cast<uint16_t>(ArmRefusal::NOT_KEPT);
  }
  log_("dead-man: what was armed couldn't be saved");
  dirty_ = true;
  return done;
}

Message Deadman::disarm(const ClientId &client, uint8_t entry, uint32_t id) {
  ArmRefusal refusal = fired_refusal_(client, entry);
  if (refusal != ArmRefusal::NONE)
    return armed_answer_(entry, ArmResult::REFUSED, id, refusal);
  auto known = clients_.find(client);
  if (known != clients_.end() && known->second.armed.erase(entry) != 0)
    dirty_ = true;
  return armed_answer_(entry, ArmResult::DISARMED, id);
}

// An entry being fired, or whose outcome isn't acknowledged, keeps its number: a report for
// it is then always for what the client armed last.
ArmRefusal Deadman::fired_refusal_(const ClientId &client, uint8_t entry) const {
  auto known = clients_.find(client);
  if (known != clients_.end() && known->second.fired.count(entry) != 0)
    return ArmRefusal::FIRED;
  if (current_ && current_->first == client && current_->second.number == entry)
    return ArmRefusal::FIRED;
  return ArmRefusal::NONE;
}

Message Deadman::ack_fired(const ClientId &client, uint8_t entry, uint32_t id) {
  auto known = clients_.find(client);
  if (known != clients_.end() && known->second.fired.erase(entry) != 0)
    dirty_ = true;
  return armed_answer_(entry, ArmResult::DISARMED, id);
}

void Deadman::stop(uint64_t now_us) {
  if (current_) {
    auto known = clients_.find(current_->first);
    if (known != clients_.end())
      known->second.armed.emplace(current_->second.number, current_->second);
  }
  current_.reset();
  pending_.reset();
  firing_.clear();
  queue_.clear();
  save(now_us);
}

std::vector<Message> Deadman::reports(const ClientId &client, uint64_t now_us) const {
  std::vector<Message> out;
  auto known = clients_.find(client);
  if (known == clients_.end())
    return out;
  for (const auto &[entry, outcome] : known->second.fired)
    out.push_back(report(outcome, now_us));
  return out;
}

std::vector<std::pair<ClientId, Message>> Deadman::just_fired(uint64_t now_us) {
  std::vector<std::pair<ClientId, Message>> out;
  for (const auto &[client, outcome] : just_fired_)
    out.emplace_back(client, report(outcome, now_us));
  just_fired_.clear();
  return out;
}

// How many other clients the gateway holds entries or reports for.
size_t Deadman::holding_(const ClientId &client) const {
  size_t n = 0;
  for (const auto &[c, known] : clients_) {
    if (c != client && known.holds())
      n++;
  }
  return n;
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
  for (auto &[client, known] : clients_) {
    if (firing_.count(client) == 0 && !known.armed.empty() && now_us - known.heard_us >= known.silence_us) {
      log_("dead-man: a client silent for " + std::to_string(known.silence_us / 1000000) + " s, putting " +
           std::to_string(known.armed.size()) + " back");
      firing_.insert(client);
      for (const auto &[number, entry] : known.armed)
        queue_.emplace_back(client, entry);
    }
  }
  if (!current_)
    next_(now_us);
  forget_(now_us);
  if (dirty_ && now_us - saved_us_ >= SAVE_EVERY_US)
    save(now_us);
}

// Drop the reports nobody acknowledged in time, then the clients holding nothing whose
// sessions have gone quiet.
void Deadman::forget_(uint64_t now_us) {
  for (auto &[client, known] : clients_) {
    for (auto it = known.fired.begin(); it != known.fired.end();) {
      if (now_us - it->second.kept_us >= REPORT_KEPT_US) {
        log_("dead-man: entry " + std::to_string(it->first) + "'s report was never acknowledged");
        it = known.fired.erase(it);
        dirty_ = true;
      } else {
        ++it;
      }
    }
  }
  for (auto it = clients_.begin(); it != clients_.end();) {
    const auto &[client, known] = *it;
    bool busy = firing_.count(client) != 0 || (current_ && current_->first == client);
    for (const auto &queued : queue_)
      busy = busy || queued.first == client;
    for (const auto &waiting : awaiting_)
      busy = busy || waiting.client == client;
    if (!known.holds() && !busy && now_us - known.heard_us >= known.silence_us)
      it = clients_.erase(it);
    else
      ++it;
  }
}

void Deadman::on_message(const Message &message, uint64_t now_us) {
  if (!pending_ || message.id != pending_->first || !current_)
    return;
  DeadmanEntry entry = current_->second;
  Step step = pending_->second;
  DeadmanOutcome no_answer{entry.number, FiredOutcome::NO_ANSWER, entry.reg, 0, 0, 0};
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
      done_({entry.number, FiredOutcome::PUT_BACK, entry.reg, *value, 0, 0}, now_us);
    } else if (*value != (entry.expected & mask(entry.width))) {
      // Someone changed it while the client was silent: theirs stands.
      done_({entry.number, FiredOutcome::SKIPPED, entry.reg, *value, 0, 0}, now_us);
    } else {
      request_(bus::WRITE_TOKEN_CMD, entry.frame, Step::WRITE, now_us);
    }
  } else {
    bool taken = !payload.empty() && payload[0] == 1;
    done_({entry.number, taken ? FiredOutcome::PUT_BACK : FiredOutcome::REFUSED, entry.reg, entry.expected, 0, 0},
          now_us);
  }
}

void Deadman::next_(uint64_t now_us) {
  while (!queue_.empty()) {
    auto [client, entry] = queue_.front();
    queue_.pop_front();
    bool more = false;
    for (const auto &queued : queue_)
      more = more || queued.first == client;
    if (!more)
      firing_.erase(client);  // its last entry: once done, it isn't firing
    auto known = clients_.find(client);
    if (known == clients_.end())
      continue;
    auto found = known->second.armed.find(entry.number);
    if (found == known->second.armed.end() || found->second != entry)
      continue;  // disarmed or armed anew since the firing began: the client knows best
    known->second.armed.erase(found);
    current_ = std::make_pair(client, entry);
    dirty_ = true;
    request_(bus::READ_TOKEN_CMD, read_request(entry.reg), Step::READ, now_us);
    return;
  }
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
  if (!current_)
    return;
  ClientId client = current_->first;
  log_("dead-man: entry " + std::to_string(outcome.entry) + " (" + std::to_string(outcome.reg) +
       "): " + outcome_name(outcome.outcome));
  DeadmanOutcome kept = outcome;
  kept.fired_us = now_us;
  kept.kept_us = now_us;
  auto known = clients_.find(client);
  if (known != clients_.end())
    known->second.fired[kept.entry] = kept;
  just_fired_.emplace_back(client, kept);
  current_.reset();
  pending_.reset();
  dirty_ = true;
  save(now_us);  // a firing is kept at once: a reboot must not fire it again
  next_(now_us);
}

// --- kept through a reboot ----------------------------------------------------------------

void Deadman::save(uint64_t now_us) {
  saved_us_ = now_us;
  dirty_ = false;
  if (!hooks_.save)
    return;
  DeadmanSaved saved{};
  saved.magic = DeadmanSaved::MAGIC;
  for (const auto &[client, known] : clients_) {
    // The entry being fired is still to be put back until its outcome is kept: a restart
    // fires it again, and its read then shows whether this firing already did.
    std::map<uint8_t, DeadmanEntry> armed = known.armed;
    bool firing = current_ && current_->first == client;
    if (firing)
      armed.emplace(current_->second.number, current_->second);
    if (armed.empty() && known.fired.empty())
      continue;
    if (saved.client_count == DeadmanSaved::CLIENTS)
      break;
    auto &c = saved.clients[saved.client_count++];
    c.owned = client.empty() ? 0 : 1;
    std::memcpy(c.id, client.data(), std::min(client.size(), DeadmanSaved::ID_LEN));
    c.silence_s = known.silence_us / 1000000;
    for (const auto &[number, entry] : armed) {
      if (c.armed_count == DeadmanSaved::ENTRIES || entry.frame.size() != DeadmanSaved::FRAME_LEN)
        continue;
      auto &a = c.armed[c.armed_count++];
      a.number = entry.number;
      a.width = entry.width;
      a.reg = entry.reg;
      a.expected = entry.expected;
      std::memcpy(a.frame, entry.frame.data(), DeadmanSaved::FRAME_LEN);
    }
    for (const auto &[number, outcome] : known.fired) {
      if (c.fired_count == DeadmanSaved::ENTRIES)
        break;
      auto &f = c.fired[c.fired_count++];
      f.entry = outcome.entry;
      f.outcome = static_cast<uint8_t>(outcome.outcome);
      f.reg = outcome.reg;
      f.read = outcome.read;
    }
  }
  hooks_.save(saved);
}

namespace {

template<typename T> void load_client(Deadman::Client &known, const T &c) {
  for (size_t i = 0; i < c.armed_count; i++) {
    const auto &a = c.armed[i];
    known.armed[a.number] = DeadmanEntry{a.number, a.width, a.reg, a.expected,
                                         std::vector<uint8_t>(a.frame, a.frame + DeadmanSaved::FRAME_LEN)};
  }
  for (size_t i = 0; i < c.fired_count; i++) {
    const auto &f = c.fired[i];
    known.fired[f.entry] =
        DeadmanOutcome{f.entry, static_cast<FiredOutcome>(f.outcome), f.reg, f.read, 0, known.heard_us};
  }
}

}  // namespace

void Deadman::load_(uint64_t now_us) {
  DeadmanSaved saved{};
  if (hooks_.load && hooks_.load(saved)) {
    if (saved.magic != DeadmanSaved::MAGIC || saved.client_count > DeadmanSaved::CLIENTS) {
      log_("dead-man: what was saved couldn't be read");
      return;
    }
    for (size_t i = 0; i < saved.client_count; i++) {
      const auto &c = saved.clients[i];
      if (c.armed_count > DeadmanSaved::ENTRIES || c.fired_count > DeadmanSaved::ENTRIES) {
        log_("dead-man: what was saved couldn't be read");
        clients_.clear();
        return;
      }
      Client known;
      known.silence_us = uint64_t(clamp_silence(c.silence_s)) * 1000000;
      known.heard_us = now_us;
      load_client(known, c);
      ClientId client = c.owned ? ClientId(reinterpret_cast<const char *>(c.id), DeadmanSaved::ID_LEN) : ClientId();
      if (known.holds())
        clients_[client] = std::move(known);
    }
  } else {
    // Revision 4 kept one set of entries: they go to the first client granted the dead-man.
    DeadmanSavedV1 v1{};
    if (!hooks_.load_v1 || !hooks_.load_v1(v1))
      return;
    if (v1.magic != DeadmanSavedV1::MAGIC || v1.armed_count > DeadmanSavedV1::ENTRIES ||
        v1.fired_count > DeadmanSavedV1::ENTRIES) {
      log_("dead-man: what was saved couldn't be read");
      return;
    }
    Client known;
    known.silence_us = uint64_t(clamp_silence(v1.silence_s)) * 1000000;
    known.heard_us = now_us;
    load_client(known, v1);
    if (known.holds()) {
      clients_[ClientId()] = std::move(known);
      dirty_ = true;
    }
  }
  size_t armed = 0;
  for (const auto &[client, known] : clients_)
    armed += known.armed.size();
  log_("dead-man: " + std::to_string(armed) + " entries armed for " + std::to_string(clients_.size()) +
       " clients from what was saved");
}

void Deadman::log_(const std::string &text) const {
  if (hooks_.log)
    hooks_.log(text);
}

}  // namespace tgw
}  // namespace nibegw
}  // namespace esphome
