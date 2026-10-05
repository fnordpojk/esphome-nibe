#include "TgwEngine.h"

#include <algorithm>

namespace esphome {
namespace nibegw {
namespace tgw {

namespace {

const request_key_type READ_KEY{bus::MODBUS40_ADDR, bus::READ_TOKEN_CMD};
const request_key_type WRITE_KEY{bus::MODBUS40_ADDR, bus::WRITE_TOKEN_CMD};

uint16_t register_of(const request_data_type &frame) {
  return frame.size() >= 5 ? frame[3] | (frame[4] << 8) : 0;
}

bool expects_answer(const RequestMeta &meta) {
  return meta.owner != nullptr && (meta.flags & request_flag::EXPECT_ANSWER) != 0;
}

}  // namespace

uint8_t bus_checksum(const uint8_t *data, size_t len) {
  uint8_t x = 0;
  for (size_t i = 0; i < len; i++)
    x ^= data[i];
  return x == bus::START_TELEGRAM ? 0xC5 : x;
}

bool valid_reply(const request_data_type &frame) {
  if (frame.size() < 4 || frame[0] != bus::START_REPLY || frame.size() != 4u + frame[2])
    return false;
  return frame.back() == bus_checksum(frame.data(), frame.size() - 1);
}

Exchange make_exchange(const uint8_t *data, size_t len, bool acknowledged, Exchange::Reply reply, size_t reply_len,
                       uint64_t t_complete_us, uint64_t t_reply_us) {
  Exchange x;
  x.data.assign(data, data + len);
  x.reply = reply;
  x.t_complete_us = t_complete_us;
  x.t_reply_us = t_reply_us;
  if (len < 6 || data[0] != bus::START_TELEGRAM)
    return x;
  x.address = (data[1] << 8) | data[2];
  x.command = data[3];
  x.telegram_len = 6u + data[4];
  if (len < x.telegram_len)
    return x;
  const uint8_t *raw = data + 5;
  size_t raw_len = data[4];
  x.parsed = data[x.telegram_len - 1] == bus_checksum(data + 1, x.telegram_len - 2);
  if (!x.parsed)
    return x;
  for (size_t i = 0; i < raw_len; i++) {
    x.payload.push_back(raw[i]);
    if (raw[i] == bus::START_TELEGRAM && i + 1 < raw_len && raw[i + 1] == bus::START_TELEGRAM)
      i++;
  }
  x.kind = acknowledged ? FrameKind::TO_GATEWAY : FrameKind::TO_OTHER;
  size_t closing = x.telegram_len + (reply != Exchange::Reply::NONE ? reply_len : 0);
  if (acknowledged && len > closing)
    x.trailer = data[len - 1];
  return x;
}

Engine::Engine(request_queues_type &queues, std::set<request_key_type> keys, size_t queue_cap,
               uint32_t default_answer_timeout_us)
    : queues_(queues),
      keys_(std::move(keys)),
      queue_cap_(queue_cap),
      default_answer_timeout_us_(default_answer_timeout_us) {
  keys_.insert(READ_KEY);
  keys_.insert(WRITE_KEY);
}

std::deque<QueuedRequest> &Engine::queue_(const request_key_type &key) {
  return queues_[key];
}

// --- requests in --------------------------------------------------------------------------

void Engine::submit(const void *client, const Message &request, uint64_t now_us) {
  request_key_type key{request.address, request.token};
  RequestMeta meta;
  meta.owner = client;
  meta.id = request.id;
  meta.deadline_us = request.ttl_ms ? now_us + uint64_t(request.ttl_ms) * 1000 : 0;
  meta.flags = request.request_flags;
  meta.answer_timeout_us =
      request.answer_timeout_ms ? uint32_t(request.answer_timeout_ms) * 1000 : default_answer_timeout_us_;
  auto reason = invalid_(request.frame, key);
  if (!reason && queue_(key).size() >= queue_cap_)
    reason = DropReason::QUEUE_FULL;
  if (reason) {
    drop_(meta, *reason, now_us);
    return;
  }
  auto &queue = queue_(key);
  uint16_t ahead = 0;
  if (request.request_flags & request_flag::PRIORITY) {
    queue.push_front(QueuedRequest{request.frame, meta});
  } else {
    queue.push_back(QueuedRequest{request.frame, meta});
    ahead = queue.size() - 1;
  }
  fate_(meta, Stage::QUEUED, now_us, ahead);
}

bool Engine::submit_plain(uint16_t address, uint8_t token, request_data_type frame, uint64_t now_us) {
  request_key_type key{address, token};
  if (invalid_(frame, key))
    return false;
  auto &queue = queue_(key);
  if (queue.size() >= queue_cap_) {
    QueuedRequest oldest = std::move(queue.front());
    queue.pop_front();
    if (oldest.meta.owner != nullptr) {
      stats.evictions++;
      drop_(oldest.meta, DropReason::EVICTED, now_us);
    }
  }
  RequestMeta meta;
  meta.answer_timeout_us = default_answer_timeout_us_;
  queue.push_back(QueuedRequest{std::move(frame), meta});
  return true;
}

bool Engine::cancel(const void *client, uint32_t id, uint64_t now_us) {
  for (auto &[key, queue] : queues_) {
    for (auto it = queue.begin(); it != queue.end(); ++it) {
      if (it->meta.owner == client && it->meta.id == id) {
        RequestMeta meta = it->meta;
        queue.erase(it);
        drop_(meta, DropReason::CANCELLED, now_us);
        return true;
      }
    }
  }
  return false;
}

void Engine::forget(const void *client) {
  for (auto &[key, queue] : queues_) {
    queue.erase(
        std::remove_if(queue.begin(), queue.end(), [client](const QueuedRequest &q) { return q.meta.owner == client; }),
        queue.end());
  }
  for (auto &[reg, waiting] : reads_) {
    for (auto &taken : waiting) {
      if (taken.meta.owner == client)
        taken.meta.owner = nullptr;
    }
  }
  for (auto &taken : writes_) {
    if (taken.meta.owner == client)
      taken.meta.owner = nullptr;
  }
}

void Engine::shutdown(uint64_t now_us) {
  for (auto &[key, queue] : queues_) {
    for (const auto &q : queue) {
      if (q.meta.owner != nullptr)
        drop_(q.meta, DropReason::SHUTDOWN, now_us);
    }
    queue.clear();
  }
}

// --- the bus ------------------------------------------------------------------------------

const QueuedRequest *Engine::reply_for(uint16_t address, uint8_t command, uint64_t now_us) {
  replying_.reset();
  request_key_type key{address, command};
  auto found = queues_.find(key);
  if (found == queues_.end())
    return nullptr;
  auto &queue = found->second;
  bool is_write = key == WRITE_KEY;
  for (auto it = queue.begin(); it != queue.end();) {
    if (it->meta.deadline_us != 0 && now_us >= it->meta.deadline_us) {
      RequestMeta meta = it->meta;
      it = queue.erase(it);
      if (meta.owner != nullptr)
        drop_(meta, DropReason::EXPIRED, now_us);
      continue;
    }
    if (it->meta.owner != nullptr && is_write && !writes_.empty()) {
      ++it;  // one protocol write in flight at a time
      continue;
    }
    replying_ = std::move(*it);
    replying_sent_us_ = now_us;
    queue.erase(it);
    fate_(replying_->meta, Stage::SENT, now_us);
    return &*replying_;
  }
  return nullptr;
}

std::optional<RequestMeta> Engine::on_exchange(const Exchange &exchange) {
  uint64_t now = exchange.t_complete_us;
  std::optional<RequestMeta> replied;
  if (exchange.reply == Exchange::Reply::QUEUED && replying_) {
    QueuedRequest sent = std::move(*replying_);
    replying_.reset();
    replied = sent.meta;
    Stage stage = exchange.trailer == bus::ACK_BYTE   ? Stage::PUMP_ACK
                  : exchange.trailer == bus::NAK_BYTE ? Stage::PUMP_NAK
                                                      : Stage::NO_ACK_SEEN;
    fate_(sent.meta, stage, now);
    if (stage != Stage::PUMP_NAK) {
      request_key_type key{exchange.address, exchange.command};
      Taken taken{sent.meta, replying_sent_us_, register_of(sent.data)};
      if (key == WRITE_KEY) {
        writes_.push_back(taken);
      } else if (key == READ_KEY) {
        reads_[taken.reg].push_back(taken);
      }
    }
  }
  if (!exchange.parsed || exchange.address != bus::MODBUS40_ADDR)
    return replied;
  std::vector<uint8_t> raw(exchange.data.begin(), exchange.data.begin() + exchange.telegram_len);
  if (exchange.command == bus::READ_ANSWER_CMD && exchange.payload.size() >= 2) {
    uint16_t reg = exchange.payload[0] | (exchange.payload[1] << 8);
    auto found = reads_.find(reg);
    if (found != reads_.end()) {
      auto &waiting = found->second;
      // One that should have been answered by now lost its answer; this one isn't it.
      while (!waiting.empty() && overdue_(waiting.front(), now)) {
        timeout_(waiting.front(), now);
        waiting.pop_front();
      }
      if (!waiting.empty()) {
        Taken read = waiting.front();
        waiting.pop_front();
        if (expects_answer(read.meta))
          answer_(read.meta, AnswerStatus::OK, raw, now);
      }
      if (waiting.empty())
        reads_.erase(found);
    }
  } else if (exchange.command == bus::WRITE_ANSWER_CMD && !writes_.empty()) {
    bool ambiguous = writes_.size() > 1;
    Taken written = writes_.front();
    writes_.pop_front();
    if (expects_answer(written.meta)) {
      if (ambiguous)
        stats.ambiguous_answers++;
      answer_(written.meta, ambiguous ? AnswerStatus::AMBIGUOUS : AnswerStatus::OK, raw, now);
    }
  }
  return replied;
}

void Engine::tick(uint64_t now_us) {
  for (auto &[key, queue] : queues_) {
    for (auto it = queue.begin(); it != queue.end();) {
      if (it->meta.deadline_us != 0 && now_us >= it->meta.deadline_us) {
        RequestMeta meta = it->meta;
        it = queue.erase(it);
        if (meta.owner != nullptr)
          drop_(meta, DropReason::EXPIRED, now_us);
      } else {
        ++it;
      }
    }
  }
  for (auto it = reads_.begin(); it != reads_.end();) {
    auto &waiting = it->second;
    for (auto r = waiting.begin(); r != waiting.end();) {
      if (overdue_(*r, now_us)) {
        timeout_(*r, now_us);
        r = waiting.erase(r);
      } else {
        ++r;
      }
    }
    it = waiting.empty() ? reads_.erase(it) : std::next(it);
  }
  for (auto it = writes_.begin(); it != writes_.end();) {
    if (overdue_(*it, now_us)) {
      timeout_(*it, now_us);
      it = writes_.erase(it);
    } else {
      ++it;
    }
  }
}

// --- out ----------------------------------------------------------------------------------

std::vector<Outgoing> Engine::take_outbox() {
  std::vector<Outgoing> out;
  out.swap(outbox_);
  return out;
}

std::map<request_key_type, size_t> Engine::depths() const {
  std::map<request_key_type, size_t> out;
  for (const auto &key : keys_) {
    auto found = queues_.find(key);
    out[key] = found == queues_.end() ? 0 : found->second.size();
  }
  return out;
}

// --- helpers ------------------------------------------------------------------------------

std::optional<DropReason> Engine::invalid_(const request_data_type &frame, const request_key_type &key) const {
  if (!valid_reply(frame))
    return DropReason::INVALID_FRAME;
  if (frame[1] != std::get<1>(key))
    return DropReason::TOKEN_MISMATCH;
  if (keys_.count(key) == 0)
    return DropReason::UNKNOWN_KEY;
  return std::nullopt;
}

bool Engine::overdue_(const Taken &taken, uint64_t now_us) const {
  return now_us >= taken.sent_us + taken.meta.answer_timeout_us;
}

void Engine::fate_(const RequestMeta &meta, Stage stage, uint64_t now_us, uint16_t detail) {
  if (meta.owner == nullptr)
    return;
  Message fate;
  fate.type = MessageType::FATE;
  fate.id = meta.id;
  fate.gw_time_us = now_us;
  fate.stage = static_cast<uint8_t>(stage);
  fate.detail = detail;
  fate.stage_time_us = now_us;
  outbox_.push_back(Outgoing{meta.owner, std::move(fate)});
}

void Engine::drop_(const RequestMeta &meta, DropReason reason, uint64_t now_us) {
  auto index = static_cast<size_t>(reason);
  if (index < stats.drops.size())
    stats.drops[index]++;
  fate_(meta, Stage::DROPPED, now_us, static_cast<uint16_t>(reason));
}

void Engine::answer_(const RequestMeta &meta, AnswerStatus status, const std::vector<uint8_t> &frame, uint64_t now_us) {
  if (meta.owner == nullptr)
    return;
  Message answer;
  answer.type = MessageType::ANSWER;
  answer.id = meta.id;
  answer.gw_time_us = now_us;
  answer.status = static_cast<uint8_t>(status);
  answer.frame = frame;
  outbox_.push_back(Outgoing{meta.owner, std::move(answer)});
}

// No answer came in time; only a protocol client that asked for one hears of it.
void Engine::timeout_(const Taken &taken, uint64_t now_us) {
  if (!expects_answer(taken.meta))
    return;
  stats.answer_timeouts++;
  answer_(taken.meta, AnswerStatus::TIMEOUT, {}, now_us);
}

}  // namespace tgw
}  // namespace nibegw
}  // namespace esphome
