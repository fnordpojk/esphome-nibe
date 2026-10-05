#include "TgwControl.h"

#include <algorithm>
#include <cstring>

namespace esphome {
namespace nibegw {
namespace tgw {

namespace {

constexpr uint32_t BASE_FEATURES =
    feature::FATE | feature::ANSWER_PAIRING | feature::FRAMES | feature::HEALTH | feature::PRIORITY | feature::TTL;
constexpr uint32_t KNOWN_SUBSCRIPTIONS = subscription::FRAMES_ALL | subscription::FRAMES_OWN | subscription::HEALTH;

uint16_t clamp(const std::vector<Option> &options, Tag tag, uint16_t low, uint16_t fallback, uint16_t high) {
  const Option *option = find_option(options, tag);
  if (option == nullptr)
    return fallback;
  return std::min<uint32_t>(std::max<uint32_t>(option->as_uint(), low), high);
}

uint32_t ms_since(uint64_t then_us, uint64_t now_us) {
  return now_us > then_us ? (now_us - then_us) / 1000 : 0;
}

}  // namespace

Control::Control(Engine &engine, const BusStats &bus, ControlSettings settings)
    : engine_(engine), bus_(bus), settings_(std::move(settings)) {}

// --- datagrams in -------------------------------------------------------------------------

std::vector<Datagram> Control::handle(const uint8_t *data, size_t len, const Peer &from, uint64_t now_us) {
  std::vector<Datagram> out;
  auto found = sessions_.find(from);
  Session *session = found == sessions_.end() ? nullptr : found->second.get();
  Decoded d = decode(data, len);
  if (!d.ok()) {
    refused_(d, from, session, now_us, out);
    return out;
  }
  const Message &msg = d.msg;
  if (msg.type == MessageType::HELLO) {
    hello_(d, data, len, from, now_us, out);
    return out;
  }
  if (session == nullptr) {
    error_(from, nullptr, settings_.has_psk ? ErrorCode::AUTH_REQUIRED : ErrorCode::NO_SESSION, msg.id, now_us, out);
    return out;
  }
  if (session->has_key && !signature_ok_(*session, d, data, len, now_us, out))
    return out;
  session->expires_us = now_us + session->lease_us;
  switch (msg.type) {
    case MessageType::KEEPALIVE:
      break;
    case MessageType::BYE:
      end_(from);
      return out;
    case MessageType::SUBSCRIBE: {
      const Option *asked = find_option(msg.options, Tag::SUBSCRIBE);
      if (asked != nullptr)
        session->subscribe = asked->as_uint() & KNOWN_SUBSCRIPTIONS;
      break;
    }
    case MessageType::REQUEST:
      engine_.submit(session, msg, now_us);
      break;
    case MessageType::CANCEL:
      if (!engine_.cancel(session, msg.id, now_us))
        error_(from, session, ErrorCode::UNKNOWN_REQUEST, msg.id, now_us, out);
      break;
    default:
      error_(from, session, ErrorCode::UNKNOWN_TYPE, msg.id, now_us, out);
      break;
  }
  flush_(out);
  return out;
}

void Control::refused_(const Decoded &d, const Peer &from, Session *session, uint64_t now_us,
                       std::vector<Datagram> &out) {
  if (settings_.has_psk && session == nullptr) {
    error_(from, nullptr, ErrorCode::AUTH_REQUIRED, 0, now_us, out);
    return;
  }
  uint32_t id = d.header_ok ? d.msg.id : 0;
  error_(from, session, d.error, id, now_us, out, d.has_error_tag, d.error_tag, d.detail);
  if (session != nullptr && d.error == ErrorCode::UNSUPPORTED_OPTION && d.header_ok &&
      d.raw_type == static_cast<uint8_t>(MessageType::REQUEST)) {
    Message fate;
    fate.type = MessageType::FATE;
    fate.id = id;
    fate.gw_time_us = now_us;
    fate.stage = static_cast<uint8_t>(Stage::DROPPED);
    fate.detail = static_cast<uint16_t>(DropReason::UNSUPPORTED_OPTION);
    fate.stage_time_us = now_us;
    send_(*session, fate, out);
  }
}

bool Control::signature_ok_(Session &session, const Decoded &d, const uint8_t *data, size_t len, uint64_t now_us,
                            std::vector<Datagram> &out) {
  uint32_t seq = 0;
  if (verify(data, len, session.key, &seq) != Verify::OK) {
    stats.auth_failures++;
    error_(session.addr, &session, ErrorCode::AUTH_FAILED, d.msg.id, now_us, out);
    return false;
  }
  if (seq <= session.recv_seq) {
    stats.replays_rejected++;
    error_(session.addr, &session, ErrorCode::REPLAY, d.msg.id, now_us, out);
    return false;
  }
  session.recv_seq = seq;
  return true;
}

void Control::hello_(const Decoded &d, const uint8_t *data, size_t len, const Peer &from, uint64_t now_us,
                     std::vector<Datagram> &out) {
  const Message &msg = d.msg;
  const auto &s = settings_;
  if (!s.sources.empty() && std::find(s.sources.begin(), s.sources.end(), from.ip) == s.sources.end()) {
    error_(from, nullptr, ErrorCode::SOURCE_REFUSED, msg.id, now_us, out);
    return;
  }
  const Option *nonce = find_option(msg.options, Tag::CLIENT_NONCE);
  if (!s.has_psk) {
    if (nonce != nullptr && nonce->critical()) {
      error_(from, nullptr, ErrorCode::UNSUPPORTED_OPTION, msg.id, now_us, out, true, nonce->tag);
      return;
    }
  } else {
    if (nonce == nullptr || !d.is_signed) {
      error_(from, nullptr, ErrorCode::AUTH_REQUIRED, msg.id, now_us, out);
      return;
    }
    uint32_t seq = 0;
    if (verify(data, len, s.psk, &seq) != Verify::OK) {
      stats.auth_failures++;
      error_(from, nullptr, ErrorCode::AUTH_FAILED, msg.id, now_us, out);
      return;
    }
  }
  if (!(msg.ver_min <= VERSION_MAJOR && VERSION_MAJOR <= msg.ver_max)) {
    error_(from, nullptr, ErrorCode::BAD_VERSION, msg.id, now_us, out);
    return;
  }
  bool known = sessions_.count(from) != 0;
  if (!known && sessions_.size() >= s.max_clients) {
    error_(from, nullptr, ErrorCode::TOO_MANY_CLIENTS, msg.id, now_us, out);
    return;
  }
  if (known)
    end_(from);

  uint16_t lease_s = clamp(msg.options, Tag::LEASE_S, LEASE_MIN_S, LEASE_DEFAULT_S, LEASE_MAX_S);
  uint16_t health_s = clamp(msg.options, Tag::HEALTH_INTERVAL_S, HEALTH_MIN_S, HEALTH_DEFAULT_S, HEALTH_MAX_S);
  const Option *asked = find_option(msg.options, Tag::SUBSCRIBE);
  auto session = std::make_unique<Session>();
  session->addr = from;
  session->subscribe = asked != nullptr ? asked->as_uint() & KNOWN_SUBSCRIPTIONS : 0;
  session->lease_us = uint64_t(lease_s) * 1000000;
  session->health_interval_us = uint64_t(health_s) * 1000000;
  session->expires_us = now_us + session->lease_us;
  session->next_health_us = now_us + session->health_interval_us;

  Message welcome;
  welcome.type = MessageType::WELCOME;
  welcome.id = msg.id;
  welcome.gw_time_us = now_us;
  auto &o = welcome.options;
  o.push_back(Option::u32(Tag::BOOT_ID, s.boot_id));
  o.push_back(Option::u32(Tag::FEATURES, BASE_FEATURES | (s.has_psk ? feature::AUTH : 0)));
  if (s.has_psk) {
    uint8_t gateway_nonce[NONCE_LEN];
    if (s.random)
      s.random(gateway_nonce, NONCE_LEN);
    o.push_back(Option::bytes(Tag::GATEWAY_NONCE, gateway_nonce, NONCE_LEN));
    if (!session_key(s.psk, nonce->value.data(), gateway_nonce, s.boot_id, session->key))
      return;
    session->has_key = true;
  }
  o.push_back(Option::text(Tag::IMPL, s.impl));
  o.push_back(Option::text(Tag::IMPL_VERSION, s.impl_version));
  o.push_back(Option::u32(Tag::UPTIME_S, uptime_s_(now_us)));
  o.push_back(Option::u8(Tag::QUEUE_CAP, engine_.queue_cap()));
  o.push_back(Option::u8(Tag::MAX_CLIENTS, s.max_clients));
  o.push_back(Option::u16(Tag::ANSWER_TIMEOUT_MS, s.answer_timeout_ms));
  o.push_back(Option::u32(Tag::TIMESTAMP_LAG_MAX_US, s.timestamp_lag_max_us));
  if (s.has_plain_ports) {
    Option ports = Option::u16(Tag::PLAIN_PORTS, s.plain_read_port);
    ports.value.push_back(s.plain_write_port & 0xFF);
    ports.value.push_back(s.plain_write_port >> 8);
    o.push_back(ports);
  }
  std::vector<uint16_t> acknowledged = s.acknowledged;
  std::sort(acknowledged.begin(), acknowledged.end());
  for (auto address : acknowledged)
    o.push_back(Option::u16(Tag::ACK_ADDRESS, address));
  o.push_back(Option::u32(Tag::SUBSCRIBE, session->subscribe));
  o.push_back(Option::u16(Tag::LEASE_S, lease_s));
  o.push_back(Option::u16(Tag::HEALTH_INTERVAL_S, health_s));

  Session &added = *session;
  sessions_[from] = std::move(session);
  send_(added, welcome, out);
}

// --- events out ---------------------------------------------------------------------------

std::vector<Datagram> Control::on_exchange(const Exchange &exchange) {
  std::vector<Datagram> out;
  auto replied = engine_.on_exchange(exchange);
  const void *owner = replied ? replied->owner : nullptr;
  for (auto &[addr, session] : sessions_) {
    bool own = owner != nullptr && owner == session.get();
    if (!((session->subscribe & subscription::FRAMES_ALL) || (own && (session->subscribe & subscription::FRAMES_OWN))))
      continue;
    session->event_seq++;
    Message frame;
    frame.type = MessageType::FRAME;
    frame.id = session->event_seq;
    frame.gw_time_us = exchange.t_complete_us;
    frame.kind = static_cast<uint8_t>(exchange.kind);
    frame.origin = static_cast<uint8_t>(origin_(exchange, replied, *session));
    frame.request_id = own ? replied->id : 0;
    frame.t_complete_us = exchange.t_complete_us;
    frame.t_reply_us = exchange.t_reply_us;
    frame.frame = exchange.data;
    send_(*session, frame, out);
  }
  flush_(out);
  return out;
}

std::vector<Datagram> Control::tick(uint64_t now_us) {
  std::vector<Datagram> out;
  engine_.tick(now_us);
  std::vector<Peer> expired;
  for (const auto &[addr, session] : sessions_) {
    if (session->expires_us <= now_us)
      expired.push_back(addr);
  }
  for (const auto &addr : expired)
    end_(addr);
  bool active = bus_.last_byte_us != 0 && now_us - bus_.last_byte_us < SILENT_AFTER_US;
  bool changed = active != bus_active_;
  bus_active_ = active;
  for (auto &[addr, session] : sessions_) {
    if (!(session->subscribe & subscription::HEALTH))
      continue;
    if (changed || now_us >= session->next_health_us) {
      session->next_health_us = now_us + session->health_interval_us;
      send_(*session, health_(*session, now_us), out);
    }
  }
  for (auto it = last_error_us_.begin(); it != last_error_us_.end();)
    it = now_us - it->second < ERROR_INTERVAL_US ? std::next(it) : last_error_us_.erase(it);
  flush_(out);
  return out;
}

std::vector<Datagram> Control::shutdown(uint64_t now_us) {
  std::vector<Datagram> out;
  engine_.shutdown(now_us);
  flush_(out);
  return out;
}

void Control::note_loop_gap(uint32_t gap_ms) {
  for (auto &[addr, session] : sessions_)
    session->loop_gap_max_ms = std::max(session->loop_gap_max_ms, gap_ms);
}

void Control::note_reply_prep(uint32_t prep_us) {
  for (auto &[addr, session] : sessions_)
    session->reply_prep_max_us = std::max(session->reply_prep_max_us, prep_us);
}

bool Control::has_frame_subscribers() const {
  for (const auto &[addr, session] : sessions_) {
    if (session->subscribe & (subscription::FRAMES_ALL | subscription::FRAMES_OWN))
      return true;
  }
  return false;
}

// --- helpers ------------------------------------------------------------------------------

Origin Control::origin_(const Exchange &exchange, const std::optional<RequestMeta> &replied,
                        const Session &session) const {
  switch (exchange.reply) {
    case Exchange::Reply::NONE:
      return exchange.kind == FrameKind::TO_GATEWAY ? Origin::ACK_ONLY : Origin::NONE;
    case Exchange::Reply::CONSTANT:
      return Origin::CONSTANT;
    case Exchange::Reply::QUEUED:
      break;
  }
  if (!replied || replied->owner == nullptr)
    return Origin::PLAIN_CLIENT;
  return replied->owner == &session ? Origin::THIS_CLIENT : Origin::OTHER_CLIENT;
}

Message Control::health_(Session &session, uint64_t now_us) {
  const auto &b = bus_;
  const auto &e = engine_.stats;
  Message health;
  health.type = MessageType::HEALTH;
  health.gw_time_us = now_us;
  auto &o = health.options;
  o.push_back(Option::u32(Tag::BOOT_ID, settings_.boot_id));
  o.push_back(Option::u32(Tag::UPTIME_S, uptime_s_(now_us)));
  o.push_back(Option::u8(Tag::BUS_STATE, static_cast<uint8_t>(bus_active_ ? BusState::ACTIVE : BusState::SILENT)));
  if (b.last_byte_us != 0)
    o.push_back(Option::u32(Tag::MS_SINCE_LAST_BYTE, ms_since(b.last_byte_us, now_us)));
  if (b.last_token_us != 0)
    o.push_back(Option::u32(Tag::MS_SINCE_LAST_TOKEN, ms_since(b.last_token_us, now_us)));
  o.push_back(Option::u32(Tag::FRAMES_OK, b.frames_ok));
  o.push_back(Option::u32(Tag::CRC_ERRORS, b.crc_errors));
  o.push_back(Option::u32(Tag::NAKS_SENT, b.naks_sent));
  if (b.counts_invalid_bytes)
    o.push_back(Option::u32(Tag::INVALID_BYTES, b.invalid_bytes));
  o.push_back(Option::u32(Tag::PUMP_NAKS, b.pump_naks));
  o.push_back(Option::u32(Tag::NO_ACK_SEEN, b.no_ack_seen));
  o.push_back(Option::u32(Tag::TOKENS_WITH_REPLY, b.tokens_with_reply));
  o.push_back(Option::u32(Tag::TOKENS_ACK_ONLY, b.tokens_ack_only));
  for (size_t reason = 0; reason < e.drops.size(); reason++) {
    if (e.drops[reason] == 0)
      continue;
    Option drops = Option::u16(Tag::DROPS, reason);
    for (int i = 0; i < 4; i++)
      drops.value.push_back((e.drops[reason] >> (8 * i)) & 0xFF);
    o.push_back(drops);
  }
  o.push_back(Option::u32(Tag::EVICTIONS, e.evictions));
  o.push_back(Option::u32(Tag::AMBIGUOUS_ANSWERS, e.ambiguous_answers));
  o.push_back(Option::u32(Tag::ANSWER_TIMEOUTS, e.answer_timeouts));
  o.push_back(Option::u32(Tag::LOOP_GAP_MAX_MS, session.loop_gap_max_ms));
  o.push_back(Option::u32(Tag::REPLY_PREP_MAX_US, session.reply_prep_max_us));
  o.push_back(Option::u32(Tag::UDP_SEND_ERRORS, stats.udp_send_errors));
  o.push_back(Option::u32(Tag::EVENTS_DROPPED, stats.events_dropped));
  o.push_back(Option::u8(Tag::CLIENTS, sessions_.size()));
  for (const auto &[key, depth] : engine_.depths()) {
    Option q = Option::u16(Tag::QUEUE_DEPTH, std::get<0>(key));
    q.value.push_back(std::get<1>(key));
    q.value.push_back(std::min<size_t>(depth, 0xFF));
    o.push_back(q);
  }
  if (settings_.has_psk) {
    o.push_back(Option::u32(Tag::AUTH_FAILURES, stats.auth_failures));
    o.push_back(Option::u32(Tag::REPLAYS_REJECTED, stats.replays_rejected));
  }
  if (settings_.platform_health)
    settings_.platform_health(o);
  session.loop_gap_max_ms = 0;
  session.reply_prep_max_us = 0;
  session.event_seq++;
  health.id = session.event_seq;
  return health;
}

void Control::flush_(std::vector<Datagram> &out) {
  for (auto &item : engine_.take_outbox()) {
    for (auto &[addr, session] : sessions_) {
      if (session.get() == item.client) {
        send_(*session, item.message, out);
        break;
      }
    }
  }
}

void Control::send_(Session &session, const Message &msg, std::vector<Datagram> &out) {
  std::vector<uint8_t> data;
  if (session.has_key) {
    session.send_seq++;
    data = encode(msg, session.key, session.send_seq);
  } else {
    data = encode(msg);
  }
  if (data.empty()) {
    stats.events_dropped++;
    return;
  }
  out.push_back(Datagram{session.addr, std::move(data)});
}

void Control::error_(const Peer &to, Session *session, ErrorCode code, uint32_t id, uint64_t now_us,
                     std::vector<Datagram> &out, bool has_tag, uint16_t tag, const std::string &detail) {
  auto last = last_error_us_.find(to);
  if (last != last_error_us_.end() && now_us - last->second < ERROR_INTERVAL_US)
    return;
  last_error_us_[to] = now_us;
  Message error;
  error.type = MessageType::ERROR;
  error.id = id;
  error.gw_time_us = now_us;
  error.code = static_cast<uint16_t>(code);
  if (has_tag)
    error.options.push_back(Option::u16(Tag::ERR_TAG, tag));
  if (!detail.empty())
    error.options.push_back(Option::text(Tag::ERR_DETAIL, detail.substr(0, 200)));
  if (session != nullptr) {
    send_(*session, error, out);
    return;
  }
  auto data = encode(error);
  if (!data.empty())
    out.push_back(Datagram{to, std::move(data)});
}

void Control::end_(const Peer &addr) {
  auto found = sessions_.find(addr);
  if (found == sessions_.end())
    return;
  engine_.forget(found->second.get());
  sessions_.erase(found);
}

uint32_t Control::uptime_s_(uint64_t now_us) const {
  return now_us > settings_.started_us ? (now_us - settings_.started_us) / 1000000 : 0;
}

}  // namespace tgw
}  // namespace nibegw
}  // namespace esphome
