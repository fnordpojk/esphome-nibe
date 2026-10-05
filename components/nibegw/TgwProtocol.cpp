#include "TgwProtocol.h"
#include "TgwCrypto.h"

#include <cstring>

namespace esphome {
namespace nibegw {
namespace tgw {

namespace {

static const char SESSION_LABEL[] = "thermaestro-gw session";

void put_u8(std::vector<uint8_t> &out, uint8_t value) {
  out.push_back(value);
}

void put_u16(std::vector<uint8_t> &out, uint16_t value) {
  out.push_back(value & 0xFF);
  out.push_back(value >> 8);
}

void put_u32(std::vector<uint8_t> &out, uint32_t value) {
  for (int i = 0; i < 4; i++)
    out.push_back((value >> (8 * i)) & 0xFF);
}

void put_u64(std::vector<uint8_t> &out, uint64_t value) {
  for (int i = 0; i < 8; i++)
    out.push_back((value >> (8 * i)) & 0xFF);
}

uint64_t get_le(const uint8_t *data, size_t len) {
  uint64_t value = 0;
  for (size_t i = 0; i < len; i++)
    value |= static_cast<uint64_t>(data[i]) << (8 * i);
  return value;
}

// How the registry lays out an option's value.
struct Spec {
  uint16_t number;
  uint8_t size;      // fixed size in bytes; 0 for text
  uint8_t text_max;  // for text: the longest allowed, 0 for no limit
  bool text;
  bool repeatable;
};

constexpr Spec fixed(Tag tag, uint8_t size, bool repeatable = false) {
  return Spec{static_cast<uint16_t>(tag), size, 0, false, repeatable};
}

constexpr Spec text(Tag tag, uint8_t max = 0) {
  return Spec{static_cast<uint16_t>(tag), 0, max, true, false};
}

constexpr Spec SPECS[] = {
    text(Tag::CLIENT_NAME, 32),
    fixed(Tag::CLIENT_NONCE, NONCE_LEN),
    fixed(Tag::SUBSCRIBE, 4),
    fixed(Tag::LEASE_S, 2),
    fixed(Tag::HEALTH_INTERVAL_S, 2),
    fixed(Tag::BOOT_ID, 4),
    fixed(Tag::GATEWAY_NONCE, NONCE_LEN),
    text(Tag::IMPL),
    text(Tag::IMPL_VERSION),
    fixed(Tag::UPTIME_S, 4),
    fixed(Tag::FEATURES, 4),
    fixed(Tag::QUEUE_CAP, 1),
    fixed(Tag::MAX_CLIENTS, 1),
    fixed(Tag::ANSWER_TIMEOUT_MS, 2),
    fixed(Tag::TIMESTAMP_LAG_MAX_US, 4),
    fixed(Tag::PLAIN_PORTS, 4),
    fixed(Tag::ACK_ADDRESS, 2, true),
    fixed(Tag::ERR_TAG, 2),
    text(Tag::ERR_DETAIL),
    fixed(Tag::BUS_STATE, 1),
    fixed(Tag::MS_SINCE_LAST_BYTE, 4),
    fixed(Tag::MS_SINCE_LAST_TOKEN, 4),
    fixed(Tag::FRAMES_OK, 4),
    fixed(Tag::CRC_ERRORS, 4),
    fixed(Tag::NAKS_SENT, 4),
    fixed(Tag::INVALID_BYTES, 4),
    fixed(Tag::PUMP_NAKS, 4),
    fixed(Tag::NO_ACK_SEEN, 4),
    fixed(Tag::TOKENS_WITH_REPLY, 4),
    fixed(Tag::TOKENS_ACK_ONLY, 4),
    fixed(Tag::DROPS, 6, true),
    fixed(Tag::EVICTIONS, 4),
    fixed(Tag::AMBIGUOUS_ANSWERS, 4),
    fixed(Tag::ANSWER_TIMEOUTS, 4),
    fixed(Tag::LOOP_GAP_MAX_MS, 4),
    fixed(Tag::REPLY_PREP_MAX_US, 4),
    fixed(Tag::UDP_SEND_ERRORS, 4),
    fixed(Tag::EVENTS_DROPPED, 4),
    fixed(Tag::CLIENTS, 1),
    fixed(Tag::QUEUE_DEPTH, 4, true),
    fixed(Tag::AUTH_FAILURES, 4),
    fixed(Tag::REPLAYS_REJECTED, 4),
    fixed(Tag::WIFI_RSSI, 1),
    fixed(Tag::FREE_HEAP, 4),
};

const Spec *spec_for(uint16_t number) {
  for (const auto &spec : SPECS) {
    if (spec.number == number)
      return &spec;
  }
  return nullptr;
}

// Strict UTF-8, as Python's bytes.decode() checks it: no overlong forms, no surrogates,
// nothing above U+10FFFF.
bool valid_utf8(const std::vector<uint8_t> &text) {
  size_t i = 0;
  while (i < text.size()) {
    uint8_t b = text[i];
    size_t extra;
    uint32_t cp;
    if (b < 0x80) {
      i++;
      continue;
    } else if (b >= 0xC2 && b <= 0xDF) {
      extra = 1;
      cp = b & 0x1F;
    } else if (b >= 0xE0 && b <= 0xEF) {
      extra = 2;
      cp = b & 0x0F;
    } else if (b >= 0xF0 && b <= 0xF4) {
      extra = 3;
      cp = b & 0x07;
    } else {
      return false;
    }
    if (i + extra >= text.size())
      return false;
    for (size_t k = 1; k <= extra; k++) {
      uint8_t c = text[i + k];
      if ((c & 0xC0) != 0x80)
        return false;
      cp = (cp << 6) | (c & 0x3F);
    }
    if ((extra == 2 && cp < 0x800) || (extra == 3 && cp < 0x10000) || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
      return false;
    i += extra + 1;
  }
  return true;
}

// Reads a message body front to back: the fixed core, then the options.
class Body {
 public:
  Body(const uint8_t *data, size_t len) : data_(data), len_(len) {}

  bool fixed(size_t size, const uint8_t **at) {
    if (len_ - pos_ < size)
      return false;
    *at = data_ + pos_;
    pos_ += size;
    return true;
  }

  bool counted(size_t size, std::vector<uint8_t> *out) {
    if (len_ - pos_ < size)
      return false;
    out->assign(data_ + pos_, data_ + pos_ + size);
    pos_ += size;
    return true;
  }

  const uint8_t *rest() const {
    return data_ + pos_;
  }
  size_t rest_len() const {
    return len_ - pos_;
  }

 private:
  const uint8_t *data_;
  size_t len_;
  size_t pos_{0};
};

void refuse(Decoded &r, ErrorCode code, const std::string &detail) {
  r.error = code;
  r.detail = detail;
}

void refuse_tag(Decoded &r, ErrorCode code, uint16_t tag, const std::string &detail) {
  refuse(r, code, detail);
  r.error_tag = tag;
  r.has_error_tag = true;
}

bool parse_options(const uint8_t *data, size_t len, Decoded &r) {
  std::vector<uint16_t> seen;
  size_t at = 0;
  while (at < len) {
    if (len - at < 4) {
      refuse(r, ErrorCode::MALFORMED, "an option's head is cut short");
      return false;
    }
    uint16_t tag = get_le(data + at, 2);
    uint16_t value_len = get_le(data + at + 2, 2);
    at += 4;
    if (len - at < value_len) {
      refuse_tag(r, ErrorCode::MALFORMED, tag, "an option runs past the body");
      return false;
    }
    Option option{tag, std::vector<uint8_t>(data + at, data + at + value_len)};
    at += value_len;
    const Spec *spec = spec_for(option.number());
    if (spec == nullptr) {
      if (option.critical()) {
        refuse_tag(r, ErrorCode::UNSUPPORTED_OPTION, tag, "unknown critical option");
        return false;
      }
    } else {
      bool twice = false;
      for (auto number : seen)
        twice = twice || number == option.number();
      if (twice && !spec->repeatable) {
        refuse_tag(r, ErrorCode::MALFORMED, tag, "an option twice");
        return false;
      }
      bool fits = spec->text ? valid_utf8(option.value) && (spec->text_max == 0 || value_len <= spec->text_max)
                             : value_len == spec->size;
      if (!fits) {
        refuse_tag(r, ErrorCode::MALFORMED, tag, "an option's value doesn't fit its tag");
        return false;
      }
    }
    seen.push_back(option.number());
    r.msg.options.push_back(std::move(option));
  }
  return true;
}

bool known_type(uint8_t type) {
  switch (static_cast<MessageType>(type)) {
    case MessageType::HELLO:
    case MessageType::KEEPALIVE:
    case MessageType::BYE:
    case MessageType::SUBSCRIBE:
    case MessageType::REQUEST:
    case MessageType::CANCEL:
    case MessageType::WELCOME:
    case MessageType::FATE:
    case MessageType::ANSWER:
    case MessageType::FRAME:
    case MessageType::HEALTH:
    case MessageType::ERROR:
      return true;
  }
  return false;
}

bool parse_core(Body &b, Decoded &r) {
  Message &m = r.msg;
  const uint8_t *at = nullptr;
  switch (m.type) {
    case MessageType::HELLO:
      if (!b.fixed(2, &at))
        return false;
      m.ver_min = at[0];
      m.ver_max = at[1];
      return true;
    case MessageType::WELCOME:
      if (!b.fixed(2, &at))
        return false;
      m.ver_major = at[0];
      m.ver_minor = at[1];
      return true;
    case MessageType::REQUEST:
      if (!b.fixed(9, &at))
        return false;
      m.address = get_le(at, 2);
      m.token = at[2];
      m.request_flags = at[3];
      m.ttl_ms = get_le(at + 4, 2);
      m.answer_timeout_ms = get_le(at + 6, 2);
      return b.counted(at[8], &m.frame);
    case MessageType::FATE:
      if (!b.fixed(12, &at))
        return false;
      m.stage = at[0];
      m.detail = get_le(at + 2, 2);
      m.stage_time_us = get_le(at + 4, 8);
      return true;
    case MessageType::ANSWER:
      if (!b.fixed(2, &at))
        return false;
      m.status = at[0];
      return b.counted(at[1], &m.frame);
    case MessageType::FRAME:
      if (!b.fixed(24, &at))
        return false;
      m.kind = at[0];
      m.origin = at[1];
      m.request_id = get_le(at + 2, 4);
      m.t_complete_us = get_le(at + 6, 8);
      m.t_reply_us = get_le(at + 14, 8);
      return b.counted(get_le(at + 22, 2), &m.frame);
    case MessageType::ERROR:
      if (!b.fixed(2, &at))
        return false;
      m.code = get_le(at, 2);
      return true;
    case MessageType::KEEPALIVE:
    case MessageType::BYE:
    case MessageType::SUBSCRIBE:
    case MessageType::CANCEL:
    case MessageType::HEALTH:
      return true;
  }
  return false;
}

bool mac(const uint8_t *key, const uint8_t *data, size_t len, uint8_t *out) {
  uint8_t full[SHA256_LEN];
  if (!hmac_sha256(key, KEY_LEN, data, len, full))
    return false;
  std::memcpy(out, full, MAC_LEN);
  return true;
}

}  // namespace

uint32_t Option::as_uint() const {
  return static_cast<uint32_t>(get_le(value.data(), value.size() > 4 ? 4 : value.size()));
}

Option Option::u8(Tag tag, uint8_t value) {
  return Option{static_cast<uint16_t>(tag), {value}};
}

Option Option::u16(Tag tag, uint16_t value) {
  Option option{static_cast<uint16_t>(tag), {}};
  put_u16(option.value, value);
  return option;
}

Option Option::u32(Tag tag, uint32_t value) {
  Option option{static_cast<uint16_t>(tag), {}};
  put_u32(option.value, value);
  return option;
}

Option Option::text(Tag tag, const std::string &value) {
  return Option{static_cast<uint16_t>(tag), std::vector<uint8_t>(value.begin(), value.end())};
}

Option Option::bytes(Tag tag, const uint8_t *data, size_t len) {
  return Option{static_cast<uint16_t>(tag), std::vector<uint8_t>(data, data + len)};
}

const Option *find_option(const std::vector<Option> &options, Tag tag) {
  for (const auto &option : options) {
    if (option.number() == static_cast<uint16_t>(tag))
      return &option;
  }
  return nullptr;
}

std::vector<uint8_t> encode(const Message &msg, const uint8_t *key, uint32_t seq) {
  std::vector<uint8_t> body;
  switch (msg.type) {
    case MessageType::HELLO:
      put_u8(body, msg.ver_min);
      put_u8(body, msg.ver_max);
      break;
    case MessageType::WELCOME:
      put_u8(body, msg.ver_major);
      put_u8(body, msg.ver_minor);
      break;
    case MessageType::REQUEST:
      put_u16(body, msg.address);
      put_u8(body, msg.token);
      put_u8(body, msg.request_flags);
      put_u16(body, msg.ttl_ms);
      put_u16(body, msg.answer_timeout_ms);
      put_u8(body, msg.frame.size());
      body.insert(body.end(), msg.frame.begin(), msg.frame.end());
      break;
    case MessageType::FATE:
      put_u8(body, msg.stage);
      put_u8(body, 0);
      put_u16(body, msg.detail);
      put_u64(body, msg.stage_time_us);
      break;
    case MessageType::ANSWER:
      put_u8(body, msg.status);
      put_u8(body, msg.frame.size());
      body.insert(body.end(), msg.frame.begin(), msg.frame.end());
      break;
    case MessageType::FRAME:
      put_u8(body, msg.kind);
      put_u8(body, msg.origin);
      put_u32(body, msg.request_id);
      put_u64(body, msg.t_complete_us);
      put_u64(body, msg.t_reply_us);
      put_u16(body, msg.frame.size());
      body.insert(body.end(), msg.frame.begin(), msg.frame.end());
      break;
    case MessageType::ERROR:
      put_u16(body, msg.code);
      break;
    case MessageType::KEEPALIVE:
    case MessageType::BYE:
    case MessageType::SUBSCRIBE:
    case MessageType::CANCEL:
    case MessageType::HEALTH:
      break;
  }
  for (const auto &option : msg.options) {
    put_u16(body, option.tag);
    put_u16(body, option.value.size());
    body.insert(body.end(), option.value.begin(), option.value.end());
  }
  size_t size = HEADER_SIZE + body.size() + (key != nullptr ? TRAILER_SIZE : 0);
  if (size > MAX_DATAGRAM)
    return {};

  std::vector<uint8_t> out;
  out.reserve(size);
  out.push_back('T');
  out.push_back('G');
  put_u8(out, VERSION_MAJOR);
  put_u8(out, REGISTRY_REVISION);
  put_u8(out, static_cast<uint8_t>(msg.type));
  put_u8(out, key != nullptr ? FLAG_AUTHENTICATED : 0);
  put_u16(out, body.size());
  put_u32(out, msg.id);
  put_u64(out, msg.gw_time_us);
  out.insert(out.end(), body.begin(), body.end());
  if (key != nullptr) {
    put_u32(out, seq);
    uint8_t tag[MAC_LEN];
    if (!mac(key, out.data(), out.size(), tag))
      return {};
    out.insert(out.end(), tag, tag + MAC_LEN);
  }
  return out;
}

Decoded decode(const uint8_t *data, size_t len) {
  Decoded r;
  if (len < HEADER_SIZE) {
    refuse(r, ErrorCode::MALFORMED, "shorter than a header");
    return r;
  }
  uint8_t ver_major = data[2];
  r.raw_type = data[4];
  uint8_t flags = data[5];
  size_t body_len = get_le(data + 6, 2);
  r.msg.id = get_le(data + 8, 4);
  r.msg.gw_time_us = get_le(data + 12, 8);
  r.header_ok = true;
  if (data[0] != 'T' || data[1] != 'G') {
    refuse(r, ErrorCode::BAD_MAGIC, "");
    return r;
  }
  if (ver_major != VERSION_MAJOR) {
    refuse(r, ErrorCode::BAD_VERSION, "another major version");
    return r;
  }
  if (!known_type(r.raw_type)) {
    refuse(r, ErrorCode::UNKNOWN_TYPE, "unknown message type");
    return r;
  }
  r.msg.type = static_cast<MessageType>(r.raw_type);
  r.is_signed = (flags & FLAG_AUTHENTICATED) != 0;
  size_t expected = HEADER_SIZE + body_len + (r.is_signed ? TRAILER_SIZE : 0);
  if (len != expected) {
    refuse(r, ErrorCode::MALFORMED, "the length doesn't match the header");
    return r;
  }
  Body body(data + HEADER_SIZE, body_len);
  if (!parse_core(body, r)) {
    refuse(r, ErrorCode::MALFORMED, "the core is cut short");
    return r;
  }
  if (!parse_options(body.rest(), body.rest_len(), r))
    return r;
  if (r.is_signed)
    r.seq = get_le(data + expected - TRAILER_SIZE, 4);
  return r;
}

Verify verify(const uint8_t *data, size_t len, const uint8_t *key, uint32_t *seq) {
  if (len < HEADER_SIZE + TRAILER_SIZE || (data[5] & FLAG_AUTHENTICATED) == 0)
    return Verify::NOT_SIGNED;
  uint8_t expected[MAC_LEN];
  if (!mac(key, data, len - MAC_LEN, expected))
    return Verify::BAD_MAC;
  uint8_t diff = 0;
  for (size_t i = 0; i < MAC_LEN; i++)
    diff |= expected[i] ^ data[len - MAC_LEN + i];
  if (diff != 0)
    return Verify::BAD_MAC;
  *seq = get_le(data + len - TRAILER_SIZE, 4);
  return Verify::OK;
}

bool session_key(const uint8_t *psk, const uint8_t *client_nonce, const uint8_t *gateway_nonce, uint32_t boot_id,
                 uint8_t *out) {
  std::vector<uint8_t> message(SESSION_LABEL, SESSION_LABEL + sizeof(SESSION_LABEL) - 1);
  message.insert(message.end(), client_nonce, client_nonce + NONCE_LEN);
  message.insert(message.end(), gateway_nonce, gateway_nonce + NONCE_LEN);
  put_u32(message, boot_id);
  return hmac_sha256(psk, KEY_LEN, message.data(), message.size(), out);
}

}  // namespace tgw
}  // namespace nibegw
}  // namespace esphome
