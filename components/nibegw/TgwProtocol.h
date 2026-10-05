#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// The Thermaestro gateway protocol (thermaestro-gw), registry revision 1: the datagram codec.
//
// One message per UDP datagram: a 20-byte header, a fixed core per message type, then
// options as tag/length/value. An authenticated message ends with a sequence number and a
// MAC. Numbers are little-endian. Platform-free, so it is tested on a host against the
// same byte sequences as the Python implementation.
//
// Specification: https://github.com/fnordpojk/thermaestro/blob/main/docs/gateway-protocol.md

namespace esphome {
namespace nibegw {
namespace tgw {

static constexpr uint8_t VERSION_MAJOR = 0;  // 0 while the protocol is a draft
static constexpr uint8_t REGISTRY_REVISION = 1;
static constexpr size_t MAX_DATAGRAM = 512;
static constexpr size_t HEADER_SIZE = 20;
static constexpr size_t MAC_LEN = 16;
static constexpr size_t TRAILER_SIZE = 4 + MAC_LEN;
static constexpr size_t KEY_LEN = 32;
static constexpr size_t NONCE_LEN = 16;
static constexpr uint8_t FLAG_AUTHENTICATED = 0x80;
static constexpr uint16_t CRITICAL = 0x8000;

enum class MessageType : uint8_t {
  HELLO = 0x01,
  KEEPALIVE = 0x02,
  BYE = 0x03,
  SUBSCRIBE = 0x04,
  REQUEST = 0x10,
  CANCEL = 0x11,
  WELCOME = 0x81,
  FATE = 0x90,
  ANSWER = 0x91,
  FRAME = 0xA0,
  HEALTH = 0xB0,
  ERROR = 0xE0,
};

enum class Stage : uint8_t { QUEUED = 1, SENT, PUMP_ACK, PUMP_NAK, NO_ACK_SEEN, DROPPED };

enum class DropReason : uint16_t {
  INVALID_FRAME = 1,
  TOKEN_MISMATCH,
  UNKNOWN_KEY,
  QUEUE_FULL,
  EXPIRED,
  CANCELLED,
  EVICTED,
  UNSUPPORTED_OPTION,
  SHUTDOWN,
};

enum class AnswerStatus : uint8_t { OK = 1, TIMEOUT, AMBIGUOUS };

enum class FrameKind : uint8_t { TO_GATEWAY = 1, TO_OTHER, UNPARSED };

enum class Origin : uint8_t { NONE = 0, ACK_ONLY, PLAIN_CLIENT, THIS_CLIENT, OTHER_CLIENT, CONSTANT };

enum class ErrorCode : uint16_t {
  NONE = 0,  // not on the wire: no error
  BAD_MAGIC = 1,
  BAD_VERSION,
  UNKNOWN_TYPE,
  MALFORMED,
  UNSUPPORTED_OPTION,
  NOT_SUBSCRIBED,
  TOO_MANY_CLIENTS,
  SOURCE_REFUSED,
  AUTH_REQUIRED,
  AUTH_FAILED,
  REPLAY,
  NO_SESSION,
  UNKNOWN_REQUEST,
};

enum class BusState : uint8_t { SILENT = 0, ACTIVE = 1 };

namespace subscription {
static constexpr uint32_t FRAMES_ALL = 1 << 0;
static constexpr uint32_t FRAMES_OWN = 1 << 1;
static constexpr uint32_t HEALTH = 1 << 2;
}  // namespace subscription

namespace feature {
static constexpr uint32_t FATE = 1 << 0;
static constexpr uint32_t ANSWER_PAIRING = 1 << 1;
static constexpr uint32_t FRAMES = 1 << 2;
static constexpr uint32_t HEALTH = 1 << 3;
static constexpr uint32_t PRIORITY = 1 << 4;
static constexpr uint32_t TTL = 1 << 5;
static constexpr uint32_t AUTH = 1 << 6;
}  // namespace feature

namespace request_flag {
static constexpr uint8_t PRIORITY = 1 << 0;
static constexpr uint8_t EXPECT_ANSWER = 1 << 1;
}  // namespace request_flag

enum class Tag : uint16_t {
  CLIENT_NAME = 0x0001,
  CLIENT_NONCE = 0x0002,
  SUBSCRIBE = 0x0003,
  LEASE_S = 0x0004,
  HEALTH_INTERVAL_S = 0x0005,
  BOOT_ID = 0x0100,
  GATEWAY_NONCE = 0x0101,
  IMPL = 0x0102,
  IMPL_VERSION = 0x0103,
  UPTIME_S = 0x0104,
  FEATURES = 0x0105,
  QUEUE_CAP = 0x0106,
  MAX_CLIENTS = 0x0107,
  ANSWER_TIMEOUT_MS = 0x0108,
  TIMESTAMP_LAG_MAX_US = 0x0109,
  PLAIN_PORTS = 0x010A,
  ACK_ADDRESS = 0x010B,
  ERR_TAG = 0x0200,
  ERR_DETAIL = 0x0201,
  BUS_STATE = 0x0301,
  MS_SINCE_LAST_BYTE = 0x0302,
  MS_SINCE_LAST_TOKEN = 0x0303,
  FRAMES_OK = 0x0304,
  CRC_ERRORS = 0x0305,
  NAKS_SENT = 0x0306,
  INVALID_BYTES = 0x0307,
  PUMP_NAKS = 0x0308,
  NO_ACK_SEEN = 0x0309,
  TOKENS_WITH_REPLY = 0x030A,
  TOKENS_ACK_ONLY = 0x030B,
  DROPS = 0x030C,
  EVICTIONS = 0x030D,
  AMBIGUOUS_ANSWERS = 0x030E,
  ANSWER_TIMEOUTS = 0x030F,
  LOOP_GAP_MAX_MS = 0x0310,
  REPLY_PREP_MAX_US = 0x0311,
  UDP_SEND_ERRORS = 0x0312,
  EVENTS_DROPPED = 0x0313,
  CLIENTS = 0x0314,
  QUEUE_DEPTH = 0x0315,
  AUTH_FAILURES = 0x0316,
  REPLAYS_REJECTED = 0x0317,
  WIFI_RSSI = 0x0318,
  FREE_HEAP = 0x0319,
};

struct Option {
  uint16_t tag{0};  // the full tag, critical bit included
  std::vector<uint8_t> value;

  uint16_t number() const {
    return tag & ~CRITICAL;
  }
  bool critical() const {
    return (tag & CRITICAL) != 0;
  }
  // A 1-, 2- or 4-byte value as an unsigned number.
  uint32_t as_uint() const;
  std::string as_text() const {
    return std::string(value.begin(), value.end());
  }

  static Option u8(Tag tag, uint8_t value);
  static Option u16(Tag tag, uint16_t value);
  static Option u32(Tag tag, uint32_t value);
  static Option text(Tag tag, const std::string &value);
  static Option bytes(Tag tag, const uint8_t *data, size_t len);
};

// The option with this tag, critical or not; nullptr if there is none.
const Option *find_option(const std::vector<Option> &options, Tag tag);

// A message. The fields of its type's fixed core are used; the others stay zero.
struct Message {
  MessageType type{MessageType::KEEPALIVE};
  uint32_t id{0};
  uint64_t gw_time_us{0};
  // HELLO
  uint8_t ver_min{VERSION_MAJOR};
  uint8_t ver_max{VERSION_MAJOR};
  // WELCOME
  uint8_t ver_major{VERSION_MAJOR};
  uint8_t ver_minor{REGISTRY_REVISION};
  // REQUEST
  uint16_t address{0};
  uint8_t token{0};
  uint8_t request_flags{0};
  uint16_t ttl_ms{0};
  uint16_t answer_timeout_ms{0};
  // FATE
  uint8_t stage{0};
  uint16_t detail{0};
  uint64_t stage_time_us{0};
  // ANSWER
  uint8_t status{0};
  // FRAME
  uint8_t kind{0};
  uint8_t origin{0};
  uint32_t request_id{0};
  uint64_t t_complete_us{0};
  uint64_t t_reply_us{0};
  // ERROR
  uint16_t code{0};
  // REQUEST and ANSWER: the frame; FRAME: the exchange's bytes
  std::vector<uint8_t> frame;
  std::vector<Option> options;
};

struct Decoded {
  ErrorCode error{ErrorCode::NONE};
  std::string detail;
  uint16_t error_tag{0};  // the option that caused it, if one did
  bool has_error_tag{false};
  bool header_ok{false};  // the header was read: msg.id and raw_type are valid
  uint8_t raw_type{0};
  bool is_signed{false};
  uint32_t seq{0};  // the trailer's sequence number; check the MAC with verify()
  Message msg;

  bool ok() const {
    return error == ErrorCode::NONE;
  }
};

// Decode one datagram. A signed message's MAC isn't checked here, since which key applies
// depends on the session.
Decoded decode(const uint8_t *data, size_t len);

// Encode a message; with a key, sign it with sequence number `seq`. Empty if it would be
// larger than MAX_DATAGRAM, or signing failed.
std::vector<uint8_t> encode(const Message &msg, const uint8_t *key = nullptr, uint32_t seq = 0);

enum class Verify : uint8_t { OK, NOT_SIGNED, BAD_MAC };

// Check a signed datagram's MAC under `key` (KEY_LEN bytes); on OK, `seq` is its sequence number.
Verify verify(const uint8_t *data, size_t len, const uint8_t *key, uint32_t *seq);

// HMAC-SHA256(psk, "thermaestro-gw session" | client nonce | gateway nonce | boot id).
bool session_key(const uint8_t *psk, const uint8_t *client_nonce, const uint8_t *gateway_nonce, uint32_t boot_id,
                 uint8_t *out);

}  // namespace tgw
}  // namespace nibegw
}  // namespace esphome
