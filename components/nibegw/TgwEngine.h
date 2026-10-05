#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <set>
#include <vector>

#include "NibeGwRequest.h"
#include "TgwProtocol.h"

// Request queues, fates and answer pairing for the Thermaestro gateway protocol.
//
// The gateway's bookkeeping, with no I/O: requests go in, the bus asks for a reply on each
// token, completed exchanges come back, and the fates and answers owed to protocol clients
// collect in an outbox. It works on the component's own request queues, so plain NibeGW
// and protocol requests share them.
//
// - Requests go out in the order they arrived. Plain requests behave as before: at most
//   `queue_cap` of them, and a new one drops the oldest plain entry. On top of those,
//   `protocol_slots` entries are reserved for protocol requests, which are refused when
//   they are taken. Neither kind pushes the other out, so a busy plain client doesn't
//   keep protocol requests waiting for a slot.
// - Reads are paired with the pump's 0x6A answers first in, first out per register: the
//   read requests the pump took, from every client and plain ones included, wait in the
//   order it took them, and an answer belongs to the oldest. A read-back after a write
//   thus never gets the answer to a request taken before the write.
// - Writes are paired with 0x6C answers by order. A protocol write isn't sent while another
//   write awaits its 0x6C; if a 0x6C arrives with more than one write in flight (a plain
//   client's can overlap), the pairing is reported as AMBIGUOUS.

namespace esphome {
namespace nibegw {
namespace tgw {

namespace bus {
static constexpr uint8_t START_TELEGRAM = 0x5C;
static constexpr uint8_t START_REPLY = 0xC0;
static constexpr uint8_t ACK_BYTE = 0x06;
static constexpr uint8_t NAK_BYTE = 0x15;
static constexpr uint16_t MODBUS40_ADDR = 0x20;
static constexpr uint8_t READ_TOKEN_CMD = 0x69;
static constexpr uint8_t READ_ANSWER_CMD = 0x6A;
static constexpr uint8_t WRITE_TOKEN_CMD = 0x6B;
static constexpr uint8_t WRITE_ANSWER_CMD = 0x6C;
}  // namespace bus

// One completed bus exchange: the pump's telegram, the reply that followed (the gateway's
// or another device's), and the byte that closed it.
struct Exchange {
  enum class Reply : uint8_t { NONE, QUEUED, CONSTANT };

  std::vector<uint8_t> data;  // every byte, as a NibeGW datagram carries them
  FrameKind kind{FrameKind::UNPARSED};
  bool parsed{false};  // the telegram's checksum was right
  uint16_t address{0};
  uint8_t command{0};
  std::vector<uint8_t> payload;  // the telegram's data, a doubled 0x5C taken as one
  size_t telegram_len{0};
  Reply reply{Reply::NONE};  // what this gateway replied with
  int trailer{-1};           // the byte after the gateway's reply or ACK; -1 if none came
  uint64_t t_complete_us{0};
  uint64_t t_reply_us{0};  // 0 if the gateway sent no reply
};

// Read an exchange as NibeGw passes it on: `reply_len` bytes after the telegram are the
// gateway's reply, if it sent one; `acknowledged` says whether the telegram was to an
// address this gateway answers for.
Exchange make_exchange(const uint8_t *data, size_t len, bool acknowledged, Exchange::Reply reply, size_t reply_len,
                       uint64_t t_complete_us, uint64_t t_reply_us);

// The XOR checksum of the bus, sent as 0xC5 when it comes out as 0x5C.
uint8_t bus_checksum(const uint8_t *data, size_t len);

// Whether `frame` is exactly one valid `C0 CMD LEN DATA CHK` reply.
bool valid_reply(const request_data_type &frame);

struct Outgoing {
  const void *client;
  Message message;
};

struct EngineStats {
  std::array<uint32_t, 10> drops{};  // by DropReason
  uint32_t evictions{0};
  uint32_t ambiguous_answers{0};
  uint32_t answer_timeouts{0};
};

class Engine {
 public:
  static constexpr uint32_t DEFAULT_ANSWER_TIMEOUT_US = 5000000;

  static constexpr size_t DEFAULT_PROTOCOL_SLOTS = 1;

  // `keys` are the (address, token) pairs a protocol request may be queued for;
  // `queue_cap` is the plain requests per queue.
  Engine(request_queues_type &queues, std::set<request_key_type> keys, size_t queue_cap,
         uint32_t default_answer_timeout_us = DEFAULT_ANSWER_TIMEOUT_US,
         size_t protocol_slots = DEFAULT_PROTOCOL_SLOTS);

  size_t queue_cap() const {
    return queue_cap_;
  }
  size_t protocol_slots() const {
    return protocol_slots_;
  }
  const std::set<request_key_type> &keys() const {
    return keys_;
  }

  void submit(const void *client, const Message &request, uint64_t now_us);
  // A plain NibeGW request; false if it was invalid.
  bool submit_plain(uint16_t address, uint8_t token, request_data_type frame, uint64_t now_us);
  bool cancel(const void *client, uint32_t id, uint64_t now_us);
  // A client's session ended: its queued requests never reach the pump, and nothing more
  // is reported to it. Reads and writes already taken keep their places.
  void forget(const void *client);
  // Drop every queued request, telling protocol clients why.
  void shutdown(uint64_t now_us);

  // The pump sent a token: the request to reply with, or nullptr. It stays valid until
  // the next call to reply_for() or on_exchange().
  const QueuedRequest *reply_for(uint16_t address, uint8_t command, uint64_t now_us);
  // The exchange that followed a token or a telegram. Returns what is known about the
  // queued request the gateway replied with, if it replied with one.
  std::optional<RequestMeta> on_exchange(const Exchange &exchange);
  // Expire queued requests and give up on answers that didn't come.
  void tick(uint64_t now_us);

  std::vector<Outgoing> take_outbox();
  std::map<request_key_type, size_t> depths() const;

  EngineStats stats;

 private:
  struct Taken {
    RequestMeta meta;
    uint64_t sent_us;
    uint16_t reg;
  };

  std::optional<DropReason> invalid_(const request_data_type &frame, const request_key_type &key) const;
  bool overdue_(const Taken &taken, uint64_t now_us) const;
  void fate_(const RequestMeta &meta, Stage stage, uint64_t now_us, uint16_t detail = 0);
  void drop_(const RequestMeta &meta, DropReason reason, uint64_t now_us);
  void answer_(const RequestMeta &meta, AnswerStatus status, const std::vector<uint8_t> &frame, uint64_t now_us);
  void timeout_(const Taken &taken, uint64_t now_us);
  std::deque<QueuedRequest> &queue_(const request_key_type &key);

  request_queues_type &queues_;
  std::set<request_key_type> keys_;
  size_t queue_cap_;
  uint32_t default_answer_timeout_us_;
  size_t protocol_slots_;
  std::optional<QueuedRequest> replying_;
  uint64_t replying_sent_us_{0};
  std::map<uint16_t, std::deque<Taken>> reads_;  // per register, the reads the pump took, oldest first
  std::deque<Taken> writes_;
  std::vector<Outgoing> outbox_;
};

}  // namespace tgw
}  // namespace nibegw
}  // namespace esphome
