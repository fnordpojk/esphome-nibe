#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "TgwEngine.h"
#include "TgwProtocol.h"

// The control port: sessions of the Thermaestro gateway protocol.
//
// Platform-free logic with time passed in: a datagram comes in with its sender, and out
// come the datagrams to send. Requests go to the engine; fates and answers come back from
// it; every completed bus exchange becomes a FRAME for the sessions subscribed to it.
//
// With a pre-shared key, authentication comes before anything else: a sender without a
// session only ever hears `auth_required` or `auth_failed`, and every message of an
// authenticated session is signed with its session key, in both directions.

namespace esphome {
namespace nibegw {
namespace tgw {

struct Peer {
  uint32_t ip{0};  // IPv4, network byte order
  uint16_t port{0};

  bool operator<(const Peer &other) const {
    return ip != other.ip ? ip < other.ip : port < other.port;
  }
  bool operator==(const Peer &other) const {
    return ip == other.ip && port == other.port;
  }
};

struct Datagram {
  Peer to;
  std::vector<uint8_t> data;
};

// What the gateway's side of the bus counts, for HEALTH.
struct BusStats {
  uint32_t frames_ok{0};
  uint32_t crc_errors{0};
  uint32_t naks_sent{0};
  uint32_t pump_naks{0};
  uint32_t no_ack_seen{0};
  uint32_t tokens_with_reply{0};
  uint32_t tokens_ack_only{0};
  bool counts_invalid_bytes{false};  // NibeGw doesn't report them, so they are left out
  uint32_t invalid_bytes{0};
  uint64_t last_byte_us{0};  // 0: none yet
  uint64_t last_token_us{0};
};

struct ControlSettings {
  bool has_psk{false};
  uint8_t psk[KEY_LEN]{};
  uint32_t boot_id{0};
  bool has_plain_ports{true};
  uint16_t plain_read_port{0};  // 0 where disabled
  uint16_t plain_write_port{0};
  uint8_t max_clients{4};
  std::vector<uint32_t> sources;  // IPv4, network byte order; empty allows any
  std::vector<uint16_t> acknowledged;
  uint16_t answer_timeout_ms{5000};
  uint32_t timestamp_lag_max_us{20000};
  uint64_t started_us{0};
  std::string impl{"esphome-nibe"};
  std::string impl_version;
  std::function<void(uint8_t *, size_t)> random;               // fills a buffer with random bytes
  std::function<void(std::vector<Option> &)> platform_health;  // e.g. WIFI_RSSI, FREE_HEAP
};

struct ControlStats {
  uint32_t auth_failures{0};
  uint32_t replays_rejected{0};
  uint32_t udp_send_errors{0};
  uint32_t events_dropped{0};
};

class Control {
 public:
  static constexpr uint16_t LEASE_MIN_S = 10, LEASE_DEFAULT_S = 120, LEASE_MAX_S = 600;
  static constexpr uint16_t HEALTH_MIN_S = 1, HEALTH_DEFAULT_S = 10, HEALTH_MAX_S = 3600;
  static constexpr uint64_t SILENT_AFTER_US = 5000000;
  static constexpr uint64_t ERROR_INTERVAL_US = 1000000;

  Control(Engine &engine, const BusStats &bus, ControlSettings settings);

  std::vector<Datagram> handle(const uint8_t *data, size_t len, const Peer &from, uint64_t now_us);
  std::vector<Datagram> on_exchange(const Exchange &exchange);
  std::vector<Datagram> tick(uint64_t now_us);
  // The gateway is stopping: report the queued requests as dropped.
  std::vector<Datagram> shutdown(uint64_t now_us);
  void note_loop_gap(uint32_t gap_ms);
  void note_reply_prep(uint32_t prep_us);

  size_t clients() const {
    return sessions_.size();
  }
  bool has_frame_subscribers() const;

  ControlStats stats;

 private:
  struct Session {
    Peer addr;
    uint32_t subscribe{0};
    uint64_t lease_us{0};
    uint64_t health_interval_us{0};
    uint64_t expires_us{0};
    uint64_t next_health_us{0};
    bool has_key{false};
    uint8_t key[KEY_LEN]{};
    uint32_t recv_seq{0};
    uint32_t send_seq{0};
    uint32_t event_seq{0};
    uint32_t loop_gap_max_ms{0};
    uint32_t reply_prep_max_us{0};
  };

  void hello_(const Decoded &d, const uint8_t *data, size_t len, const Peer &from, uint64_t now_us,
              std::vector<Datagram> &out);
  void refused_(const Decoded &d, const Peer &from, Session *session, uint64_t now_us, std::vector<Datagram> &out);
  bool signature_ok_(Session &session, const Decoded &d, const uint8_t *data, size_t len, uint64_t now_us,
                     std::vector<Datagram> &out);
  Message health_(Session &session, uint64_t now_us);
  Origin origin_(const Exchange &exchange, const std::optional<RequestMeta> &replied, const Session &session) const;
  void flush_(std::vector<Datagram> &out);
  void send_(Session &session, const Message &msg, std::vector<Datagram> &out);
  void error_(const Peer &to, Session *session, ErrorCode code, uint32_t id, uint64_t now_us,
              std::vector<Datagram> &out, bool has_tag = false, uint16_t tag = 0, const std::string &detail = "");
  void end_(const Peer &addr);
  uint32_t uptime_s_(uint64_t now_us) const;

  Engine &engine_;
  const BusStats &bus_;
  ControlSettings settings_;
  std::map<Peer, std::unique_ptr<Session>> sessions_;
  std::map<Peer, uint64_t> last_error_us_;
  bool bus_active_{false};
};

}  // namespace tgw
}  // namespace nibegw
}  // namespace esphome
