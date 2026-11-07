#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "TgwEngine.h"
#include "TgwProtocol.h"

// The dead-man: put back what a silent client changed (gateway-protocol.md §15).
//
// An authenticated client arms entries: a register, the value it wrote, and the write that
// puts the register's earlier value back. Each client is known by the id it gives in HELLO,
// the same across its sessions, and has its own entries, its own silence and its own
// reports. Once no session of a client has said anything for its silence, each of its armed
// entries is fired in turn: the gateway reads the register, and only where it still holds
// what the client wrote does it send the write. Someone who changed it meanwhile is never
// written over. Each entry fires once; what came of it is kept until that client
// acknowledges it.
//
// It is a client of the engine like any other: its reads and writes wait in the same
// queues, and a write waits for the one in flight. There is no I/O here: what is held is
// handed to `save`, and an ARM is confirmed only once the platform says it is kept
// (`saved`), so a reboot of the gateway right after keeps it.

namespace esphome {
namespace nibegw {
namespace tgw {

using ClientId = std::string;  // CLIENT_ID's 16 bytes; empty: entries saved before clients were known

struct DeadmanEntry {
  uint8_t number{0};
  uint8_t width{0};
  uint16_t reg{0};
  uint32_t expected{0};
  std::vector<uint8_t> frame;

  bool operator==(const DeadmanEntry &other) const {
    return number == other.number && width == other.width && reg == other.reg && expected == other.expected &&
           frame == other.frame;
  }
  bool operator!=(const DeadmanEntry &other) const {
    return !(*this == other);
  }
};

struct DeadmanOutcome {
  uint8_t entry{0};
  FiredOutcome outcome{FiredOutcome::NO_ANSWER};
  uint16_t reg{0};
  uint32_t read{0};
  uint64_t fired_us{0};  // 0 when it fired before the gateway restarted
  uint64_t kept_us{0};   // when it was kept, on this boot's clock
};

// What a gateway of registry revision 4 kept: one set of entries, no clients.
struct DeadmanSavedV1 {
  static constexpr uint32_t MAGIC = 0x31444754;  // "TGD1"
  static constexpr size_t ENTRIES = 16;
  static constexpr size_t FRAME_LEN = 10;  // C0 6B 06, the register and value, the checksum

  struct Armed {
    uint8_t number;
    uint8_t width;
    uint16_t reg;
    uint32_t expected;
    uint8_t frame[FRAME_LEN];
  };
  struct Fired {
    uint8_t entry;
    uint8_t outcome;
    uint16_t reg;
    uint32_t read;
  };

  uint32_t magic;
  uint16_t silence_s;
  uint8_t armed_count;
  uint8_t fired_count;
  Armed armed[ENTRIES];
  Fired fired[ENTRIES];
};

// What is kept through a reboot, in one fixed layout so it can be saved as one blob.
struct DeadmanSaved {
  static constexpr uint32_t MAGIC = 0x32444754;  // "TGD2"
  static constexpr size_t CLIENTS = 4;
  static constexpr size_t ENTRIES = 16;
  static constexpr size_t FRAME_LEN = DeadmanSavedV1::FRAME_LEN;
  static constexpr size_t ID_LEN = 16;

  using Armed = DeadmanSavedV1::Armed;
  using Fired = DeadmanSavedV1::Fired;
  struct Client {
    uint8_t id[ID_LEN];
    uint16_t silence_s;
    uint8_t armed_count;
    uint8_t fired_count;
    uint8_t owned;  // 0: entries saved before clients were known
    uint8_t reserved[3];
    Armed armed[ENTRIES];
    Fired fired[ENTRIES];
  };

  uint32_t magic;
  uint8_t client_count;
  uint8_t reserved[3];
  Client clients[CLIENTS];
};

struct DeadmanHooks {
  std::function<bool(DeadmanSaved &)> load;      // what was saved; false if nothing was
  std::function<bool(DeadmanSavedV1 &)> load_v1;  // what revision 4 saved; false if nothing was
  // Hands over what is to be kept. Where it is set, the platform calls `Control::saved`
  // once it is written, and an ARM is confirmed only then.
  std::function<void(const DeadmanSaved &)> save;
  std::function<void(const std::string &)> log;
};

class Deadman {
 public:
  static constexpr uint8_t ENTRIES = 16;
  static constexpr size_t MAX_CLIENTS = DeadmanSaved::CLIENTS;  // holding entries or reports at once
  static constexpr uint16_t SILENCE_MIN_S = 300, SILENCE_DEFAULT_S = 900, SILENCE_MAX_S = 7200;
  static constexpr uint64_t SAVE_EVERY_US = 600000000;  // a disarm or an acknowledgment, at most this often
  static constexpr uint64_t REPORT_KEPT_US = 30ull * 24 * 3600 * 1000000;  // unacknowledged, then dropped
  static constexpr uint16_t REQUEST_TTL_MS = 60000;
  static constexpr uint32_t FIRST_ID = 0x80000000;  // its own request ids, apart from any client's

  struct Client {
    uint64_t silence_us{uint64_t(SILENCE_DEFAULT_S) * 1000000};
    uint64_t heard_us{0};
    std::map<uint8_t, DeadmanEntry> armed;
    std::map<uint8_t, DeadmanOutcome> fired;

    bool holds() const {
      return !armed.empty() || !fired.empty();
    }
  };

  // An ARM's answer that waits for its entry to be kept, and who asked.
  struct Awaiting {
    uint64_t asker;
    ClientId client;
    Message answer;
    std::optional<DeadmanEntry> before;  // what the entry held, put back if it can't be kept
  };

  Deadman(Engine &engine, uint64_t now_us, DeadmanHooks hooks = {});

  // --- the client ---

  // The silence and the entries granted to a session of `client`; nullopt when the gateway
  // already holds entries for as many other clients as it can.
  std::optional<std::pair<uint16_t, uint8_t>> grant(const ClientId &client, uint32_t asked_s, uint32_t asked_entries,
                                                    uint64_t now_us);
  // What is held for `client`: entries armed, and reports not acknowledged.
  std::pair<size_t, size_t> counts(const ClientId &client) const;
  // A session of `client` spoke: its silence starts again, and a firing of its entries under
  // way stops after the entry being fired.
  void heard(const ClientId &client, uint64_t now_us);
  // The answer, or nullopt where it waits for the entry to be kept (`saved`). `asker` is
  // the caller's, handed back with the answer.
  std::optional<Message> arm(const ClientId &client, const Message &msg, uint8_t entries, uint16_t silence_s,
                             uint64_t asker, uint64_t now_us);
  Message disarm(const ClientId &client, uint8_t entry, uint32_t id);
  Message ack_fired(const ClientId &client, uint8_t entry, uint32_t id);
  // What was handed to `save` is written (or, `ok` false, couldn't be): the ARMs waiting
  // for it are answered.
  std::vector<Awaiting> saved(bool ok);
  // The gateway is stopping: an entry being fired is armed again, and what is armed is
  // kept, so a restart fires it.
  void stop(uint64_t now_us);
  // A FIRED report for each of `client`'s entries fired and not acknowledged, in entry order.
  std::vector<Message> reports(const ClientId &client, uint64_t now_us) const;
  // The entries that fired since this was last asked, each with its client: told to its
  // sessions at once, as one may be back while an entry was under way.
  std::vector<std::pair<ClientId, Message>> just_fired(uint64_t now_us);

  // --- firing ---

  void tick(uint64_t now_us);
  // A fate or an answer for one of its own requests.
  void on_message(const Message &message, uint64_t now_us);
  void save(uint64_t now_us);

  const std::map<ClientId, Client> &clients() const {
    return clients_;
  }

 private:
  enum class Step : uint8_t { READ, WRITE };

  static ArmRefusal refusal_(const Message &msg, uint8_t entries);
  ArmRefusal fired_refusal_(const ClientId &client, uint8_t entry) const;
  static Message armed_answer_(uint8_t entry, ArmResult result, uint32_t id, ArmRefusal detail = ArmRefusal::NONE);
  size_t holding_(const ClientId &client) const;
  void forget_(uint64_t now_us);
  void next_(uint64_t now_us);
  void request_(uint8_t token, std::vector<uint8_t> frame, Step step, uint64_t now_us);
  void done_(const DeadmanOutcome &outcome, uint64_t now_us);
  void load_(uint64_t now_us);
  void log_(const std::string &text) const;

  Engine &engine_;
  DeadmanHooks hooks_;
  std::map<ClientId, Client> clients_;
  std::set<ClientId> firing_;
  std::deque<std::pair<ClientId, DeadmanEntry>> queue_;
  std::optional<std::pair<ClientId, DeadmanEntry>> current_;
  std::optional<std::pair<uint32_t, Step>> pending_;  // the request in flight for the current entry
  std::vector<std::pair<ClientId, DeadmanOutcome>> just_fired_;
  std::vector<Awaiting> awaiting_;
  uint32_t next_id_{FIRST_ID};
  bool dirty_{false};
  uint64_t saved_us_;
};

}  // namespace tgw
}  // namespace nibegw
}  // namespace esphome
