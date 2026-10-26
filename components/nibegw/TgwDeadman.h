#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "TgwEngine.h"
#include "TgwProtocol.h"

// The dead-man: put back what a silent client changed (gateway-protocol.md §15).
//
// An authenticated client arms entries: a register, the value it wrote, and the write that
// puts the register's earlier value back. Once no session granted the dead-man has said
// anything for its silence, each armed entry is fired in turn: the gateway reads the
// register, and only where it still holds what the client wrote does it send the write.
// Someone who changed it meanwhile is never written over. Each entry fires once; what came
// of it is kept until a session acknowledges it.
//
// It is a client of the engine like any other: its reads and writes wait in the same
// queues, and a write waits for the one in flight. There is no I/O here: what is armed is
// handed to `save` now and then, so a reboot of the gateway keeps it.

namespace esphome {
namespace nibegw {
namespace tgw {

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
};

// What is kept through a reboot, in one fixed layout so it can be saved as one blob.
struct DeadmanSaved {
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

struct DeadmanHooks {
  std::function<bool(DeadmanSaved &)> load;        // what was saved; false if nothing was
  std::function<void(const DeadmanSaved &)> save;  // kept by the time it returns, or very soon after
  std::function<void(const std::string &)> log;
};

class Deadman {
 public:
  static constexpr uint8_t ENTRIES = 16;
  static constexpr uint16_t SILENCE_MIN_S = 300, SILENCE_DEFAULT_S = 900, SILENCE_MAX_S = 7200;
  static constexpr uint64_t SAVE_EVERY_US = 600000000;  // armed entries that changed, at most this often
  static constexpr uint16_t REQUEST_TTL_MS = 60000;
  static constexpr uint32_t FIRST_ID = 0x80000000;  // its own request ids, apart from any client's

  Deadman(Engine &engine, uint64_t now_us, DeadmanHooks hooks = {});

  // --- the client ---

  // The silence and the entries granted for what was asked.
  std::pair<uint16_t, uint8_t> grant(uint32_t asked_s, uint32_t asked_entries);
  // A session granted the dead-man spoke: the silence starts again, and a firing under way
  // stops after its current entry.
  void heard(uint64_t now_us);
  Message arm(const Message &msg, uint8_t entries);
  Message disarm(uint8_t entry, uint32_t id);
  Message ack_fired(uint8_t entry, uint32_t id);
  // The gateway is stopping: an entry being fired is armed again, and what is armed is
  // kept, so a restart fires it.
  void stop(uint64_t now_us);
  // A FIRED report for each entry fired and not acknowledged, in entry order.
  std::vector<Message> reports(uint64_t now_us) const;
  // The entries that fired since this was last asked: told to the sessions there are at
  // once, as one may be back while an entry was under way.
  std::vector<Message> just_fired(uint64_t now_us);

  // --- firing ---

  void tick(uint64_t now_us);
  // A fate or an answer for one of its own requests.
  void on_message(const Message &message, uint64_t now_us);
  void save(uint64_t now_us);

  const std::map<uint8_t, DeadmanEntry> &armed() const {
    return armed_;
  }
  const std::map<uint8_t, DeadmanOutcome> &fired() const {
    return fired_;
  }
  uint16_t silence_s() const {
    return silence_us_ / 1000000;
  }

 private:
  enum class Step : uint8_t { READ, WRITE };

  static ArmRefusal refusal_(const Message &msg, uint8_t entries);
  ArmRefusal fired_refusal_(uint8_t entry) const;
  static Message armed_answer_(uint8_t entry, ArmResult result, uint32_t id, ArmRefusal detail = ArmRefusal::NONE);
  void next_(uint64_t now_us);
  void request_(uint8_t token, std::vector<uint8_t> frame, Step step, uint64_t now_us);
  void done_(const DeadmanOutcome &outcome, uint64_t now_us);
  void load_();
  void log_(const std::string &text) const;

  Engine &engine_;
  DeadmanHooks hooks_;
  uint64_t silence_us_{uint64_t(SILENCE_DEFAULT_S) * 1000000};
  std::map<uint8_t, DeadmanEntry> armed_;
  std::map<uint8_t, DeadmanOutcome> fired_;
  uint64_t heard_us_;
  bool firing_{false};
  std::deque<DeadmanEntry> queue_;
  std::optional<DeadmanEntry> current_;
  std::optional<std::pair<uint32_t, Step>> pending_;  // the request in flight for the current entry
  std::vector<DeadmanOutcome> just_fired_;
  uint32_t next_id_{FIRST_ID};
  bool dirty_{false};
  uint64_t saved_us_;
};

}  // namespace tgw
}  // namespace nibegw
}  // namespace esphome
