// The dead-man: what a silent client changed is put back, and only where nobody else has
// changed it since (gateway-protocol.md §15). Each client has its own entries, silence and
// reports. Case for case as the Python gateway's tests, and an ARM confirmed only once kept.

#include "test.h"
#include "../components/nibegw/TgwControl.h"

#include <cstring>
#include <memory>
#include <optional>
#include <set>

using namespace esphome::nibegw;
using tgw::ArmRefusal;
using tgw::ArmResult;
using tgw::FiredOutcome;
using tgw::MessageType;
using tgw::Tag;

namespace {

const tgw::Peer A{0x0A0200C0, 40000};  // 192.0.2.10
const tgw::Peer B{0x0A0200C0, 40001};
const tgw::Peer C{0x0B0200C0, 40000};  // 192.0.2.11
const std::vector<uint8_t> THERMAESTRO(16, 0xA1);
const std::vector<uint8_t> RIG(16, 0xB2);

tgw::ClientId id(const std::vector<uint8_t> &client) {
  return tgw::ClientId(client.begin(), client.end());
}
const request_key_type READ_KEY{0x20, 0x69};
const request_key_type WRITE_KEY{0x20, 0x6B};
constexpr uint32_t BOOT = 0xDEADBEEF;
constexpr uint64_t S = 1000000;
constexpr uint16_t OFFSET = 47011;
constexpr uint32_t SET = 0xFFFE, FOUND = 0xFFFC;  // Thermaestro's -2, the household's -4

std::vector<uint8_t> psk() {
  std::vector<uint8_t> key(32);
  for (int i = 0; i < 32; i++)
    key[i] = i;
  return key;
}

std::vector<uint8_t> nonce() {
  std::vector<uint8_t> n(16);
  for (int i = 0; i < 16; i++)
    n[i] = 0x10 + i;
  return n;
}

// What the gateway keeps through a reboot: shared by the gateways a test restarts.
struct Store {
  std::optional<tgw::DeadmanSaved> saved;
  std::optional<tgw::DeadmanSavedV1> saved_v1;  // what a gateway of revision 4 kept
};

// A gateway: its queues, engine and control port, started at 0.
struct Gateway {
  request_queues_type queues;
  tgw::BusStats bus;
  tgw::Engine engine{queues, {READ_KEY, WRITE_KEY}, 3};
  std::unique_ptr<tgw::Control> control;

  explicit Gateway(std::shared_ptr<Store> store = nullptr, bool with_psk = true) {
    tgw::ControlSettings s;
    s.boot_id = BOOT;
    s.plain_read_port = 9999;
    s.acknowledged = {0x20};
    s.impl_version = "test";
    s.random = [](uint8_t *out, size_t len) {
      for (size_t i = 0; i < len; i++)
        out[i] = 0x20 + i;
    };
    if (with_psk) {
      s.has_psk = true;
      std::memcpy(s.psk, psk().data(), 32);
    }
    if (store) {
      s.deadman.load = [store](tgw::DeadmanSaved &saved) {
        if (!store->saved)
          return false;
        saved = *store->saved;
        return true;
      };
      s.deadman.load_v1 = [store](tgw::DeadmanSavedV1 &saved) {
        if (!store->saved_v1)
          return false;
        saved = *store->saved_v1;
        return true;
      };
      s.deadman.save = [store](const tgw::DeadmanSaved &saved) { store->saved = saved; };
    }
    control = std::make_unique<tgw::Control>(engine, bus, s);
  }

  const tgw::Deadman &deadman() const {
    return *control->deadman();
  }
};

// The ARMs waiting for their entries to be kept, answered once the platform has written
// them (or, `ok` false, couldn't).
std::vector<tgw::Message> written(Gateway &g, const tgw::Peer &to, uint64_t now_us, bool ok = true);

std::vector<tgw::Message> decoded_to(const std::vector<tgw::Datagram> &out, const tgw::Peer &to) {
  std::vector<tgw::Message> found;
  for (const auto &d : out) {
    if (d.to == to)
      found.push_back(tgw::decode(d.data.data(), d.data.size()).msg);
  }
  return found;
}

std::vector<tgw::Message> written(Gateway &g, const tgw::Peer &to, uint64_t now_us, bool ok) {
  return decoded_to(g.control->saved(ok, now_us), to);
}

// An authenticated session, with its signing state.
struct Client {
  tgw::Control &control;
  tgw::Peer addr;
  std::vector<uint8_t> key = std::vector<uint8_t>(32);
  uint32_t seq{1};
  tgw::Message welcome;
  std::vector<tgw::Message> after_welcome;

  Client(Gateway &g, const tgw::Peer &a, uint64_t now_us, std::vector<tgw::Option> options = {},
         const std::vector<uint8_t> &client = THERMAESTRO)
      : control(*g.control), addr(a) {
    tgw::Message hello;
    hello.type = MessageType::HELLO;
    hello.id = 1;
    hello.options.push_back({static_cast<uint16_t>(static_cast<uint16_t>(Tag::CLIENT_NONCE) | tgw::CRITICAL), nonce()});
    for (auto &o : options)
      hello.options.push_back(o);
    if (!client.empty())
      hello.options.push_back({static_cast<uint16_t>(Tag::CLIENT_ID), client});
    auto data = tgw::encode(hello, psk().data(), 1);
    auto replies = decoded_to(control.handle(data.data(), data.size(), addr, now_us), addr);
    CHECK(!replies.empty() && replies[0].type == MessageType::WELCOME);
    if (replies.empty())
      return;
    welcome = replies[0];
    after_welcome.assign(replies.begin() + 1, replies.end());
    const tgw::Option *gateway_nonce = tgw::find_option(welcome.options, Tag::GATEWAY_NONCE);
    CHECK(gateway_nonce != nullptr);
    if (gateway_nonce != nullptr)
      tgw::session_key(psk().data(), nonce().data(), gateway_nonce->value.data(), BOOT, key.data());
  }

  std::vector<tgw::Message> send(const tgw::Message &msg, uint64_t now_us) {
    auto data = tgw::encode(msg, key.data(), ++seq);
    return decoded_to(control.handle(data.data(), data.size(), addr, now_us), addr);
  }
};

tgw::Option asking(uint16_t seconds = 900, uint8_t entries = 16) {
  tgw::Option o = tgw::Option::u16(Tag::DEADMAN, seconds);
  o.value.push_back(entries);
  o.value.push_back(0);
  o.value.push_back(0);
  return o;
}

std::vector<uint8_t> write_request(uint16_t reg, uint32_t value) {
  std::vector<uint8_t> frame{0xC0, 0x6B, 0x06, uint8_t(reg), uint8_t(reg >> 8)};
  for (int i = 0; i < 4; i++)
    frame.push_back(value >> (8 * i));
  frame.push_back(tgw::bus_checksum(frame.data(), frame.size()));
  return frame;
}

std::vector<uint8_t> read_request(uint16_t reg) {
  std::vector<uint8_t> frame{0xC0, 0x69, 0x02, uint8_t(reg), uint8_t(reg >> 8)};
  frame.push_back(tgw::bus_checksum(frame.data(), frame.size()));
  return frame;
}

tgw::Message arm(uint8_t entry = 0, uint16_t reg = OFFSET, uint32_t expected = SET, uint32_t put = FOUND) {
  tgw::Message m;
  m.type = MessageType::ARM;
  m.id = 10 + entry;
  m.entry = entry;
  m.width = 2;
  m.reg = reg;
  m.expected = expected;
  m.frame = write_request(reg, put);
  return m;
}

tgw::Message simple(MessageType type, uint8_t entry = 0, uint32_t id = 0) {
  tgw::Message m;
  m.type = type;
  m.id = id;
  m.entry = entry;
  return m;
}

uint32_t opt(const tgw::Message &m, Tag tag) {
  const tgw::Option *o = tgw::find_option(m.options, tag);
  return o == nullptr ? 0xFFFFFFFF : o->as_uint();
}

std::vector<uint8_t> deadman_option(const tgw::Message &welcome) {
  const tgw::Option *o = tgw::find_option(welcome.options, Tag::DEADMAN);
  return o == nullptr ? std::vector<uint8_t>{} : o->value;
}

// A telegram from the pump to MODBUS40, a 0x5C in its data sent doubled.
std::vector<uint8_t> telegram(uint8_t command, const std::vector<uint8_t> &payload) {
  std::vector<uint8_t> data;
  for (auto b : payload) {
    data.push_back(b);
    if (b == 0x5C)
      data.push_back(b);
  }
  std::vector<uint8_t> t{0x5C, 0x00, 0x20, command, uint8_t(data.size())};
  t.insert(t.end(), data.begin(), data.end());
  t.push_back(tgw::bus_checksum(t.data() + 1, t.size() - 1));
  return t;
}

// The pump's side of the bus: tokens, and the answers to what it took.
struct Pump {
  Gateway &g;
  std::map<uint16_t, uint32_t> registers;
  std::vector<std::pair<uint16_t, uint32_t>> writes;
  std::vector<tgw::Datagram> sent;  // what the gateway sent the clients meanwhile

  Pump(Gateway &gateway, std::map<uint16_t, uint32_t> values) : g(gateway), registers(std::move(values)) {}

  void exchange(std::vector<uint8_t> data, tgw::Exchange::Reply reply, size_t reply_len, uint64_t now_us,
                uint64_t reply_us) {
    data.push_back(0x06);
    auto x = tgw::make_exchange(data.data(), data.size(), true, reply, reply_len, now_us, reply_us);
    auto out = g.control->on_exchange(x);
    sent.insert(sent.end(), out.begin(), out.end());
  }

  void cycle(uint64_t now_us, std::vector<uint8_t> tokens = {0x69, 0x6B}) {
    for (uint8_t token : tokens) {
      const QueuedRequest *queued = g.engine.reply_for(0x20, token, now_us);
      std::optional<std::vector<uint8_t>> reply;
      if (queued != nullptr)
        reply = queued->data;
      auto data = telegram(token, {});
      if (reply)
        data.insert(data.end(), reply->begin(), reply->end());
      exchange(data, reply ? tgw::Exchange::Reply::QUEUED : tgw::Exchange::Reply::NONE, reply ? reply->size() : 0,
               now_us, reply ? now_us : 0);
      if (!reply)
        continue;
      uint16_t reg = (*reply)[3] | ((*reply)[4] << 8);
      std::vector<uint8_t> answer;
      if (token == 0x69) {
        uint32_t value = registers.count(reg) ? registers[reg] : 0;
        answer = telegram(0x6A, {uint8_t(reg), uint8_t(reg >> 8), uint8_t(value), uint8_t(value >> 8),
                                 uint8_t(value >> 16), uint8_t(value >> 24)});
      } else {
        uint32_t value = ((*reply)[5] | ((*reply)[6] << 8)) & 0xFFFF;
        registers[reg] = value;
        writes.emplace_back(reg, value);
        answer = telegram(0x6C, {0x01});
      }
      exchange(answer, tgw::Exchange::Reply::NONE, 0, now_us + 1000, 0);
    }
  }

  void run(uint64_t start_us, uint64_t until_us, uint64_t step_us = S) {
    for (uint64_t t = start_us; t <= until_us; t += step_us) {
      auto out = g.control->tick(t);
      sent.insert(sent.end(), out.begin(), out.end());
      cycle(t);
    }
  }
};

using Writes = std::vector<std::pair<uint16_t, uint32_t>>;

bool is_answer(const std::vector<tgw::Message> &replies, ArmResult result, ArmRefusal detail = ArmRefusal::NONE) {
  return replies.size() == 1 && replies[0].type == MessageType::ARMED &&
         replies[0].result == static_cast<uint8_t>(result) && replies[0].detail == static_cast<uint16_t>(detail);
}

bool is_fired(const tgw::Message &m, uint8_t entry, FiredOutcome outcome) {
  return m.type == MessageType::FIRED && m.entry == entry && m.outcome == static_cast<uint8_t>(outcome);
}

std::set<uint8_t> armed_numbers(const Gateway &g, const std::vector<uint8_t> &client = THERMAESTRO) {
  std::set<uint8_t> numbers;
  auto found = g.deadman().clients().find(id(client));
  if (found != g.deadman().clients().end()) {
    for (const auto &[number, entry] : found->second.armed)
      numbers.insert(number);
  }
  return numbers;
}

// Armed (and kept) at 299 s and silent for 300 s, so fired at 599 s; the gateway gone
// without a word while its read (or, with `past_read`, its write) is still out.
std::shared_ptr<Store> firing_saved(bool past_read) {
  auto store = std::make_shared<Store>();
  Gateway g(store);
  Client(g, A, 0, {asking(300)}).send(arm(), 299 * S);
  written(g, A, 299 * S);
  Pump pump{g, {{OFFSET, SET}}};
  g.control->tick(599 * S);  // the read is queued
  if (past_read)
    pump.cycle(599 * S + 500000, {0x69});  // answered: the write is queued
  g.control->tick(tgw::Deadman::SAVE_EVERY_US);
  CHECK(pump.writes.empty());
  return store;
}

}  // namespace

TEST(deadman_granted_only_with_a_key_and_when_asked) {
  Gateway g;
  Client granted(g, A, 0, {asking(60, 40)});
  CHECK(test::hex(deadman_option(granted.welcome)) == test::hex({0x2C, 0x01, 16, 0, 0}));  // 300 s, 16 entries
  CHECK(opt(granted.welcome, Tag::FEATURES) & tgw::feature::DEADMAN);
  Client plain(g, B, 0);
  CHECK(deadman_option(plain.welcome).empty());
  CHECK(is_answer(plain.send(arm(), 1), ArmResult::REFUSED, ArmRefusal::NOT_GRANTED));

  Gateway keyless(nullptr, false);
  tgw::Message hello;
  hello.type = MessageType::HELLO;
  hello.id = 1;
  hello.options.push_back(asking());
  auto data = tgw::encode(hello);
  auto replies = decoded_to(keyless.control->handle(data.data(), data.size(), A, 0), A);
  CHECK(replies.size() == 1 && deadman_option(replies[0]).empty());
  CHECK(!(opt(replies.at(0), Tag::FEATURES) & tgw::feature::DEADMAN));
  CHECK(keyless.control->deadman() == nullptr);
}

TEST(deadman_what_arm_refuses) {
  Gateway g;
  Client client(g, A, 0, {asking(900, 4)});
  CHECK(is_answer(client.send(arm(4), 1), ArmResult::REFUSED, ArmRefusal::NO_SUCH_ENTRY));
  tgw::Message m = arm();
  m.width = 3;
  CHECK(is_answer(client.send(m, 1), ArmResult::REFUSED, ArmRefusal::BAD_WIDTH));
  m = arm();
  m.frame = read_request(OFFSET);
  CHECK(is_answer(client.send(m, 1), ArmResult::REFUSED, ArmRefusal::INVALID_FRAME));
  m = arm();
  m.reg = 47012;
  CHECK(is_answer(client.send(m, 1), ArmResult::REFUSED, ArmRefusal::REGISTER_MISMATCH));
  auto armed = client.send(arm(), 2);
  CHECK(is_answer(armed, ArmResult::ARMED));
  CHECK(armed.at(0).id == 10 && armed.at(0).gw_time_us == 2);
}

TEST(deadman_a_silent_client_has_its_change_put_back_and_hears_of_it) {
  Gateway g;
  Client client(g, A, 0, {asking()});
  client.send(arm(), 1 * S);
  Pump pump{g, {{OFFSET, SET}}};
  pump.run(2 * S, 899 * S, 60 * S);
  CHECK(pump.writes.empty());  // still within its silence
  pump.run(902 * S, 910 * S);
  CHECK((pump.writes == Writes{{OFFSET, FOUND}}));
  Client back(g, A, 1000 * S, {asking()});
  CHECK(test::hex(deadman_option(back.welcome)) == test::hex({0x84, 0x03, 16, 0, 1}));
  CHECK(back.after_welcome.size() == 1);
  if (back.after_welcome.size() == 1) {
    const auto &fired = back.after_welcome[0];
    CHECK(is_fired(fired, 0, FiredOutcome::PUT_BACK) && fired.reg == OFFSET);
    CHECK(fired.fired_us > 900 * S && fired.id == 0);
  }
  CHECK(is_answer(back.send(simple(MessageType::ACK_FIRED, 0, 7), 1001 * S), ArmResult::DISARMED));
  Client again(g, A, 1002 * S, {asking()});
  CHECK(again.after_welcome.empty());
  pump.run(1003 * S, 3000 * S, 60 * S);
  CHECK((pump.writes == Writes{{OFFSET, FOUND}}));  // once only
}

TEST(deadman_a_change_made_by_someone_else_is_never_written_over) {
  Gateway g;
  Client(g, A, 0, {asking()}).send(arm(), 1 * S);
  Pump pump{g, {{OFFSET, 0x0001}}};  // set to +1 at the pump while Thermaestro was away
  pump.run(901 * S, 910 * S);
  CHECK(pump.writes.empty());
  CHECK(pump.registers[OFFSET] == 0x0001);
  Client back(g, A, 1000 * S, {asking()});
  CHECK(back.after_welcome.size() == 1);
  if (back.after_welcome.size() == 1) {
    CHECK(is_fired(back.after_welcome[0], 0, FiredOutcome::SKIPPED));
    CHECK(back.after_welcome[0].read == 0x0001);
  }
}

TEST(deadman_any_message_from_the_client_keeps_it_from_firing_and_disarm_ends_it) {
  Gateway g;
  Client client(g, A, 0, {asking()});
  client.send(arm(), 1 * S);
  Pump pump{g, {{OFFSET, SET}}};
  for (uint64_t t = 600; t < 3000; t += 600) {
    client.send(simple(MessageType::KEEPALIVE), t * S);
    pump.run(t * S, t * S + 10 * S);
  }
  CHECK(pump.writes.empty());
  CHECK(is_answer(client.send(simple(MessageType::DISARM, 0), 3000 * S), ArmResult::DISARMED));
  pump.run(3001 * S, 6000 * S, 60 * S);
  CHECK(pump.writes.empty());
}

TEST(deadman_a_client_back_meanwhile_stops_the_firing_after_the_entry_under_way) {
  Gateway g;
  Client client(g, A, 0, {asking()});
  client.send(arm(0), 1 * S);
  client.send(arm(1, 47376, 0xFF6A, 0x0096), 1 * S);
  Pump pump{g, {{OFFSET, SET}, {47376, 0xFF6A}}};
  g.control->tick(901 * S);  // entry 0's read is queued
  Client back(g, A, 901 * S + 1, {asking()});
  pump.run(902 * S, 920 * S);
  CHECK((pump.writes == Writes{{OFFSET, FOUND}}));
  CHECK(armed_numbers(g) == std::set<uint8_t>{1});
}

TEST(deadman_an_entry_keeps_its_number_until_its_outcome_is_acknowledged) {
  // Being fired, or fired and not acknowledged, an entry is neither armed anew nor
  // disarmed: a report for it is always for what the client armed last.
  Gateway g;
  Client(g, A, 0, {asking(300)}).send(arm(0), 1 * S);
  Pump pump{g, {{OFFSET, SET}}};
  g.control->tick(302 * S);  // silent: its read is queued
  Client back(g, A, 302 * S + 1, {asking(300)});
  CHECK(is_answer(back.send(arm(0, OFFSET, 0x0003), 303 * S), ArmResult::REFUSED, ArmRefusal::FIRED));
  CHECK(is_answer(back.send(simple(MessageType::DISARM, 0, 20), 303 * S), ArmResult::REFUSED, ArmRefusal::FIRED));
  pump.run(304 * S, 310 * S);
  CHECK((pump.writes == Writes{{OFFSET, FOUND}}));  // the firing under way, as it was armed
  CHECK(is_answer(back.send(arm(0, OFFSET, 0x0003), 311 * S), ArmResult::REFUSED, ArmRefusal::FIRED));
  CHECK(is_answer(back.send(simple(MessageType::ACK_FIRED, 0, 21), 312 * S), ArmResult::DISARMED));
  CHECK(is_answer(back.send(arm(0, OFFSET, 0x0003), 313 * S), ArmResult::ARMED));
}

TEST(deadman_an_entry_that_fires_once_a_client_is_back_is_reported_at_once) {
  // The entry under way as a session starts isn't in its WELCOME: it is reported as it
  // finishes, not only at the next one.
  Gateway g;
  Client(g, A, 0, {asking(300)}).send(arm(0), 1 * S);
  Pump pump{g, {{OFFSET, 0x0001}}};  // set at the pump meanwhile
  g.control->tick(302 * S);          // its read is queued
  Client back(g, A, 302 * S + 1, {asking(300)});
  CHECK(back.after_welcome.empty());
  pump.cycle(303 * S);
  std::vector<tgw::Message> reports;
  for (const auto &m : decoded_to(pump.sent, A)) {
    if (m.type == MessageType::FIRED)
      reports.push_back(m);
  }
  CHECK(reports.size() == 1);
  if (reports.size() == 1)
    CHECK(is_fired(reports[0], 0, FiredOutcome::SKIPPED) && reports[0].read == 0x0001);
}

TEST(deadman_kept_through_a_restart_of_the_gateway) {
  auto store = std::make_shared<Store>();
  {
    Gateway g(store);
    Client client(g, A, 0, {asking()});
    CHECK(client.send(arm(), 1 * S).empty());  // not confirmed until it is kept
    // Handed over at once: the gateway may reboot right after, the client gone.
    CHECK(store->saved && store->saved->client_count == 1 && store->saved->clients[0].armed_count == 1 &&
          store->saved->clients[0].armed[0].reg == OFFSET && store->saved->clients[0].owned == 1);
    CHECK(is_answer(written(g, A, 1 * S + 10), ArmResult::ARMED));
  }
  {
    Gateway restarted(store);  // the silence counts from the restart
    Pump pump{restarted, {{OFFSET, SET}}};
    pump.run(0, 899 * S, 60 * S);
    CHECK(pump.writes.empty());
    pump.run(901 * S, 910 * S);
    CHECK((pump.writes == Writes{{OFFSET, FOUND}}));
  }
  // Fired and kept at once: a second restart reports it, and doesn't fire it again.
  Gateway again(store);
  Pump pump{again, {{OFFSET, SET}}};
  pump.run(901 * S, 910 * S);
  CHECK(pump.writes.empty());
  Client back(again, A, 1000 * S, {asking()});
  CHECK(back.after_welcome.size() == 1);
  if (back.after_welcome.size() == 1)
    CHECK(is_fired(back.after_welcome[0], 0, FiredOutcome::PUT_BACK) && back.after_welcome[0].fired_us == 0);
}

TEST(deadman_stopping_mid_firing_keeps_the_entry_armed) {
  auto store = std::make_shared<Store>();
  Gateway g(store);
  Client(g, A, 0, {asking()}).send(arm(), 1 * S);
  written(g, A, 1 * S);
  g.control->tick(901 * S);  // its read is queued
  g.control->shutdown(902 * S);
  CHECK(store->saved && store->saved->client_count == 1 && store->saved->clients[0].armed_count == 1 &&
        store->saved->clients[0].armed[0].number == 0);
}

TEST(deadman_a_restart_during_a_firing_fires_it_again) {
  for (bool past_read : {false, true}) {
    auto store = firing_saved(past_read);
    Gateway restarted(store);
    Pump pump{restarted, {{OFFSET, SET}}};  // still as the client left it
    pump.run(0, 310 * S);
    CHECK_MSG((pump.writes == Writes{{OFFSET, FOUND}}), past_read ? "past the read" : "at the read");
    Client back(restarted, A, 1000 * S, {asking()});
    CHECK(back.after_welcome.size() == 1);
    if (back.after_welcome.size() == 1)
      CHECK(is_fired(back.after_welcome[0], 0, FiredOutcome::PUT_BACK));
  }
}

TEST(deadman_after_a_restart_a_register_already_back_or_changed_isnt_written) {
  for (auto [value, outcome] :
       {std::make_pair(FOUND, FiredOutcome::PUT_BACK), std::make_pair(uint32_t(0x0001), FiredOutcome::SKIPPED)}) {
    auto store = firing_saved(true);
    Gateway restarted(store);
    // The write before the restart went through, or someone set the register meanwhile.
    Pump pump{restarted, {{OFFSET, value}}};
    pump.run(0, 310 * S);
    CHECK(pump.writes.empty());
    CHECK(pump.registers[OFFSET] == value);
    Client back(restarted, A, 1000 * S, {asking()});
    CHECK(back.after_welcome.size() == 1);
    if (back.after_welcome.size() == 1)
      CHECK(is_fired(back.after_welcome[0], 0, outcome) && back.after_welcome[0].read == value);
  }
}

TEST(deadman_a_4_byte_entry_compares_both_words) {
  Gateway g;
  Client client(g, A, 0, {asking(300)});
  tgw::Message m = arm(0, 47212, 0x00010002, 0x00030004);
  m.width = 4;
  CHECK(is_answer(client.send(m, 1 * S), ArmResult::ARMED));
  Pump pump{g, {{47212, 0x00050002}}};  // the low word as set, the high one not
  pump.run(302 * S, 310 * S);
  CHECK(pump.writes.empty());
  Client back(g, A, 400 * S, {asking(300)});
  CHECK(back.after_welcome.size() == 1);
  if (back.after_welcome.size() == 1)
    CHECK(is_fired(back.after_welcome[0], 0, FiredOutcome::SKIPPED) && back.after_welcome[0].read == 0x00050002);
}

// --- each client its own ------------------------------------------------------------------

TEST(deadman_granted_only_to_a_client_that_says_who_it_is) {
  Gateway g;
  Client anonymous(g, A, 0, {asking()}, {});
  CHECK(deadman_option(anonymous.welcome).empty());
  CHECK(is_answer(anonymous.send(arm(), 1 * S), ArmResult::REFUSED, ArmRefusal::NOT_GRANTED));
}

TEST(deadman_two_clients_entries_of_one_number_are_each_their_own) {
  Gateway g;
  Client thermaestro(g, A, 0, {asking()});
  Client rig(g, B, 0, {asking()}, RIG);
  thermaestro.send(arm(0), 1 * S);
  rig.send(arm(0, 47376, 0xFF6A, 0x0096), 2 * S);
  rig.send(simple(MessageType::DISARM, 0, 30), 3 * S);  // the rig puts its own back
  Pump pump{g, {{OFFSET, SET}, {47376, 0xFF6A}}};
  pump.run(904 * S, 910 * S);
  CHECK((pump.writes == Writes{{OFFSET, FOUND}}));  // Thermaestro's entry 0: not replaced, not dropped
}

TEST(deadman_another_client_talking_doesnt_keep_a_silent_ones_entries_from_firing) {
  Gateway g;
  Client(g, A, 0, {asking()}).send(arm(0), 1 * S);
  Client rig(g, B, 0, {asking()}, RIG);
  rig.send(arm(0, 47376, 0xFF6A, 0x0096), 1 * S);
  Pump pump{g, {{OFFSET, SET}, {47376, 0xFF6A}}};
  for (uint64_t t = 60; t < 1200; t += 60) {
    rig.send(simple(MessageType::KEEPALIVE), t * S);
    pump.run(t * S, t * S + 10 * S);
  }
  CHECK((pump.writes == Writes{{OFFSET, FOUND}}));  // Thermaestro's, after its own silence; not the rig's
}

TEST(deadman_a_client_back_from_another_address_is_the_same_client) {
  // A restart of Thermaestro binds another port: its entries are still its own.
  Gateway g;
  Client(g, A, 0, {asking()}).send(arm(0), 1 * S);
  Pump pump{g, {{OFFSET, SET}}};
  Client back(g, C, 600 * S, {asking()});
  CHECK(test::hex(deadman_option(back.welcome)) == test::hex({0x84, 0x03, 16, 1, 0}));  // its entry, held for it
  pump.run(901 * S, 1400 * S, 60 * S);
  CHECK(pump.writes.empty());  // its silence started again at 600 s
  Client again(g, C, 1401 * S, {asking()});  // its lease ended meanwhile
  CHECK(is_answer(again.send(simple(MessageType::DISARM, 0, 31), 1401 * S), ArmResult::DISARMED));
  pump.run(1402 * S, 4000 * S, 60 * S);
  CHECK(pump.writes.empty());
}

TEST(deadman_a_report_goes_to_its_own_client_only) {
  Gateway g;
  Client(g, A, 0, {asking(300)}).send(arm(0), 1 * S);
  Pump pump{g, {{OFFSET, SET}}};
  Client rig(g, B, 0, {asking()}, RIG);
  for (uint64_t t = 60; t < 400; t += 60) {
    rig.send(simple(MessageType::KEEPALIVE), t * S);
    pump.run(t * S, t * S + 10 * S);
  }
  CHECK((pump.writes == Writes{{OFFSET, FOUND}}));
  for (const auto &m : decoded_to(pump.sent, B))
    CHECK(m.type != MessageType::FIRED);
  rig.send(simple(MessageType::ACK_FIRED, 0, 32), 401 * S);  // the rig's entry 0 has no report: no effect
  Client back(g, A, 402 * S, {asking(300)});
  CHECK(back.after_welcome.size() == 1);
  if (back.after_welcome.size() == 1)
    CHECK(is_fired(back.after_welcome[0], 0, FiredOutcome::PUT_BACK));
  Client rig_again(g, B, 403 * S, {asking()}, RIG);
  CHECK(rig_again.after_welcome.empty());
}

namespace {

std::shared_ptr<Store> saved_by_revision_4() {
  auto store = std::make_shared<Store>();
  tgw::DeadmanSavedV1 v1{};
  v1.magic = tgw::DeadmanSavedV1::MAGIC;
  v1.silence_s = 300;
  v1.armed_count = 1;
  auto &a = v1.armed[0];
  a.number = 3;
  a.width = 2;
  a.reg = OFFSET;
  a.expected = SET;
  auto frame = write_request(OFFSET, FOUND);
  std::memcpy(a.frame, frame.data(), frame.size());
  store->saved_v1 = v1;
  return store;
}

}  // namespace

TEST(deadman_what_revision_4_kept_is_the_first_granted_clients) {
  auto store = saved_by_revision_4();
  Gateway g(store);
  Client first(g, A, 0, {asking(300)});
  CHECK(test::hex(deadman_option(first.welcome)) == test::hex({0x2C, 0x01, 16, 1, 0}));
  CHECK(is_answer(first.send(simple(MessageType::DISARM, 3, 33), 1 * S), ArmResult::DISARMED));
  Pump pump{g, {{OFFSET, SET}}};
  pump.run(2 * S, 2000 * S, 60 * S);
  CHECK(pump.writes.empty());
}

TEST(deadman_what_revision_4_kept_fires_if_nobody_comes) {
  auto store = saved_by_revision_4();
  Gateway g(store);
  Pump pump{g, {{OFFSET, SET}}};
  pump.run(0, 310 * S);
  CHECK((pump.writes == Writes{{OFFSET, FOUND}}));
  CHECK(store->saved && store->saved->client_count == 1 && store->saved->clients[0].owned == 0);
  Client first(g, A, 400 * S, {asking(300)});
  CHECK(first.after_welcome.size() == 1);
  if (first.after_welcome.size() == 1)
    CHECK(is_fired(first.after_welcome[0], 3, FiredOutcome::PUT_BACK));
}

TEST(deadman_no_dead_man_for_a_client_past_those_held_for) {
  Gateway g;
  for (uint8_t n = 0; n < tgw::Deadman::MAX_CLIENTS; n++) {
    Client held(g, A, n * S, {asking()}, std::vector<uint8_t>(16, n));
    held.send(arm(0), n * S + 1);
    held.send(simple(MessageType::BYE), n * S + 2);
  }
  Client late(g, A, 10 * S, {asking()}, std::vector<uint8_t>(16, 0xEE));
  CHECK(deadman_option(late.welcome).empty());
  Client again(g, B, 11 * S, {asking()}, std::vector<uint8_t>(16, 0));
  CHECK(!deadman_option(again.welcome).empty());  // one it holds for
}

TEST(deadman_an_arm_past_the_clients_held_for_is_refused) {
  // Granted while there was room, and another took it meanwhile.
  Gateway g;
  for (uint8_t n = 0; size_t(n) + 1 < tgw::Deadman::MAX_CLIENTS; n++) {
    Client held(g, A, n * S, {asking()}, std::vector<uint8_t>(16, n));
    held.send(arm(0), n * S + 1);
    held.send(simple(MessageType::BYE), n * S + 2);
  }
  Client first(g, A, 10 * S, {asking()}, std::vector<uint8_t>(16, 0xE0));
  Client second(g, B, 10 * S, {asking()}, std::vector<uint8_t>(16, 0xE1));
  CHECK(is_answer(first.send(arm(0), 11 * S), ArmResult::ARMED));
  CHECK(is_answer(second.send(arm(0), 12 * S), ArmResult::REFUSED, ArmRefusal::NO_ROOM));
}

TEST(deadman_an_arm_is_confirmed_once_it_is_kept) {
  auto store = std::make_shared<Store>();
  Gateway g(store);
  Client client(g, A, 0, {asking()});
  CHECK(client.send(arm(0), 1 * S).empty());
  CHECK(client.send(arm(1, 47376, 0xFF6A, 0x0096), 1 * S).empty());
  auto answers = written(g, A, 1 * S + 20000);
  CHECK(answers.size() == 2);
  if (answers.size() == 2) {
    CHECK(answers[0].type == MessageType::ARMED && answers[0].entry == 0 && answers[0].id == 10);
    CHECK(answers[1].type == MessageType::ARMED && answers[1].entry == 1 && answers[1].id == 11);
    CHECK(answers[1].result == static_cast<uint8_t>(ArmResult::ARMED) && answers[1].gw_time_us == 1 * S + 20000);
  }
  CHECK(written(g, A, 2 * S).empty());  // each answered once
}

TEST(deadman_an_arm_that_cant_be_kept_is_refused_and_not_armed) {
  auto store = std::make_shared<Store>();
  Gateway g(store);
  Client client(g, A, 0, {asking()});
  client.send(arm(0), 1 * S);
  CHECK(is_answer(written(g, A, 1 * S + 20000, false), ArmResult::REFUSED, ArmRefusal::NOT_KEPT));
  CHECK(armed_numbers(g).empty());
  Pump pump{g, {{OFFSET, SET}}};
  pump.run(901 * S, 910 * S);
  CHECK(pump.writes.empty());  // not armed: the client doesn't make the change
}

TEST(deadman_a_report_nobody_acknowledges_is_dropped_in_time) {
  Gateway g;
  Client(g, A, 0, {asking(300)}, RIG).send(arm(0), 1 * S);
  Pump pump{g, {{OFFSET, SET}}};
  pump.run(302 * S, 310 * S);
  CHECK((pump.writes == Writes{{OFFSET, FOUND}}));
  const auto &clients = g.deadman().clients();
  CHECK(clients.count(id(RIG)) == 1);
  if (clients.count(id(RIG)) == 0)
    return;
  uint64_t kept_us = clients.at(id(RIG)).fired.at(0).kept_us;
  g.control->tick(kept_us + tgw::Deadman::REPORT_KEPT_US - S);
  CHECK(g.deadman().clients().count(id(RIG)) == 1);
  g.control->tick(kept_us + tgw::Deadman::REPORT_KEPT_US);
  CHECK(g.deadman().clients().count(id(RIG)) == 0);  // nothing left for it: forgotten
  Client back(g, A, kept_us + tgw::Deadman::REPORT_KEPT_US + S, {asking(300)}, RIG);
  CHECK(back.after_welcome.empty());
}
