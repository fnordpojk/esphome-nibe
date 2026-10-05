// Sessions on the control port, case for case as the Python gateway's tests check them.

#include "test.h"
#include "../components/nibegw/TgwControl.h"

#include <cstring>
#include <memory>

using namespace esphome::nibegw;
using tgw::ErrorCode;
using tgw::MessageType;
using tgw::Tag;

namespace {

const tgw::Peer A{0x0A0200C0, 40000};  // 192.0.2.10
const tgw::Peer B{0x0B0200C0, 40001};  // 192.0.2.11
const request_key_type READ_KEY{0x20, 0x69};
const request_key_type WRITE_KEY{0x20, 0x6B};
const std::vector<uint8_t> READ_TOKEN = test::unhex("5c0020690049");

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

struct Fixture {
  request_queues_type queues;
  tgw::BusStats bus;
  tgw::Engine engine{queues, {READ_KEY, WRITE_KEY}, 3};
  std::unique_ptr<tgw::Control> control;

  explicit Fixture(bool with_psk = false, uint8_t max_clients = 4, std::vector<uint32_t> sources = {}) {
    tgw::ControlSettings s;
    s.boot_id = 0xDEADBEEF;
    s.plain_read_port = 9999;
    s.plain_write_port = 10000;
    s.max_clients = max_clients;
    s.sources = std::move(sources);
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
    control = std::make_unique<tgw::Control>(engine, bus, s);
  }

  // Send `msg` from `from`; the decoded replies to it.
  std::vector<tgw::Decoded> send(const tgw::Peer &from, const tgw::Message &msg, uint64_t now_us = 0,
                                 const uint8_t *key = nullptr, uint32_t seq = 0) {
    auto data = tgw::encode(msg, key, seq);
    std::vector<tgw::Decoded> replies;
    for (const auto &d : control->handle(data.data(), data.size(), from, now_us)) {
      if (d.to == from)
        replies.push_back(tgw::decode(d.data.data(), d.data.size()));
    }
    return replies;
  }
};

tgw::Message hello(std::vector<tgw::Option> options = {}, uint32_t id = 1) {
  tgw::Message m;
  m.type = MessageType::HELLO;
  m.id = id;
  m.options = std::move(options);
  return m;
}

tgw::Message request(uint32_t id, uint16_t reg = 47134) {
  tgw::Message m;
  m.type = MessageType::REQUEST;
  m.id = id;
  m.address = 0x20;
  m.token = 0x69;
  m.frame = {0xC0, 0x69, 0x02, static_cast<uint8_t>(reg), static_cast<uint8_t>(reg >> 8)};
  m.frame.push_back(tgw::bus_checksum(m.frame.data(), m.frame.size()));
  return m;
}

tgw::Message simple(MessageType type, uint32_t id = 0) {
  tgw::Message m;
  m.type = type;
  m.id = id;
  return m;
}

uint32_t opt(const tgw::Message &m, Tag tag) {
  const tgw::Option *o = tgw::find_option(m.options, tag);
  CHECK_MSG(o != nullptr, std::to_string(static_cast<int>(tag)));
  return o == nullptr ? 0xFFFFFFFF : o->as_uint();
}

bool is_error(const std::vector<tgw::Decoded> &replies, ErrorCode code) {
  return replies.size() == 1 && replies[0].msg.type == MessageType::ERROR &&
         replies[0].msg.code == static_cast<uint16_t>(code);
}

tgw::Exchange exchange_for(tgw::Engine &engine, uint64_t now_us) {
  const QueuedRequest *sent = engine.reply_for(0x20, 0x69, now_us);
  std::vector<uint8_t> data = READ_TOKEN;
  size_t reply_len = 0;
  if (sent != nullptr) {
    data.insert(data.end(), sent->data.begin(), sent->data.end());
    reply_len = sent->data.size();
  }
  data.push_back(0x06);
  return tgw::make_exchange(data.data(), data.size(), true,
                            sent != nullptr ? tgw::Exchange::Reply::QUEUED : tgw::Exchange::Reply::NONE, reply_len,
                            now_us + 20000, sent != nullptr ? now_us : 0);
}

std::vector<std::pair<tgw::Peer, tgw::Message>> frames(const std::vector<tgw::Datagram> &out) {
  std::vector<std::pair<tgw::Peer, tgw::Message>> found;
  for (const auto &d : out) {
    auto decoded = tgw::decode(d.data.data(), d.data.size());
    if (decoded.ok() && decoded.msg.type == MessageType::FRAME)
      found.emplace_back(d.to, decoded.msg);
  }
  return found;
}

}  // namespace

TEST(control_hello_gets_a_welcome) {
  Fixture f;
  auto replies = f.send(A, hello({tgw::Option::u16(Tag::LEASE_S, 60)}, 5), 1000);
  CHECK(replies.size() == 1);
  const auto &w = replies[0].msg;
  CHECK(w.type == MessageType::WELCOME);
  CHECK(w.id == 5 && w.gw_time_us == 1000);
  CHECK(opt(w, Tag::BOOT_ID) == 0xDEADBEEF);
  CHECK(opt(w, Tag::LEASE_S) == 60);
  CHECK(tgw::find_option(w.options, Tag::IMPL)->as_text() == "esphome-nibe");
  CHECK(opt(w, Tag::QUEUE_CAP) == 3 && opt(w, Tag::PROTOCOL_SLOTS) == 1);
  CHECK(test::hex(tgw::find_option(w.options, Tag::PLAIN_PORTS)->value) == "0f271027");
  CHECK(opt(w, Tag::ACK_ADDRESS) == 0x20);
  CHECK(opt(w, Tag::FEATURES) & tgw::feature::FATE);
  CHECK(!(opt(w, Tag::FEATURES) & tgw::feature::AUTH));
  CHECK(f.control->clients() == 1);
}

TEST(control_lease_is_clamped) {
  Fixture f;
  auto replies = f.send(A, hello({tgw::Option::u16(Tag::LEASE_S, 1)}));
  CHECK(opt(replies.at(0).msg, Tag::LEASE_S) == 10);
}

TEST(control_a_client_outside_the_version_range_is_refused) {
  Fixture f;
  tgw::Message m = hello({}, 3);
  m.ver_min = 1;
  m.ver_max = 2;
  auto replies = f.send(A, m);
  CHECK(is_error(replies, ErrorCode::BAD_VERSION));
  CHECK(replies.at(0).msg.id == 3);
  CHECK(f.control->clients() == 0);
}

TEST(control_messages_without_a_session_are_refused) {
  Fixture f;
  CHECK(is_error(f.send(A, simple(MessageType::KEEPALIVE, 9)), ErrorCode::NO_SESSION));
}

TEST(control_too_many_clients) {
  Fixture f(false, 1);
  f.send(A, hello());
  CHECK(is_error(f.send(B, hello()), ErrorCode::TOO_MANY_CLIENTS));
}

TEST(control_a_source_filter_refuses_other_addresses) {
  Fixture f(false, 4, {0x630200C0});  // 192.0.2.99
  CHECK(is_error(f.send(A, hello()), ErrorCode::SOURCE_REFUSED));
}

TEST(control_a_request_is_queued_and_its_fate_reported) {
  Fixture f;
  f.send(A, hello());
  auto replies = f.send(A, request(42), 5000);
  CHECK(replies.size() == 1);
  CHECK(replies[0].msg.type == MessageType::FATE);
  CHECK(replies[0].msg.id == 42 && replies[0].msg.stage == static_cast<uint8_t>(tgw::Stage::QUEUED));
  CHECK(f.engine.depths()[READ_KEY] == 1);
}

TEST(control_cancel_of_an_unknown_request) {
  Fixture f;
  f.send(A, hello());
  auto replies = f.send(A, simple(MessageType::CANCEL, 77));
  CHECK(is_error(replies, ErrorCode::UNKNOWN_REQUEST));
  CHECK(replies.at(0).msg.id == 77);
}

TEST(control_a_request_with_an_unknown_critical_option) {
  Fixture f;
  f.send(A, hello());
  tgw::Message m = request(8);
  m.options.push_back({static_cast<uint16_t>(0x0499 | tgw::CRITICAL), {}});
  auto replies = f.send(A, m);
  bool error = false, fate = false;
  for (const auto &r : replies) {
    error = error ||
            (r.msg.type == MessageType::ERROR && r.msg.code == static_cast<uint16_t>(ErrorCode::UNSUPPORTED_OPTION));
    fate = fate || (r.msg.type == MessageType::FATE && r.msg.stage == static_cast<uint8_t>(tgw::Stage::DROPPED) &&
                    r.msg.detail == static_cast<uint16_t>(tgw::DropReason::UNSUPPORTED_OPTION));
  }
  CHECK(error);
  CHECK(fate);
}

TEST(control_frames_go_to_subscribers_with_the_origin_per_recipient) {
  Fixture f;
  f.send(A, hello({tgw::Option::u32(Tag::SUBSCRIBE, tgw::subscription::FRAMES_OWN)}));
  f.send(B, hello({tgw::Option::u32(Tag::SUBSCRIBE, tgw::subscription::FRAMES_ALL)}));
  f.send(A, request(42));
  auto found = frames(f.control->on_exchange(exchange_for(f.engine, 1000000)));
  CHECK(found.size() == 2);
  for (const auto &[to, frame] : found) {
    if (to == A) {
      CHECK(frame.origin == static_cast<uint8_t>(tgw::Origin::THIS_CLIENT) && frame.request_id == 42);
    } else {
      CHECK(frame.origin == static_cast<uint8_t>(tgw::Origin::OTHER_CLIENT) && frame.request_id == 0);
    }
  }
  CHECK(found.size() == 2 && found[0].second.frame == found[1].second.frame);
  // An ACK-only exchange is nobody's own, so only the FRAMES_ALL client sees it.
  found = frames(f.control->on_exchange(exchange_for(f.engine, 2000000)));
  CHECK(found.size() == 1 && found[0].first == B);
}

TEST(control_plain_and_constant_origins) {
  Fixture f;
  f.send(A, hello({tgw::Option::u32(Tag::SUBSCRIBE, tgw::subscription::FRAMES_ALL)}));
  CHECK(f.engine.submit_plain(0x20, 0x69, request(0).frame, 0));
  auto found = frames(f.control->on_exchange(exchange_for(f.engine, 10)));
  CHECK(found.size() == 1 && found[0].second.origin == static_cast<uint8_t>(tgw::Origin::PLAIN_CLIENT));
  auto data = READ_TOKEN;
  auto constant = request(0).frame;
  data.insert(data.end(), constant.begin(), constant.end());
  data.push_back(0x06);
  auto x = tgw::make_exchange(data.data(), data.size(), true, tgw::Exchange::Reply::CONSTANT, constant.size(), 10, 5);
  found = frames(f.control->on_exchange(x));
  CHECK(found.size() == 1 && found[0].second.origin == static_cast<uint8_t>(tgw::Origin::CONSTANT));
}

TEST(control_the_lease_runs_out) {
  Fixture f;
  f.send(A, hello({tgw::Option::u16(Tag::LEASE_S, 10)}));
  f.send(A, request(1));
  f.control->tick(9000000);
  CHECK(f.control->clients() == 1);
  f.control->tick(10000001);
  CHECK(f.control->clients() == 0);
  CHECK(f.engine.depths()[READ_KEY] == 0);
}

TEST(control_keepalive_renews_and_bye_ends) {
  Fixture f;
  f.send(A, hello({tgw::Option::u16(Tag::LEASE_S, 10)}));
  f.send(A, simple(MessageType::KEEPALIVE), 8000000);
  f.control->tick(15000000);
  CHECK(f.control->clients() == 1);
  f.send(A, simple(MessageType::BYE), 15000000);
  CHECK(f.control->clients() == 0);
}

TEST(control_health_on_its_interval) {
  Fixture f;
  f.bus.frames_ok = 1234;
  f.send(A, hello({tgw::Option::u32(Tag::SUBSCRIBE, tgw::subscription::HEALTH),
                   tgw::Option::u16(Tag::HEALTH_INTERVAL_S, 5)}));
  CHECK(f.control->tick(4000000).empty());
  auto out = f.control->tick(5000000);
  CHECK(out.size() == 1);
  auto health = tgw::decode(out.at(0).data.data(), out.at(0).data.size()).msg;
  CHECK(out.at(0).to == A);
  CHECK(health.type == MessageType::HEALTH && health.id == 1);
  CHECK(opt(health, Tag::FRAMES_OK) == 1234);
  CHECK(opt(health, Tag::CLIENTS) == 1);
  CHECK(opt(health, Tag::UPTIME_S) == 5);
  CHECK(opt(health, Tag::BUS_STATE) == static_cast<uint8_t>(tgw::BusState::SILENT));
  CHECK(tgw::find_option(health.options, Tag::INVALID_BYTES) == nullptr);  // not measured here
}

TEST(control_health_at_once_when_the_bus_wakes_up) {
  Fixture f;
  f.send(A, hello({tgw::Option::u32(Tag::SUBSCRIBE, tgw::subscription::HEALTH)}));
  CHECK(f.control->tick(1000000).empty());
  f.bus.last_byte_us = 1500000;
  auto out = f.control->tick(1600000);
  CHECK(out.size() == 1);
  auto health = tgw::decode(out.at(0).data.data(), out.at(0).data.size()).msg;
  CHECK(opt(health, Tag::BUS_STATE) == static_cast<uint8_t>(tgw::BusState::ACTIVE));
  CHECK(opt(health, Tag::MS_SINCE_LAST_BYTE) == 100);
  CHECK(f.control->tick(1700000).empty());
}

TEST(control_errors_are_rate_limited) {
  Fixture f;
  CHECK(f.send(A, simple(MessageType::KEEPALIVE), 0).size() == 1);
  CHECK(f.send(A, simple(MessageType::KEEPALIVE), 100000).empty());
  CHECK(f.send(A, simple(MessageType::KEEPALIVE), 1100000).size() == 1);
}

TEST(control_critical_nonce_to_a_gateway_without_a_psk) {
  Fixture f;
  auto n = nonce();
  auto replies =
      f.send(A, hello({{static_cast<uint16_t>(static_cast<uint16_t>(Tag::CLIENT_NONCE) | tgw::CRITICAL), n}}));
  CHECK(is_error(replies, ErrorCode::UNSUPPORTED_OPTION));
  CHECK(f.control->clients() == 0);
}

// --- with a PSK ---------------------------------------------------------------------------

TEST(control_an_unsigned_hello_needs_authentication) {
  Fixture f(true);
  CHECK(is_error(f.send(A, hello()), ErrorCode::AUTH_REQUIRED));
  CHECK(f.control->clients() == 0);
}

TEST(control_a_hello_signed_with_the_wrong_key) {
  Fixture f(true);
  std::vector<uint8_t> wrong(32, 'x');
  auto replies =
      f.send(A, hello({{static_cast<uint16_t>(static_cast<uint16_t>(Tag::CLIENT_NONCE) | tgw::CRITICAL), nonce()}}), 0,
             wrong.data(), 1);
  CHECK(is_error(replies, ErrorCode::AUTH_FAILED));
}

TEST(control_an_authenticated_session) {
  Fixture f(true);
  auto key_psk = psk();
  auto signed_hello =
      tgw::encode(hello({{static_cast<uint16_t>(static_cast<uint16_t>(Tag::CLIENT_NONCE) | tgw::CRITICAL), nonce()}}),
                  key_psk.data(), 1);
  auto out = f.control->handle(signed_hello.data(), signed_hello.size(), A, 0);
  CHECK(out.size() == 1);
  auto welcome = tgw::decode(out.at(0).data.data(), out.at(0).data.size()).msg;
  const tgw::Option *gateway_nonce = tgw::find_option(welcome.options, Tag::GATEWAY_NONCE);
  CHECK(gateway_nonce != nullptr);
  std::vector<uint8_t> key(32);
  tgw::session_key(key_psk.data(), nonce().data(), gateway_nonce->value.data(), 0xDEADBEEF, key.data());
  uint32_t seq = 0;
  CHECK(tgw::verify(out[0].data.data(), out[0].data.size(), key.data(), &seq) == tgw::Verify::OK && seq == 1);
  CHECK(opt(welcome, Tag::FEATURES) & tgw::feature::AUTH);

  auto unsigned_request = tgw::encode(request(5));
  out = f.control->handle(unsigned_request.data(), unsigned_request.size(), A, 10);
  CHECK(out.size() == 1);
  auto error = tgw::decode(out.at(0).data.data(), out.at(0).data.size()).msg;
  CHECK(error.type == MessageType::ERROR && error.code == static_cast<uint16_t>(ErrorCode::AUTH_FAILED));
  CHECK(tgw::verify(out[0].data.data(), out[0].data.size(), key.data(), &seq) == tgw::Verify::OK && seq == 2);

  auto signed_request = tgw::encode(request(5), key.data(), 1);
  out = f.control->handle(signed_request.data(), signed_request.size(), A, 2000000);
  CHECK(out.size() == 1);
  CHECK(tgw::verify(out.at(0).data.data(), out.at(0).data.size(), key.data(), &seq) == tgw::Verify::OK && seq == 3);
  CHECK(f.engine.depths()[READ_KEY] == 1);

  auto replay = f.send(A, request(5), 4000000, key.data(), 1);
  CHECK(replay.size() == 1 && replay[0].msg.code == static_cast<uint16_t>(ErrorCode::REPLAY));
}
