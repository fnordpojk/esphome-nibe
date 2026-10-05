// The engine's behavior, case for case as the Python gateway's tests check it.

#include "test.h"
#include "../components/nibegw/TgwEngine.h"

#include <tuple>

using namespace esphome::nibegw;
using tgw::AnswerStatus;
using tgw::DropReason;
using tgw::Stage;

namespace {

int client_a = 1;
int client_b = 2;
const void *const A = &client_a;
const void *const B = &client_b;

const request_key_type READ_KEY{0x20, 0x69};
const request_key_type WRITE_KEY{0x20, 0x6B};
const std::vector<uint8_t> READ_TOKEN = test::unhex("5c0020690049");
const std::vector<uint8_t> WRITE_TOKEN = test::unhex("5c00206b004b");

request_data_type reply(uint8_t command, const std::vector<uint8_t> &data) {
  request_data_type frame{0xC0, command, static_cast<uint8_t>(data.size())};
  frame.insert(frame.end(), data.begin(), data.end());
  frame.push_back(tgw::bus_checksum(frame.data(), frame.size()));
  return frame;
}

request_data_type read_request(uint16_t reg) {
  return reply(0x69, {static_cast<uint8_t>(reg), static_cast<uint8_t>(reg >> 8)});
}

request_data_type write_request(uint16_t reg, uint32_t value) {
  return reply(
      0x6B, {static_cast<uint8_t>(reg), static_cast<uint8_t>(reg >> 8), static_cast<uint8_t>(value),
             static_cast<uint8_t>(value >> 8), static_cast<uint8_t>(value >> 16), static_cast<uint8_t>(value >> 24)});
}

std::vector<uint8_t> telegram(uint8_t command, const std::vector<uint8_t> &payload) {
  std::vector<uint8_t> out{0x5C, 0x00, 0x20, command, static_cast<uint8_t>(payload.size())};
  out.insert(out.end(), payload.begin(), payload.end());
  out.push_back(tgw::bus_checksum(out.data() + 1, out.size() - 1));
  return out;
}

std::vector<uint8_t> read_answer(uint16_t reg, uint16_t value) {
  return telegram(0x6A, {static_cast<uint8_t>(reg), static_cast<uint8_t>(reg >> 8), static_cast<uint8_t>(value),
                         static_cast<uint8_t>(value >> 8), 0, 0});
}

std::vector<uint8_t> write_answer(uint8_t result) {
  return telegram(0x6C, {result});
}

tgw::Message read(uint32_t id, uint16_t reg = 47134, uint8_t flags = tgw::request_flag::EXPECT_ANSWER,
                  uint16_t ttl_ms = 0, uint16_t answer_timeout_ms = 0) {
  tgw::Message m;
  m.type = tgw::MessageType::REQUEST;
  m.id = id;
  m.address = 0x20;
  m.token = 0x69;
  m.request_flags = flags;
  m.ttl_ms = ttl_ms;
  m.answer_timeout_ms = answer_timeout_ms;
  m.frame = read_request(reg);
  return m;
}

tgw::Message write(uint32_t id, uint16_t reg = 47387, uint32_t value = 1) {
  tgw::Message m;
  m.type = tgw::MessageType::REQUEST;
  m.id = id;
  m.address = 0x20;
  m.token = 0x6B;
  m.request_flags = tgw::request_flag::EXPECT_ANSWER;
  m.frame = write_request(reg, value);
  return m;
}

using Fate = std::tuple<const void *, uint32_t, Stage, uint16_t>;
using Answer = std::tuple<const void *, uint32_t, AnswerStatus>;

std::vector<Fate> fates(const std::vector<tgw::Outgoing> &out) {
  std::vector<Fate> found;
  for (const auto &o : out) {
    if (o.message.type == tgw::MessageType::FATE)
      found.emplace_back(o.client, o.message.id, static_cast<Stage>(o.message.stage), o.message.detail);
  }
  return found;
}

std::vector<Answer> answers(const std::vector<tgw::Outgoing> &out) {
  std::vector<Answer> found;
  for (const auto &o : out) {
    if (o.message.type == tgw::MessageType::ANSWER)
      found.emplace_back(o.client, o.message.id, static_cast<AnswerStatus>(o.message.status));
  }
  return found;
}

// Three protocol slots, so these tests can queue several protocol requests per key; the
// gateway reserves one by default (tested below).
struct Fixture {
  request_queues_type queues;
  tgw::Engine e{queues, {READ_KEY, WRITE_KEY}, 3, tgw::Engine::DEFAULT_ANSWER_TIMEOUT_US, 3};
};

struct OneSlot {
  request_queues_type queues;
  tgw::Engine e{queues, {READ_KEY, WRITE_KEY}, 3};
};

void plain(tgw::Engine &e, uint16_t reg) {
  CHECK(e.submit_plain(0x20, 0x69, read_request(reg), 0));
}

std::vector<uint16_t> sent_order(tgw::Engine &e) {
  std::vector<uint16_t> order;
  while (const QueuedRequest *sent = e.reply_for(0x20, 0x69, 1))
    order.push_back(sent->data[3] | (sent->data[4] << 8));
  return order;
}

// The pump sends a token; the engine answers; the pump closes with `trailer` (-1: none).
std::optional<RequestMeta> token_exchange(tgw::Engine &e, const std::vector<uint8_t> &token, uint64_t now_us,
                                          int trailer = 0x06) {
  const QueuedRequest *sent = e.reply_for(0x20, token[3], now_us);
  std::vector<uint8_t> data = token;
  size_t reply_len = 0;
  auto kind = tgw::Exchange::Reply::NONE;
  if (sent != nullptr) {
    data.insert(data.end(), sent->data.begin(), sent->data.end());
    reply_len = sent->data.size();
    kind = tgw::Exchange::Reply::QUEUED;
  } else {
    trailer = 0x06;  // the gateway ACKs
  }
  if (trailer >= 0)
    data.push_back(trailer);
  auto x =
      tgw::make_exchange(data.data(), data.size(), true, kind, reply_len, now_us + 10000, sent != nullptr ? now_us : 0);
  return e.on_exchange(x);
}

void data_exchange(tgw::Engine &e, const std::vector<uint8_t> &telegram, uint64_t now_us) {
  std::vector<uint8_t> data = telegram;
  data.push_back(0x06);
  auto x = tgw::make_exchange(data.data(), data.size(), true, tgw::Exchange::Reply::NONE, 0, now_us, 0);
  e.on_exchange(x);
}

}  // namespace

// --- submitting ---------------------------------------------------------------------------

TEST(engine_a_valid_request_is_queued) {
  Fixture f;
  f.e.submit(A, read(1), 0);
  f.e.submit(A, read(2, 40004), 0);
  CHECK((fates(f.e.take_outbox()) == std::vector<Fate>{{A, 1, Stage::QUEUED, 0}, {A, 2, Stage::QUEUED, 1}}));
}

TEST(engine_invalid_requests_are_dropped_with_a_reason) {
  Fixture f;
  tgw::Message bad = read(1);
  bad.frame = test::unhex("c069021eb800");
  tgw::Message mismatch = read(2);
  mismatch.frame = write_request(47387, 1);
  tgw::Message unknown = read(3);
  unknown.address = 0x19;
  unknown.token = 0x60;
  unknown.frame = test::unhex("c06000a0");
  for (const auto &r : {bad, mismatch, unknown})
    f.e.submit(A, r, 0);
  CHECK((fates(f.e.take_outbox()) ==
         std::vector<Fate>{{A, 1, Stage::DROPPED, static_cast<uint16_t>(DropReason::INVALID_FRAME)},
                           {A, 2, Stage::DROPPED, static_cast<uint16_t>(DropReason::TOKEN_MISMATCH)},
                           {A, 3, Stage::DROPPED, static_cast<uint16_t>(DropReason::UNKNOWN_KEY)}}));
}

TEST(engine_one_slot_is_reserved_for_protocol_requests) {
  OneSlot f;
  f.e.submit(A, read(1), 0);
  f.e.submit(B, read(2, 40004), 0);
  CHECK((fates(f.e.take_outbox()) ==
         std::vector<Fate>{{A, 1, Stage::QUEUED, 0},
                           {B, 2, Stage::DROPPED, static_cast<uint16_t>(DropReason::QUEUE_FULL)}}));
  CHECK(f.e.stats.drops[static_cast<size_t>(DropReason::QUEUE_FULL)] == 1);
}

TEST(engine_a_protocol_request_gets_in_when_plain_requests_fill_theirs) {
  OneSlot f;
  for (uint16_t reg : {40001, 40002, 40003})
    plain(f.e, reg);
  f.e.submit(A, read(1), 0);
  CHECK((fates(f.e.take_outbox()) == std::vector<Fate>{{A, 1, Stage::QUEUED, 3}}));
  CHECK(f.e.depths()[READ_KEY] == 4);
}

TEST(engine_plain_requests_push_out_only_plain_ones) {
  OneSlot f;
  plain(f.e, 40001);
  f.e.submit(A, read(1), 0);
  for (uint16_t reg : {40002, 40003, 40004})
    plain(f.e, reg);
  CHECK((fates(f.e.take_outbox()) == std::vector<Fate>{{A, 1, Stage::QUEUED, 1}}));
  CHECK(f.e.stats.evictions == 0);
  // The oldest plain request went; the rest go in the order they arrived.
  CHECK((sent_order(f.e) == std::vector<uint16_t>{47134, 40002, 40003, 40004}));
}

TEST(engine_priority_goes_to_the_front) {
  OneSlot f;
  plain(f.e, 40001);
  f.e.submit(A, read(2, 40004, tgw::request_flag::PRIORITY), 0);
  CHECK((fates(f.e.take_outbox()) == std::vector<Fate>{{A, 2, Stage::QUEUED, 0}}));
  CHECK((sent_order(f.e) == std::vector<uint16_t>{40004, 40001}));
}

// --- on the bus ---------------------------------------------------------------------------

TEST(engine_sent_then_acked_by_the_pump) {
  Fixture f;
  f.e.submit(A, read(1), 0);
  f.e.take_outbox();
  token_exchange(f.e, READ_TOKEN, 1000000);
  auto out = f.e.take_outbox();
  CHECK((fates(out) == std::vector<Fate>{{A, 1, Stage::SENT, 0}, {A, 1, Stage::PUMP_ACK, 0}}));
  CHECK(!out.empty() && out[0].message.stage_time_us == 1000000);
}

TEST(engine_pump_nak_and_no_ack_seen) {
  Fixture f;
  f.e.submit(A, read(1), 0);
  f.e.submit(A, read(2, 40004), 0);
  f.e.take_outbox();
  token_exchange(f.e, READ_TOKEN, 1000, 0x15);
  token_exchange(f.e, READ_TOKEN, 2000, -1);
  auto out = fates(f.e.take_outbox());
  bool nak = false, no_ack = false;
  for (const auto &[client, id, stage, detail] : out) {
    nak = nak || (id == 1 && stage == Stage::PUMP_NAK);
    no_ack = no_ack || (id == 2 && stage == Stage::NO_ACK_SEEN);
  }
  CHECK(nak);
  CHECK(no_ack);
}

TEST(engine_an_empty_queue_gets_no_reply) {
  Fixture f;
  CHECK(f.e.reply_for(0x20, 0x69, 0) == nullptr);
}

TEST(engine_an_expired_request_is_dropped_when_its_token_comes) {
  Fixture f;
  f.e.submit(A, read(1, 47134, tgw::request_flag::EXPECT_ANSWER, 100), 0);
  f.e.submit(A, read(2, 40004), 0);
  f.e.take_outbox();
  const QueuedRequest *sent = f.e.reply_for(0x20, 0x69, 200000);
  CHECK(sent != nullptr && sent->data == read_request(40004));
  auto out = fates(f.e.take_outbox());
  CHECK((out.front() == Fate{A, 1, Stage::DROPPED, static_cast<uint16_t>(DropReason::EXPIRED)}));
}

TEST(engine_cancel) {
  Fixture f;
  f.e.submit(A, read(1), 0);
  f.e.take_outbox();
  CHECK(f.e.cancel(A, 1, 10));
  CHECK(!f.e.cancel(A, 1, 10));
  CHECK(!f.e.cancel(B, 99, 10));
  CHECK((fates(f.e.take_outbox()) ==
         std::vector<Fate>{{A, 1, Stage::DROPPED, static_cast<uint16_t>(DropReason::CANCELLED)}}));
  CHECK(f.e.reply_for(0x20, 0x69, 20) == nullptr);
}

TEST(engine_forgetting_a_client_removes_its_requests_silently) {
  Fixture f;
  f.e.submit(A, read(1), 0);
  f.e.submit(B, read(2, 40004), 0);
  f.e.take_outbox();
  f.e.forget(A);
  const QueuedRequest *sent = f.e.reply_for(0x20, 0x69, 1);
  CHECK(sent != nullptr && sent->data == read_request(40004));
  CHECK((fates(f.e.take_outbox()) == std::vector<Fate>{{B, 2, Stage::SENT, 0}}));
}

// --- answers ------------------------------------------------------------------------------

TEST(engine_read_answers_pair_first_in_first_out_per_register) {
  Fixture f;
  f.e.submit(A, read(1), 0);
  f.e.submit(B, read(7), 0);
  f.e.take_outbox();
  token_exchange(f.e, READ_TOKEN, 1000);
  token_exchange(f.e, READ_TOKEN, 2000);
  f.e.take_outbox();
  data_exchange(f.e, read_answer(47134, 45), 1000000);
  auto out = f.e.take_outbox();
  CHECK((answers(out) == std::vector<Answer>{{A, 1, AnswerStatus::OK}}));
  CHECK(!out.empty() && out[0].message.frame == read_answer(47134, 45));
  data_exchange(f.e, read_answer(47134, 46), 1001000);
  CHECK((answers(f.e.take_outbox()) == std::vector<Answer>{{B, 7, AnswerStatus::OK}}));
}

TEST(engine_a_read_back_doesnt_get_the_answer_to_a_plain_read_taken_before_it) {
  Fixture f;
  CHECK(f.e.submit_plain(0x20, 0x69, read_request(47387), 0));
  token_exchange(f.e, READ_TOKEN, 1000);
  f.e.submit(A, read(1, 47387), 2000);
  token_exchange(f.e, READ_TOKEN, 3000);
  f.e.take_outbox();
  data_exchange(f.e, read_answer(47387, 1), 1000000);
  CHECK(answers(f.e.take_outbox()).empty());
  data_exchange(f.e, read_answer(47387, 0), 1003000);
  CHECK((answers(f.e.take_outbox()) == std::vector<Answer>{{A, 1, AnswerStatus::OK}}));
}

TEST(engine_a_nakked_read_waits_for_no_answer) {
  Fixture f;
  f.e.submit(A, read(1), 0);
  f.e.submit(A, read(2), 0);
  f.e.take_outbox();
  token_exchange(f.e, READ_TOKEN, 1000, 0x15);
  token_exchange(f.e, READ_TOKEN, 2000);
  f.e.take_outbox();
  data_exchange(f.e, read_answer(47134, 45), 1000000);
  CHECK((answers(f.e.take_outbox()) == std::vector<Answer>{{A, 2, AnswerStatus::OK}}));
}

TEST(engine_a_read_that_timed_out_leaves_the_list) {
  Fixture f;
  f.e.submit(A, read(1, 47134, tgw::request_flag::EXPECT_ANSWER, 0, 1000), 0);
  f.e.take_outbox();
  token_exchange(f.e, READ_TOKEN, 0);
  f.e.tick(1100000);
  CHECK((answers(f.e.take_outbox()) == std::vector<Answer>{{A, 1, AnswerStatus::TIMEOUT}}));
  f.e.submit(B, read(2), 1200000);
  token_exchange(f.e, READ_TOKEN, 1300000);
  f.e.take_outbox();
  data_exchange(f.e, read_answer(47134, 45), 2300000);
  CHECK((answers(f.e.take_outbox()) == std::vector<Answer>{{B, 2, AnswerStatus::OK}}));
}

TEST(engine_an_overdue_read_times_out_when_an_answer_comes_before_the_tick) {
  Fixture f;
  f.e.submit(A, read(1, 47134, tgw::request_flag::EXPECT_ANSWER, 0, 1000), 0);
  f.e.submit(B, read(2), 0);
  f.e.take_outbox();
  token_exchange(f.e, READ_TOKEN, 0);
  token_exchange(f.e, READ_TOKEN, 500000);
  f.e.take_outbox();
  data_exchange(f.e, read_answer(47134, 45), 1500000);
  CHECK((answers(f.e.take_outbox()) == std::vector<Answer>{{A, 1, AnswerStatus::TIMEOUT}, {B, 2, AnswerStatus::OK}}));
}

TEST(engine_a_forgotten_clients_read_keeps_its_place) {
  Fixture f;
  f.e.submit(A, read(1), 0);
  f.e.submit(B, read(2), 0);
  f.e.take_outbox();
  token_exchange(f.e, READ_TOKEN, 1000);
  token_exchange(f.e, READ_TOKEN, 2000);
  f.e.take_outbox();
  f.e.forget(A);
  data_exchange(f.e, read_answer(47134, 45), 1000000);
  CHECK(answers(f.e.take_outbox()).empty());
  data_exchange(f.e, read_answer(47134, 46), 1001000);
  CHECK((answers(f.e.take_outbox()) == std::vector<Answer>{{B, 2, AnswerStatus::OK}}));
}

TEST(engine_an_answer_for_another_register_isnt_paired) {
  Fixture f;
  f.e.submit(A, read(1), 0);
  f.e.take_outbox();
  token_exchange(f.e, READ_TOKEN, 1000);
  f.e.take_outbox();
  data_exchange(f.e, read_answer(40004, 12), 1000000);
  CHECK(answers(f.e.take_outbox()).empty());
}

TEST(engine_no_answer_in_time) {
  Fixture f;
  f.e.submit(A, read(1, 47134, tgw::request_flag::EXPECT_ANSWER, 0, 2000), 0);
  f.e.take_outbox();
  token_exchange(f.e, READ_TOKEN, 1000);
  f.e.take_outbox();
  f.e.tick(1500000);
  CHECK(answers(f.e.take_outbox()).empty());
  f.e.tick(2100000);
  CHECK((answers(f.e.take_outbox()) == std::vector<Answer>{{A, 1, AnswerStatus::TIMEOUT}}));
  CHECK(f.e.stats.answer_timeouts == 1);
}

TEST(engine_one_protocol_write_in_flight) {
  Fixture f;
  f.e.submit(A, write(1), 0);
  f.e.submit(A, write(2, 47387, 0), 0);
  f.e.take_outbox();
  token_exchange(f.e, WRITE_TOKEN, 1000);
  // The first write awaits its 0x6C, so the second isn't sent on the next token.
  CHECK(f.e.reply_for(0x20, 0x6B, 2000) == nullptr);
  f.e.take_outbox();
  data_exchange(f.e, write_answer(1), 500000);
  CHECK((answers(f.e.take_outbox()) == std::vector<Answer>{{A, 1, AnswerStatus::OK}}));
  const QueuedRequest *sent = f.e.reply_for(0x20, 0x6B, 600000);
  CHECK(sent != nullptr && sent->data == write_request(47387, 0));
}

TEST(engine_a_plain_write_in_flight_makes_the_pairing_ambiguous) {
  Fixture f;
  f.e.submit(A, write(1), 0);
  f.e.take_outbox();
  token_exchange(f.e, WRITE_TOKEN, 1000);
  f.e.submit_plain(0x20, 0x6B, write_request(47388, 2), 2000);
  token_exchange(f.e, WRITE_TOKEN, 3000);
  f.e.take_outbox();
  data_exchange(f.e, write_answer(1), 500000);
  CHECK((answers(f.e.take_outbox()) == std::vector<Answer>{{A, 1, AnswerStatus::AMBIGUOUS}}));
  CHECK(f.e.stats.ambiguous_answers == 1);
}

TEST(engine_a_nakked_write_isnt_in_flight) {
  Fixture f;
  f.e.submit(A, write(1), 0);
  f.e.submit(A, write(2, 47387, 0), 0);
  f.e.take_outbox();
  token_exchange(f.e, WRITE_TOKEN, 1000, 0x15);
  CHECK(f.e.reply_for(0x20, 0x6B, 2000) != nullptr);
}

TEST(engine_the_accessory_token_isnt_a_queue) {
  Fixture f;
  CHECK(f.e.reply_for(0x20, 0xEE, 0) == nullptr);
}

TEST(engine_queue_depths) {
  Fixture f;
  f.e.submit(A, read(1), 0);
  auto depths = f.e.depths();
  CHECK(depths.size() == 2);
  CHECK(depths[READ_KEY] == 1);
  CHECK(depths[WRITE_KEY] == 0);
}

TEST(engine_the_exchange_tells_whose_request_was_sent) {
  Fixture f;
  f.e.submit(A, read(1), 0);
  auto meta = token_exchange(f.e, READ_TOKEN, 0);
  CHECK(meta.has_value() && meta->owner == A && meta->id == 1);
  CHECK(f.e.submit_plain(0x20, 0x69, read_request(1), 0));
  meta = token_exchange(f.e, READ_TOKEN, 0);
  CHECK(meta.has_value() && meta->owner == nullptr);
  CHECK(!token_exchange(f.e, READ_TOKEN, 0).has_value());
}

// --- reading exchanges --------------------------------------------------------------------

TEST(exchange_a_doubled_start_byte_in_the_data_is_one_byte) {
  auto data = test::unhex("5c00206a071eb85c5c000000eb06");
  auto x = tgw::make_exchange(data.data(), data.size(), true, tgw::Exchange::Reply::NONE, 0, 1, 0);
  CHECK(x.parsed);
  CHECK(x.kind == tgw::FrameKind::TO_GATEWAY);
  CHECK(test::hex(x.payload) == "1eb85c000000");
  CHECK(x.trailer == 0x06);
}

TEST(exchange_a_bad_checksum_is_unparsed) {
  auto data = test::unhex("5c002069004815");
  auto x = tgw::make_exchange(data.data(), data.size(), true, tgw::Exchange::Reply::NONE, 0, 1, 0);
  CHECK(!x.parsed);
  CHECK(x.kind == tgw::FrameKind::UNPARSED);
}

TEST(exchange_a_reply_without_an_ack_has_no_trailer) {
  auto data = test::unhex("5c0020690049c069021eb80d");
  auto x = tgw::make_exchange(data.data(), data.size(), true, tgw::Exchange::Reply::QUEUED, 6, 1, 0);
  CHECK(x.trailer == -1);
  data.push_back(0x15);
  x = tgw::make_exchange(data.data(), data.size(), true, tgw::Exchange::Reply::QUEUED, 6, 1, 0);
  CHECK(x.trailer == 0x15);
}

TEST(exchange_another_devices_telegram) {
  auto data = test::unhex("5c0019600079c06000a006");
  auto x = tgw::make_exchange(data.data(), data.size(), false, tgw::Exchange::Reply::NONE, 0, 1, 0);
  CHECK(x.parsed);
  CHECK(x.kind == tgw::FrameKind::TO_OTHER);
  CHECK(x.address == 0x19);
}
