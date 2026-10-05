#include "test.h"
#include "../components/nibegw/TgwProtocol.h"

using namespace esphome::nibegw;

namespace {

struct MessageVector {
  const char *name;
  const char *hex;
  tgw::Message (*expected)();
};

struct InvalidVector {
  const char *name;
  const char *hex;
  tgw::ErrorCode error;
  bool has_tag;
  uint16_t tag;
};

struct AuthVectors {
  const char *psk;
  const char *client_nonce;
  const char *gateway_nonce;
  uint32_t boot_id;
  const char *session_key;
};

struct SignedVector {
  const char *name;
  const char *key;  // "psk" or "session_key"
  uint32_t seq;
  const char *hex;
  bool good;
};

#include "build/vectors.inc"

std::string differences(const tgw::Message &a, const tgw::Message &b) {
  std::string out;
  auto field = [&](const char *name, uint64_t x, uint64_t y) {
    if (x != y)
      out += std::string(name) + " " + std::to_string(x) + " != " + std::to_string(y) + "; ";
  };
  field("type", static_cast<uint8_t>(a.type), static_cast<uint8_t>(b.type));
  field("id", a.id, b.id);
  field("gw_time_us", a.gw_time_us, b.gw_time_us);
  field("ver_min", a.ver_min, b.ver_min);
  field("ver_max", a.ver_max, b.ver_max);
  field("ver_major", a.ver_major, b.ver_major);
  field("ver_minor", a.ver_minor, b.ver_minor);
  field("address", a.address, b.address);
  field("token", a.token, b.token);
  field("request_flags", a.request_flags, b.request_flags);
  field("ttl_ms", a.ttl_ms, b.ttl_ms);
  field("answer_timeout_ms", a.answer_timeout_ms, b.answer_timeout_ms);
  field("stage", a.stage, b.stage);
  field("detail", a.detail, b.detail);
  field("stage_time_us", a.stage_time_us, b.stage_time_us);
  field("status", a.status, b.status);
  field("kind", a.kind, b.kind);
  field("origin", a.origin, b.origin);
  field("request_id", a.request_id, b.request_id);
  field("t_complete_us", a.t_complete_us, b.t_complete_us);
  field("t_reply_us", a.t_reply_us, b.t_reply_us);
  field("code", a.code, b.code);
  if (a.frame != b.frame)
    out += "frame " + test::hex(a.frame) + " != " + test::hex(b.frame) + "; ";
  if (a.options.size() != b.options.size()) {
    out += "options count; ";
  } else {
    for (size_t i = 0; i < a.options.size(); i++) {
      if (a.options[i].tag != b.options[i].tag || a.options[i].value != b.options[i].value)
        out += "option " + std::to_string(i) + "; ";
    }
  }
  return out;
}

}  // namespace

TEST(the_vectors_are_all_there) {
  CHECK(std::size(MESSAGE_VECTORS) == 18);
  CHECK(std::size(INVALID_VECTORS) == 14);
  CHECK(std::size(SIGNED_VECTORS) == 3);
}

TEST(every_message_vector_decodes_to_its_fields) {
  for (const auto &v : MESSAGE_VECTORS) {
    auto data = test::unhex(v.hex);
    auto decoded = tgw::decode(data.data(), data.size());
    CHECK_MSG(decoded.ok(), std::string(v.name) + ": " + decoded.detail);
    auto diff = differences(decoded.msg, v.expected());
    CHECK_MSG(diff.empty(), std::string(v.name) + ": " + diff);
  }
}

TEST(every_message_vector_encodes_to_its_bytes) {
  for (const auto &v : MESSAGE_VECTORS) {
    auto encoded = tgw::encode(v.expected());
    CHECK_MSG(test::hex(encoded) == v.hex, std::string(v.name) + ": " + test::hex(encoded));
  }
}

TEST(every_invalid_vector_is_refused_with_its_error) {
  for (const auto &v : INVALID_VECTORS) {
    auto data = test::unhex(v.hex);
    auto decoded = tgw::decode(data.data(), data.size());
    CHECK_MSG(decoded.error == v.error,
              std::string(v.name) + ": got " + std::to_string(static_cast<int>(decoded.error)));
    if (v.has_tag)
      CHECK_MSG(decoded.has_error_tag && decoded.error_tag == v.tag, v.name);
  }
}

TEST(the_session_key_matches) {
  auto psk = test::unhex(AUTH.psk);
  auto client_nonce = test::unhex(AUTH.client_nonce);
  auto gateway_nonce = test::unhex(AUTH.gateway_nonce);
  std::vector<uint8_t> key(tgw::KEY_LEN);
  CHECK(tgw::session_key(psk.data(), client_nonce.data(), gateway_nonce.data(), AUTH.boot_id, key.data()));
  CHECK(test::hex(key) == AUTH.session_key);
}

TEST(signed_vectors_verify_and_a_flipped_bit_doesnt) {
  auto psk = test::unhex(AUTH.psk);
  auto session = test::unhex(AUTH.session_key);
  for (const auto &v : SIGNED_VECTORS) {
    auto data = test::unhex(v.hex);
    const auto &key = std::string(v.key) == "psk" ? psk : session;
    uint32_t seq = 0;
    auto result = tgw::verify(data.data(), data.size(), key.data(), &seq);
    if (v.good) {
      CHECK_MSG(result == tgw::Verify::OK, v.name);
      CHECK_MSG(seq == v.seq, v.name);
    } else {
      CHECK_MSG(result == tgw::Verify::BAD_MAC, v.name);
    }
  }
}

TEST(signing_reproduces_the_signed_vectors) {
  auto psk = test::unhex(AUTH.psk);
  auto session = test::unhex(AUTH.session_key);
  for (const auto &v : SIGNED_VECTORS) {
    if (!v.good)
      continue;
    auto data = test::unhex(v.hex);
    auto decoded = tgw::decode(data.data(), data.size());
    CHECK_MSG(decoded.ok() && decoded.is_signed, v.name);
    const auto &key = std::string(v.key) == "psk" ? psk : session;
    auto again = tgw::encode(decoded.msg, key.data(), v.seq);
    CHECK_MSG(test::hex(again) == v.hex, std::string(v.name) + ": " + test::hex(again));
  }
}

TEST(an_unsigned_datagram_doesnt_verify) {
  tgw::Message keepalive;
  auto data = tgw::encode(keepalive);
  uint32_t seq = 0;
  std::vector<uint8_t> key(tgw::KEY_LEN);
  CHECK(tgw::verify(data.data(), data.size(), key.data(), &seq) == tgw::Verify::NOT_SIGNED);
}

TEST(a_message_too_big_isnt_encoded) {
  tgw::Message frame;
  frame.type = tgw::MessageType::FRAME;
  frame.frame.resize(tgw::MAX_DATAGRAM);
  CHECK(tgw::encode(frame).empty());
}

TEST(text_must_be_utf8) {
  // A HELLO whose CLIENT_NAME holds `name`.
  auto hello = [](std::vector<uint8_t> name) {
    tgw::Message m;
    m.type = tgw::MessageType::HELLO;
    m.options.push_back({static_cast<uint16_t>(tgw::Tag::CLIENT_NAME), std::move(name)});
    auto data = tgw::encode(m);
    return tgw::decode(data.data(), data.size()).error;
  };
  CHECK(hello({'o', 'k'}) == tgw::ErrorCode::NONE);
  CHECK(hello({0xC3, 0xA5}) == tgw::ErrorCode::NONE);                   // å
  CHECK(hello({0xF0, 0x9F, 0x94, 0xA5}) == tgw::ErrorCode::NONE);       // a 4-byte character
  CHECK(hello({0xC0, 0xAF}) == tgw::ErrorCode::MALFORMED);              // overlong
  CHECK(hello({0xED, 0xA0, 0x80}) == tgw::ErrorCode::MALFORMED);        // a surrogate
  CHECK(hello({0xE2, 0x82}) == tgw::ErrorCode::MALFORMED);              // cut short
  CHECK(hello({0xF4, 0x90, 0x80, 0x80}) == tgw::ErrorCode::MALFORMED);  // above U+10FFFF
}
