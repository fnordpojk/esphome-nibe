#include "test.h"
#include "../components/nibegw/TgwCrypto.h"

#include <string>

namespace test {
void sha256_for_tests(const uint8_t *data, size_t len, uint8_t *out);
}

using namespace esphome::nibegw;

static std::string digest(const std::string &text) {
  std::vector<uint8_t> out(tgw::SHA256_LEN);
  test::sha256_for_tests(reinterpret_cast<const uint8_t *>(text.data()), text.size(), out.data());
  return test::hex(out);
}

TEST(the_test_sha256_matches_fips_180_values) {
  CHECK(digest("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  CHECK(digest("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  CHECK(digest("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST(the_test_hmac_matches_rfc_4231_case_2) {
  std::string key = "Jefe";
  std::string data = "what do ya want for nothing?";
  std::vector<uint8_t> out(tgw::SHA256_LEN);
  CHECK(tgw::hmac_sha256(reinterpret_cast<const uint8_t *>(key.data()), key.size(),
                         reinterpret_cast<const uint8_t *>(data.data()), data.size(), out.data()));
  CHECK(test::hex(out) == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}
