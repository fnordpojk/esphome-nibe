#include "test.h"

namespace test {

static int failures = 0;
static const char *current = "";

std::vector<Case> &cases() {
  static std::vector<Case> all;
  return all;
}

void fail(const char *file, int line, const std::string &what) {
  failures++;
  std::printf("FAIL %s (%s:%d): %s\n", current, file, line, what.c_str());
}

std::string hex(const std::vector<uint8_t> &data) {
  static const char DIGITS[] = "0123456789abcdef";
  std::string out;
  for (auto b : data) {
    out += DIGITS[b >> 4];
    out += DIGITS[b & 0x0F];
  }
  return out;
}

std::vector<uint8_t> unhex(const std::string &text) {
  std::vector<uint8_t> out;
  for (size_t i = 0; i + 1 < text.size(); i += 2)
    out.push_back(std::stoi(text.substr(i, 2), nullptr, 16));
  return out;
}

}  // namespace test

int main() {
  for (const auto &c : test::cases()) {
    test::current = c.name;
    c.fn();
  }
  std::printf("%zu tests, %d failures\n", test::cases().size(), test::failures);
  return test::failures == 0 ? 0 : 1;
}
