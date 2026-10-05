#pragma once

// A minimal test runner for the platform-free parts of the component.

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace test {

struct Case {
  const char *name;
  void (*fn)();
};

std::vector<Case> &cases();
void fail(const char *file, int line, const std::string &what);
std::string hex(const std::vector<uint8_t> &data);
std::vector<uint8_t> unhex(const std::string &text);

struct Register {
  Register(const char *name, void (*fn)()) {
    cases().push_back({name, fn});
  }
};

}  // namespace test

#define TEST(name) \
  static void name(); \
  static test::Register register_##name(#name, name); \
  static void name()

#define CHECK(cond) \
  do { \
    if (!(cond)) \
      test::fail(__FILE__, __LINE__, #cond); \
  } while (0)

#define CHECK_MSG(cond, msg) \
  do { \
    if (!(cond)) \
      test::fail(__FILE__, __LINE__, std::string(#cond) + ": " + (msg)); \
  } while (0)
