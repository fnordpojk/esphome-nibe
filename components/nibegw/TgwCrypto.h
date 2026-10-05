#pragma once

#include <cstddef>
#include <cstdint>

namespace esphome {
namespace nibegw {
namespace tgw {

static constexpr size_t SHA256_LEN = 32;

// HMAC-SHA256 of `data` under `key`. False where the platform offers no implementation;
// the configuration refuses a pre-shared key there.
bool hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t len, uint8_t *out);

}  // namespace tgw
}  // namespace nibegw
}  // namespace esphome
