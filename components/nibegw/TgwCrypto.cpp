#include "TgwCrypto.h"

#if defined(NIBEGW_TGW_HOST_TEST)
// The host tests link their own implementation.
#elif __has_include("mbedtls/md.h")
#include "mbedtls/md.h"

namespace esphome {
namespace nibegw {
namespace tgw {

bool hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t len, uint8_t *out) {
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return info != nullptr && mbedtls_md_hmac(info, key, key_len, data, len, out) == 0;
}

}  // namespace tgw
}  // namespace nibegw
}  // namespace esphome
#else

namespace esphome {
namespace nibegw {
namespace tgw {

bool hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t len, uint8_t *out) {
  return false;
}

}  // namespace tgw
}  // namespace nibegw
}  // namespace esphome
#endif
