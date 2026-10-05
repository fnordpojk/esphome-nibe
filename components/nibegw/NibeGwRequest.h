#pragma once

#include <cstdint>
#include <vector>

namespace esphome {
namespace nibegw {

using request_data_type = std::vector<uint8_t>;

// What is known about a queued request besides its bytes. A plain NibeGW request,
// received on a UDP port, carries none of it.
struct RequestMeta {
  const void *owner{nullptr};  // who queued it and is told what became of it; nullptr if nobody
  uint32_t id{0};              // the owner's id for it
  uint64_t deadline_us{0};     // drop it if its token comes later than this; 0 for no limit
  uint8_t flags{0};
  uint32_t answer_timeout_us{0};
};

struct QueuedRequest {
  request_data_type data;
  RequestMeta meta;
};

}  // namespace nibegw
}  // namespace esphome
