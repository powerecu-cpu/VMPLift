#pragma once

#include <cstdint>
#include <optional>
#include <vector>

namespace vmp {

class RollingKey {
public:
  RollingKey() = default;
  explicit RollingKey(std::uint32_t seed) : key_(seed) {}

  void reset(std::uint32_t seed) { key_ = seed; }
  std::uint32_t key() const { return key_; }

  std::uint32_t decrypt_u32(std::uint32_t encrypted);
  std::uint64_t decrypt_ptr(std::uint64_t encrypted, std::uint64_t image_base);

  static std::optional<std::uint32_t> guess_seed_from_handler_tail(
      const std::vector<std::uint8_t>& tail_bytes);

private:
  std::uint32_t key_ = 0;
  std::uint32_t advance();
};

}
