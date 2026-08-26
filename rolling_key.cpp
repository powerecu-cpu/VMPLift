#include "rolling_key.hpp"

namespace vmp {

std::uint32_t RollingKey::advance() {
  key_ = (key_ * 0x343FD + 0x269EC3) & 0xFFFFFFFFu;
  return key_;
}

std::uint32_t RollingKey::decrypt_u32(std::uint32_t enc) {
  return enc ^ advance();
}

std::uint64_t RollingKey::decrypt_ptr(std::uint64_t enc, std::uint64_t image_base) {
  auto lo = decrypt_u32(static_cast<std::uint32_t>(enc & 0xFFFFFFFFu));
  auto hi = decrypt_u32(static_cast<std::uint32_t>(enc >> 32));
  auto val = (static_cast<std::uint64_t>(hi) << 32) | lo;
  if (val < 0x10000) {
    return image_base + val;
  }
  return val;
}

std::optional<std::uint32_t> RollingKey::guess_seed_from_handler_tail(
    const std::vector<std::uint8_t>& tail) {
  if (tail.size() < 8) {
    return std::nullopt;
  }
  std::uint32_t seed = 0;
  for (std::size_t i = 0; i + 4 <= tail.size(); i += 4) {
    seed ^= static_cast<std::uint32_t>(tail[i]) |
            (static_cast<std::uint32_t>(tail[i + 1]) << 8) |
            (static_cast<std::uint32_t>(tail[i + 2]) << 16) |
            (static_cast<std::uint32_t>(tail[i + 3]) << 24);
  }
  if (seed == 0) {
    return std::nullopt;
  }
  return seed;
}

}
