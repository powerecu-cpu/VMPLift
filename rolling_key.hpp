#pragma once

#include "vm_types.hpp"

#include <cstdint>
#include <optional>
#include <vector>

namespace vmp {

enum class MixKind : std::uint8_t {
  Add, Sub, XorImm, Not, Neg, Inc, Dec, Rol, Ror, Bswap
};

struct MixOp {
  MixKind kind = MixKind::XorImm;
  std::uint32_t imm = 0;
  std::uint8_t width = 4;
};

class RollingKey {
public:
  RollingKey() = default;
  explicit RollingKey(std::uint64_t seed) : key_(seed) {}

  void reset(std::uint64_t seed) { key_ = seed; }
  std::uint64_t key() const { return key_; }

  void set_mixer(std::vector<MixOp> mixer) { mixer_ = std::move(mixer); }
  const std::vector<MixOp>& mixer() const { return mixer_; }

  std::uint32_t decrypt_u32(std::uint32_t encrypted);
  std::uint64_t decrypt_ptr(std::uint64_t encrypted, std::uint64_t image_base);

  static std::uint64_t seed_from_vip(std::uint64_t vip_va) { return vip_va; } // novmp: key = vip

  static std::vector<MixOp> extract_mixer(const std::uint8_t* bytes, std::size_t n);
  static std::vector<MixOp> extract_mixer(const std::vector<RawInsn>& insns);
  static std::vector<std::uint32_t> vip_decrypt_guesses(std::uint32_t enc, std::uint64_t key);
  static std::optional<std::uint32_t> guess_seed_from_handler_tail(const std::vector<std::uint8_t>& tail);
  static std::uint32_t apply_mixer(std::uint32_t value, const std::vector<MixOp>& mixer);

private:
  std::uint64_t key_ = 0;
  std::vector<MixOp> mixer_;
};

}
