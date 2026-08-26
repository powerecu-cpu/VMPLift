#pragma once

#include "pe_image.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace vmp {

struct VipSeed {
  std::optional<std::uint32_t> enc_push_imm;
  std::optional<std::uint64_t> movabs_imm;
  std::string movabs_reg;
  std::uint64_t image_high = 0;
  std::string note;
};

struct VipStep {
  std::uint64_t handler_va = 0;
  std::uint64_t vip = 0;
  std::uint32_t fetched_enc = 0;
  std::optional<std::uint64_t> next_handler;
  std::string vip_reg;
  std::string key_reg;
  std::string note;
};

struct VipTrace {
  VipSeed seed;
  std::vector<VipStep> steps;
  std::uint64_t initial_vip = 0;
  std::uint64_t rolling_key = 0;
  bool seeded = false;
};

VipSeed extract_vip_seed(const PeImage& image, std::uint64_t vmenter_va);

VipTrace unicorn_vip_trace(const PeImage& image, std::uint64_t start_va,
                           std::size_t max_handlers = 64, std::size_t max_insns_each = 2048);

std::string format_vip_trace_text(const VipTrace& tr);

}
