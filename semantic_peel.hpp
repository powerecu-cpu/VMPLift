#pragma once

#include "handler_classify.hpp"
#include "pe_image.hpp"
#include "vip_context.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace vmp {

struct FetchEvent {
  std::uint64_t addr = 0;
  std::uint32_t size = 0;
  std::uint64_t enc = 0;
  std::uint64_t dec = 0;
  bool decrypted = false;
  std::string via_reg;
};

struct HandlerEffect {
  std::uint64_t handler_va = 0;
  std::uint64_t vip_before = 0;
  std::uint64_t vip_after = 0;
  std::int64_t vip_delta = 0;
  std::uint64_t key_before = 0;
  std::uint64_t key_after = 0;
  std::string vip_reg;
  std::string key_reg;
  std::string vsp_reg;
  std::int64_t vsp_delta = 0;
  int pushes = 0;
  int pops = 0;
  int alu_add = 0, alu_sub = 0, alu_xor = 0, alu_and = 0, alu_or = 0;
  int alu_not = 0, alu_neg = 0, alu_shl = 0, alu_shr = 0;
  int mem_load = 0, mem_store = 0;
  bool has_xfer = false;
  bool has_ret_exit = false;
  std::optional<std::uint64_t> next_handler;
  std::vector<FetchEvent> fetches;
  std::optional<std::uint64_t> pushed_imm;
  VmOpKind kind = VmOpKind::Unknown;
  int confidence = 0;
  std::string why;
};

struct SemanticTrace {
  VipTrace vip;
  std::vector<HandlerEffect> effects;
  std::string key_reg;
  std::string vip_reg;
  std::string vsp_reg;
};

SemanticTrace unicorn_semantic_trace(const PeImage& image, std::uint64_t vmenter_va,
                                     std::size_t max_handlers = 256,
                                     std::size_t max_insns_each = 4096);

void peel_effect(HandlerEffect& e);

}
