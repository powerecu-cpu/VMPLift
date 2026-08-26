#pragma once

#include "indirect_dispatch.hpp"
#include "pe_image.hpp"
#include "vm_types.hpp"

#include <capstone/capstone.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace vmp {

struct HandlerBoundary {
  std::size_t end_index = 0;
  std::optional<std::uint64_t> next_handler_va;
  bool is_vmexit = false;
  std::string reason;
};

struct DiscoveryOptions {
  std::size_t max_blocks = 256;
  std::size_t max_depth = 8;
  std::size_t max_insns_per_block = 128;
  bool vmp_sections_only = true;
};

struct DiscoveryResult {
  std::uint64_t root_va = 0;
  std::vector<std::uint64_t> handler_vas;
  std::vector<HandlerBlock> blocks;
  std::size_t truncated = 0;
};

class DispatchResolver {
public:
  explicit DispatchResolver(const PeImage& image);
  ~DispatchResolver();

  std::vector<RawInsn> linear_disasm(std::uint64_t va, std::size_t max_insns,
                                     std::size_t max_bytes = 0x1000) const;

  HandlerBoundary analyze_boundary(const std::vector<RawInsn>& insns) const;

  HandlerBlock lift_block(std::uint64_t handler_va, std::size_t max_insns) const;

  DiscoveryResult discover_callgraph(std::uint64_t root_va,
                                     const DiscoveryOptions& opts) const;

  WalkResult walk_chain(std::uint64_t entry_va, std::size_t max_handlers,
                        std::size_t max_insns_per_handler) const;

  std::optional<std::uint64_t> resolve_reg_dispatch(const std::vector<RawInsn>& insns) const;

private:
  const PeImage& image_;
  std::uint64_t image_base_;
  csh cs_handle_ = 0;

  bool is_vmp_va(std::uint64_t va) const;
  bool is_plausible_handler(std::uint64_t va) const;
  std::optional<std::uint64_t> imm_branch_target(const RawInsn& insn) const;
};

}
