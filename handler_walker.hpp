#pragma once

#include "dispatch_resolver.hpp"
#include "pe_image.hpp"
#include "vm_types.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace vmp {

class HandlerWalker {
public:
  HandlerWalker(const PeImage& image, std::uint64_t image_base);
  ~HandlerWalker();

  WalkResult walk_from(std::uint64_t entry_va, std::size_t max_handlers,
                       std::size_t max_insns_per_handler) const;

  DiscoveryResult discover(std::uint64_t root_va, const DiscoveryOptions& opts) const;

  std::optional<HandlerBlock> lift_single_handler(std::uint64_t handler_va,
                                                  std::size_t max_insns) const;

private:
  const PeImage& image_;
  std::uint64_t image_base_;
  std::unique_ptr<DispatchResolver> resolver_;

  std::vector<RawInsn> disassemble_range(std::uint64_t va, std::size_t max_bytes,
                                         std::size_t max_insns) const;
  std::optional<std::uint64_t> extract_next_handler(const HandlerBlock& block) const;
  bool is_in_vmp_region(std::uint64_t va) const;
};

}
