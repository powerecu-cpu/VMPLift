#include "handler_walker.hpp"

#include "dispatch_resolver.hpp"
#include "util.hpp"

#include <memory>

namespace vmp {

HandlerWalker::HandlerWalker(const PeImage& image, std::uint64_t image_base)
    : image_(image), image_base_(image_base), resolver_(std::make_unique<DispatchResolver>(image)) {}

HandlerWalker::~HandlerWalker() = default;

bool HandlerWalker::is_in_vmp_region(std::uint64_t va) const {
  const auto* sec = image_.section_for_va(va);
  if (!sec) {
    return false;
  }
  return is_vmp_section_name(sec->name) || sec->name == ".text";
}

std::vector<RawInsn> HandlerWalker::disassemble_range(std::uint64_t va, std::size_t max_bytes,
                                                      std::size_t max_insns) const {
  return resolver_->linear_disasm(va, max_insns, max_bytes);
}

std::optional<HandlerBlock> HandlerWalker::lift_single_handler(std::uint64_t va,
                                                               std::size_t max_insns) const {
  if (!is_in_vmp_region(va) && !image_.contains_va(va)) {
    return std::nullopt;
  }
  auto blk = resolver_->lift_block(va, max_insns);
  if (blk.insns.empty()) {
    return std::nullopt;
  }
  return blk;
}

std::optional<std::uint64_t> HandlerWalker::extract_next_handler(const HandlerBlock& blk) const {
  if (blk.next_handler_va) {
    return blk.next_handler_va;
  }
  return resolver_->analyze_boundary(blk.insns).next_handler_va;
}

WalkResult HandlerWalker::walk_from(std::uint64_t entry, std::size_t max_handlers,
                                      std::size_t max_insns) const {
  return resolver_->walk_chain(entry, max_handlers, max_insns);
}

DiscoveryResult HandlerWalker::discover(std::uint64_t root, const DiscoveryOptions& opts) const {
  return resolver_->discover_callgraph(root, opts);
}

}
