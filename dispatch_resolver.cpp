#include "dispatch_resolver.hpp"

#include "indirect_dispatch.hpp"
#include "util.hpp"

#include <capstone/capstone.h>
#include <capstone/x86.h>

#include <deque>
#include <set>

namespace vmp {

namespace {

bool is_call(const std::string& m) { return m == "call"; }

bool is_jcc(const std::string& m) {
  return !m.empty() && m[0] == 'j' && m != "jmp" && m != "call";
}

}

DispatchResolver::DispatchResolver(const PeImage& image)
    : image_(image), image_base_(image.image_base()) {
  cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle_);
  cs_option(cs_handle_, CS_OPT_DETAIL, CS_OPT_ON);
}

DispatchResolver::~DispatchResolver() {
  if (cs_handle_) {
    cs_close(&cs_handle_);
  }
}

bool DispatchResolver::is_vmp_va(std::uint64_t va) const {
  const auto* sec = image_.section_for_va(va);
  if (!sec) {
    return false;
  }

  return is_vmp_section_name(sec->name) || sec->name == ".text";
}

bool DispatchResolver::is_plausible_handler(std::uint64_t va) const {
  if (!image_.contains_va(va)) {
    return false;
  }
  auto bytes = image_.read_at_va(va, 8);
  if (bytes.empty()) {
    return false;
  }
  int nz = 0;
  for (auto b : bytes) {
    if (b != 0 && b != 0xCC) {
      nz++;
    }
  }
  return nz >= 2;
}

std::optional<std::uint64_t> DispatchResolver::imm_branch_target(const RawInsn& insn) const {
  if (insn.branch_target != 0) {
    return insn.branch_target;
  }
  return std::nullopt;
}

std::vector<RawInsn> DispatchResolver::linear_disasm(std::uint64_t va, std::size_t max_insns,
                                                     std::size_t max_bytes) const {
  std::vector<RawInsn> out;
  std::uint64_t cur = va;
  std::uint64_t end = va + max_bytes;

  for (std::size_t n = 0; n < max_insns && cur < end; n++) {
    auto bytes = image_.read_at_va(cur, 16);
    if (bytes.empty()) {
      break;
    }

    cs_insn* raw_cs = nullptr;
    auto count = cs_disasm(cs_handle_, bytes.data(), bytes.size(), cur, 1, &raw_cs);
    if (count == 0) {
      cur++;
      continue;
    }

    RawInsn ri;
    ri.va = raw_cs[0].address;
    ri.mnemonic = raw_cs[0].mnemonic;
    ri.op_str = raw_cs[0].op_str;
    ri.size = raw_cs[0].size;
    std::copy_n(raw_cs[0].bytes, std::min<std::size_t>(ri.size, 16), ri.bytes);

    if (raw_cs[0].detail) {
      const auto& x86 = raw_cs[0].detail->x86;
      for (std::uint8_t j = 0; j < x86.op_count; j++) {
        const auto& op = x86.operands[j];
        if (op.type == X86_OP_IMM) {
          ri.has_imm = true;
          ri.imm = op.imm;
          ri.branch_target = static_cast<std::uint64_t>(op.imm);
        }
        if (op.type == X86_OP_MEM && op.mem.base == X86_REG_RIP) {
          ri.rip_rel = true;
          ri.lea_target = cur + ri.size + static_cast<std::uint64_t>(op.mem.disp);
        }
        if (op.type == X86_OP_REG && (ri.mnemonic == "jmp" || ri.mnemonic == "call") && j == 0) {
          ri.is_branch = true;
          ri.is_reg_branch = true;
          ri.branch_reg = x86_reg_name(op.reg);
        }
      }
      if (x86.op_count >= 1 && x86.operands[0].type == X86_OP_IMM &&
          (ri.mnemonic == "jmp" || ri.mnemonic == "call" || is_jcc(ri.mnemonic))) {
        ri.is_branch = true;
        ri.branch_target = static_cast<std::uint64_t>(x86.operands[0].imm);
        ri.is_reg_branch = false;
      }
    }

    ri.is_call = ri.mnemonic == "call";
    ri.is_ret = (ri.mnemonic == "ret" || ri.mnemonic == "retf" || ri.mnemonic == "retn");
    if (ri.mnemonic == "jmp") {
      ri.is_branch = true;
    }

    cs_free(raw_cs, count);
    out.push_back(ri);
    cur += ri.size;

    if (ri.is_ret) break;
    if (ri.mnemonic == "jmp") break;
    if (ri.is_reg_branch) break;
  }

  return out;
}

HandlerBoundary DispatchResolver::analyze_boundary(const std::vector<RawInsn>& insns) const {
  HandlerBoundary b;
  if (insns.empty()) {
    b.reason = "empty";
    return b;
  }

  b.end_index = insns.size() - 1;

  std::size_t first_xfer = insns.size();
  for (std::size_t i = 0; i < insns.size(); i++) {
    const auto& in = insns[i];
    if (in.is_reg_branch || (in.mnemonic == "jmp" && !in.is_reg_branch) || in.is_ret) {
      first_xfer = i;
      break;
    }
  }

  if (first_xfer < insns.size() && insns[first_xfer].is_reg_branch) {
    if (auto next = resolve_reg_dispatch(insns)) {
      b.next_handler_va = next;
      b.end_index = first_xfer;
      b.reason = "jmp_reg";
      return b;
    }
  }

  std::size_t last_cf = insns.size();
  for (std::size_t i = insns.size(); i-- > 0;) {
    if (insns[i].is_ret || insns[i].mnemonic == "jmp" || insns[i].is_call) {
      last_cf = i;
      break;
    }
  }

  if (last_cf < insns.size() && insns[last_cf].is_reg_branch) {
    if (auto next = resolve_reg_dispatch(insns)) {
      if (is_plausible_handler(*next)) {
        b.next_handler_va = next;
        b.end_index = last_cf;
        b.reason = "jmp_reg";
        return b;
      }
    }
  }

  bool had_reg_xfer = false;
  for (const auto& in : insns) {
    if (in.is_reg_branch) {
      had_reg_xfer = true;
      break;
    }
  }

  if (!had_reg_xfer && last_cf < insns.size() && insns[last_cf].is_ret) {
    b.is_vmexit = true;
    b.end_index = last_cf;
    b.reason = "ret";
    return b;
  }

  if (!had_reg_xfer) {
    for (std::size_t i = insns.size(); i-- > 0;) {
      if (insns[i].is_ret) {
        b.is_vmexit = true;
        b.end_index = i;
        b.reason = "ret";
        return b;
      }
    }
  }

  std::optional<std::uint64_t> tail_jmp;
  for (std::size_t i = insns.size(); i-- > 0;) {
    const auto& in = insns[i];
    if (in.mnemonic == "jmp" && in.branch_target != 0 && !in.is_reg_branch) {
      if (is_vmp_va(in.branch_target) && is_plausible_handler(in.branch_target)) {
        tail_jmp = in.branch_target;
        b.end_index = i;
        b.reason = "tail_jmp";
        break;
      }
    }
  }

  if (tail_jmp) {
    b.next_handler_va = tail_jmp;
    return b;
  }

  for (std::size_t i = insns.size(); i-- > 0;) {
    const auto& in = insns[i];
    if (is_call(in.mnemonic) && in.branch_target != 0 && is_vmp_va(in.branch_target) &&
        !in.is_reg_branch) {
      b.next_handler_va = in.branch_target;
      b.end_index = i;
      b.reason = "tail_call";
      return b;
    }
  }

  bool had_reg = false;
  for (const auto& in : insns) {
    if (in.is_reg_branch) {
      had_reg = true;
      break;
    }
  }
  if (had_reg && !insns.empty()) {
    if (auto next = unicorn_tail_next(image_, insns.front().va)) {
      if (is_plausible_handler(*next) && *next != insns.front().va) {
        b.next_handler_va = next;
        b.reason = "unicorn";
        return b;
      }
    }
  }

  b.reason = "unknown";
  return b;
}

std::optional<std::uint64_t> DispatchResolver::resolve_reg_dispatch(
    const std::vector<RawInsn>& insns) const {

  if (insns.empty()) {
    return std::nullopt;
  }
  return unicorn_tail_next(image_, insns.front().va);
}

HandlerBlock DispatchResolver::lift_block(std::uint64_t handler_va, std::size_t max_insns) const {
  HandlerBlock blk;
  blk.entry_va = handler_va;
  blk.insns = linear_disasm(handler_va, max_insns);

  auto boundary = analyze_boundary(blk.insns);
  if (boundary.end_index + 1 < blk.insns.size()) {
    blk.insns.resize(boundary.end_index + 1);
  }

  blk.is_exit = boundary.is_vmexit;
  blk.next_handler_va = boundary.next_handler_va;
  blk.stop_reason = boundary.reason;
  return blk;
}

DiscoveryResult DispatchResolver::discover_callgraph(std::uint64_t root_va,
                                                     const DiscoveryOptions& opts) const {
  DiscoveryResult res;
  res.root_va = root_va;

  struct QNode {
    std::uint64_t va;
    std::size_t depth;
  };

  std::deque<QNode> q;
  std::set<std::uint64_t> seen;

  if (is_plausible_handler(root_va)) {
    q.push_back({root_va, 0});
  }

  while (!q.empty() && res.handler_vas.size() < opts.max_blocks) {
    auto [va, depth] = q.front();
    q.pop_front();

    if (!seen.insert(va).second) {
      continue;
    }
    if (opts.vmp_sections_only && !is_vmp_va(va)) {
      continue;
    }

    res.handler_vas.push_back(va);
    auto insns = linear_disasm(va, opts.max_insns_per_block);
    res.blocks.push_back([&] {
      HandlerBlock hb;
      hb.entry_va = va;
      hb.insns = insns;
      auto bd = analyze_boundary(insns);
      if (bd.end_index + 1 < hb.insns.size()) {
        hb.insns.resize(bd.end_index + 1);
      }
      hb.is_exit = bd.is_vmexit;
      hb.next_handler_va = bd.next_handler_va;
      hb.stop_reason = bd.reason;
      return hb;
    }());

    if (depth >= opts.max_depth) {
      continue;
    }

    for (const auto& in : insns) {
      if (is_call(in.mnemonic) || in.mnemonic == "jmp") {
        auto tgt = imm_branch_target(in);
        if (!tgt || in.is_reg_branch) {
          continue;
        }
        if (!is_vmp_va(*tgt) || !is_plausible_handler(*tgt)) {
          continue;
        }
        if (!seen.count(*tgt)) {
          q.push_back({*tgt, depth + 1});
        }
      }
    }
    if (res.blocks.back().next_handler_va) {
      auto nxt = *res.blocks.back().next_handler_va;
      if (!seen.count(nxt) && is_plausible_handler(nxt)) {
        q.push_back({nxt, depth + 1});
      }
    }
  }

  if (!q.empty() || seen.size() >= opts.max_blocks) {
    res.truncated = static_cast<std::size_t>(q.size());
  }

  return res;
}

WalkResult DispatchResolver::walk_chain(std::uint64_t entry_va, std::size_t max_handlers,
                                        std::size_t max_insns_per_handler) const {
  WalkResult wr;
  wr.start_va = entry_va;

  std::set<std::uint64_t> visited;
  std::uint64_t cur = entry_va;

  while (wr.handlers.size() < max_handlers) {
    if (!visited.insert(cur).second) {
      break;
    }

    auto blk = lift_block(cur, max_insns_per_handler);
    if (blk.insns.empty()) {
      wr.truncated++;
      break;
    }

    wr.handlers.push_back(blk);

    if (blk.is_exit) {
      break;
    }
    if (!blk.next_handler_va) {
      wr.truncated++;
      break;
    }
    cur = *blk.next_handler_va;
  }

  return wr;
}

}
