#include "indirect_dispatch.hpp"

#include "util.hpp"
#include "vip_context.hpp"

#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <unicorn/unicorn.h>

#include <algorithm>
#include <cstring>
#include <deque>
#include <set>
#include <string>
#include <vector>

namespace vmp {

std::string x86_reg_name(int capstone_reg) {
  switch (capstone_reg) {
    case X86_REG_RAX:
    case X86_REG_EAX:
      return "rax";
    case X86_REG_RCX:
    case X86_REG_ECX:
      return "rcx";
    case X86_REG_RDX:
    case X86_REG_EDX:
      return "rdx";
    case X86_REG_RBX:
    case X86_REG_EBX:
      return "rbx";
    case X86_REG_RSP:
    case X86_REG_ESP:
      return "rsp";
    case X86_REG_RBP:
    case X86_REG_EBP:
      return "rbp";
    case X86_REG_RSI:
    case X86_REG_ESI:
      return "rsi";
    case X86_REG_RDI:
    case X86_REG_EDI:
      return "rdi";
    case X86_REG_R8:
    case X86_REG_R8D:
      return "r8";
    case X86_REG_R9:
    case X86_REG_R9D:
      return "r9";
    case X86_REG_R10:
    case X86_REG_R10D:
      return "r10";
    case X86_REG_R11:
    case X86_REG_R11D:
      return "r11";
    case X86_REG_R12:
    case X86_REG_R12D:
      return "r12";
    case X86_REG_R13:
    case X86_REG_R13D:
      return "r13";
    case X86_REG_R14:
    case X86_REG_R14D:
      return "r14";
    case X86_REG_R15:
    case X86_REG_R15D:
      return "r15";
    default:
      return {};
  }
}

bool unicorn_available() { return true; }

namespace {

int unicorn_reg(const std::string& name) {
  if (name == "rax") return UC_X86_REG_RAX;
  if (name == "rcx") return UC_X86_REG_RCX;
  if (name == "rdx") return UC_X86_REG_RDX;
  if (name == "rbx") return UC_X86_REG_RBX;
  if (name == "rsp") return UC_X86_REG_RSP;
  if (name == "rbp") return UC_X86_REG_RBP;
  if (name == "rsi") return UC_X86_REG_RSI;
  if (name == "rdi") return UC_X86_REG_RDI;
  if (name == "r8") return UC_X86_REG_R8;
  if (name == "r9") return UC_X86_REG_R9;
  if (name == "r10") return UC_X86_REG_R10;
  if (name == "r11") return UC_X86_REG_R11;
  if (name == "r12") return UC_X86_REG_R12;
  if (name == "r13") return UC_X86_REG_R13;
  if (name == "r14") return UC_X86_REG_R14;
  if (name == "r15") return UC_X86_REG_R15;
  if (name == "rip") return UC_X86_REG_RIP;
  return 0;
}

bool looks_like_code(const PeImage& image, std::uint64_t va) {
  if (!image.contains_va(va)) {
    return false;
  }
  auto* sec = image.section_for_va(va);
  if (!sec) {
    return false;
  }

  if (!is_vmp_section_name(sec->name) && sec->name != ".text") {
    return false;
  }
  auto b = image.read_at_va(va, 4);
  if (b.size() < 2) {
    return false;
  }
  int nz = 0;
  for (auto x : b) {
    if (x != 0 && x != 0xCC) nz++;
  }
  return nz >= 2;
}

struct Slice {
  uc_engine* uc = nullptr;
  csh cs = 0;
  const PeImage* image = nullptr;
  std::uint64_t next = 0;
  std::uint64_t start = 0;
  bool hit = false;
  bool saw_ret = false;
  std::size_t steps = 0;
  std::size_t max_insns = 2048;
};

void on_code(uc_engine* uc, std::uint64_t addr, std::uint32_t size, void* user) {
  auto* st = static_cast<Slice*>(user);
  if (++st->steps > st->max_insns) {
    uc_emu_stop(uc);
    return;
  }

  std::uint8_t buf[16]{};
  auto n = size < 15u ? size : 15u;
  if (uc_mem_read(uc, addr, buf, n) != UC_ERR_OK) {
    uc_emu_stop(uc);
    return;
  }

  cs_insn* ins = nullptr;
  auto count = cs_disasm(st->cs, buf, n, addr, 1, &ins);
  if (count == 0) {
    return;
  }

  std::string mnem = ins[0].mnemonic;
  if (mnem == "ret" || mnem == "retn" || mnem == "retf") {
    st->saw_ret = true;
    uc_emu_stop(uc);
    cs_free(ins, count);
    return;
  }

  const bool xfer = (mnem == "jmp" || mnem == "call");
  if (xfer && ins[0].detail && ins[0].detail->x86.op_count >= 1) {
    const auto& op = ins[0].detail->x86.operands[0];
    if (op.type == X86_OP_REG) {
      auto rname = x86_reg_name(op.reg);
      auto ureg = unicorn_reg(rname);
      std::uint64_t target = 0;
      if (ureg != 0) {
        uc_reg_read(uc, ureg, &target);
      }

      if (target && target != addr && target != st->start && looks_like_code(*st->image, target)) {
        st->next = target;
        st->hit = true;
        uc_emu_stop(uc);
      }
    }
  }
  cs_free(ins, count);
}

bool on_unmapped(uc_engine* , uc_mem_type , std::uint64_t addr, int ,
                 std::int64_t , void* user) {
  auto* st = static_cast<Slice*>(user);
  auto page = addr & ~0xFFFULL;

  if (uc_mem_map(st->uc, page, 0x1000, UC_PROT_ALL) == UC_ERR_OK) {
    return true;
  }
  return false;
}

bool map_pe_image(uc_engine* uc, const PeImage& image) {
  auto base = image.image_base();
  auto img_sz = (image.size_of_image() + 0xFFF) & ~0xFFFULL;
  if (img_sz < 0x1000) {
    img_sz = 0x1000;
  }

  if (uc_mem_map(uc, base, img_sz, UC_PROT_ALL) != UC_ERR_OK) {
    return false;
  }

  for (const auto& sec : image.sections()) {
    auto va = base + sec.virtual_address;
    auto want = static_cast<std::size_t>(
        sec.raw_size ? (sec.raw_size < sec.virtual_size ? sec.raw_size : sec.virtual_size)
                     : sec.virtual_size);
    if (want == 0) {
      continue;
    }
    auto bytes = image.read_at_va(va, want);
    if (!bytes.empty()) {
      uc_mem_write(uc, va, bytes.data(), bytes.size());
    }

    if (sec.virtual_size > want) {
      auto gap = static_cast<std::size_t>(sec.virtual_size - want);
      if (gap > 0x100000) gap = 0x100000;
      std::vector<std::uint8_t> z(gap, 0);
      uc_mem_write(uc, va + want, z.data(), z.size());
    }
  }
  return true;
}

}

std::optional<std::uint64_t> unicorn_tail_next(const PeImage& image, std::uint64_t handler_va,
                                               std::size_t max_insns) {

  auto tr = unicorn_vip_trace(image, handler_va, 1, max_insns);
  if (!tr.steps.empty() && tr.steps.front().next_handler &&
      *tr.steps.front().next_handler != handler_va) {
    return tr.steps.front().next_handler;
  }
  return std::nullopt;
}

std::vector<std::uint64_t> unicorn_discover_edges(const PeImage& image, std::uint64_t root_va,
                                                  std::size_t max_handlers, std::size_t max_insns) {
  std::vector<std::uint64_t> found;
  std::deque<std::uint64_t> q;
  std::set<std::uint64_t> seen;

  if (!looks_like_code(image, root_va)) {
    return found;
  }
  q.push_back(root_va);

  while (!q.empty() && found.size() < max_handlers) {
    auto va = q.front();
    q.pop_front();
    if (!seen.insert(va).second) {
      continue;
    }
    found.push_back(va);

    auto nxt = unicorn_tail_next(image, va, max_insns);
    if (nxt && !seen.count(*nxt) && looks_like_code(image, *nxt)) {
      q.push_back(*nxt);
    }
  }
  return found;
}

}
