#include "vip_context.hpp"

#include "util.hpp"

#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <unicorn/unicorn.h>

#include <cstdio>
#include <cstring>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace vmp {

namespace {

std::string reg_name(int capstone_reg) {
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
  return 0;
}

bool in_vmp_or_text(const PeImage& image, std::uint64_t va) {
  auto* sec = image.section_for_va(va);
  if (!sec) return false;
  return is_vmp_section_name(sec->name) || sec->name == ".text";
}

bool looks_like_code_va(const PeImage& image, std::uint64_t va) {
  if (!image.contains_va(va)) return false;
  if (in_vmp_or_text(image, va)) {
    auto b = image.read_at_va(va, 4);
    if (b.size() < 2) return false;
    int nz = 0;
    for (auto x : b)
      if (x && x != 0xCC) nz++;
    return nz >= 1;
  }

  auto b = image.read_at_va(va, 8);
  if (b.size() < 4) return false;
  int nz = 0;
  for (auto x : b)
    if (x && x != 0xCC) nz++;
  return nz >= 3;
}

std::uint64_t read_mem_op_addr(uc_engine* uc, const cs_x86_op& op) {
  std::uint64_t addr = static_cast<std::uint64_t>(op.mem.disp);
  if (op.mem.base != X86_REG_INVALID) {
    auto rn = reg_name(op.mem.base);
    auto ur = unicorn_reg(rn);
    std::uint64_t base = 0;
    if (ur) uc_reg_read(uc, ur, &base);
    addr += base;
  }
  if (op.mem.index != X86_REG_INVALID) {
    auto rn = reg_name(op.mem.index);
    auto ur = unicorn_reg(rn);
    std::uint64_t idx = 0;
    if (ur) uc_reg_read(uc, ur, &idx);
    addr += idx * (op.mem.scale ? op.mem.scale : 1);
  }
  return addr;
}

bool map_pe(uc_engine* uc, const PeImage& image) {
  auto base = image.image_base();
  auto img_sz = (image.size_of_image() + 0xFFF) & ~0xFFFULL;
  if (img_sz < 0x1000) img_sz = 0x1000;
  if (uc_mem_map(uc, base, img_sz, UC_PROT_ALL) != UC_ERR_OK) return false;
  for (const auto& sec : image.sections()) {
    auto va = base + sec.virtual_address;
    auto want = static_cast<std::size_t>(
        sec.raw_size ? (sec.raw_size < sec.virtual_size ? sec.raw_size : sec.virtual_size)
                     : sec.virtual_size);
    if (!want) continue;
    auto bytes = image.read_at_va(va, want);
    if (!bytes.empty()) uc_mem_write(uc, va, bytes.data(), bytes.size());
  }
  return true;
}

struct Session {
  uc_engine* uc = nullptr;
  csh cs = 0;
  const PeImage* image = nullptr;

  std::uint64_t handler_entry = 0;
  std::uint64_t next = 0;
  std::uint64_t vip = 0;
  std::uint64_t key = 0;
  std::string vip_reg;
  std::string key_reg;
  std::uint32_t last_fetch = 0;
  int vip_reads = 0;
  std::size_t steps = 0;
  std::size_t max_insns = 2048;
  bool hit = false;
  bool saw_ret = false;
  bool stop_xfer = false;
};

void snapshot_context(Session* st) {
  const char* regs[] = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
                        "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"};
  for (auto* rn : regs) {
    std::uint64_t v = 0;
    auto ur = unicorn_reg(rn);
    if (!ur) continue;
    uc_reg_read(st->uc, ur, &v);
    if (!v || !st->image->contains_va(v)) continue;
    auto* sec = st->image->section_for_va(v);
    if (!sec || !is_vmp_section_name(sec->name)) continue;
    if (st->vip == 0 || v == st->vip || st->vip_reads == 0) {
      st->vip = v;
      st->vip_reg = rn;
    } else if (st->key == 0 && v != st->vip) {
      st->key = v;
      st->key_reg = rn;
    }
  }
}

void on_code(uc_engine* uc, std::uint64_t addr, std::uint32_t size, void* user) {
  auto* st = static_cast<Session*>(user);
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
  if (!count) return;

  std::string mnem = ins[0].mnemonic;

  if (mnem.rfind("rep", 0) == 0 || mnem == "movsb" || mnem == "movsw" || mnem == "movsd" ||
      mnem == "movsq" || mnem == "stosb" || mnem == "stosq" || mnem == "scasb" ||
      mnem == "cmpsb") {
    std::uint64_t rip = addr + ins[0].size;
    uc_reg_write(uc, UC_X86_REG_RIP, &rip);
    cs_free(ins, count);
    return;
  }

  if (mnem == "ret" || mnem == "retn" || mnem == "retf") {
    std::uint64_t rsp = 0;
    uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
    std::uint64_t ret_target = 0;
    if (uc_mem_read(uc, rsp, &ret_target, 8) == UC_ERR_OK && ret_target &&
        ret_target != addr && ret_target != st->handler_entry &&
        looks_like_code_va(*st->image, ret_target)) {
      st->next = ret_target;
      st->hit = true;
      st->stop_xfer = true;
      snapshot_context(st);
      uc_emu_stop(uc);
      cs_free(ins, count);
      return;
    }

    st->saw_ret = true;
    st->stop_xfer = true;
    uc_emu_stop(uc);
    cs_free(ins, count);
    return;
  }

  if ((mnem == "jmp" || mnem == "call") && ins[0].detail && ins[0].detail->x86.op_count >= 1) {

    if (mnem == "call") {
      cs_free(ins, count);
      return;
    }
    const auto& op = ins[0].detail->x86.operands[0];
    std::uint64_t target = 0;
    if (op.type == X86_OP_IMM) {
      target = static_cast<std::uint64_t>(op.imm);
    } else if (op.type == X86_OP_REG) {
      auto ureg = unicorn_reg(reg_name(op.reg));
      if (ureg) uc_reg_read(uc, ureg, &target);
    } else if (op.type == X86_OP_MEM) {
      auto mem_addr = read_mem_op_addr(uc, op);
      uc_mem_read(uc, mem_addr, &target, 8);
    }

    if (target && target != addr && target != st->handler_entry &&
        looks_like_code_va(*st->image, target)) {
      st->next = target;
      st->hit = true;
      st->stop_xfer = true;
      snapshot_context(st);
      uc_emu_stop(uc);
    }
  }
  cs_free(ins, count);
}

void on_mem_read(uc_engine* , uc_mem_type , std::uint64_t addr, int size,
                 std::int64_t , void* user) {
  auto* st = static_cast<Session*>(user);
  if (size != 1 && size != 2 && size != 4 && size != 8) return;
  if (!st->image->contains_va(addr)) return;
  auto* sec = st->image->section_for_va(addr);
  if (!sec || !is_vmp_section_name(sec->name)) return;
  st->vip = addr;
  st->vip_reads++;
  if (size == 4) {
    std::uint8_t b[4]{};
    if (uc_mem_read(st->uc, addr, b, 4) == UC_ERR_OK) {
      st->last_fetch = static_cast<std::uint32_t>(b[0]) | (static_cast<std::uint32_t>(b[1]) << 8) |
                       (static_cast<std::uint32_t>(b[2]) << 16) |
                       (static_cast<std::uint32_t>(b[3]) << 24);
    }
  }
}

bool on_unmapped(uc_engine* uc, uc_mem_type , std::uint64_t addr, int , std::int64_t ,
                 void* ) {
  auto page = addr & ~0xFFFULL;
  return uc_mem_map(uc, page, 0x1000, UC_PROT_ALL) == UC_ERR_OK;
}

std::optional<std::uint64_t> static_next_handler(csh cs, const PeImage& image, std::uint64_t va) {
  auto bytes = image.read_at_va(va, 256);
  if (bytes.size() < 8) return std::nullopt;
  cs_insn* ins = nullptr;
  auto n = cs_disasm(cs, bytes.data(), bytes.size(), va, 48, &ins);
  std::optional<std::uint64_t> next;
  for (std::size_t i = 0; i < n; i++) {
    std::string m = ins[i].mnemonic;
    if (m == "jmp" && ins[i].detail && ins[i].detail->x86.op_count >= 1) {
      const auto& op = ins[i].detail->x86.operands[0];
      if (op.type == X86_OP_IMM) {
        auto t = static_cast<std::uint64_t>(op.imm);
        if (t != va && looks_like_code_va(image, t)) {
          next = t;
          break;
        }
      }
    }
    if (m == "ret" || m == "retn" || m == "retf") break;
  }
  cs_free(ins, n);
  return next;
}

}

VipSeed extract_vip_seed(const PeImage& image, std::uint64_t vmenter_va) {
  VipSeed seed;
  seed.image_high = image.image_base() & 0xFFFFFFFF00000000ULL;
  seed.note = "none";

  auto bytes = image.read_at_va(vmenter_va, 128);
  if (bytes.size() < 8) return seed;

  csh cs{};
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs) != CS_ERR_OK) return seed;
  cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);
  cs_insn* ins = nullptr;
  auto n = cs_disasm(cs, bytes.data(), bytes.size(), vmenter_va, 24, &ins);

  for (std::size_t i = 0; i < n; i++) {
    std::string m = ins[i].mnemonic;
    if (m == "push" && ins[i].detail) {
      const auto& x86 = ins[i].detail->x86;
      if (x86.op_count >= 1 && x86.operands[0].type == X86_OP_IMM) {
        auto imm = static_cast<std::uint64_t>(x86.operands[0].imm);
        if (imm <= 0xFFFFFFFFULL) {
          seed.enc_push_imm = static_cast<std::uint32_t>(imm);
          seed.note = "push_imm";
        }
      }
    }
    if ((m == "mov" || m == "movabs") && ins[i].detail) {
      const auto& x86 = ins[i].detail->x86;
      if (x86.op_count >= 2 && x86.operands[1].type == X86_OP_IMM &&
          x86.operands[0].type == X86_OP_REG) {
        auto imm = static_cast<std::uint64_t>(x86.operands[1].imm);

        bool ntstatus = (imm & 0xFFFF0000ULL) == 0xC0000000ULL;
        bool tiny = imm <= 0xFFFF;
        if (!tiny && !ntstatus && !seed.movabs_imm) {
          seed.movabs_imm = imm;
          seed.movabs_reg = reg_name(x86.operands[0].reg);
          if (seed.movabs_reg.empty()) seed.movabs_reg = "rbp";
          if (seed.note == "none") seed.note = "movabs";
          else seed.note += "+movabs";
        }
      }
    }
  }
  cs_free(ins, n);
  cs_close(&cs);
  return seed;
}

VipTrace unicorn_vip_trace(const PeImage& image, std::uint64_t start_va, std::size_t max_handlers,
                           std::size_t max_insns_each) {
  VipTrace tr;
  tr.seed = extract_vip_seed(image, start_va);
  tr.seeded = tr.seed.enc_push_imm.has_value() || tr.seed.movabs_imm.has_value();

  Session st;
  st.image = &image;
  st.max_insns = max_insns_each;

  if (cs_open(CS_ARCH_X86, CS_MODE_64, &st.cs) != CS_ERR_OK) return tr;
  cs_option(st.cs, CS_OPT_DETAIL, CS_OPT_ON);
  if (uc_open(UC_ARCH_X86, UC_MODE_64, &st.uc) != UC_ERR_OK) {
    cs_close(&st.cs);
    return tr;
  }
  if (!map_pe(st.uc, image)) {
    uc_close(st.uc);
    cs_close(&st.cs);
    return tr;
  }

  constexpr std::uint64_t kStack = 0x7FE00000ULL;
  constexpr std::uint64_t kStackSz = 0x200000ULL;
  uc_mem_map(st.uc, kStack, kStackSz, UC_PROT_ALL);
  std::uint64_t rsp = kStack + kStackSz - 0x400;

  bool start_is_push_call = false;
  {
    auto b = image.read_at_va(start_va, 10);
    start_is_push_call = b.size() >= 10 && b[0] == 0x68 && b[5] == 0xE8;
  }
  if (tr.seed.enc_push_imm && !start_is_push_call) {
    rsp -= 8;
    std::uint64_t imm = *tr.seed.enc_push_imm;
    uc_mem_write(st.uc, rsp, &imm, 8);
  }
  rsp -= 8;
  std::uint64_t ret = image.image_base() + 0x1000;
  uc_mem_write(st.uc, rsp, &ret, 8);
  uc_reg_write(st.uc, UC_X86_REG_RSP, &rsp);

  std::uint64_t junk = 0x1111111111111111ULL;
  std::uint64_t z = 0;
  for (int r : {UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RSI,
                UC_X86_REG_RDI, UC_X86_REG_R8,  UC_X86_REG_R9,  UC_X86_REG_R10, UC_X86_REG_R11,
                UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15}) {
    uc_reg_write(st.uc, r, &junk);
  }
  uc_reg_write(st.uc, UC_X86_REG_RBP, &z);
  if (tr.seed.movabs_imm) {
    std::uint64_t m = *tr.seed.movabs_imm;
    auto ur = unicorn_reg(tr.seed.movabs_reg.empty() ? "rbp" : tr.seed.movabs_reg);
    if (!ur) ur = UC_X86_REG_RBP;
    uc_reg_write(st.uc, ur, &m);
  }

  uc_hook h_code{}, h_mem{}, h_unmap{};
  uc_hook_add(st.uc, &h_code, UC_HOOK_CODE, reinterpret_cast<void*>(on_code), &st, 1, 0);
  uc_hook_add(st.uc, &h_mem, UC_HOOK_MEM_READ, reinterpret_cast<void*>(on_mem_read), &st, 1, 0);
  uc_hook_add(st.uc, &h_unmap, UC_HOOK_MEM_UNMAPPED, reinterpret_cast<void*>(on_unmapped), &st, 1,
              0);

  std::set<std::uint64_t> seen;
  std::uint64_t cur = start_va;

  std::size_t soft_stalls = 0;

  for (std::size_t i = 0; i < max_handlers; i++) {
    bool revisit = !seen.insert(cur).second;
    if (revisit && soft_stalls > 2) break;

    st.handler_entry = cur;
    st.next = 0;
    st.hit = false;
    st.saw_ret = false;
    st.stop_xfer = false;
    st.steps = 0;
    st.vip_reads = 0;
    st.last_fetch = 0;

    uc_emu_start(st.uc, cur, 0, 0, max_insns_each);

    VipStep step;
    step.handler_va = cur;
    step.vip = st.vip;
    step.fetched_enc = st.last_fetch;
    step.vip_reg = st.vip_reg;
    step.key_reg = st.key_reg;
    if (st.hit) step.next_handler = st.next;
    if (st.vip_reads) {
      char buf[64];
      std::snprintf(buf, sizeof(buf), "vip_reads=%d", st.vip_reads);
      step.note = buf;
    } else if (st.hit && st.saw_ret) {
      step.note = "ret_xfer";
    } else if (st.saw_ret) {
      step.note = "ret";
    } else if (st.hit) {
      step.note = "xfer";
    } else {
      step.note = "stall";
    }
    tr.steps.push_back(step);

    if (i == 0) {
      tr.initial_vip = st.vip;
    }
    if (st.key) tr.rolling_key = st.key;

    if (st.saw_ret && !st.hit) break;

    if (!st.hit) {

      if (auto nxt = static_next_handler(st.cs, image, cur)) {
        tr.steps.back().next_handler = *nxt;
        tr.steps.back().note = "stall_recover";
        soft_stalls++;
        if (soft_stalls > 32) break;

        cur = *nxt;
        uc_reg_write(st.uc, UC_X86_REG_RIP, &cur);
        continue;
      }
      break;
    }
    soft_stalls = 0;
    cur = st.next;
    uc_reg_write(st.uc, UC_X86_REG_RIP, &cur);
  }

  uc_close(st.uc);
  cs_close(&st.cs);
  return tr;
}

std::string format_vip_trace_text(const VipTrace& tr) {
  std::ostringstream oss;
  oss << "; vip trace\n";
  oss << "; seed=" << tr.seed.note;
  if (tr.seed.enc_push_imm) oss << " push_imm=0x" << std::hex << *tr.seed.enc_push_imm;
  if (tr.seed.movabs_imm) oss << " movabs=0x" << std::hex << *tr.seed.movabs_imm;
  oss << std::dec << "\n";
  if (tr.initial_vip) oss << "; initial_vip=" << hex_u64(tr.initial_vip) << "\n";
  if (tr.rolling_key) oss << "; key_candidate=" << hex_u64(tr.rolling_key) << "\n";
  oss << "; steps=" << tr.steps.size() << "\n\n";

  for (std::size_t i = 0; i < tr.steps.size(); i++) {
    const auto& s = tr.steps[i];
    oss << "VOP_" << i << ":\n";
    oss << "  handler  " << hex_u64(s.handler_va) << "\n";
    if (s.vip) {
      oss << "  vip      " << hex_u64(s.vip);
      if (!s.vip_reg.empty()) oss << " (" << s.vip_reg << ")";
      oss << "\n";
      oss << "  fetch    0x" << std::hex << s.fetched_enc << std::dec << "  ; enc dword @ vip\n";
    }
    if (s.next_handler) oss << "  next     " << hex_u64(*s.next_handler) << "\n";
    if (!s.note.empty()) oss << "  ; " << s.note << "\n";
    oss << "\n";
  }
  return oss.str();
}

}
