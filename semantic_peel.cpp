#include "semantic_peel.hpp"

#include "util.hpp"

#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <unicorn/unicorn.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <set>
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

bool in_vmp(const PeImage& image, std::uint64_t va) {
  auto* sec = image.section_for_va(va);
  return sec && is_vmp_section_name(sec->name);
}

bool looks_like_code_va(const PeImage& image, std::uint64_t va) {
  if (!image.contains_va(va)) return false;
  auto* sec = image.section_for_va(va);
  if (!sec) return false;
  if (!is_vmp_section_name(sec->name) && sec->name != ".text") {
    auto b = image.read_at_va(va, 8);
    if (b.size() < 4) return false;
    int nz = 0;
    for (auto x : b)
      if (x && x != 0xCC) nz++;
    return nz >= 3;
  }
  auto b = image.read_at_va(va, 4);
  if (b.size() < 2) return false;
  int nz = 0;
  for (auto x : b)
    if (x && x != 0xCC) nz++;
  return nz >= 1;
}

std::uint64_t read_mem_op_addr(uc_engine* uc, const cs_x86_op& op) {
  std::uint64_t addr = static_cast<std::uint64_t>(op.mem.disp);
  if (op.mem.base != X86_REG_INVALID) {
    auto ur = unicorn_reg(reg_name(op.mem.base));
    std::uint64_t base = 0;
    if (ur) uc_reg_read(uc, ur, &base);
    addr += base;
  }
  if (op.mem.index != X86_REG_INVALID) {
    auto ur = unicorn_reg(reg_name(op.mem.index));
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

struct DeepSession {
  uc_engine* uc = nullptr;
  csh cs = 0;
  const PeImage* image = nullptr;

  std::uint64_t handler_entry = 0;
  std::uint64_t next = 0;
  bool hit = false;
  bool saw_ret = false;
  std::size_t steps = 0;
  std::size_t max_insns = 4096;

  std::uint64_t vip = 0;
  std::uint64_t key_val = 0;
  std::string vip_reg;
  std::string key_reg;
  std::string vsp_reg;
  std::uint64_t vsp = 0;

  HandlerEffect* cur = nullptr;
  std::uint64_t gpr_enter[16]{};
  std::uint64_t last_vip_fetch_enc = 0;
  bool have_last_fetch = false;
  int post_fetch_watch = 0;
  bool key_pending_refresh = false;
  int xor_src_hits[16]{};
};

const char* kGprs[] = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                       "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"};

void read_gprs(uc_engine* uc, std::uint64_t out[16]) {
  for (int i = 0; i < 16; i++) {
    auto ur = unicorn_reg(kGprs[i]);
    out[i] = 0;
    if (ur) uc_reg_read(uc, ur, &out[i]);
  }
}

void refresh_context_ptrs(DeepSession* st) {
  for (int i = 0; i < 16; i++) {
    if (std::string(kGprs[i]) == "rsp") continue;
    std::uint64_t v = 0;
    auto ur = unicorn_reg(kGprs[i]);
    if (!ur) continue;
    uc_reg_read(st->uc, ur, &v);
    if (!v || !st->image->contains_va(v)) continue;
    if (!in_vmp(*st->image, v)) continue;

    if (st->have_last_fetch && st->cur && !st->cur->fetches.empty()) {
      auto fa = st->cur->fetches.back().addr;
      if (v == fa || (v < fa && fa - v < 0x40) || (v > fa && v - fa < 0x40)) {
        st->vip = v;
        st->vip_reg = kGprs[i];
        continue;
      }
    }
    if (st->vip_reg.empty() || st->vip == 0) {
      st->vip = v;
      st->vip_reg = kGprs[i];
    }
  }
}

void apply_key_decrypt(DeepSession* st, FetchEvent& fe) {
  std::uint32_t enc32 = static_cast<std::uint32_t>(fe.enc);
  if (!st->key_reg.empty()) {
    auto ur = unicorn_reg(st->key_reg);
    std::uint64_t kv = 0;
    if (ur) uc_reg_read(st->uc, ur, &kv);
    st->key_val = kv;
  }
  if (st->key_val || !st->key_reg.empty()) {
    fe.dec = enc32 ^ static_cast<std::uint32_t>(st->key_val);
    fe.decrypted = true;
    if (st->cur && !st->cur->pushed_imm) st->cur->pushed_imm = fe.dec;
  }
}

void try_bind_decrypt(DeepSession* st) {
  if (!st->cur || !st->have_last_fetch || st->cur->fetches.empty()) return;
  auto& fe = st->cur->fetches.back();
  std::uint64_t gpr[16];
  read_gprs(st->uc, gpr);
  std::uint32_t enc32 = static_cast<std::uint32_t>(fe.enc);

  if (!st->key_reg.empty() || st->key_val) {
    apply_key_decrypt(st, fe);

    for (int i = 0; i < 16; i++) {
      if (std::string(kGprs[i]) == "rsp") continue;
      if (static_cast<std::uint32_t>(gpr[i]) == static_cast<std::uint32_t>(fe.dec) &&
          gpr[i] != st->gpr_enter[i]) {
        fe.via_reg = kGprs[i];
        st->cur->pushed_imm = fe.dec;
        break;
      }
    }
    return;
  }

  for (int di = 0; di < 16; di++) {
    if (std::string(kGprs[di]) == "rsp") continue;
    if (gpr[di] == st->gpr_enter[di]) continue;
    std::uint32_t d32 = static_cast<std::uint32_t>(gpr[di]);
    std::uint32_t implied_key = enc32 ^ d32;

    const bool looks_small = d32 < 0x100000u;
    const bool looks_rva = d32 > 0x1000u && d32 < 0x2000000u;
    const bool looks_img = st->image->contains_va(gpr[di]);
    if (!(looks_small || looks_rva || looks_img)) continue;

    for (int ki = 0; ki < 16; ki++) {
      if (ki == di) continue;
      if (std::string(kGprs[ki]) == "rsp") continue;
      if (static_cast<std::uint32_t>(gpr[ki]) == implied_key) {
        st->key_reg = kGprs[ki];
        st->key_val = implied_key;
        fe.dec = d32;
        fe.decrypted = true;
        fe.via_reg = kGprs[di];
        st->cur->pushed_imm = d32;
        return;
      }
    }

    st->key_val = implied_key;
    fe.dec = d32;
    fe.decrypted = true;
    fe.via_reg = kGprs[di];
    st->cur->pushed_imm = d32;
    return;
  }
}

void on_mem_read(uc_engine* , uc_mem_type , std::uint64_t addr, int size,
                 std::int64_t , void* user) {
  auto* st = static_cast<DeepSession*>(user);
  if (!st->cur || !st->image->contains_va(addr)) return;
  if (!in_vmp(*st->image, addr)) {

    if (!st->vsp_reg.empty() && st->vsp) {
      std::int64_t off = static_cast<std::int64_t>(addr - st->vsp);
      if (off >= -0x400 && off <= 0x400) st->cur->mem_load++;
    }
    return;
  }

  std::uint64_t enc = 0;
  std::uint8_t b[8]{};
  auto n = static_cast<std::size_t>(size);
  if (n > 8) n = 8;
  if (uc_mem_read(st->uc, addr, b, n) != UC_ERR_OK) return;
  for (std::size_t i = 0; i < n; i++) enc |= static_cast<std::uint64_t>(b[i]) << (8 * i);

  FetchEvent fe;
  fe.addr = addr;
  fe.size = static_cast<std::uint32_t>(size);
  fe.enc = enc;

  if (st->key_val || !st->key_reg.empty()) {
    apply_key_decrypt(st, fe);
  }
  st->cur->fetches.push_back(fe);
  st->vip = addr;
  st->last_vip_fetch_enc = enc;
  st->have_last_fetch = true;
  st->post_fetch_watch = 24;
}

void on_mem_write(uc_engine* , uc_mem_type , std::uint64_t addr, int size,
                  std::int64_t value, void* user) {
  auto* st = static_cast<DeepSession*>(user);
  if (!st->cur) return;

  if (size == 8 || size == 4) {
    std::uint64_t gpr[16];
    read_gprs(st->uc, gpr);
    for (int i = 0; i < 16; i++) {
      if (std::string(kGprs[i]) == "rsp") continue;

      if (gpr[i] && (addr == gpr[i] || (addr + 8 == gpr[i]) || (addr == gpr[i] - 8))) {
        st->vsp_reg = kGprs[i];
        st->vsp = gpr[i];
        st->cur->vsp_reg = kGprs[i];
        st->cur->pushes++;

        auto uval = static_cast<std::uint64_t>(value);
        if (uval < 0x7FD00000ULL || uval >= 0x80000000ULL) {
          st->cur->pushed_imm = uval;
        }

        if (st->have_last_fetch && st->cur->fetches.size()) {
          auto& fe = st->cur->fetches.back();
          if (!fe.decrypted) {
            fe.dec = static_cast<std::uint64_t>(value);
            fe.decrypted = true;
          }
        }
        break;
      }
    }
    if (!st->vsp_reg.empty() && st->vsp) {
      std::int64_t off = static_cast<std::int64_t>(addr - st->vsp);
      if (off >= -0x400 && off <= 0x400) st->cur->mem_store++;
    }
  }
}

void on_code(uc_engine* uc, std::uint64_t addr, std::uint32_t size, void* user) {
  auto* st = static_cast<DeepSession*>(user);
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
      mnem == "movsq" || mnem == "stosb" || mnem == "stosq") {
    std::uint64_t rip = addr + ins[0].size;
    uc_reg_write(uc, UC_X86_REG_RIP, &rip);
    cs_free(ins, count);
    return;
  }

  if (st->cur) {
    if (mnem == "add" || mnem == "adc") st->cur->alu_add++;
    else if (mnem == "sub" || mnem == "sbb") st->cur->alu_sub++;
    else if (mnem == "xor") st->cur->alu_xor++;
    else if (mnem == "and") st->cur->alu_and++;
    else if (mnem == "or") st->cur->alu_or++;
    else if (mnem == "not") st->cur->alu_not++;
    else if (mnem == "neg") st->cur->alu_neg++;
    else if (mnem == "shl" || mnem == "sal") st->cur->alu_shl++;
    else if (mnem == "shr" || mnem == "sar") st->cur->alu_shr++;
    else if (mnem == "push") st->cur->pushes++;
    else if (mnem == "pop") st->cur->pops++;

    if (!st->key_reg.empty() && ins[0].detail) {
      const auto& x86 = ins[0].detail->x86;
      if (x86.op_count >= 1 && x86.operands[0].type == X86_OP_REG) {
        auto dn = reg_name(x86.operands[0].reg);
        if (dn == st->key_reg) {
          auto ur = unicorn_reg(st->key_reg);
          std::uint64_t kv = 0;
          if (ur) uc_reg_read(uc, ur, &kv);

          st->key_pending_refresh = true;
        }
      }
    }

    if (mnem == "xor" && ins[0].detail) {
      const auto& x86 = ins[0].detail->x86;
      if (x86.op_count >= 2 && x86.operands[0].type == X86_OP_REG &&
          x86.operands[1].type == X86_OP_REG) {
        auto dn = reg_name(x86.operands[0].reg);
        auto sn = reg_name(x86.operands[1].reg);
        if (!sn.empty() && sn != dn) {
          for (int hi = 0; hi < 16; hi++) {
            if (kGprs[hi] == sn) {
              st->xor_src_hits[hi]++;
              break;
            }
          }
          if (st->key_reg.empty()) st->key_reg = sn;
          auto ur = unicorn_reg(st->key_reg.empty() ? sn : st->key_reg);
          std::uint64_t kv = 0;
          if (ur) uc_reg_read(uc, ur, &kv);
          st->key_val = kv;
        }
      }
    }
  }

  if (st->post_fetch_watch > 0) {
    st->post_fetch_watch--;
    if (st->key_pending_refresh && !st->key_reg.empty()) {
      auto ur = unicorn_reg(st->key_reg);
      std::uint64_t kv = 0;
      if (ur) uc_reg_read(uc, ur, &kv);
      st->key_val = kv;
      st->key_pending_refresh = false;
    }
    try_bind_decrypt(st);
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
      if (st->cur) {
        st->cur->has_xfer = true;
        st->cur->next_handler = ret_target;
      }
      uc_emu_stop(uc);
      cs_free(ins, count);
      return;
    }
    st->saw_ret = true;
    if (st->cur) st->cur->has_ret_exit = true;
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

      if (!in_vmp(*st->image, target)) {
        auto* sec = st->image->section_for_va(target);
        const bool to_text = sec && sec->name == ".text";
        const bool to_sentinel = target == (st->image->image_base() + 0x1000);
        if (to_text || to_sentinel || !st->image->contains_va(target)) {
          st->saw_ret = true;
          if (st->cur) {
            st->cur->has_ret_exit = true;
            st->cur->has_xfer = false;
          }
          uc_emu_stop(uc);
          cs_free(ins, count);
          return;
        }
      }

      const std::uint64_t lo = target < st->handler_entry ? target : st->handler_entry;
      const std::uint64_t hi = target < st->handler_entry ? st->handler_entry : target;
      if (hi - lo < 0x100ull) {
        cs_free(ins, count);
        return;
      }
      st->next = target;
      st->hit = true;
      if (st->cur) {
        st->cur->has_xfer = true;
        st->cur->next_handler = target;
      }
      refresh_context_ptrs(st);
      uc_emu_stop(uc);
    }
  }
  cs_free(ins, count);
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

void peel_effect(HandlerEffect& e) {
  for (auto& f : e.fetches) {
    if (!f.decrypted && e.pushed_imm) {
      f.dec = *e.pushed_imm;
      f.decrypted = true;
    }
  }

  const bool got_fetch = !e.fetches.empty();
  const bool got_imm = e.pushed_imm.has_value() ||
                       std::any_of(e.fetches.begin(), e.fetches.end(),
                                   [](const FetchEvent& f) { return f.decrypted; });
  const int alu = e.alu_add + e.alu_sub + e.alu_xor + e.alu_and + e.alu_or + e.alu_not +
                  e.alu_neg + e.alu_shl + e.alu_shr;
  const bool stackish = e.mem_load > 0 || e.mem_store > 0 || e.vsp_delta != 0 ||
                        (!e.vsp_reg.empty() && (e.pushes > 0 || e.pops > 0));
  const bool xfer = e.has_xfer || e.next_handler.has_value();

  if (e.has_ret_exit && !xfer) {
    e.kind = VmOpKind::VmExit;
    e.confidence = 95;
    e.why = "semantic:ret_exit";
    return;
  }

  if (got_imm) {

    if (stackish && alu >= 1 && e.mem_store + e.mem_load >= 1) {

    } else {
      e.kind = VmOpKind::FetchImm;
      e.confidence = got_fetch ? 88 : 75;
      e.why = got_fetch ? "semantic:vip_dec" : "semantic:imm";
      return;
    }
  }
  if (got_fetch && e.vip_delta != 0) {
    e.kind = VmOpKind::FetchImm;
    e.confidence = 72;
    e.why = "semantic:vip_advance";
    return;
  }


  if (xfer && !got_fetch && !stackish) {
    e.kind = VmOpKind::CalcJmp;
    e.confidence = alu ? 50 : 40;
    e.why = alu ? "semantic:keychain" : "semantic:dispatch";
    return;
  }

  if (e.alu_not >= 1 && e.alu_and >= 1) {
    e.kind = VmOpKind::Nor;
    e.confidence = 82;
    e.why = "semantic:nor";
    return;
  }
  if (e.alu_add >= 1 && e.alu_add >= e.alu_xor && e.alu_add >= e.alu_sub) {
    e.kind = VmOpKind::Add;
    e.confidence = e.alu_add >= 2 ? 80 : 68;
    e.why = "semantic:add";
    return;
  }
  if (e.alu_sub >= 1 && e.alu_sub >= e.alu_xor) {
    e.kind = VmOpKind::Sub;
    e.confidence = e.alu_sub >= 2 ? 78 : 65;
    e.why = "semantic:sub";
    return;
  }
  if (e.alu_xor >= 1) {
    e.kind = VmOpKind::Xor;
    e.confidence = e.alu_xor >= 2 ? 78 : 65;
    e.why = "semantic:xor";
    return;
  }
  if (e.alu_and >= 1 && e.alu_not == 0) {
    e.kind = VmOpKind::And;
    e.confidence = 70;
    e.why = "semantic:and";
    return;
  }
  if (e.alu_or >= 1) {
    e.kind = VmOpKind::Or;
    e.confidence = 70;
    e.why = "semantic:or";
    return;
  }
  if (e.alu_shl + e.alu_shr >= 1) {
    e.kind = e.alu_shl >= e.alu_shr ? VmOpKind::Shl : VmOpKind::Shr;
    e.confidence = 72;
    e.why = "semantic:shift";
    return;
  }
  if (e.alu_not >= 1) {
    e.kind = VmOpKind::Not;
    e.confidence = 70;
    e.why = "semantic:not";
    return;
  }
  if (e.alu_neg >= 1) {
    e.kind = VmOpKind::Neg;
    e.confidence = 70;
    e.why = "semantic:neg";
    return;
  }
  if (e.mem_load >= 1) {
    e.kind = VmOpKind::Load;
    e.confidence = 70;
    e.why = "semantic:load";
    return;
  }
  if (e.mem_store >= 1) {
    e.kind = VmOpKind::Store;
    e.confidence = 70;
    e.why = "semantic:store";
    return;
  }
  if (e.pushes >= 1 && e.pops == 0) {
    e.kind = VmOpKind::Push;
    e.confidence = got_imm ? 75 : 60;
    e.why = "semantic:push";
    return;
  }
  if (e.pops >= 1 && e.pushes == 0) {
    e.kind = VmOpKind::Pop;
    e.confidence = 65;
    e.why = "semantic:pop";
    return;
  }
  if (xfer) {
    e.kind = VmOpKind::CalcJmp;
    e.confidence = 35;
    e.why = "semantic:xfer";
    return;
  }
  e.kind = VmOpKind::Unknown;
  e.confidence = 10;
  e.why = "semantic:no_effect";
}

SemanticTrace unicorn_semantic_trace(const PeImage& image, std::uint64_t start_va,
                                     std::size_t max_handlers, std::size_t max_insns_each) {
  SemanticTrace out;
  out.vip.seed = extract_vip_seed(image, start_va);
  out.vip.seeded = out.vip.seed.enc_push_imm.has_value() || out.vip.seed.movabs_imm.has_value();

  DeepSession st;
  st.image = &image;
  st.max_insns = max_insns_each;

  if (cs_open(CS_ARCH_X86, CS_MODE_64, &st.cs) != CS_ERR_OK) return out;
  cs_option(st.cs, CS_OPT_DETAIL, CS_OPT_ON);
  if (uc_open(UC_ARCH_X86, UC_MODE_64, &st.uc) != UC_ERR_OK) {
    cs_close(&st.cs);
    return out;
  }
  if (!map_pe(st.uc, image)) {
    uc_close(st.uc);
    cs_close(&st.cs);
    return out;
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
  if (out.vip.seed.enc_push_imm && !start_is_push_call) {
    rsp -= 8;
    std::uint64_t imm = *out.vip.seed.enc_push_imm;
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
  if (out.vip.seed.movabs_imm) {
    std::uint64_t m = *out.vip.seed.movabs_imm;
    auto ur = unicorn_reg(out.vip.seed.movabs_reg.empty() ? "rbp" : out.vip.seed.movabs_reg);
    if (!ur) ur = UC_X86_REG_RBP;
    uc_reg_write(st.uc, ur, &m);
  }

  constexpr std::uint64_t kVsp = 0x7FD00000ULL;
  uc_mem_map(st.uc, kVsp, 0x10000, UC_PROT_ALL);

  uc_hook h_code{}, h_rd{}, h_wr{}, h_unmap{};
  uc_hook_add(st.uc, &h_code, UC_HOOK_CODE, reinterpret_cast<void*>(on_code), &st, 1, 0);
  uc_hook_add(st.uc, &h_rd, UC_HOOK_MEM_READ, reinterpret_cast<void*>(on_mem_read), &st, 1, 0);
  uc_hook_add(st.uc, &h_wr, UC_HOOK_MEM_WRITE, reinterpret_cast<void*>(on_mem_write), &st, 1, 0);
  uc_hook_add(st.uc, &h_unmap, UC_HOOK_MEM_UNMAPPED, reinterpret_cast<void*>(on_unmapped), &st, 1,
              0);

  std::set<std::uint64_t> seen;
  std::uint64_t cur = start_va;
  std::size_t soft_stalls = 0;

  for (std::size_t i = 0; i < max_handlers; i++) {
    bool revisit = !seen.insert(cur).second;
    if (revisit && soft_stalls > 4) break;

    HandlerEffect eff;
    eff.handler_va = cur;
    eff.vip_before = st.vip;
    eff.key_before = st.key_val;
    eff.vip_reg = st.vip_reg;
    eff.key_reg = st.key_reg;
    eff.vsp_reg = st.vsp_reg;

    st.handler_entry = cur;
    st.next = 0;
    st.hit = false;
    st.saw_ret = false;
    st.steps = 0;
    st.have_last_fetch = false;
    st.post_fetch_watch = 0;
    st.cur = &eff;
    read_gprs(st.uc, st.gpr_enter);

    uc_emu_start(st.uc, cur, 0, 0, max_insns_each);


    {
      int best = -1, bestn = 0;
      for (int hi = 0; hi < 16; hi++) {
        if (st.xor_src_hits[hi] <= bestn) continue;
        auto ur = unicorn_reg(kGprs[hi]);
        std::uint64_t kv = 0;
        if (ur) uc_reg_read(st.uc, ur, &kv);
        if (kv && image.contains_va(kv)) continue;
        if (std::string(kGprs[hi]) == "rsp") continue;
        bestn = st.xor_src_hits[hi];
        best = hi;
      }
      if (best >= 0 && bestn >= 2) {
        st.key_reg = kGprs[best];
        auto ur = unicorn_reg(st.key_reg);
        std::uint64_t kv = 0;
        if (ur) uc_reg_read(st.uc, ur, &kv);
        st.key_val = kv;
      }
    }

    if (!st.key_reg.empty()) {
      auto ur = unicorn_reg(st.key_reg);
      std::uint64_t kv = 0;
      if (ur) uc_reg_read(st.uc, ur, &kv);
      if (!(kv && image.contains_va(kv))) st.key_val = kv;
    }

    for (auto& f : eff.fetches) {
      if (!f.decrypted && (st.key_val || !st.key_reg.empty())) {
        f.dec = static_cast<std::uint32_t>(f.enc) ^ static_cast<std::uint32_t>(st.key_val);
        f.decrypted = true;
        if (!eff.pushed_imm) eff.pushed_imm = f.dec;
      }
    }

    if (!st.vip && out.vip.seed.enc_push_imm && st.key_val) {
      const std::uint32_t enc = *out.vip.seed.enc_push_imm;
      const std::uint32_t k = static_cast<std::uint32_t>(st.key_val);
      const std::uint32_t candidates[] = {
          enc ^ k,
          enc - k,
          enc + k,
          static_cast<std::uint32_t>(enc ^ (k * 0x343FD + 0x269EC3)),
      };
      for (auto rva : candidates) {
        auto va = image.image_base() + rva;
        if (in_vmp(image, va)) {
          st.vip = va;

          std::uint64_t gpr[16];
          read_gprs(st.uc, gpr);
          for (int gi = 0; gi < 16; gi++) {
            if (gpr[gi] == va || static_cast<std::uint32_t>(gpr[gi]) == rva) {
              st.vip_reg = kGprs[gi];
              break;
            }
          }
          if (st.vip_reg.empty()) {

            st.vip_reg = "rsi";
            auto ur = unicorn_reg("rsi");
            if (ur) uc_reg_write(st.uc, ur, &va);
          }
          break;
        }
      }
    }

    if (!st.vip) {
      std::uint64_t gpr[16];
      read_gprs(st.uc, gpr);
      for (int gi = 0; gi < 16; gi++) {
        if (std::string(kGprs[gi]) == "rsp") continue;
        auto v = gpr[gi];
        if (v && in_vmp(image, v) && v != cur && (v < cur || v - cur > 0x200)) {

          auto b = image.read_at_va(v, 4);
          st.vip = v;
          st.vip_reg = kGprs[gi];
          break;
        }
      }
    }

    eff.vip_after = st.vip;
    eff.key_after = st.key_val;
    eff.key_reg = st.key_reg;
    eff.vip_reg = st.vip_reg;
    eff.vip_delta = static_cast<std::int64_t>(eff.vip_after - eff.vip_before);
    if (st.hit) {
      eff.has_xfer = true;
      eff.next_handler = st.next;
    }
    if (st.vsp_reg.size()) {
      auto ur = unicorn_reg(st.vsp_reg);
      std::uint64_t vsp_now = 0;
      if (ur) uc_reg_read(st.uc, ur, &vsp_now);
      if (st.vsp) eff.vsp_delta = static_cast<std::int64_t>(vsp_now - st.vsp);
      st.vsp = vsp_now ? vsp_now : st.vsp;
    }
    peel_effect(eff);
    out.effects.push_back(eff);

    VipStep step;
    step.handler_va = cur;
    step.vip = st.vip;
    step.vip_reg = st.vip_reg;
    step.key_reg = st.key_reg;
    if (!eff.fetches.empty())
      step.fetched_enc = static_cast<std::uint32_t>(eff.fetches.back().enc);
    if (eff.next_handler) step.next_handler = *eff.next_handler;
    if (!eff.fetches.empty() && eff.fetches.back().decrypted)
      step.note = "dec=0x" + hex_u64(eff.fetches.back().dec).substr(2);
    else if (st.hit)
      step.note = "xfer";
    else if (st.saw_ret)
      step.note = "ret";
    else
      step.note = "stall";
    out.vip.steps.push_back(step);

    if (i == 0) out.vip.initial_vip = st.vip;
    if (st.key_val) out.vip.rolling_key = st.key_val;
    out.key_reg = st.key_reg;
    out.vip_reg = st.vip_reg;
    out.vsp_reg = st.vsp_reg;

    st.cur = nullptr;

    if (st.saw_ret && !st.hit) break;
    if (!st.hit) {
      if (auto nxt = static_next_handler(st.cs, image, cur)) {
        out.effects.back().next_handler = *nxt;
        out.effects.back().has_xfer = true;
        out.vip.steps.back().next_handler = *nxt;
        out.vip.steps.back().note = "stall_recover";
        if (out.effects.back().kind == VmOpKind::Unknown ||
            out.effects.back().kind == VmOpKind::CalcJmp) {
          peel_effect(out.effects.back());
        }
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
  return out;
}

}
