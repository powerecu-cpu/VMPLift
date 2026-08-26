#include "rolling_key.hpp"

#include <capstone/capstone.h>
#include <capstone/x86.h>

#include <cstring>
#include <string>

namespace vmp {

namespace {

std::uint32_t mask32(std::uint8_t width) {
  if (width >= 4) return 0xFFFFFFFFu;
  if (width == 2) return 0xFFFFu;
  return 0xFFu;
}

std::uint32_t rotl(std::uint32_t x, std::uint32_t n, std::uint8_t width) {
  const std::uint32_t bits = static_cast<std::uint32_t>(width) * 8u;
  const std::uint32_t m = mask32(width);
  if (!bits) return x;
  n %= bits;
  x &= m;
  if (!n) return x;
  return ((x << n) | (x >> (bits - n))) & m;
}

std::uint32_t rotr(std::uint32_t x, std::uint32_t n, std::uint8_t width) {
  const std::uint32_t bits = static_cast<std::uint32_t>(width) * 8u;
  const std::uint32_t m = mask32(width);
  if (!bits) return x;
  n %= bits;
  x &= m;
  if (!n) return x;
  return ((x >> n) | (x << (bits - n))) & m;
}

int extend_reg(int r) {
  switch (r) {
    case X86_REG_AL:
    case X86_REG_AH:
    case X86_REG_AX:
    case X86_REG_EAX:
      return X86_REG_RAX;
    case X86_REG_CL:
    case X86_REG_CH:
    case X86_REG_CX:
    case X86_REG_ECX:
      return X86_REG_RCX;
    case X86_REG_DL:
    case X86_REG_DH:
    case X86_REG_DX:
    case X86_REG_EDX:
      return X86_REG_RDX;
    case X86_REG_BL:
    case X86_REG_BH:
    case X86_REG_BX:
    case X86_REG_EBX:
      return X86_REG_RBX;
    case X86_REG_SPL:
    case X86_REG_SP:
    case X86_REG_ESP:
      return X86_REG_RSP;
    case X86_REG_BPL:
    case X86_REG_BP:
    case X86_REG_EBP:
      return X86_REG_RBP;
    case X86_REG_SIL:
    case X86_REG_SI:
    case X86_REG_ESI:
      return X86_REG_RSI;
    case X86_REG_DIL:
    case X86_REG_DI:
    case X86_REG_EDI:
      return X86_REG_RDI;
    case X86_REG_R8B:
    case X86_REG_R8W:
    case X86_REG_R8D:
      return X86_REG_R8;
    case X86_REG_R9B:
    case X86_REG_R9W:
    case X86_REG_R9D:
      return X86_REG_R9;
    case X86_REG_R10B:
    case X86_REG_R10W:
    case X86_REG_R10D:
      return X86_REG_R10;
    case X86_REG_R11B:
    case X86_REG_R11W:
    case X86_REG_R11D:
      return X86_REG_R11;
    case X86_REG_R12B:
    case X86_REG_R12W:
    case X86_REG_R12D:
      return X86_REG_R12;
    case X86_REG_R13B:
    case X86_REG_R13W:
    case X86_REG_R13D:
      return X86_REG_R13;
    case X86_REG_R14B:
    case X86_REG_R14W:
    case X86_REG_R14D:
      return X86_REG_R14;
    case X86_REG_R15B:
    case X86_REG_R15W:
    case X86_REG_R15D:
      return X86_REG_R15;
    default:
      return r;
  }
}

bool is_junk(int id) {
  switch (id) {
    case X86_INS_NOP:
    case X86_INS_FNOP:
    case X86_INS_CMP:
    case X86_INS_TEST:
    case X86_INS_BT:
    case X86_INS_CLC:
    case X86_INS_STC:
    case X86_INS_CLD:
    case X86_INS_STD:
    case X86_INS_LAHF:
    case X86_INS_SAHF:
    case X86_INS_CWDE:
    case X86_INS_CDQE:
      return true;
    default:
      return false;
  }
}

std::uint8_t width_from_size(std::uint8_t sz) {
  if (sz >= 8) return 4;
  if (sz == 0) return 4;
  return sz > 4 ? 4 : sz;
}

bool mix_from_insn(const cs_insn& in, int dest_ext, MixOp& out) {
  if (!in.detail) return false;
  const cs_x86& x = in.detail->x86;
  if (x.op_count < 1) return false;
  if (x.operands[0].type != X86_OP_REG) return false;
  if (extend_reg(x.operands[0].reg) != dest_ext) return false;

  out.width = width_from_size(static_cast<std::uint8_t>(x.operands[0].size));
  out.imm = 0;

  switch (in.id) {
    case X86_INS_NOT:
      out.kind = MixKind::Not;
      return true;
    case X86_INS_NEG:
      out.kind = MixKind::Neg;
      return true;
    case X86_INS_INC:
      out.kind = MixKind::Inc;
      return true;
    case X86_INS_DEC:
      out.kind = MixKind::Dec;
      return true;
    case X86_INS_BSWAP:
      out.kind = MixKind::Bswap;
      return true;
    case X86_INS_ADD:
    case X86_INS_SUB:
    case X86_INS_XOR:
    case X86_INS_ROL:
    case X86_INS_ROR:
    case X86_INS_SHL:
    case X86_INS_SHR:
      if (x.op_count < 2 || x.operands[1].type != X86_OP_IMM) return false;
      out.imm = static_cast<std::uint32_t>(x.operands[1].imm);
      if (in.id == X86_INS_ADD) out.kind = MixKind::Add;
      else if (in.id == X86_INS_SUB) out.kind = MixKind::Sub;
      else if (in.id == X86_INS_XOR) out.kind = MixKind::XorImm;
      else if (in.id == X86_INS_ROL || in.id == X86_INS_SHL) out.kind = MixKind::Rol;
      else out.kind = MixKind::Ror;
      return true;
    default:
      return false;
  }
}

bool writes_dest(const cs_insn& in, int dest_ext) {
  if (!in.detail) return false;
  for (std::uint8_t i = 0; i < in.detail->regs_write_count; i++) {
    if (extend_reg(in.detail->regs_write[i]) == dest_ext) return true;
  }
  const cs_x86& x = in.detail->x86;
  if (x.op_count && x.operands[0].type == X86_OP_REG &&
      extend_reg(x.operands[0].reg) == dest_ext) {
    switch (in.id) {
      case X86_INS_MOV:
      case X86_INS_MOVABS:
      case X86_INS_MOVZX:
      case X86_INS_MOVSX:
      case X86_INS_MOVSXD:
      case X86_INS_LEA:
      case X86_INS_XCHG:
      case X86_INS_POP:
        return true;
      default:
        break;
    }
  }
  return false;
}

std::vector<MixOp> extract_from_cs(cs_insn* insns, std::size_t n) {
  std::vector<MixOp> best;
  for (std::size_t i = 0; i < n; i++) {
    const cs_insn& pro = insns[i];
    if (pro.id != X86_INS_XOR || !pro.detail) continue;
    const cs_x86& px = pro.detail->x86;
    if (px.op_count != 2) continue;
    if (px.operands[0].type != X86_OP_REG || px.operands[1].type != X86_OP_REG) continue;
    const int dest = extend_reg(px.operands[0].reg);
    const int key = extend_reg(px.operands[1].reg);
    if (dest == key || dest == X86_REG_RSP || key == X86_REG_RSP) continue;

    std::vector<MixOp> cur;
    bool ok = false;
    for (std::size_t j = i + 1; j < n; j++) {
      const cs_insn& in = insns[j];
      if (in.id == X86_INS_XOR && in.detail) {
        const cs_x86& x = in.detail->x86;
        if (x.op_count == 2 && x.operands[0].type == X86_OP_REG &&
            x.operands[1].type == X86_OP_REG &&
            extend_reg(x.operands[0].reg) == key &&
            extend_reg(x.operands[1].reg) == dest) {
          ok = true;
          break;
        }
        if (x.op_count == 2 && x.operands[0].type == X86_OP_MEM &&
            x.operands[1].type == X86_OP_REG &&
            x.operands[0].mem.base == X86_REG_RSP && x.operands[0].mem.disp == 0 &&
            extend_reg(x.operands[1].reg) == dest) {
          ok = true;
          break;
        }
      }
      MixOp op{};
      if (mix_from_insn(in, dest, op)) {
        cur.push_back(op);
        continue;
      }
      if (is_junk(in.id)) continue;
      if (writes_dest(in, dest)) {
        ok = false;
        break;
      }
    }
    if (ok && cur.size() >= best.size()) best = std::move(cur);
  }
  return best;
}

}

std::uint32_t RollingKey::apply_mixer(std::uint32_t value, const std::vector<MixOp>& mixer) {
  for (const auto& op : mixer) {
    const std::uint32_t m = mask32(op.width);
    value &= m;
    switch (op.kind) {
      case MixKind::Add:
        value = (value + op.imm) & m;
        break;
      case MixKind::Sub:
        value = (value - op.imm) & m;
        break;
      case MixKind::XorImm:
        value = (value ^ op.imm) & m;
        break;
      case MixKind::Not:
        value = (~value) & m;
        break;
      case MixKind::Neg:
        value = (0u - value) & m;
        break;
      case MixKind::Inc:
        value = (value + 1u) & m;
        break;
      case MixKind::Dec:
        value = (value - 1u) & m;
        break;
      case MixKind::Rol:
        value = rotl(value, op.imm, op.width);
        break;
      case MixKind::Ror:
        value = rotr(value, op.imm, op.width);
        break;
      case MixKind::Bswap:
        if (op.width >= 4) {
          value = ((value & 0x000000FFu) << 24) | ((value & 0x0000FF00u) << 8) |
                  ((value & 0x00FF0000u) >> 8) | ((value & 0xFF000000u) >> 24);
        } else if (op.width == 2) {
          value = ((value & 0xFFu) << 8) | ((value >> 8) & 0xFFu);
        }
        value &= m;
        break;
    }
  }
  return value;
}

std::uint32_t RollingKey::decrypt_u32(std::uint32_t enc) {
  // xor, mix, then key ^= plain. same skeleton as novmp rkey.hpp
  const std::uint32_t k = static_cast<std::uint32_t>(key_);
  std::uint32_t v = enc ^ k;
  v = apply_mixer(v, mixer_);
  key_ ^= v;
  return v;
}

std::uint64_t RollingKey::decrypt_ptr(std::uint64_t enc, std::uint64_t image_base) {
  auto lo = decrypt_u32(static_cast<std::uint32_t>(enc & 0xFFFFFFFFu));
  auto hi = decrypt_u32(static_cast<std::uint32_t>(enc >> 32));
  auto val = (static_cast<std::uint64_t>(hi) << 32) | lo;
  if (val < 0x10000) return image_base + val;
  return val;
}

std::vector<MixOp> RollingKey::extract_mixer(const std::uint8_t* bytes, std::size_t n) {
  if (!bytes || n < 4) return {};
  csh h = 0;
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) != CS_ERR_OK) return {};
  cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
  cs_insn* insns = nullptr;
  const std::size_t count = cs_disasm(h, bytes, n, 0, 0, &insns);
  std::vector<MixOp> out;
  if (count && insns) {
    out = extract_from_cs(insns, count);
    cs_free(insns, count);
  }
  cs_close(&h);
  return out;
}

std::vector<MixOp> RollingKey::extract_mixer(const std::vector<RawInsn>& insns) {
  std::vector<std::uint8_t> buf;
  buf.reserve(insns.size() * 8);
  for (const auto& in : insns) {
    if (!in.size) continue;
    buf.insert(buf.end(), in.bytes, in.bytes + in.size);
    if (buf.size() > 0x400) break;
  }
  return extract_mixer(buf.data(), buf.size());
}

std::vector<std::uint32_t> RollingKey::vip_decrypt_guesses(std::uint32_t enc,
                                                           std::uint64_t key) {
  const std::uint32_t k32 = static_cast<std::uint32_t>(key);
  const std::uint32_t khi = static_cast<std::uint32_t>(key >> 32);
  return {
      enc ^ k32,
      enc - k32,
      enc + k32,
      enc ^ khi,
      static_cast<std::uint32_t>(enc ^ key),
  };
}

std::optional<std::uint32_t> RollingKey::guess_seed_from_handler_tail(
    const std::vector<std::uint8_t>& tail) {
  (void)tail;
  return std::nullopt;
}

}
