#include "handler_classify.hpp"

#include "dispatch_resolver.hpp"
#include "l4_recover.hpp"
#include "semantic_peel.hpp"
#include "util.hpp"

#include <algorithm>
#include <sstream>
#include <string>

namespace vmp {

namespace {

struct Counts {
  int push = 0, pop = 0, pushfq = 0, popfq = 0;
  int add = 0, sub = 0, xor_ = 0, and_ = 0, or_ = 0, not_ = 0, neg = 0;
  int shl = 0, shr = 0, rol = 0, ror = 0, bswap = 0;
  int mov = 0, lea = 0, xchg = 0;
  int jmp = 0, call = 0, ret = 0;
  int mem = 0;
  int total = 0;
};

Counts count_insns(const HandlerBlock& blk) {
  Counts c;
  c.total = static_cast<int>(blk.insns.size());
  for (const auto& in : blk.insns) {
    const auto& m = in.mnemonic;
    if (m == "push") c.push++;
    else if (m == "pop") c.pop++;
    else if (m == "pushfq") c.pushfq++;
    else if (m == "popfq") c.popfq++;
    else if (m == "add" || m == "adc") c.add++;
    else if (m == "sub" || m == "sbb") c.sub++;
    else if (m == "xor") c.xor_++;
    else if (m == "and") c.and_++;
    else if (m == "or") c.or_++;
    else if (m == "not") c.not_++;
    else if (m == "neg") c.neg++;
    else if (m == "shl" || m == "sal") c.shl++;
    else if (m == "shr" || m == "sar") c.shr++;
    else if (m == "rol") c.rol++;
    else if (m == "ror") c.ror++;
    else if (m == "bswap") c.bswap++;
    else if (m == "mov" || m == "movabs" || m == "movzx" || m == "movsx" || m == "movsxd")
      c.mov++;
    else if (m == "lea") c.lea++;
    else if (m == "xchg") c.xchg++;
    else if (m == "jmp") c.jmp++;
    else if (m == "call") c.call++;
    else if (m == "ret" || m == "retn" || m == "retf") c.ret++;

    if (in.op_str.find('[') != std::string::npos) c.mem++;
  }
  return c;
}

}

std::string vmop_name(VmOpKind k) {
  switch (k) {
    case VmOpKind::VmEnter:
      return "vmenter";
    case VmOpKind::VmExit:
      return "vmexit";
    case VmOpKind::CalcJmp:
      return "calc_jmp";
    case VmOpKind::FetchImm:
      return "fetch";
    case VmOpKind::Push:
      return "push";
    case VmOpKind::Pop:
      return "pop";
    case VmOpKind::Add:
      return "add";
    case VmOpKind::Sub:
      return "sub";
    case VmOpKind::Xor:
      return "xor";
    case VmOpKind::And:
      return "and";
    case VmOpKind::Or:
      return "or";
    case VmOpKind::Nor:
      return "nor";
    case VmOpKind::Shl:
      return "shl";
    case VmOpKind::Shr:
      return "shr";
    case VmOpKind::Not:
      return "not";
    case VmOpKind::Neg:
      return "neg";
    case VmOpKind::Load:
      return "load";
    case VmOpKind::Store:
      return "store";
    case VmOpKind::Mov:
      return "mov";
    case VmOpKind::Flags:
      return "flags";
    default:
      return "unk";
  }
}

ClassifiedHandler classify_handler(const HandlerBlock& blk) {
  ClassifiedHandler out;
  out.va = blk.entry_va;
  out.insn_count = blk.insns.size();
  auto c = count_insns(blk);

  const bool xfer_stop = blk.stop_reason == "jmp_reg" || blk.stop_reason == "unicorn" ||
                         blk.stop_reason == "xfer" || blk.stop_reason == "tail_jmp" ||
                         blk.stop_reason == "tail_call" || blk.next_handler_va.has_value();

  if ((blk.is_exit || c.ret > 0) && !xfer_stop && (c.pop >= 4 || c.popfq || blk.is_exit)) {
    out.kind = VmOpKind::VmExit;
    out.confidence = blk.is_exit ? 90 : 75;
    out.why = "ret/vmexit";
  } else if (c.push >= 6 && c.pushfq >= 1 && c.total < 40) {
    out.kind = VmOpKind::VmEnter;
    out.confidence = 85;
    out.why = "push storm + pushfq";
  } else if (xfer_stop && (c.xor_ >= 2 || c.rol + c.ror + c.bswap + c.neg + c.not_ >= 1)) {
    out.kind = VmOpKind::CalcJmp;
    out.confidence = 75;
    out.why = "xfer+decrypt";
  } else if (xfer_stop) {
    out.kind = VmOpKind::CalcJmp;
    out.confidence = 55;
    out.why = "has next edge";
  } else if (c.pushfq || c.popfq) {
    out.kind = VmOpKind::Flags;
    out.confidence = 60;
    out.why = "flags xfer";
  } else if ((c.not_ >= 1 && c.and_ >= 1) || (c.not_ >= 2 && c.and_ >= 1)) {

    out.kind = VmOpKind::Nor;
    out.confidence = 65;
    out.why = "not+and (~nor)";
  } else if (c.add >= 2 && c.add + c.sub >= c.xor_) {
    out.kind = VmOpKind::Add;
    out.confidence = 55;
    out.why = "add-heavy";
  } else if (c.sub >= 2) {
    out.kind = VmOpKind::Sub;
    out.confidence = 50;
    out.why = "sub-heavy";
  } else if (c.xor_ >= 3 && (c.rol + c.ror + c.bswap + c.neg + c.not_) >= 2) {

    out.kind = VmOpKind::CalcJmp;
    out.confidence = 70;
    out.why = "xor+transforms (fdj-ish)";
  } else if (c.xor_ >= 2 && c.mem >= 1) {
    out.kind = VmOpKind::Xor;
    out.confidence = 45;
    out.why = "xor+mem";
  } else if (c.and_ >= 2) {
    out.kind = VmOpKind::And;
    out.confidence = 45;
    out.why = "and-heavy";
  } else if (c.or_ >= 2) {
    out.kind = VmOpKind::Or;
    out.confidence = 45;
    out.why = "or-heavy";
  } else if (c.shl + c.shr >= 2) {
    out.kind = (c.shl >= c.shr) ? VmOpKind::Shl : VmOpKind::Shr;
    out.confidence = 50;
    out.why = "shift";
  } else if (c.push >= 2 && c.pop == 0 && c.mem <= 2) {
    out.kind = VmOpKind::Push;
    out.confidence = 40;
    out.why = "pushes";
  } else if (c.pop >= 2 && c.push == 0) {
    out.kind = VmOpKind::Pop;
    out.confidence = 40;
    out.why = "pops";
  } else if (c.mem >= 3 && c.mov >= 2) {
    out.kind = VmOpKind::Load;
    out.confidence = 35;
    out.why = "mem heavy";
  } else if (c.mov + c.lea >= 3) {
    out.kind = VmOpKind::Mov;
    out.confidence = 30;
    out.why = "mov/lea";
  } else if (c.ret > 0 && !xfer_stop) {
    out.kind = VmOpKind::VmExit;
    out.confidence = 50;
    out.why = "lonely ret";
  } else {
    out.kind = VmOpKind::Unknown;
    out.confidence = 10;
    out.why = "no pattern";
  }

  out.name = vmop_name(out.kind);
  return out;
}

DevirtResult run_devirt(const PeImage& image, std::uint64_t vmenter_va,
                        const std::vector<HandlerBlock>& blocks, std::size_t max_vip_steps) {
  DevirtResult res;

  auto sem = unicorn_semantic_trace(image, vmenter_va, max_vip_steps, 4096);
  res.vip = sem.vip;

    if (!sem.effects.empty()) {
    if (sem.vip.rolling_key) res.vip.rolling_key = sem.vip.rolling_key;

    for (std::size_t i = 0; i < sem.effects.size(); i++) {
      auto e = sem.effects[i];
      peel_effect(e);

      DevirtOp op;
      op.index = i;
      op.handler_va = e.handler_va;
      op.vip = e.vip_after ? e.vip_after : e.vip_before;
      op.next = e.next_handler;
      op.kind = e.kind;
      op.confidence = e.confidence;
      op.mnemonic = vmop_name(e.kind);
      op.comment = e.why;
      op.semantic = true;
      if (!e.fetches.empty()) {
        op.fetch_enc = static_cast<std::uint32_t>(e.fetches.back().enc);
        if (e.fetches.back().decrypted) op.fetch_dec = e.fetches.back().dec;
      }

      if (e.pushed_imm) op.fetch_dec = *e.pushed_imm;

      if (op.kind == VmOpKind::Unknown) {
        DispatchResolver dr(image);
        auto blk = dr.lift_block(e.handler_va, 256);
        if (e.next_handler) {
          blk.next_handler_va = e.next_handler;
          blk.stop_reason = "xfer";
          blk.is_exit = false;
        }
        auto cl = classify_handler(blk);
        if (cl.kind != VmOpKind::Unknown && cl.kind != VmOpKind::CalcJmp) {
          op.kind = cl.kind;
          op.confidence = cl.confidence;
          op.mnemonic = cl.name;
          op.comment = cl.why + "+mn";
          op.semantic = false;
        }
      }

      ClassifiedHandler ch;
      ch.va = op.handler_va;
      ch.kind = op.kind;
      ch.name = op.mnemonic;
      ch.confidence = op.confidence;
      ch.why = op.comment;
      res.handlers.push_back(ch);
      if (op.kind == VmOpKind::Unknown) res.unknown++;
      else res.classified++;
      res.stream.push_back(op);
    }
  } else if (!res.vip.steps.empty()) {

    res.vip = unicorn_vip_trace(image, vmenter_va, max_vip_steps, 4096);
    for (std::size_t i = 0; i < res.vip.steps.size(); i++) {
      const auto& s = res.vip.steps[i];
      DevirtOp op;
      op.index = i;
      op.handler_va = s.handler_va;
      op.vip = s.vip;
      op.fetch_enc = s.fetched_enc;
      op.next = s.next_handler;
      op.comment = s.note;
      DispatchResolver dr(image);
      auto blk = dr.lift_block(s.handler_va, 256);
      if (s.next_handler) {
        blk.next_handler_va = s.next_handler;
        blk.stop_reason = "xfer";
        blk.is_exit = false;
      }
      auto cl = classify_handler(blk);
      op.kind = cl.kind;
      op.confidence = cl.confidence;
      op.mnemonic = cl.name;
      res.handlers.push_back(cl);
      if (cl.kind == VmOpKind::Unknown) res.unknown++;
      else res.classified++;
      res.stream.push_back(op);
    }
  } else {
    for (const auto& b : blocks) {
      auto cl = classify_handler(b);
      res.handlers.push_back(cl);
      if (cl.kind == VmOpKind::Unknown) res.unknown++;
      else res.classified++;
    }
    for (std::size_t i = 0; i < blocks.size(); i++) {
      const auto& cl = res.handlers[i];
      DevirtOp op;
      op.index = i;
      op.handler_va = cl.va;
      op.kind = cl.kind;
      op.mnemonic = cl.name;
      op.confidence = cl.confidence;
      op.comment = cl.why;
      op.next = blocks[i].next_handler_va;
      res.stream.push_back(op);
    }
  }

  std::ostringstream vasm;
  vasm << "; stream\n";
  vasm << "; vmenter " << hex_u64(vmenter_va) << " vip_seed=" << res.vip.seed.note;
  if (!sem.key_reg.empty()) vasm << " key_reg=" << sem.key_reg;
  if (!sem.vip_reg.empty()) vasm << " vip_reg=" << sem.vip_reg;
  if (!sem.vsp_reg.empty()) vasm << " vsp_reg=" << sem.vsp_reg;
  vasm << "\n; steps=" << res.stream.size() << " classified=" << res.classified
       << " unknown=" << res.unknown << " key=" << hex_u64(res.vip.rolling_key) << "\n\n";
  for (const auto& op : res.stream) {
    vasm << "  " << op.mnemonic;
    if (op.fetch_dec) vasm << "  imm=" << hex_u64(*op.fetch_dec);
    else if (op.fetch_enc) vasm << "  ; enc=" << hex_u64(op.fetch_enc);
    if (op.vip) vasm << " vip=" << hex_u64(op.vip);
    vasm << "  @" << hex_u64(op.handler_va);
    if (op.confidence) vasm << "  conf=" << op.confidence;
    if (op.semantic) vasm << "  [sem]";
    if (!op.comment.empty()) vasm << "  ; " << op.comment;
    vasm << "\n";
    if (op.next) vasm << "       -> " << hex_u64(*op.next) << "\n";
  }
  res.vasm = vasm.str();

  std::ostringstream nat;
  nat << "void recovered(void) {\n";
  nat << "  uint64_t vsp[512]; int top = 0;\n";
  for (const auto& op : res.stream) {
    switch (op.kind) {
      case VmOpKind::VmEnter:
        break;
      case VmOpKind::VmExit:
        nat << "  return;\n";
        break;
      case VmOpKind::CalcJmp:
      case VmOpKind::Mov:
        break;
      case VmOpKind::FetchImm:
      case VmOpKind::Push: {
        if (op.fetch_dec) {
          nat << "  vsp[top++] = " << hex_u64(*op.fetch_dec) << "ull;\n";
        } else if (op.fetch_enc) {
          nat << "  vsp[top++] = " << hex_u64(op.fetch_enc) << "ull;\n";
        } else {
          nat << "  vsp[top++] = 0;\n";
        }
        break;
      }
      case VmOpKind::Add:
        nat << "  vsp[top-2] += vsp[top-1]; --top;\n";
        break;
      case VmOpKind::Sub:
        nat << "  vsp[top-2] -= vsp[top-1]; --top;\n";
        break;
      case VmOpKind::Xor:
        if (op.fetch_dec) {
          nat << "  vsp[top-1] ^= " << hex_u64(*op.fetch_dec) << "ull;\n";
        } else {
          nat << "  vsp[top-2] ^= vsp[top-1]; --top;\n";
        }
        break;
      case VmOpKind::And:
        nat << "  vsp[top-2] &= vsp[top-1]; --top;\n";
        break;
      case VmOpKind::Or:
        nat << "  vsp[top-2] |= vsp[top-1]; --top;\n";
        break;
      case VmOpKind::Nor:
        nat << "  vsp[top-2] = ~(vsp[top-2] | vsp[top-1]); --top;\n";
        break;
      case VmOpKind::Shl:
        if (op.fetch_dec) {
          nat << "  vsp[top-1] <<= (" << hex_u64(*op.fetch_dec) << "ull & 63);\n";
        } else {
          nat << "  vsp[top-2] <<= (vsp[top-1] & 63); --top;\n";
        }
        break;
      case VmOpKind::Shr:
        nat << "  vsp[top-2] >>= (vsp[top-1] & 63); --top;\n";
        break;
      case VmOpKind::Not:
        nat << "  vsp[top-1] = ~vsp[top-1];\n";
        break;
      case VmOpKind::Neg:
        nat << "  vsp[top-1] = (uint64_t)-(int64_t)vsp[top-1];\n";
        break;
      case VmOpKind::Pop:
        nat << "  --top;\n";
        break;
      case VmOpKind::Load:
        nat << "  vsp[top-1] = *(uint64_t*)vsp[top-1];\n";
        break;
      case VmOpKind::Store:
        nat << "  *(uint64_t*)vsp[top-1] = vsp[top-2]; top -= 2;\n";
        break;
      case VmOpKind::Flags:
        break;
      default:
        break;
    }
  }
  nat << "}\n";
  res.native_pseudo = nat.str();

  auto l4 = recover_l4(image, vmenter_va, res);
  res.native_l4 = std::move(l4.c_source);
  res.l4_summary = std::move(l4.summary);

  return res;
}

}
