#include "ir_lifter.hpp"

#include "util.hpp"

#include <sstream>
#include <unordered_map>

namespace vmp {

std::string IrLifter::fresh_temp() const {
  return "%t" + std::to_string(temp_++);
}

IrOp IrLifter::map_mnemonic(const std::string& m) const {
  static const std::unordered_map<std::string, IrOp> tbl = {
      {"mov", IrOp::Mov},   {"movabs", IrOp::Mov}, {"lea", IrOp::Mov},   {"xor", IrOp::Xor},
      {"add", IrOp::Add},   {"sub", IrOp::Sub},    {"and", IrOp::And},   {"or", IrOp::Or},
      {"shl", IrOp::Shl},   {"shr", IrOp::Shr},    {"sar", IrOp::Shr},   {"cmp", IrOp::Cmp},
      {"test", IrOp::Cmp},  {"call", IrOp::Call},  {"ret", IrOp::Ret},   {"jmp", IrOp::Branch},
      {"pop", IrOp::Load},  {"push", IrOp::Store},
  };
  auto it = tbl.find(m);
  if (it == tbl.end()) {
    return IrOp::Unknown;
  }
  return it->second;
}

IrInst IrLifter::lift_insn(const RawInsn& in) const {
  IrInst out;
  out.source_va = in.va;
  out.mnemonic = in.mnemonic;
  out.op = map_mnemonic(in.mnemonic);
  out.comment = in.op_str;

  IrValue dst;
  dst.name = fresh_temp();
  out.results.push_back(dst);

  IrValue src;
  src.name = in.op_str.empty() ? "?" : in.op_str;
  out.operands.push_back(src);

  if (in.branch_target != 0) {
    IrValue tgt;
    tgt.name = hex_u64(in.branch_target);
    tgt.constant = static_cast<std::int64_t>(in.branch_target);
    out.operands.push_back(tgt);
  }

  return out;
}

IrFunction IrLifter::lift_handler(const HandlerBlock& hb, int index) const {
  IrFunction fn;
  fn.entry_va = hb.entry_va;
  fn.name = "handler_" + std::to_string(index) + "_" + hex_u64(hb.entry_va, false);

  for (const auto& in : hb.insns) {
    fn.blocks.push_back(lift_insn(in));
  }

  if (hb.next_handler_va) {
    IrInst edge;
    edge.op = IrOp::Branch;
    edge.mnemonic = "vm_next";
    edge.comment = "next";
    IrValue tgt;
    tgt.name = hex_u64(*hb.next_handler_va);
    tgt.constant = static_cast<std::int64_t>(*hb.next_handler_va);
    edge.operands.push_back(tgt);
    fn.blocks.push_back(edge);
  }

  if (hb.is_exit) {
    IrInst x;
    x.op = IrOp::Ret;
    x.mnemonic = "vmexit";
    fn.blocks.push_back(x);
  }

  return fn;
}

std::string IrLifter::emit_llvm_text(const IrFunction& fn) const {
  std::ostringstream oss;
  oss << "; " << hex_u64(fn.entry_va) << "\n";
  oss << "define i64 @" << fn.name << "() {\n";
  oss << "entry:\n";

  for (const auto& inst : fn.blocks) {
    oss << "  ; " << hex_u64(inst.source_va) << " " << inst.mnemonic;
    if (!inst.comment.empty()) {
      oss << " " << inst.comment;
    }
    oss << "\n";

    switch (inst.op) {
      case IrOp::Mov:
      case IrOp::Xor:
      case IrOp::Add:
      case IrOp::Sub:
      case IrOp::And:
      case IrOp::Or:
      case IrOp::Shl:
      case IrOp::Shr:
        if (!inst.results.empty()) {

          oss << "  " << inst.results[0].name << " = add i64 0, 0 ; " << inst.mnemonic << " "
              << inst.comment << "\n";
        }
        break;
      case IrOp::Branch:
        if (!inst.operands.empty()) {
          oss << "  br label %" << inst.operands[0].name << "\n";
        }
        break;
      case IrOp::Ret:
        oss << "  ret i64 0\n";
        break;
      default:
        oss << "  ; unlowered " << inst.mnemonic << "\n";
        break;
    }
  }

  oss << "}\n\n";
  return oss.str();
}

std::string IrLifter::emit_pseudo_c(const IrFunction& fn) const {
  std::ostringstream oss;
  oss << "// " << hex_u64(fn.entry_va) << "\n";
  oss << "void " << fn.name << "() {\n";
  for (const auto& inst : fn.blocks) {
    if (inst.op == IrOp::Branch && !inst.operands.empty()) {
      oss << "  goto " << inst.operands[0].name << ";\n";
      continue;
    }
    if (inst.op == IrOp::Ret) {
      oss << "  return;\n";
      continue;
    }
    if (inst.source_va != 0) {
      oss << "  // " << hex_u64(inst.source_va) << ": " << inst.mnemonic << " " << inst.comment
          << "\n";
    }
  }
  oss << "}\n\n";
  return oss.str();
}

}
