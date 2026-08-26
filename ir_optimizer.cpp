#include "ir_optimizer.hpp"

namespace vmp {

IrFunction IrOptimizer::optimize(IrFunction fn) const {
  fold_constants(fn);
  remove_identity_ops(fn);
  remove_dead(fn);
  return fn;
}

void IrOptimizer::fold_constants(IrFunction& fn) const {
  for (auto& inst : fn.blocks) {
    for (auto& op : inst.operands) {
      if (op.constant) continue;
      if (op.name.rfind("0x", 0) == 0) {
        try {
          op.constant = static_cast<std::int64_t>(std::stoull(op.name.substr(2), nullptr, 16));
        } catch (...) {
        }
      }
    }
    if (inst.operands.size() < 2 || !inst.operands[0].constant || !inst.operands[1].constant)
      continue;
    if (inst.op == IrOp::Add) {
      inst.operands[0].constant = *inst.operands[0].constant + *inst.operands[1].constant;
      inst.op = IrOp::Mov;
      inst.operands.resize(1);
    } else if (inst.op == IrOp::Xor) {
      inst.operands[0].constant = *inst.operands[0].constant ^ *inst.operands[1].constant;
      inst.op = IrOp::Mov;
      inst.operands.resize(1);
    }
  }
}

void IrOptimizer::remove_identity_ops(IrFunction& fn) const {
  std::vector<IrInst> kept;
  for (const auto& inst : fn.blocks) {
    if (inst.op == IrOp::Unknown && inst.mnemonic == "nop") continue;
    if (inst.op == IrOp::Xor && inst.operands.size() >= 2 && inst.operands[1].constant &&
        *inst.operands[1].constant == 0)
      continue;
    if (inst.op == IrOp::Add && inst.operands.size() >= 2 && inst.operands[1].constant &&
        *inst.operands[1].constant == 0)
      continue;
    kept.push_back(inst);
  }
  fn.blocks = std::move(kept);
}

void IrOptimizer::remove_dead(IrFunction& fn) const {
  if (fn.stack_machine) return;
  std::vector<IrInst> kept;
  for (const auto& inst : fn.blocks) {
    if (inst.op == IrOp::Unknown && inst.mnemonic.empty()) continue;
    kept.push_back(inst);
  }
  fn.blocks = std::move(kept);
}

}
