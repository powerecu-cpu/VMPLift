#include "ir_optimizer.hpp"

#include <unordered_set>

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
      if (op.name.rfind("0x", 0) == 0) {
        try {
          op.constant = static_cast<std::int64_t>(std::stoull(op.name.substr(2), nullptr, 16));
        } catch (...) {
        }
      }
    }
  }
}

void IrOptimizer::remove_identity_ops(IrFunction& fn) const {
  std::vector<IrInst> kept;
  kept.reserve(fn.blocks.size());
  for (const auto& inst : fn.blocks) {
    if (inst.op == IrOp::Unknown && inst.mnemonic == "nop") {
      continue;
    }
    kept.push_back(inst);
  }
  fn.blocks = std::move(kept);
}

void IrOptimizer::remove_dead(IrFunction& fn) const {
  std::unordered_set<std::string> live;
  for (auto it = fn.blocks.rbegin(); it != fn.blocks.rend(); ++it) {
    if (it->op == IrOp::Branch || it->op == IrOp::Ret || it->op == IrOp::Call) {
      for (const auto& op : it->operands) {
        live.insert(op.name);
      }
    }
    for (const auto& r : it->results) {
      if (live.count(r.name)) {
        for (const auto& op : it->operands) {
          live.insert(op.name);
        }
      }
    }
  }

  std::vector<IrInst> kept;
  for (const auto& inst : fn.blocks) {
    if (inst.op == IrOp::Mov || inst.op == IrOp::Add || inst.op == IrOp::Xor) {
      if (!inst.results.empty() && !live.count(inst.results[0].name)) {
        continue;
      }
    }
    kept.push_back(inst);
  }
  fn.blocks = std::move(kept);
}

}
