#pragma once

#include "handler_classify.hpp"
#include "handler_walker.hpp"
#include "vm_types.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace vmp {

enum class IrOp {
  Invalid,
  Load,
  Store,
  Mov,
  Xor,
  Add,
  Sub,
  And,
  Or,
  Nor,
  Not,
  Neg,
  Shl,
  Shr,
  Cmp,
  Branch,
  Call,
  Ret,
  Phi,
  Unknown,
};

struct IrValue {
  std::string name;
  std::string type = "i64";
  std::optional<std::int64_t> constant;
};

struct IrInst {
  std::uint64_t source_va = 0;
  IrOp op = IrOp::Invalid;
  std::string mnemonic;
  std::vector<IrValue> operands;
  std::vector<IrValue> results;
  std::string comment;
};

struct IrFunction {
  std::string name;
  std::uint64_t entry_va = 0;
  std::vector<IrInst> blocks;
  bool stack_machine = false;
};

class IrLifter {
public:
  IrFunction lift_handler(const HandlerBlock& handler, int index) const;
  IrFunction lift_vm_stream(const std::vector<DevirtOp>& ops, std::uint64_t entry) const;
  std::string emit_llvm_text(const IrFunction& fn) const;
  std::string emit_pseudo_c(const IrFunction& fn) const;

private:
  mutable int temp_ = 0;
  std::string fresh_temp() const;
  IrOp map_mnemonic(const std::string& mnemonic) const;
  IrInst lift_insn(const RawInsn& insn) const;
};

}
