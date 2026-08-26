#pragma once

#include "ir_lifter.hpp"

namespace vmp {

class IrOptimizer {
public:
  IrFunction optimize(IrFunction fn) const;

private:
  void fold_constants(IrFunction& fn) const;
  void remove_identity_ops(IrFunction& fn) const;
  void remove_dead(IrFunction& fn) const;
};

}
