#pragma once

#include "vm_types.hpp"
#include "vip_context.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace vmp {

enum class VmOpKind {
  Unknown,
  VmEnter,
  VmExit,
  CalcJmp,
  FetchImm,
  Push,
  Pop,
  Add,
  Sub,
  Xor,
  And,
  Or,
  Nor,
  Shl,
  Shr,
  Not,
  Neg,
  Load,
  Store,
  Mov,
  Flags,
};

struct ClassifiedHandler {
  std::uint64_t va = 0;
  VmOpKind kind = VmOpKind::Unknown;
  std::string name;
  int confidence = 0;
  std::string why;
  std::size_t insn_count = 0;
};

struct DevirtOp {
  std::size_t index = 0;
  std::uint64_t handler_va = 0;
  VmOpKind kind = VmOpKind::Unknown;
  std::string mnemonic;
  std::uint64_t vip = 0;
  std::uint32_t fetch_enc = 0;
  std::optional<std::uint64_t> fetch_dec;
  std::optional<std::uint64_t> next;
  int confidence = 0;
  std::string comment;
  bool semantic = false;
};

struct DevirtResult {
  std::vector<ClassifiedHandler> handlers;
  std::vector<DevirtOp> stream;
  VipTrace vip;
  std::string vasm;
  std::string native_pseudo;
  std::string native_l4;
  std::string l4_summary;
  std::size_t classified = 0;
  std::size_t unknown = 0;
};

ClassifiedHandler classify_handler(const HandlerBlock& blk);
std::string vmop_name(VmOpKind k);

DevirtResult run_devirt(const PeImage& image, std::uint64_t vmenter_va,
                        const std::vector<HandlerBlock>& blocks,
                        std::size_t max_vip_steps = 64);

}
