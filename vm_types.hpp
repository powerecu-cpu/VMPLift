#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace vmp {

struct RawInsn {
  std::uint64_t va = 0;
  std::string mnemonic;
  std::string op_str;
  std::uint8_t bytes[16]{};
  std::size_t size = 0;
  bool is_branch = false;
  bool is_call = false;
  bool is_ret = false;
  bool is_reg_branch = false;
  bool has_imm = false;
  bool rip_rel = false;
  std::uint64_t branch_target = 0;
  std::uint64_t lea_target = 0;
  std::int64_t imm = 0;
  std::string branch_reg;
};

struct HandlerBlock {
  std::uint64_t entry_va = 0;
  std::vector<RawInsn> insns;
  std::optional<std::uint64_t> next_handler_va;
  std::vector<std::uint64_t> branch_targets;
  bool is_exit = false;
  std::string stop_reason;
};

struct WalkResult {
  std::uint64_t start_va = 0;
  std::vector<HandlerBlock> handlers;
  std::size_t truncated = 0;
};

}
