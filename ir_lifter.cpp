#include "ir_lifter.hpp"

#include "util.hpp"

#include <cctype>
#include <sstream>
#include <unordered_map>

namespace vmp {

namespace {

std::string trim(std::string s) {
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
  return s;
}

std::vector<std::string> split_operands(const std::string& s) {
  std::vector<std::string> out;
  std::string cur;
  int depth = 0;
  for (char c : s) {
    if (c == '[') depth++;
    if (c == ']' && depth) depth--;
    if (c == ',' && depth == 0) {
      auto t = trim(cur);
      if (!t.empty()) out.push_back(std::move(t));
      cur.clear();
    } else {
      cur.push_back(c);
    }
  }
  auto t = trim(cur);
  if (!t.empty()) out.push_back(std::move(t));
  return out;
}

std::string llvm_id(std::string s) {
  for (char& c : s) {
    if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '.') c = '_';
  }
  while (!s.empty() && s.front() == '_') s.erase(s.begin());
  if (s.empty() || std::isdigit(static_cast<unsigned char>(s.front()))) s = "v" + s;
  return s;
}

IrValue make_val(const std::string& raw) {
  IrValue v;
  auto t = trim(raw);
  v.name = llvm_id(t.empty() ? "unk" : t);
  if (t.size() > 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X')) {
    try {
      v.constant = static_cast<std::int64_t>(std::stoull(t, nullptr, 16));
    } catch (...) {
    }
  } else if (!t.empty() && (std::isdigit(static_cast<unsigned char>(t[0])) || t[0] == '-')) {
    try {
      v.constant = static_cast<std::int64_t>(std::stoll(t, nullptr, 0));
    } catch (...) {
    }
  }
  return v;
}

std::string llvm_operand(const IrValue& v) {
  if (v.constant) return std::to_string(*v.constant);
  if (!v.name.empty() && v.name[0] == '%') return v.name;
  return "%" + v.name;
}

IrOp kind_to_ir(VmOpKind k) {
  switch (k) {
    case VmOpKind::Add: return IrOp::Add;
    case VmOpKind::Sub: return IrOp::Sub;
    case VmOpKind::Xor: return IrOp::Xor;
    case VmOpKind::And: return IrOp::And;
    case VmOpKind::Or: return IrOp::Or;
    case VmOpKind::Nor: return IrOp::Nor; // not+and, recon slides
    case VmOpKind::Not: return IrOp::Not;
    case VmOpKind::Neg: return IrOp::Neg;
    case VmOpKind::Shl: return IrOp::Shl;
    case VmOpKind::Shr: return IrOp::Shr;
    case VmOpKind::Load:
    case VmOpKind::Pop: return IrOp::Load;
    case VmOpKind::Store:
    case VmOpKind::Push:
    case VmOpKind::FetchImm: return IrOp::Store;
    case VmOpKind::CalcJmp: return IrOp::Branch;
    case VmOpKind::VmExit: return IrOp::Ret;
    case VmOpKind::Mov: return IrOp::Mov;
    default: return IrOp::Unknown;
  }
}

}

std::string IrLifter::fresh_temp() const {
  return "%t" + std::to_string(temp_++);
}

IrOp IrLifter::map_mnemonic(const std::string& m) const {
  static const std::unordered_map<std::string, IrOp> tbl = {
      {"mov", IrOp::Mov},   {"movabs", IrOp::Mov}, {"lea", IrOp::Mov},   {"xor", IrOp::Xor},
      {"add", IrOp::Add},   {"adc", IrOp::Add},    {"sub", IrOp::Sub},   {"sbb", IrOp::Sub},
      {"and", IrOp::And},   {"or", IrOp::Or},      {"not", IrOp::Not},   {"neg", IrOp::Neg},
      {"shl", IrOp::Shl},   {"sal", IrOp::Shl},    {"shr", IrOp::Shr},   {"sar", IrOp::Shr},
      {"cmp", IrOp::Cmp},   {"test", IrOp::Cmp},   {"call", IrOp::Call}, {"ret", IrOp::Ret},
      {"jmp", IrOp::Branch},{"pop", IrOp::Load},   {"push", IrOp::Store},
  };
  auto it = tbl.find(m);
  return it == tbl.end() ? IrOp::Unknown : it->second;
}

IrInst IrLifter::lift_insn(const RawInsn& in) const {
  IrInst out;
  out.source_va = in.va;
  out.mnemonic = in.mnemonic;
  out.op = map_mnemonic(in.mnemonic);
  out.comment = in.op_str;

  auto parts = split_operands(in.op_str);
  for (const auto& p : parts) out.operands.push_back(make_val(p));

  if (!out.operands.empty() && out.op != IrOp::Store && out.op != IrOp::Cmp &&
      out.op != IrOp::Branch && out.op != IrOp::Call && out.op != IrOp::Ret) {
    IrValue dst = out.operands[0];
    dst.name = llvm_id(dst.name);
    out.results.push_back(dst);
  } else if (out.op != IrOp::Store && out.op != IrOp::Ret && out.op != IrOp::Branch) {
    IrValue dst;
    dst.name = fresh_temp();
    if (!dst.name.empty() && dst.name[0] == '%') dst.name.erase(dst.name.begin());
    out.results.push_back(dst);
  }

  if (in.branch_target != 0) {
    IrValue tgt;
    tgt.name = hex_u64(in.branch_target, false);
    tgt.constant = static_cast<std::int64_t>(in.branch_target);
    out.operands.push_back(tgt);
  }
  return out;
}

IrFunction IrLifter::lift_handler(const HandlerBlock& hb, int index) const {
  IrFunction fn;
  fn.entry_va = hb.entry_va;
  fn.name = "handler_" + std::to_string(index) + "_" + hex_u64(hb.entry_va, false);
  fn.stack_machine = false;

  for (const auto& in : hb.insns) fn.blocks.push_back(lift_insn(in));

  if (hb.next_handler_va) {
    IrInst edge;
    edge.op = IrOp::Branch;
    edge.mnemonic = "calc_jmp";
    edge.comment = "next handler";
    IrValue tgt;
    tgt.name = hex_u64(*hb.next_handler_va, false);
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

IrFunction IrLifter::lift_vm_stream(const std::vector<DevirtOp>& ops, std::uint64_t entry) const {
  IrFunction fn;
  fn.entry_va = entry;
  fn.name = "vm_trace_" + hex_u64(entry, false);
  fn.stack_machine = true;

  IrInst enter;
  enter.op = IrOp::Mov;
  enter.mnemonic = "vmenter";
  enter.source_va = entry;
  enter.comment = "push context, load vip/vsp/key";
  fn.blocks.push_back(enter);

  for (const auto& op : ops) {
    IrInst inst;
    inst.source_va = op.handler_va;
    inst.mnemonic = op.mnemonic;
    inst.comment = op.comment;
    inst.op = kind_to_ir(op.kind);
    if (op.fetch_dec) {
      IrValue imm;
      imm.name = "imm";
      imm.constant = static_cast<std::int64_t>(*op.fetch_dec);
      inst.operands.push_back(imm);
    } else if (op.fetch_enc) {
      IrValue enc;
      enc.name = "enc";
      enc.constant = static_cast<std::int64_t>(op.fetch_enc);
      inst.operands.push_back(enc);
      inst.comment += " encrypted vip word";
    }
    if (op.next) {
      IrValue nxt;
      nxt.name = hex_u64(*op.next, false);
      nxt.constant = static_cast<std::int64_t>(*op.next);
      inst.operands.push_back(nxt);
    }
    fn.blocks.push_back(inst);
  }
  return fn;
}

std::string IrLifter::emit_llvm_text(const IrFunction& fn) const {
  std::ostringstream oss;
  oss << "; " << hex_u64(fn.entry_va) << " " << (fn.stack_machine ? "stack" : "native")
      << "\n";
  oss << "define i64 @" << fn.name << "() {\n";
  oss << "entry:\n";

  if (fn.stack_machine) {
    std::vector<std::string> stk;
    auto take = [&]() -> std::string {
      if (stk.empty()) {
        auto t = fresh_temp();
        oss << "  " << t << " = add i64 0, 0 ; stack undef\n";
        return t;
      }
      auto v = stk.back();
      stk.pop_back();
      return v;
    };

    for (const auto& inst : fn.blocks) {
      oss << "  ; " << hex_u64(inst.source_va) << " " << inst.mnemonic;
      if (!inst.comment.empty()) oss << " " << inst.comment;
      oss << "\n";

      auto bin = [&](const char* opname) {
        auto b = take();
        auto a = take();
        auto t = fresh_temp();
        oss << "  " << t << " = " << opname << " i64 " << a << ", " << b << "\n";
        stk.push_back(t);
      };

      switch (inst.op) {
        case IrOp::Store: {
          auto t = fresh_temp();
          if (!inst.operands.empty() && inst.operands[0].constant) {
            oss << "  " << t << " = add i64 0, " << *inst.operands[0].constant << "\n";
          } else {
            oss << "  " << t << " = load i64, i64* @vip_imm\n";
          }
          stk.push_back(t);
          break;
        }
        case IrOp::Load: {
          auto addr = take();
          auto t = fresh_temp();
          oss << "  " << t << " = load i64, i64* inttoptr (i64 " << addr << " to i64*)\n";
          stk.push_back(t);
          break;
        }
        case IrOp::Add:
          bin("add");
          break;
        case IrOp::Sub:
          bin("sub");
          break;
        case IrOp::Xor:
          bin("xor");
          break;
        case IrOp::And:
          bin("and");
          break;
        case IrOp::Or:
          bin("or");
          break;
        case IrOp::Nor: {
          auto b = take();
          auto a = take();
          auto na = fresh_temp();
          auto nb = fresh_temp();
          auto t = fresh_temp();
          oss << "  " << na << " = xor i64 " << a << ", -1\n";
          oss << "  " << nb << " = xor i64 " << b << ", -1\n";
          oss << "  " << t << " = and i64 " << na << ", " << nb << "\n";
          stk.push_back(t);
          break;
        }
        case IrOp::Not: {
          auto a = take();
          auto t = fresh_temp();
          oss << "  " << t << " = xor i64 " << a << ", -1\n";
          stk.push_back(t);
          break;
        }
        case IrOp::Neg: {
          auto a = take();
          auto t = fresh_temp();
          oss << "  " << t << " = sub i64 0, " << a << "\n";
          stk.push_back(t);
          break;
        }
        case IrOp::Shl:
          bin("shl");
          break;
        case IrOp::Shr:
          bin("lshr");
          break;
        case IrOp::Branch:
          if (!inst.operands.empty() && inst.operands.back().constant)
            oss << "  ; calc_jmp " << hex_u64(static_cast<std::uint64_t>(*inst.operands.back().constant))
                << "\n";
          else
            oss << "  ; calc_jmp\n";
          break;
        case IrOp::Ret: {
          std::string v = stk.empty() ? "0" : stk.back();
          oss << "  ret i64 " << v << "\n";
          break;
        }
        case IrOp::Mov:
          break;
        default:
          oss << "  ; vmop " << inst.mnemonic << "\n";
          break;
      }
    }
    if (fn.blocks.empty() || fn.blocks.back().op != IrOp::Ret) {
      oss << "  ret i64 " << (stk.empty() ? "0" : stk.back()) << "\n";
    }
    oss << "}\n\n";
    return oss.str();
  }

  for (const auto& inst : fn.blocks) {
    oss << "  ; " << hex_u64(inst.source_va) << " " << inst.mnemonic;
    if (!inst.comment.empty()) oss << " " << inst.comment;
    oss << "\n";

    auto lhs = inst.operands.size() > 0 ? llvm_operand(inst.operands[0]) : "0";
    auto rhs = inst.operands.size() > 1 ? llvm_operand(inst.operands[1]) : "0";
    std::string dst;
    if (!inst.results.empty()) {
      dst = inst.results[0].name;
      if (dst.empty() || dst[0] != '%') dst = "%" + llvm_id(dst);
    }

    switch (inst.op) {
      case IrOp::Mov:
        if (!dst.empty()) oss << "  " << dst << " = add i64 " << rhs << ", 0\n";
        break;
      case IrOp::Xor:
        if (!dst.empty()) oss << "  " << dst << " = xor i64 " << lhs << ", " << rhs << "\n";
        break;
      case IrOp::Add:
        if (!dst.empty()) oss << "  " << dst << " = add i64 " << lhs << ", " << rhs << "\n";
        break;
      case IrOp::Sub:
        if (!dst.empty()) oss << "  " << dst << " = sub i64 " << lhs << ", " << rhs << "\n";
        break;
      case IrOp::And:
        if (!dst.empty()) oss << "  " << dst << " = and i64 " << lhs << ", " << rhs << "\n";
        break;
      case IrOp::Or:
        if (!dst.empty()) oss << "  " << dst << " = or i64 " << lhs << ", " << rhs << "\n";
        break;
      case IrOp::Not:
        if (!dst.empty()) oss << "  " << dst << " = xor i64 " << lhs << ", -1\n";
        break;
      case IrOp::Neg:
        if (!dst.empty()) oss << "  " << dst << " = sub i64 0, " << lhs << "\n";
        break;
      case IrOp::Shl:
        if (!dst.empty()) oss << "  " << dst << " = shl i64 " << lhs << ", " << rhs << "\n";
        break;
      case IrOp::Shr:
        if (!dst.empty()) oss << "  " << dst << " = lshr i64 " << lhs << ", " << rhs << "\n";
        break;
      case IrOp::Load:
        if (!dst.empty())
          oss << "  " << dst << " = load i64, i64* inttoptr (i64 " << lhs << " to i64*)\n";
        break;
      case IrOp::Store:
        oss << "  store i64 " << lhs << ", i64* inttoptr (i64 " << rhs << " to i64*)\n";
        break;
      case IrOp::Cmp:
        oss << "  " << fresh_temp() << " = icmp eq i64 " << lhs << ", " << rhs << "\n";
        break;
      case IrOp::Branch:
        if (!inst.operands.empty())
          oss << "  br label %h_" << llvm_id(inst.operands.back().name) << "\n";
        break;
      case IrOp::Call:
        oss << "  " << fresh_temp() << " = call i64 @native(" << lhs << ")\n";
        break;
      case IrOp::Ret:
        oss << "  ret i64 " << (inst.operands.empty() ? "0" : lhs) << "\n";
        break;
      default:
        oss << "  ; " << inst.mnemonic << " " << inst.comment << "\n";
        break;
    }
  }
  oss << "  ret i64 0\n";
  oss << "}\n\n";
  return oss.str();
}

std::string IrLifter::emit_pseudo_c(const IrFunction& fn) const {
  std::ostringstream oss;
  oss << "/* " << hex_u64(fn.entry_va) << (fn.stack_machine ? " vm stack" : " handler") << " */\n";

  if (fn.stack_machine) {
    oss << "uint64_t " << fn.name << "(void) {\n";
    oss << "  uint64_t s[512]; int sp = 0;\n";
    for (const auto& inst : fn.blocks) {
      oss << "  /* " << hex_u64(inst.source_va) << " " << inst.mnemonic << " */\n";
      switch (inst.op) {
        case IrOp::Store:
          if (!inst.operands.empty() && inst.operands[0].constant)
            oss << "  s[sp++] = " << static_cast<std::uint64_t>(*inst.operands[0].constant)
                << "ull;\n";
          else
            oss << "  s[sp++] = vip_fetch();\n";
          break;
        case IrOp::Load:
          oss << "  { uint64_t a = s[--sp]; s[sp++] = *(uint64_t*)a; }\n";
          break;
        case IrOp::Add:
          oss << "  s[sp-2] += s[sp-1]; --sp;\n";
          break;
        case IrOp::Sub:
          oss << "  s[sp-2] -= s[sp-1]; --sp;\n";
          break;
        case IrOp::Xor:
          oss << "  s[sp-2] ^= s[sp-1]; --sp;\n";
          break;
        case IrOp::And:
          oss << "  s[sp-2] &= s[sp-1]; --sp;\n";
          break;
        case IrOp::Or:
          oss << "  s[sp-2] |= s[sp-1]; --sp;\n";
          break;
        case IrOp::Nor:
          oss << "  s[sp-2] = ~(s[sp-2] | s[sp-1]); --sp;\n";
          break;
        case IrOp::Not:
          oss << "  s[sp-1] = ~s[sp-1];\n";
          break;
        case IrOp::Neg:
          oss << "  s[sp-1] = 0 - s[sp-1];\n";
          break;
        case IrOp::Shl:
          oss << "  s[sp-2] <<= (s[sp-1] & 63); --sp;\n";
          break;
        case IrOp::Shr:
          oss << "  s[sp-2] >>= (s[sp-1] & 63); --sp;\n";
          break;
        case IrOp::Ret:
          oss << "  return sp ? s[sp-1] : 0;\n";
          break;
        case IrOp::Branch:
          oss << "  /* calc_jmp next handler */\n";
          break;
        default:
          break;
      }
    }
    oss << "  return sp ? s[sp-1] : 0;\n";
    oss << "}\n\n";
    return oss.str();
  }

  oss << "void " << fn.name << "(void) {\n";
  for (const auto& inst : fn.blocks) {
    auto a = inst.operands.size() > 0 ? inst.operands[0].name : "r0";
    auto b = inst.operands.size() > 1 ? inst.operands[1].name : "r1";
    switch (inst.op) {
      case IrOp::Xor:
        oss << "  " << a << " ^= " << b << ";\n";
        break;
      case IrOp::Add:
        oss << "  " << a << " += " << b << ";\n";
        break;
      case IrOp::Sub:
        oss << "  " << a << " -= " << b << ";\n";
        break;
      case IrOp::And:
        oss << "  " << a << " &= " << b << ";\n";
        break;
      case IrOp::Or:
        oss << "  " << a << " |= " << b << ";\n";
        break;
      case IrOp::Not:
        oss << "  " << a << " = ~" << a << ";\n";
        break;
      case IrOp::Neg:
        oss << "  " << a << " = -" << a << ";\n";
        break;
      case IrOp::Mov:
        oss << "  " << a << " = " << b << ";\n";
        break;
      case IrOp::Shl:
        oss << "  " << a << " <<= " << b << ";\n";
        break;
      case IrOp::Shr:
        oss << "  " << a << " >>= " << b << ";\n";
        break;
      case IrOp::Load:
        oss << "  " << a << " = *(uint64_t*)(" << a << ");\n";
        break;
      case IrOp::Store:
        oss << "  *(uint64_t*)(" << b << ") = " << a << ";\n";
        break;
      case IrOp::Branch:
        oss << "  goto handler_" << b << ";\n";
        break;
      case IrOp::Ret:
        oss << "  return;\n";
        break;
      default:
        if (inst.source_va)
          oss << "  /* " << hex_u64(inst.source_va) << " " << inst.mnemonic << " " << inst.comment
              << " */\n";
        break;
    }
  }
  oss << "}\n\n";
  return oss.str();
}

}
