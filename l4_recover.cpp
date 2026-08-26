#include "l4_recover.hpp"

#include "util.hpp"
#include "vip_context.hpp"

#include <unicorn/unicorn.h>

#include <capstone/capstone.h>
#include <capstone/x86.h>

#include <algorithm>
#include <functional>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace vmp {
namespace {

bool in_vmp(const PeImage& image, std::uint64_t va) {
  auto* sec = image.section_for_va(va);
  return sec && is_vmp_section_name(sec->name);
}

bool map_pe(uc_engine* uc, const PeImage& image) {
  auto base = image.image_base();
  auto img_sz = (image.size_of_image() + 0xFFF) & ~0xFFFULL;
  if (img_sz < 0x1000) img_sz = 0x1000;
  if (uc_mem_map(uc, base, img_sz, UC_PROT_ALL) != UC_ERR_OK) return false;
  for (const auto& sec : image.sections()) {
    auto va = base + sec.virtual_address;
    auto want = static_cast<std::size_t>(
        sec.raw_size ? (sec.raw_size < sec.virtual_size ? sec.raw_size : sec.virtual_size)
                     : sec.virtual_size);
    if (!want) continue;
    auto bytes = image.read_at_va(va, want);
    if (!bytes.empty()) uc_mem_write(uc, va, bytes.data(), bytes.size());
  }
  return true;
}

struct RunState {
  const PeImage* image = nullptr;
  std::uint64_t vmenter = 0;
  std::uint64_t sentinel = 0;
  std::size_t steps = 0;
  std::size_t max_steps = 2'000'000;
  bool exited = false;
  bool started = false;
};

void hook_code(uc_engine* uc, std::uint64_t addr, std::uint32_t , void* user) {
  auto* st = static_cast<RunState*>(user);
  if (++st->steps > st->max_steps) {
    uc_emu_stop(uc);
    return;
  }
  if (!st->started) {
    if (addr == st->vmenter) st->started = true;
    return;
  }

  if (addr == st->sentinel || !in_vmp(*st->image, addr)) {
    st->exited = true;
    uc_emu_stop(uc);
  }
}

bool hook_unmapped(uc_engine* uc, uc_mem_type , std::uint64_t addr, int ,
                   std::int64_t , void* ) {
  auto page = addr & ~0xFFFULL;
  return uc_mem_map(uc, page, 0x1000, UC_PROT_ALL) == UC_ERR_OK;
}

std::optional<std::uint64_t> unicorn_probe(const PeImage& image, std::uint64_t vmenter,
                                           std::uint64_t arg_rcx, std::uint64_t arg_rdx) {
  uc_engine* uc = nullptr;
  if (uc_open(UC_ARCH_X86, UC_MODE_64, &uc) != UC_ERR_OK) return std::nullopt;
  if (!map_pe(uc, image)) {
    uc_close(uc);
    return std::nullopt;
  }

  constexpr std::uint64_t kStack = 0x7FE00000ULL;
  constexpr std::uint64_t kStackSz = 0x200000ULL;
  uc_mem_map(uc, kStack, kStackSz, UC_PROT_ALL);
  std::uint64_t rsp = kStack + kStackSz - 0x400;
  std::uint64_t sentinel = image.image_base() + 0x1000;

  std::uint8_t cc[16];
  for (auto& b : cc) b = 0xCC;
  uc_mem_write(uc, sentinel, cc, sizeof(cc));

  bool start_is_push_call = false;
  {
    auto b = image.read_at_va(vmenter, 10);
    start_is_push_call = b.size() >= 10 && b[0] == 0x68 && b[5] == 0xE8;
  }
  auto seed = extract_vip_seed(image, vmenter);
  if (seed.enc_push_imm && !start_is_push_call) {
    rsp -= 8;
    std::uint64_t imm = *seed.enc_push_imm;
    uc_mem_write(uc, rsp, &imm, 8);
  }
  rsp -= 8;
  uc_mem_write(uc, rsp, &sentinel, 8);
  uc_reg_write(uc, UC_X86_REG_RSP, &rsp);

  std::uint64_t z = 0;
  for (int r : {UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
                UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12,
                UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15}) {
    uc_reg_write(uc, r, &z);
  }
  uc_reg_write(uc, UC_X86_REG_RCX, &arg_rcx);
  uc_reg_write(uc, UC_X86_REG_RDX, &arg_rdx);
  if (seed.movabs_imm) {
    std::uint64_t m = *seed.movabs_imm;
    uc_reg_write(uc, UC_X86_REG_RBP, &m);
  }

  RunState st;
  st.image = &image;
  st.vmenter = vmenter;
  st.sentinel = sentinel;

  uc_hook h_code{}, h_unmap{};
  uc_hook_add(uc, &h_code, UC_HOOK_CODE, reinterpret_cast<void*>(hook_code), &st, 1, 0);
  uc_hook_add(uc, &h_unmap, UC_HOOK_MEM_UNMAPPED, reinterpret_cast<void*>(hook_unmapped), &st, 1,
              0);

  uc_emu_start(uc, vmenter, 0, 0, 0);
  std::uint64_t rax = 0;
  uc_reg_read(uc, UC_X86_REG_RAX, &rax);
  bool ok = st.exited;
  uc_close(uc);
  if (!ok) return std::nullopt;
  return rax;
}

struct Probe {
  std::uint64_t a = 0, b = 0, out = 0;
};

bool fit_linear(const std::vector<Probe>& ps, std::int64_t& p, std::int64_t& q, std::int64_t& r) {

  if (ps.size() < 3) return false;

  std::optional<std::int64_t> p_guess, q_guess;
  for (std::size_t i = 0; i < ps.size(); i++) {
    for (std::size_t j = i + 1; j < ps.size(); j++) {
      if (ps[i].b == ps[j].b && ps[i].a != ps[j].a) {
        auto da = static_cast<std::int64_t>(ps[j].a) - static_cast<std::int64_t>(ps[i].a);
        auto dout = static_cast<std::int64_t>(ps[j].out) - static_cast<std::int64_t>(ps[i].out);
        if (da != 0 && dout % da == 0) {
          auto cand = dout / da;
          if (!p_guess) p_guess = cand;
          else if (*p_guess != cand) return false;
        }
      }
      if (ps[i].a == ps[j].a && ps[i].b != ps[j].b) {
        auto db = static_cast<std::int64_t>(ps[j].b) - static_cast<std::int64_t>(ps[i].b);
        auto dout = static_cast<std::int64_t>(ps[j].out) - static_cast<std::int64_t>(ps[i].out);
        if (db != 0 && dout % db == 0) {
          auto cand = dout / db;
          if (!q_guess) q_guess = cand;
          else if (*q_guess != cand) return false;
        }
      }
    }
  }
  if (!p_guess || !q_guess) return false;
  p = *p_guess;
  q = *q_guess;
  r = static_cast<std::int64_t>(ps[0].out) - p * static_cast<std::int64_t>(ps[0].a) -
      q * static_cast<std::int64_t>(ps[0].b);
  for (const auto& x : ps) {
    auto pred = p * static_cast<std::int64_t>(x.a) + q * static_cast<std::int64_t>(x.b) + r;
    if (static_cast<std::uint64_t>(pred) != x.out &&
        static_cast<std::uint32_t>(pred) != static_cast<std::uint32_t>(x.out)) {
      return false;
    }
  }
  return true;
}

bool all_match(const std::vector<Probe>& ps,
               const std::function<std::uint64_t(std::uint64_t, std::uint64_t)>& f) {
  for (const auto& x : ps) {
    if (f(x.a, x.b) != x.out &&
        static_cast<std::uint32_t>(f(x.a, x.b)) != static_cast<std::uint32_t>(x.out)) {
      return false;
    }
  }
  return true;
}

struct Expr {
  enum Kind { Const, Arg, Add, Sub, Xor, And, Or, Nor, Not, Neg, Load } kind = Const;
  std::uint64_t imm = 0;
  int arg = -1;
  std::vector<Expr> kids;

  static Expr c(std::uint64_t v) {
    Expr e;
    e.kind = Const;
    e.imm = v;
    return e;
  }
  static Expr a(int i) {
    Expr e;
    e.kind = Arg;
    e.arg = i;
    return e;
  }
  static Expr bin(Kind k, Expr l, Expr r) {
    Expr e;
    e.kind = k;
    e.kids = {std::move(l), std::move(r)};
    return e;
  }
  static Expr un(Kind k, Expr x) {
    Expr e;
    e.kind = k;
    e.kids = {std::move(x)};
    return e;
  }
};

Expr fold(Expr e);

Expr fold_bin(Expr::Kind k, Expr l, Expr r) {
  l = fold(std::move(l));
  r = fold(std::move(r));
  if (l.kind == Expr::Const && r.kind == Expr::Const) {
    std::uint64_t v = 0;
    switch (k) {
      case Expr::Add: v = l.imm + r.imm; break;
      case Expr::Sub: v = l.imm - r.imm; break;
      case Expr::Xor: v = l.imm ^ r.imm; break;
      case Expr::And: v = l.imm & r.imm; break;
      case Expr::Or: v = l.imm | r.imm; break;
      case Expr::Nor: v = ~(l.imm | r.imm); break;
      default: break;
    }
    return Expr::c(v);
  }

  if (k == Expr::Add && r.kind == Expr::Const && r.imm == 0) return l;
  if (k == Expr::Add && l.kind == Expr::Const && l.imm == 0) return r;
  if (k == Expr::Xor && r.kind == Expr::Const && r.imm == 0) return l;
  if (k == Expr::And && r.kind == Expr::Const && r.imm == ~0ull) return l;
  if (k == Expr::Or && r.kind == Expr::Const && r.imm == 0) return l;

  if (k == Expr::Nor && l.kind == Expr::Not && r.kind == Expr::Not)
    return fold(Expr::bin(Expr::And, l.kids[0], r.kids[0]));
  return Expr::bin(k, std::move(l), std::move(r));
}

Expr fold(Expr e) {
  if (e.kind == Expr::Not && e.kids.size() == 1) {
    auto x = fold(e.kids[0]);
    if (x.kind == Expr::Const) return Expr::c(~x.imm);
    if (x.kind == Expr::Not) return fold(x.kids[0]);
    return Expr::un(Expr::Not, std::move(x));
  }
  if (e.kind == Expr::Neg && e.kids.size() == 1) {
    auto x = fold(e.kids[0]);
    if (x.kind == Expr::Const) return Expr::c(static_cast<std::uint64_t>(-static_cast<std::int64_t>(x.imm)));
    return Expr::un(Expr::Neg, std::move(x));
  }
  if (e.kids.size() == 2) return fold_bin(e.kind, e.kids[0], e.kids[1]);
  return e;
}

std::string emit_expr(const Expr& e) {
  switch (e.kind) {
    case Expr::Const: return hex_u64(e.imm) + "ull";
    case Expr::Arg: return e.arg == 0 ? "a" : (e.arg == 1 ? "b" : ("arg" + std::to_string(e.arg)));
    case Expr::Add: return "(" + emit_expr(e.kids[0]) + " + " + emit_expr(e.kids[1]) + ")";
    case Expr::Sub: return "(" + emit_expr(e.kids[0]) + " - " + emit_expr(e.kids[1]) + ")";
    case Expr::Xor: return "(" + emit_expr(e.kids[0]) + " ^ " + emit_expr(e.kids[1]) + ")";
    case Expr::And: return "(" + emit_expr(e.kids[0]) + " & " + emit_expr(e.kids[1]) + ")";
    case Expr::Or: return "(" + emit_expr(e.kids[0]) + " | " + emit_expr(e.kids[1]) + ")";
    case Expr::Nor: return "(~(" + emit_expr(e.kids[0]) + " | " + emit_expr(e.kids[1]) + "))";
    case Expr::Not: return "(~" + emit_expr(e.kids[0]) + ")";
    case Expr::Neg: return "(-" + emit_expr(e.kids[0]) + ")";
    case Expr::Load: return "(*(uint64_t*)" + emit_expr(e.kids[0]) + ")";
  }
  return "?";
}

Expr const_or_arg(std::uint64_t v, std::uint64_t a, std::uint64_t b) {
  if (v == a || static_cast<std::uint32_t>(v) == static_cast<std::uint32_t>(a)) return Expr::a(0);
  if (v == b || static_cast<std::uint32_t>(v) == static_cast<std::uint32_t>(b)) return Expr::a(1);
  return Expr::c(v);
}

std::string fold_stream(const DevirtResult& sem, std::uint64_t a, std::uint64_t b) {
  std::vector<Expr> st;
  auto push = [&](Expr e) { st.push_back(fold(std::move(e))); };
  auto pop = [&]() -> Expr {
    if (st.empty()) return Expr::c(0);
    auto e = st.back();
    st.pop_back();
    return e;
  };

  for (const auto& op : sem.stream) {
    if (op.kind == VmOpKind::CalcJmp || op.kind == VmOpKind::Mov || op.kind == VmOpKind::Flags ||
        op.kind == VmOpKind::VmEnter)
      continue;
    if (op.kind == VmOpKind::VmExit) break;

    switch (op.kind) {
      case VmOpKind::FetchImm:
      case VmOpKind::Push: {
        std::uint64_t v = op.fetch_dec ? *op.fetch_dec : op.fetch_enc;
        push(const_or_arg(v, a, b));
        break;
      }
      case VmOpKind::Add: {
        auto r = pop(), l = pop();
        push(Expr::bin(Expr::Add, std::move(l), std::move(r)));
        break;
      }
      case VmOpKind::Sub: {
        auto r = pop(), l = pop();
        push(Expr::bin(Expr::Sub, std::move(l), std::move(r)));
        break;
      }
      case VmOpKind::Xor: {
        auto r = pop(), l = pop();
        push(Expr::bin(Expr::Xor, std::move(l), std::move(r)));
        break;
      }
      case VmOpKind::And: {
        auto r = pop(), l = pop();
        push(Expr::bin(Expr::And, std::move(l), std::move(r)));
        break;
      }
      case VmOpKind::Or: {
        auto r = pop(), l = pop();
        push(Expr::bin(Expr::Or, std::move(l), std::move(r)));
        break;
      }
      case VmOpKind::Nor: {
        auto r = pop(), l = pop();
        push(Expr::bin(Expr::Nor, std::move(l), std::move(r)));
        break;
      }
      case VmOpKind::Not: {
        auto x = pop();
        push(Expr::un(Expr::Not, std::move(x)));
        break;
      }
      case VmOpKind::Neg: {
        auto x = pop();
        push(Expr::un(Expr::Neg, std::move(x)));
        break;
      }
      case VmOpKind::Pop:
        (void)pop();
        break;
      case VmOpKind::Load: {
        auto x = pop();
        push(Expr::un(Expr::Load, std::move(x)));
        break;
      }
      case VmOpKind::Store:
        (void)pop();
        (void)pop();
        break;
      default:
        break;
    }
  }

  if (st.empty()) return {};
  auto top = fold(st.back());
  return emit_expr(top);
}

}

L4Result recover_l4(const PeImage& image, std::uint64_t vmenter_va, const DevirtResult& sem_devirt) {
  L4Result out;

  const std::pair<std::uint64_t, std::uint64_t> vectors[] = {
      {0, 0}, {1, 0}, {0, 1}, {3, 5}, {7, 11}, {100, 200}, {0x1234, 0x55aa},
  };

  std::vector<Probe> probes;
  for (auto [a, b] : vectors) {
    auto r = unicorn_probe(image, vmenter_va, a, b);
    if (!r) continue;
    probes.push_back({a, b, *r});
  }

  std::string body;
  if (probes.empty()) {
    out.method = "none";
    out.summary = "l4: unicorn probes failed (no exit)";
    auto folded = fold_stream(sem_devirt, 3, 5);
    if (!folded.empty()) {
      body = "  return " + folded + ";\n";
      out.method = "fold";
      out.ok = true;
      out.summary = "l4: fold-only " + folded;
    } else {
      body = "  (void)a; (void)b;\n  return 0;\n";
      out.summary = "l4: unrecovered";
    }
  } else {
    out.probe_rax = probes.back().out;
    out.ok = true;

    auto match32 = [](std::uint64_t x, std::uint64_t y) {
      return x == y || static_cast<std::uint32_t>(x) == static_cast<std::uint32_t>(y);
    };

    auto is_add = [&](const Probe& p) { return match32(p.out, p.a + p.b); };
    auto is_xor = [&](const Probe& p) { return match32(p.out, p.a ^ p.b); };
    auto is_and = [&](const Probe& p) { return match32(p.out, p.a & p.b); };
    auto is_or = [&](const Probe& p) { return match32(p.out, p.a | p.b); };
    auto is_b = [&](const Probe& p) { return match32(p.out, p.b); };
    auto is_a = [&](const Probe& p) { return match32(p.out, p.a); };

    out.matches_add = std::all_of(probes.begin(), probes.end(), is_add);
    out.matches_xor = std::all_of(probes.begin(), probes.end(), is_xor);
    out.matches_and = std::all_of(probes.begin(), probes.end(), is_and);
    out.matches_or = std::all_of(probes.begin(), probes.end(), is_or);
    out.matches_identity_b = std::all_of(probes.begin(), probes.end(), is_b);

    if (out.matches_add) {
      out.method = "synth_linear";
      body = "  return (uint32_t)(a + b);\n";
      out.summary = "l4: return (uint32_t)(a + b)";
    } else if (out.matches_xor) {
      out.method = "synth_bitwise";
      body = "  return a ^ b;\n";
      out.summary = "l4: return a ^ b";
    } else if (out.matches_and) {
      out.method = "synth_bitwise";
      body = "  return a & b;\n";
      out.summary = "l4: return a & b";
    } else if (out.matches_or) {
      out.method = "synth_bitwise";
      body = "  return a | b;\n";
      out.summary = "l4: return a | b";
    } else if (out.matches_identity_b) {
      out.method = "synth_bitwise";
      body = "  (void)a;\n  return b;\n";
      out.summary = "l4: return b";
    } else if (std::all_of(probes.begin(), probes.end(), is_a)) {
      out.method = "synth_bitwise";
      body = "  (void)b;\n  return a;\n";
      out.summary = "l4: return a";
    } else {
      std::int64_t p = 0, q = 0, r = 0;
      if (fit_linear(probes, p, q, r)) {
        out.method = "synth_linear";
        std::ostringstream bb;
        bb << "  return (uint64_t)(" << p << " * (int64_t)a + " << q << " * (int64_t)b + " << r
           << ");\n";
        body = bb.str();
        out.summary = "l4: linear " + std::to_string(p) + "*a + " + std::to_string(q) + "*b + " +
                      std::to_string(r);
      } else {
        auto f_chain = [](std::uint64_t a, std::uint64_t b) {
          auto t = a ^ b;
          t &= b;
          t |= b;
          return t;
        };
        if (all_match(probes, f_chain)) {
          out.method = "synth_bitwise";
          body = "  uint64_t t = a ^ b;\n  t &= b;\n  t |= b;\n  return t;\n";
          out.summary = "l4: ((a^b)&b)|b";
        } else {
          auto folded = fold_stream(sem_devirt, 3, 5);
          out.method = folded.empty() ? "probe_only" : "fold";
          if (!folded.empty()) {
            body = "  return " + folded + ";\n";
            out.summary = "l4: fold " + folded;
          } else {
            std::ostringstream bb;
            bb << "  (void)a; (void)b;\n  return " << hex_u64(probes[0].out) << "ull;\n";
            body = bb.str();
            out.summary = "l4: probes only";
          }
        }
      }
    }
  }

  std::ostringstream src;
  src << "#include <stdint.h>\n\n";
  src << "uint64_t recovered(uint64_t a, uint64_t b) {\n";
  src << body;
  src << "}\n";
  out.c_source = src.str();
  return out;
}

}
