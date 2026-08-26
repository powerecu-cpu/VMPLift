#include "vmp_version.hpp"

#include "dispatch_resolver.hpp"
#include "rolling_key.hpp"
#include "util.hpp"
#include "vmenter.hpp"

#include <cmath>
#include <cctype>
#include <sstream>

namespace vmp {

namespace {

constexpr std::uint32_t kExec = 0x20000000u;
constexpr std::uint32_t kRead = 0x40000000u;
constexpr std::uint32_t kUninit = 0x00000080u;


bool die_vmp_chars(std::uint32_t c) {
  return c == 0x60000060u || c == 0xE0000060u || c == 0xE0000040u || c == 0x68000060u ||
         c == 0xE2000060u || c == 0x68000020u || c == 0x60000020u;
}

bool toolchain_name(const std::string& n) {
  return n == ".text" || n == ".rdata" || n == ".data" || n == ".pdata" || n == ".rsrc" ||
         n == ".reloc" || n == ".idata" || n == ".edata" || n == ".bss" || n == ".tls" ||
         n == ".CRT" || n == ".gfids" || n == ".debug" || n == ".fptable" || n == ".xdata" ||
         n == ".textbss" || n == ".00cfg" || n == ".msvcjmc" || n == ".didat" || n == ".voltbl";
}

double shannon(const std::vector<std::uint8_t>& b) {
  if (b.size() < 64) return 0;
  unsigned c[256]{};
  for (auto x : b) c[x]++;
  double e = 0;
  const double n = static_cast<double>(b.size());
  for (int i = 0; i < 256; i++) {
    if (!c[i]) continue;
    double p = c[i] / n;
    e -= p * std::log2(p);
  }
  return e;
}

bool looks_lzma(const std::vector<std::uint8_t>& b) {
  return b.size() >= 5 && b[0] == 0x5D && b[1] == 0x00 && b[2] == 0x00;
}

int ep_section_index(const PeImage& image) {
  const auto rva = image.entry_point_rva();
  const auto& secs = image.sections();
  for (int i = 0; i < static_cast<int>(secs.size()); i++) {
    const auto& s = secs[static_cast<std::size_t>(i)];
    if (rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size) return i;
  }
  return -1;
}

// VMPStatic detectVMP310: EP lives in a later RX stub; >=3 earlier sections are
// virtual-only (raw=0) originals the loader fills; stub entropy >= 7.0.
bool packed_310_layout(const PeImage& image, double* stub_ent) {
  const int ep_idx = ep_section_index(image);
  if (ep_idx < 1) return false;
  const auto& stub = image.sections()[static_cast<std::size_t>(ep_idx)];
  if ((stub.characteristics & (kExec | kRead)) != (kExec | kRead)) return false;
  if (stub.raw_size == 0) return false;
  int packed = 0;
  for (int i = 0; i < ep_idx; i++) {
    const auto& s = image.sections()[static_cast<std::size_t>(i)];
    if (s.raw_size == 0 && s.raw_offset == 0 && (s.characteristics & kUninit) == 0) packed++;
  }
  if (packed < 3) return false;
  auto chunk = image.read_at_va(image.image_base() + stub.virtual_address,
                               static_cast<std::size_t>(stub.raw_size > 0x8000 ? 0x8000 : stub.raw_size));
  const double ent = shannon(chunk);
  if (stub_ent) *stub_ent = ent;
  return ent >= 7.0;
}

std::string classify_ep(const std::vector<std::uint8_t>& b) {
  if (b.size() < 6) return "short";
  // DIE compareEP family
  if (b[0] == 0x68 && b[5] == 0xE9) return "push+jmp";     // 1.60-2.05
  if (b[0] == 0x68 && b[5] == 0xE8) return "push+call";    // 1.60-3.x vmenter / 3.0X
  if (b[0] == 0x9C && b[1] == 0xE9) return "pushfq+jmp";   // 2.x
  if (b[0] == 0x9C && b[1] == 0xFF) return "pushfq+ff";    // 2.x
  if (b[0] == 0x54 && b.size() >= 8 && b[1] == 0xC7) return "2.06";
  // 3.8/3.10 stub: push reg; pushfq; movabs (Wave ..XV)
  if (b.size() >= 4 && b[0] >= 0x50 && b[0] <= 0x57 && b[1] == 0x9C && b[2] == 0x48 &&
      b[3] == 0xBE)
    return "push+fq+movabs";
  if (b[0] == 0x9C && b.size() >= 3 && b[1] == 0x48 && b[2] == 0xBE) return "pushfq+movabs";
  return "other";
}

bool is_2x_ep(const std::string& sig) {
  return sig == "push+jmp" || sig == "pushfq+jmp" || sig == "pushfq+ff" || sig == "2.06";
}

bool is_38_stub_ep(const std::string& sig) {
  return sig == "push+fq+movabs" || sig == "pushfq+movabs";
}

int vip_advances(const std::vector<RawInsn>& insns) {
  int n = 0;
  for (const auto& in : insns) {
    if (in.mnemonic != "add" && in.mnemonic != "sub" && in.mnemonic != "lea") continue;
    const auto& o = in.op_str;
    if (o.find(", 4") != std::string::npos || o.find(", 8") != std::string::npos ||
        o.find(" + 4") != std::string::npos || o.find(" + 8") != std::string::npos)
      n++;
  }
  return n;
}

int alu_ops(const std::vector<RawInsn>& insns) {
  int n = 0;
  for (const auto& in : insns) {
    const auto& m = in.mnemonic;
    if (m == "xor" || m == "add" || m == "sub" || m == "neg" || m == "not" || m == "rol" ||
        m == "ror" || m == "bswap")
      n++;
  }
  return n;
}

struct HandlerProbe {
  bool jmp_reg = false;
  bool mixer = false;
  bool merged = false;
  int insns = 0;
  int vip_step = 0;
  std::uint64_t next = 0;
};

std::uint64_t push_call_target(const PeImage& image, std::uint64_t va) {
  auto b = image.read_at_va(va, 10);
  if (b.size() < 10 || b[0] != 0x68 || b[5] != 0xE8) return 0;
  const auto rel = static_cast<std::int32_t>(b[6] | (b[7] << 8) | (b[8] << 16) | (b[9] << 24));
  return va + 10 + static_cast<std::uint64_t>(rel);
}

HandlerProbe probe_one(DispatchResolver& dr, std::uint64_t va) {
  HandlerProbe p;
  if (!va) return p;
  auto blk = dr.lift_block(va, 96);
  p.insns = static_cast<int>(blk.insns.size());
  p.vip_step = vip_advances(blk.insns);
  const int alu = alu_ops(blk.insns);
  for (const auto& in : blk.insns) {
    if (in.is_reg_branch) p.jmp_reg = true;
  }
  p.mixer = !RollingKey::extract_mixer(blk.insns).empty();
  if (blk.next_handler_va) p.next = *blk.next_handler_va;
  p.merged = p.insns >= 40 && (p.mixer || p.vip_step >= 1 || (p.jmp_reg && alu >= 4));
  if (p.mixer && p.insns >= 28 && p.vip_step >= 2) p.merged = true;
  return p;
}

HandlerProbe probe_va(DispatchResolver& dr, std::uint64_t va) {
  auto p = probe_one(dr, va);
  if (!p.next || p.next == va) return p;
  auto nxt = probe_one(dr, p.next);
  if (nxt.mixer || nxt.jmp_reg || nxt.merged || nxt.insns > p.insns) {
    if (nxt.insns > p.insns) p.insns = nxt.insns;
    p.jmp_reg = p.jmp_reg || nxt.jmp_reg;
    p.mixer = p.mixer || nxt.mixer;
    p.merged = p.merged || nxt.merged;
    if (nxt.vip_step > p.vip_step) p.vip_step = nxt.vip_step;
  }
  return p;
}

}

VersionInfo detect_version(const PeImage& image) {
  VersionInfo info;
  bool vmp0 = false, vmp1 = false;
  bool collision0 = false;  // DIE getSectionNameCollision style: .xxxx0
  bool random_plain = false;  
  double best_ent = 0;
  bool lzma = false;
  int extra_exec = 0;

  for (const auto& sec : image.sections()) {
    if (sec.name == ".vmp0") vmp0 = true;
    if (sec.name == ".vmp1") vmp1 = true;

    const bool extra = !toolchain_name(sec.name);
    const bool exec = (sec.characteristics & kExec) != 0;
    const bool die = die_vmp_chars(sec.characteristics);

    if (extra && (exec || die || is_vmp_section_name(sec.name))) {
      info.vmp_sections.push_back(sec.name);
      extra_exec++;
      if (!sec.name.empty() && std::isdigit(static_cast<unsigned char>(sec.name.back())) &&
          sec.name != ".vmp0" && sec.name != ".vmp1" && sec.name != ".vmp2")
        collision0 = true;
      if (!sec.name.empty() && !std::isdigit(static_cast<unsigned char>(sec.name.back())) &&
          sec.name.rfind(".vmp", 0) != 0)
        random_plain = true;
    }

    if (!extra && !die) continue;
    auto n = static_cast<std::size_t>(sec.raw_size ? sec.raw_size : sec.virtual_size);
    if (n > 0x8000) n = 0x8000;
    auto chunk = image.read_at_va(image.image_base() + sec.virtual_address, n);
    const double ent = shannon(chunk);
    if (ent > best_ent) best_ent = ent;
    if (looks_lzma(chunk) && ent > 7.0) lzma = true;
  }

  info.randomized_sections = collision0 || random_plain;
  info.entropy = best_ent;

  double stub_ent = 0;
  const bool packed310 = packed_310_layout(image, &stub_ent);
  info.packed = packed310;
  if (packed310 && stub_ent > info.entropy) info.entropy = stub_ent;

  const auto ep_va = image.image_base() + image.entry_point_rva();
  info.ep_sig = classify_ep(image.read_at_va(ep_va, 16));
  const auto* ep_sec = image.section_for_va(ep_va);
  const bool ep_in_stub = ep_sec && !toolchain_name(ep_sec->name);

  VmenterScanner sc(image);
  auto sites = sc.scan_all();
  int n_push = 0, n_stub = 0, n_pushfq = 0;
  for (const auto& s : sites) {
    if (s.kind == VmenterKind::PushCallEnter) n_push++;
    else if (s.kind == VmenterKind::ExportStubJump) n_stub++;
    else if (s.kind == VmenterKind::PushFqMovAbs) n_pushfq++;
  }
  info.push_call_enters = n_push;

  HandlerProbe hp;
  try {
    DispatchResolver dr(image);
    std::vector<std::uint64_t> cand;
    if (auto best = VmenterScanner::pick_best(sites)) {
      if (auto stub = push_call_target(image, *best)) cand.push_back(stub);
      for (const auto& s : sites) {
        if (s.va != *best) continue;
        if (s.first_handler_va) cand.push_back(s.first_handler_va);
        break;
      }
    }
    int added = 0;
    for (const auto& s : sites) {
      if (s.kind != VmenterKind::PushCallEnter) continue;
      if (auto stub = push_call_target(image, s.va)) cand.push_back(stub);
      if (++added >= 2) break;
    }
    for (auto va : cand) {
      if (!va) continue;
      auto p = probe_va(dr, va);
      if (p.insns > hp.insns) hp.insns = p.insns;
      hp.jmp_reg = hp.jmp_reg || p.jmp_reg;
      hp.mixer = hp.mixer || p.mixer;
      hp.merged = hp.merged || p.merged;
      if (p.vip_step > hp.vip_step) hp.vip_step = p.vip_step;
    }
  } catch (...) {
  }

  info.handler_insns = hp.insns;
  info.chain_dispatch = hp.jmp_reg || hp.mixer;
  info.uses_rolling_key = hp.mixer || hp.jmp_reg || n_push > 0;
  info.has_merged_handlers = hp.merged;

  const bool is_3x = n_push >= 1 || hp.mixer || hp.jmp_reg || is_38_stub_ep(info.ep_sig) ||
                     info.ep_sig == "push+call";
  const bool classic_pair = vmp0 && vmp1;

  std::ostringstream why;
  why << "ep=" << info.ep_sig << " push+call=" << n_push << " chain=" << (int)hp.jmp_reg
      << " mixer=" << (int)hp.mixer << " merged=" << (int)hp.merged << " hins=" << hp.insns
      << " vip+=" << hp.vip_step << " ent=" << best_ent;
  if (packed310) why << " packed310";
  if (collision0) why << " name0";
  if (random_plain) why << " randname";
  if (ep_in_stub) why << " ep-stub";
  if (lzma) why << " lzma";
  if (classic_pair) why << " .vmp0+1";
  info.why = why.str();

  auto set38 = [&](const char* label, int conf, bool merged_flag) {
    info.version = VmpVersion::Vmp38Plus;
    info.label = label;
    info.has_merged_handlers = merged_flag || hp.merged;
    info.uses_rolling_key = true;
    info.confidence = conf;
    if (info.confidence > 95) info.confidence = 95;
  };

  if (is_2x_ep(info.ep_sig) && n_push == 0 && !hp.mixer) {
    info.version = VmpVersion::Vmp30;
    info.label = "VMProtect 2.x";
    info.confidence = 70;
    return info;
  }


  if (packed310) {
    set38("VMProtect 3.10+ packed", 90, true);
    return info;
  }


  if (ep_in_stub && random_plain && is_3x) {
    set38("VMProtect 3.8-3.10+", 85, true);
    return info;
  }


  if (is_3x && hp.merged) {
    set38("VMProtect 3.8-3.10+", 80, true);
    return info;
  }


  if (is_3x && (collision0 || random_plain) && !classic_pair && extra_exec >= 1) {
    set38("VMProtect 3.8-3.10+", hp.mixer || n_push >= 4 ? 75 : 60, hp.merged);
    if (!info.has_merged_handlers && hp.insns >= 40) info.has_merged_handlers = true;
    return info;
  }

  if (is_3x && classic_pair && !hp.merged) {
    info.version = VmpVersion::Vmp35;
    info.label = "VMProtect 3.5.x";
    info.uses_rolling_key = true;
    info.has_merged_handlers = false;
    info.confidence = 65;
    return info;
  }

  if (is_3x && (vmp0 || vmp1) && hp.merged) {
    info.version = VmpVersion::Vmp36;
    info.label = "VMProtect 3.6.x / early merge";
    info.uses_rolling_key = true;
    info.has_merged_handlers = true;
    info.confidence = 55;
    return info;
  }

  if (is_3x) {
    set38("VMProtect 3.x (push+call/chain)", 50, hp.merged);
    return info;
  }

  if (!info.vmp_sections.empty()) {
    info.version = VmpVersion::Vmp30;
    info.label = "VMProtect 3.0-3.4";
    info.confidence = 30;
    return info;
  }

  info.label = "Unknown / unpacked";
  info.why += " no enter";
  return info;
}

}
