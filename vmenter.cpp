#include "vmenter.hpp"

#include "util.hpp"

#include <capstone/capstone.h>
#include <capstone/x86.h>

#include <algorithm>
#include <set>
#include <string>

namespace vmp {

namespace {

bool looks_like_push_imm(const std::vector<std::uint8_t>& b) {
  if (b.size() < 2) {
    return false;
  }
  if (b[0] == 0x6A) {
    return true;
  }
  return b[0] == 0x68;
}

bool looks_like_pushfq(const std::vector<std::uint8_t>& b) {
  return b.size() >= 1 && b[0] == 0x9C;
}

bool looks_like_push_reg_fq(const std::vector<std::uint8_t>& b) {
  return b.size() >= 2 && b[0] >= 0x50 && b[0] <= 0x57 && b[1] == 0x9C;
}

}

VmenterScanner::VmenterScanner(const PeImage& image) : image_(image) {}

bool VmenterScanner::is_likely_code_va(std::uint64_t va) const {
  if (!image_.contains_va(va)) {
    return false;
  }
  auto bytes = image_.read_at_va(va, 16);
  if (bytes.empty()) {
    return false;
  }
  int ok = 0;
  for (auto b : bytes) {
    if (b != 0x00 && b != 0xCC && b != 0x90) {
      ok++;
    }
  }
  return ok >= 4;
}

bool VmenterScanner::looks_like_vmp_region(std::uint64_t va) const {
  auto* sec = image_.section_for_va(va);
  if (!sec) {
    return false;
  }
  return is_vmp_section_name(sec->name) || sec->name == ".text";
}

int VmenterScanner::score_prologue(std::uint64_t va) const {

  auto bytes = image_.read_at_va(va, 96);
  if (bytes.size() < 8) {
    return 0;
  }

  csh cs{};
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs) != CS_ERR_OK) {
    return 0;
  }
  cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);

  cs_insn* ins = nullptr;
  auto n = cs_disasm(cs, bytes.data(), bytes.size(), va, 16, &ins);
  int score = 0;
  int pushes = 0;
  bool saw_fq = false;
  bool saw_xfer = false;

  for (std::size_t i = 0; i < n; i++) {
    std::string m = ins[i].mnemonic;
    if (m == "push") {
      pushes++;
      score += 4;
    } else if (m == "pushfq") {
      saw_fq = true;
      score += 12;
    } else if (m == "mov" || m == "lea") {
      score += 2;
    } else if (m == "jmp" || m == "call") {
      saw_xfer = true;
      if (ins[i].detail && ins[i].detail->x86.op_count >= 1) {
        const auto& op = ins[i].detail->x86.operands[0];
        if (op.type == X86_OP_IMM && looks_like_vmp_region(static_cast<std::uint64_t>(op.imm))) {
          score += 25;
        } else if (op.type == X86_OP_REG) {
          score += 8;
        }
      }
      break;
    } else if (m == "ret" || m == "int3" || m == "ud2") {
      score -= 20;
      break;
    } else if (m == "nop") {
      score -= 1;
    }
  }

  if (pushes >= 4 && saw_fq) {
    score += 15;
  } else if (pushes >= 2 && saw_fq) {
    score += 8;
  }
  if (!saw_xfer && pushes < 2) {
    score = score / 2;
  }

  cs_free(ins, n);
  cs_close(&cs);
  if (score < 0) {
    score = 0;
  }
  if (score > 100) {
    score = 100;
  }
  return score;
}

std::optional<std::uint64_t> VmenterScanner::follow_code_stub(std::uint64_t va,
                                                              std::size_t max_insns) const {
  auto bytes = image_.read_at_va(va, 64);
  if (bytes.size() < 5) {
    return std::nullopt;
  }

  csh cs{};
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs) != CS_ERR_OK) {
    return std::nullopt;
  }
  cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);

  cs_insn* ins = nullptr;
  auto n = cs_disasm(cs, bytes.data(), bytes.size(), va, max_insns, &ins);
  std::optional<std::uint64_t> jmp_target;
  for (std::size_t i = 0; i < n; i++) {
    std::string m = ins[i].mnemonic;
    if (m == "jmp" && ins[i].detail && ins[i].detail->x86.op_count >= 1) {
      const auto& op = ins[i].detail->x86.operands[0];
      if (op.type == X86_OP_IMM) {
        jmp_target = static_cast<std::uint64_t>(op.imm);
        break;
      }
    }

    if (m == "call" || m == "ret" || m == "pushfq") {
      break;
    }
  }
  cs_free(ins, n);
  cs_close(&cs);
  return jmp_target;
}

std::optional<VmenterSite> VmenterScanner::probe_entry(std::uint64_t va, VmenterKind kind,
                                                       const std::string& source,
                                                       int confidence) const {
  if (!is_likely_code_va(va)) {
    return std::nullopt;
  }
  VmenterSite site;
  site.va = va;
  site.rva = image_.va_to_rva(va).value_or(0);
  site.kind = kind;
  site.source = source;
  site.confidence = confidence;

  if (auto tgt = follow_code_stub(va, 8)) {
    if (looks_like_vmp_region(*tgt)) {
      site.first_handler_va = *tgt;
    }
  }
  return site;
}

std::vector<VmenterSite> VmenterScanner::scan_exports() const {
  std::vector<VmenterSite> out;
  for (const auto& [name, rva] : image_.named_exports()) {
    auto export_va = image_.image_base() + rva;
    auto target = follow_code_stub(export_va);
    if (!target) {

      if (looks_like_vmp_region(export_va) && score_prologue(export_va) >= 20) {
        target = export_va;
      } else {
        continue;
      }
    }
    if (!looks_like_vmp_region(*target)) {
      continue;
    }
    int conf = 90 + std::min(8, score_prologue(*target) / 12);
    auto site = probe_entry(*target, VmenterKind::ExportStubJump, "export:" + name, conf);
    if (site) {
      site->first_handler_va = *target;
      out.push_back(*site);
    }
  }
  return out;
}

std::vector<VmenterSite> VmenterScanner::scan_entry_point() const {
  std::vector<VmenterSite> out;
  auto ep = image_.image_base() + image_.entry_point_rva();
  if (!image_.contains_va(ep)) {
    return out;
  }

  std::uint64_t cur = ep;
  for (int hop = 0; hop < 4; hop++) {
    if (looks_like_vmp_region(cur)) {
      int sc = score_prologue(cur);

      int conf = 0;
      if (sc >= 40) {
        conf = 88 + std::min(10, sc / 10);
      } else if (sc >= 20) {
        conf = 50 + sc / 4;
      } else {
        conf = std::min(35, sc);
      }
      auto site = probe_entry(cur, VmenterKind::EntryPoint,
                              hop == 0 ? "entry" : "entry:hop" + std::to_string(hop), conf);
      if (site) {
        out.push_back(*site);
      }
      break;
    }
    auto next = follow_code_stub(cur);
    if (!next || *next == cur) {
      break;
    }
    cur = *next;
  }
  return out;
}

std::vector<VmenterSite> VmenterScanner::scan_vmp_sections() const {
  std::vector<VmenterSite> out;
  std::set<std::uint64_t> seen;

  auto add_site = [&](std::uint64_t va, VmenterKind kind, const std::string& src, int conf) {
    if (!seen.insert(va).second) return;
    if (auto s = probe_entry(va, kind, src, conf)) out.push_back(*s);
  };


  for (const auto& sec : image_.sections()) {
    if (!is_vmp_section_name(sec.name) && sec.name != ".text") continue;
    auto start = image_.image_base() + sec.virtual_address;
    auto scan_sz = sec.raw_size ? sec.raw_size : sec.virtual_size;
    if (scan_sz > 0x400000) scan_sz = 0x400000;
    auto chunk = image_.read_at_va(start, static_cast<std::size_t>(scan_sz));
    if (chunk.size() < 10) continue;

    for (std::size_t i = 0; i + 10 < chunk.size(); i++) {
      if (chunk[i] != 0x68 || chunk[i + 5] != 0xE8) continue;
      auto va = start + i;
      auto rel = static_cast<std::int32_t>(chunk[i + 6] | (chunk[i + 7] << 8) |
                                           (chunk[i + 8] << 16) | (chunk[i + 9] << 24));
      auto call_va = va + 5;
      auto stub = static_cast<std::uint64_t>(static_cast<std::int64_t>(call_va + 5) + rel);
      if (!image_.contains_va(stub) || !looks_like_vmp_region(stub)) continue;
      int stub_sc = score_prologue(stub);
      if (stub_sc < 40) continue;
      int conf = 88 + std::min(10, stub_sc / 10);
      if (conf > 98) conf = 98;
      add_site(va, VmenterKind::PushCallEnter, sec.name + ":push+call", conf);
    }
  }

  {
    auto ep = image_.image_base() + image_.entry_point_rva();

    for (const auto& sec : image_.sections()) {
      if (sec.name != ".text") continue;
      auto start = image_.image_base() + sec.virtual_address;
      auto chunk = image_.read_at_va(start, std::min<std::uint32_t>(sec.raw_size ? sec.raw_size : 0x2000, 0x2000));
      csh cs{};
      if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs) != CS_ERR_OK) break;
      cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);
      cs_insn* ins = nullptr;
      auto n = cs_disasm(cs, chunk.data(), chunk.size(), start, 64, &ins);
      for (std::size_t i = 0; i < n; i++) {
        std::string m = ins[i].mnemonic;
        if ((m != "jmp" && m != "call") || !ins[i].detail) continue;
        const auto& op = ins[i].detail->x86.operands[0];
        if (op.type != X86_OP_IMM) continue;
        auto t = static_cast<std::uint64_t>(op.imm);
        auto b = image_.read_at_va(t, 10);
        if (b.size() < 10 || b[0] != 0x68 || b[5] != 0xE8) continue;
        add_site(t, VmenterKind::PushCallEnter, ".text:jmp->push+call", 96);
      }
      cs_free(ins, n);
      cs_close(&cs);
      (void)ep;
    }
  }

  for (const auto& sec : image_.sections()) {
    if (!is_vmp_section_name(sec.name) && sec.name != ".text") {
      continue;
    }
    auto start = image_.image_base() + sec.virtual_address;
    auto scan_sz = sec.raw_size ? sec.raw_size : sec.virtual_size;
    if (sec.name == ".text") {
      if (scan_sz > 0x20000) {
        scan_sz = 0x20000;
      }
    } else if (scan_sz > 0x400000) {
      scan_sz = 0x400000;
    }

    auto chunk = image_.read_at_va(start, static_cast<std::size_t>(scan_sz));
    if (chunk.size() < 16) {
      continue;
    }

    for (std::size_t i = 0; i + 16 < chunk.size(); i += 16) {
      auto va = start + i;
      if (seen.count(va)) continue;

      std::vector<std::uint8_t> win(chunk.begin() + static_cast<std::ptrdiff_t>(i),
                                    chunk.begin() + static_cast<std::ptrdiff_t>(i + 16));

      int base = 0;
      VmenterKind kind = VmenterKind::ClassicPushImm;
      std::string src = sec.name;

      if (looks_like_push_reg_fq(win)) {
        base = 55;
        kind = VmenterKind::PushFqMovAbs;
        src += ":push+fq";
      } else if (looks_like_pushfq(win)) {
        base = 50;
        kind = VmenterKind::PushFqMovAbs;
      } else if (looks_like_push_imm(win)) {

        base = 55;
        kind = VmenterKind::ClassicPushImm;
        src += ":push_imm";
      } else {
        continue;
      }

      int sc = score_prologue(va);
      if (sc < 25) {
        continue;
      }
      int conf = base + std::min(25, sc / 3);
      if (conf > 82) {
        conf = 82;
      }

      add_site(va, kind, src, conf);
    }
  }

  std::sort(out.begin(), out.end(), [](const VmenterSite& a, const VmenterSite& b) {
    if (a.confidence != b.confidence) {
      return a.confidence > b.confidence;
    }
    return a.va < b.va;
  });
  if (out.size() > 180) {
    out.resize(180);
  }
  return out;
}

std::vector<VmenterSite> VmenterScanner::scan_all() const {
  std::vector<VmenterSite> all;
  std::set<std::uint64_t> dedupe;

  auto merge = [&](const std::vector<VmenterSite>& batch) {
    for (const auto& s : batch) {
      auto key = s.va & ~0xFULL;
      if (dedupe.insert(key).second) {
        all.push_back(s);
      }
    }
  };

  merge(scan_exports());
  merge(scan_entry_point());
  merge(scan_vmp_sections());

  std::sort(all.begin(), all.end(), [](const VmenterSite& a, const VmenterSite& b) {
    if (a.confidence != b.confidence) {
      return a.confidence > b.confidence;
    }

    auto rank = [](VmenterKind k) {
      switch (k) {
        case VmenterKind::ExportStubJump:
          return 0;
        case VmenterKind::EntryPoint:
          return 1;
        default:
          return 2;
      }
    };
    if (rank(a.kind) != rank(b.kind)) {
      return rank(a.kind) < rank(b.kind);
    }
    return a.va < b.va;
  });
  return all;
}

std::optional<std::uint64_t> VmenterScanner::pick_best(const std::vector<VmenterSite>& sites) {
  if (sites.empty()) {
    return std::nullopt;
  }

  for (const auto& s : sites) {
    if (s.kind == VmenterKind::ExportStubJump && s.confidence >= 88) {
      return s.va;
    }
  }

  for (const auto& s : sites) {
    if (s.kind == VmenterKind::PushCallEnter && s.confidence >= 85) {
      return s.va;
    }
  }

  for (const auto& s : sites) {
    if (s.kind != VmenterKind::EntryPoint && s.confidence >= 60 &&
        (s.source.find("push") != std::string::npos || s.source.find("fq") != std::string::npos ||
         s.confidence >= 68)) {
      return s.va;
    }
  }

  for (const auto& s : sites) {
    if (s.kind == VmenterKind::EntryPoint && s.confidence >= 85) {
      return s.va;
    }
  }

  for (const auto& s : sites) {
    if (s.confidence >= 88) {
      return s.va;
    }
  }

  return sites.front().va;
}

}
