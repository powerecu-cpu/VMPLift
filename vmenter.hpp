#pragma once

#include "pe_image.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace vmp {

enum class VmenterKind {
  ClassicPushImm,
  PushFqMovAbs,
  ExportStubJump,
  EntryPoint,
  CallSetup,
  PushCallEnter,
};

struct VmenterSite {
  std::uint64_t va = 0;
  std::uint64_t rva = 0;
  VmenterKind kind = VmenterKind::ClassicPushImm;
  std::string source;
  int confidence = 0;
  std::uint64_t first_handler_va = 0;
};

class VmenterScanner {
public:
  explicit VmenterScanner(const PeImage& image);

  std::vector<VmenterSite> scan_all() const;
  std::vector<VmenterSite> scan_exports() const;
  std::vector<VmenterSite> scan_entry_point() const;
  std::vector<VmenterSite> scan_vmp_sections() const;

  static std::optional<std::uint64_t> pick_best(const std::vector<VmenterSite>& sites);

private:
  const PeImage& image_;

  bool is_likely_code_va(std::uint64_t va) const;
  bool looks_like_vmp_region(std::uint64_t va) const;
  int score_prologue(std::uint64_t va) const;

  std::optional<VmenterSite> probe_entry(std::uint64_t va, VmenterKind kind,
                                         const std::string& source, int confidence) const;
  std::optional<std::uint64_t> follow_code_stub(std::uint64_t va, std::size_t max_insns = 12) const;
};

}
