#pragma once

#include "pe_image.hpp"

#include <string>
#include <vector>

namespace vmp {

enum class VmpVersion {
  Unknown,
  Vmp30,
  Vmp35,
  Vmp36,
  Vmp38Plus,
};

struct VersionInfo {
  VmpVersion version = VmpVersion::Unknown;
  std::string label;
  bool has_merged_handlers = false;
  bool uses_rolling_key = false;
  bool randomized_sections = false;
  bool packed = false;
  bool chain_dispatch = false;
  int confidence = 0;
  int push_call_enters = 0;
  int handler_insns = 0;
  double entropy = 0;
  std::string why;
  std::string ep_sig;
  std::vector<std::string> vmp_sections;
};

VersionInfo detect_version(const PeImage& image);

}
