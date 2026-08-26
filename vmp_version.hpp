#pragma once

#include "pe_image.hpp"

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
  std::vector<std::string> vmp_sections;
};

VersionInfo detect_version(const PeImage& image);

}
