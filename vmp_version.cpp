#include "util.hpp"
#include "vmp_version.hpp"

namespace vmp {

VersionInfo detect_version(const PeImage& image) {
  VersionInfo info;
  bool vmp0 = false;
  bool vmp1 = false;
  bool weird_sections = false;

  for (const auto& sec : image.sections()) {
    if (sec.name == ".vmp0") {
      vmp0 = true;
      info.vmp_sections.push_back(sec.name);
    } else if (sec.name == ".vmp1") {
      vmp1 = true;
      info.vmp_sections.push_back(sec.name);
    } else if (is_vmp_section_name(sec.name)) {
      info.vmp_sections.push_back(sec.name);
      if (sec.name != ".vmp0" && sec.name != ".vmp1" && sec.name != ".vmp2") {
        weird_sections = true;
      }
    }
  }

  info.randomized_sections = weird_sections;

  if (vmp0 && vmp1) {
    info.version = VmpVersion::Vmp35;
    info.label = "VMProtect 3.5.x";
    info.uses_rolling_key = true;
    info.has_merged_handlers = false;
    return info;
  }

  if (vmp0 || vmp1) {
    info.version = VmpVersion::Vmp36;
    info.label = "VMProtect 3.6.x";
    info.uses_rolling_key = true;
    info.has_merged_handlers = true;
    return info;
  }

  if (weird_sections || !info.vmp_sections.empty()) {
    info.version = VmpVersion::Vmp38Plus;

    info.label = "VMProtect 3.8-3.10+ (merged handlers)";
    info.uses_rolling_key = true;
    info.has_merged_handlers = true;
    return info;
  }

  if (!info.vmp_sections.empty()) {
    info.version = VmpVersion::Vmp30;
    info.label = "VMProtect 3.0-3.4";
    return info;
  }

  info.version = VmpVersion::Unknown;
  info.label = "Unknown / unpacked";
  return info;
}

}
