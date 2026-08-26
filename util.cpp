#include "util.hpp"

#include <cctype>
#include <iomanip>
#include <sstream>

namespace vmp {

std::string hex_u64(std::uint64_t value, bool prefix) {
  std::ostringstream oss;
  if (prefix) {
    oss << "0x";
  }
  oss << std::hex << std::nouppercase << value;
  return oss.str();
}

std::optional<std::uint64_t> parse_hex_u64(const std::string& text) {
  if (text.empty()) {
    return std::nullopt;
  }
  std::string value = text;
  if (value.rfind("0x", 0) == 0 || value.rfind("0X", 0) == 0) {
    value = value.substr(2);
  }
  if (value.empty()) {
    return std::nullopt;
  }
  for (char ch : value) {
    if (!std::isxdigit(static_cast<unsigned char>(ch))) {
      return std::nullopt;
    }
  }
  return std::stoull(value, nullptr, 16);
}

bool is_vmp_section_name(const std::string& name) {
  if (name.rfind(".vmp", 0) == 0) {
    return true;
  }
  if (name == ".kbB0" || name == ".kbB1") {
    return true;
  }
  if (name.size() >= 2 && name[0] == '.' && name != ".text" && name != ".rdata" &&
      name != ".data" && name != ".pdata" && name != ".rsrc" && name != ".reloc" &&
      name != ".idata" && name != ".edata" && name != ".tls" && name != ".debug" &&
      name != ".fptable") {
    const auto is_standard = name == ".bss" || name == ".CRT" || name == ".gfids";
    if (!is_standard) {
      return true;
    }
  }
  return false;
}

}
