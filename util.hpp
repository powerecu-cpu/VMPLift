#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace vmp {

std::string hex_u64(std::uint64_t value, bool prefix = true);
std::optional<std::uint64_t> parse_hex_u64(const std::string& text);
bool is_vmp_section_name(const std::string& name);

}
