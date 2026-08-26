#pragma once

#include "pe_image.hpp"
#include "vm_types.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace vmp {

bool unicorn_available();

std::optional<std::uint64_t> unicorn_tail_next(const PeImage& image, std::uint64_t handler_va,
                                               std::size_t max_insns = 2048);

std::vector<std::uint64_t> unicorn_discover_edges(const PeImage& image, std::uint64_t root_va,
                                                  std::size_t max_handlers = 256,
                                                  std::size_t max_insns = 2048);

std::string x86_reg_name(int capstone_reg);

}
