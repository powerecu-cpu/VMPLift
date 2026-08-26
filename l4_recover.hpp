#pragma once

#include "handler_classify.hpp"
#include "pe_image.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace vmp {

struct L4Result {
  bool ok = false;
  std::string method;
  std::string c_source;
  std::string summary;
  std::uint64_t probe_rax = 0;
  bool matches_add = false;
  bool matches_xor = false;
  bool matches_and = false;
  bool matches_or = false;
  bool matches_identity_b = false;
};

L4Result recover_l4(const PeImage& image, std::uint64_t vmenter_va,
                    const DevirtResult& sem_devirt);

}
