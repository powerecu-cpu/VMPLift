#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace vmp {

struct SectionInfo {
  std::string name;
  std::uint64_t virtual_address = 0;
  std::uint64_t virtual_size = 0;
  std::uint64_t raw_offset = 0;
  std::uint64_t raw_size = 0;
  std::uint32_t characteristics = 0;
};

class PeImage {
public:
  static PeImage load(const std::string& path);

  const std::string& path() const { return path_; }
  bool is_64bit() const { return is_64bit_; }
  std::uint64_t image_base() const { return image_base_; }
  std::uint64_t entry_point_rva() const { return entry_point_rva_; }
  std::uint64_t size_of_image() const { return size_of_image_; }
  const std::vector<SectionInfo>& sections() const { return sections_; }
  const std::vector<std::uint8_t>& bytes() const { return bytes_; }

  std::optional<std::uint64_t> rva_to_va(std::uint64_t rva) const;
  std::optional<std::uint64_t> va_to_rva(std::uint64_t va) const;
  std::optional<std::uint64_t> va_to_offset(std::uint64_t va) const;
  std::optional<std::uint64_t> offset_to_va(std::uint64_t offset) const;

  bool contains_va(std::uint64_t va) const;
  const SectionInfo* section_for_va(std::uint64_t va) const;
  const SectionInfo* section_by_name(const std::string& name) const;

  std::vector<std::uint8_t> read_at_va(std::uint64_t va, std::size_t size) const;
  std::optional<std::uint8_t> read_u8(std::uint64_t va) const;
  std::optional<std::uint32_t> read_u32(std::uint64_t va) const;
  std::optional<std::uint64_t> read_u64(std::uint64_t va) const;

  std::vector<std::uint64_t> export_rvas() const;
  std::vector<std::pair<std::string, std::uint64_t>> named_exports() const;

private:
  PeImage() = default;

  std::string path_;
  bool is_64bit_ = false;
  std::uint64_t image_base_ = 0;
  std::uint64_t size_of_image_ = 0;
  std::uint64_t entry_point_rva_ = 0;
  std::vector<SectionInfo> sections_;
  std::vector<std::uint8_t> bytes_;
  std::vector<std::uint64_t> export_rvas_;
  std::vector<std::pair<std::string, std::uint64_t>> named_exports_;
};

}
