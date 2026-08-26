#include "pe_image.hpp"
#include "util.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <cstring>
#include <fstream>
#include <stdexcept>

namespace vmp {

namespace {

std::string trim_name(const char* raw, std::size_t n) {
  std::string s(raw, strnlen(raw, n));
  while (!s.empty() && s.back() == '\0') {
    s.pop_back();
  }
  return s;
}

}

PeImage PeImage::load(const std::string& path) {
  PeImage img;
  img.path_ = path;

  std::ifstream f(path, std::ios::binary);
  if (!f) {
    throw std::runtime_error("failed to open: " + path);
  }

  f.seekg(0, std::ios::end);
  auto file_size = static_cast<std::size_t>(f.tellg());
  f.seekg(0, std::ios::beg);
  img.bytes_.resize(file_size);
  f.read(reinterpret_cast<char*>(img.bytes_.data()), static_cast<std::streamsize>(file_size));

  if (file_size < sizeof(IMAGE_DOS_HEADER)) {
    throw std::runtime_error("file too small");
  }

  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(img.bytes_.data());
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
    throw std::runtime_error("not MZ");
  }

  if (static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > file_size) {
    throw std::runtime_error("bad pe offset");
  }

  const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(img.bytes_.data() + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) {
    throw std::runtime_error("not PE");
  }

  img.is_64bit_ = nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  if (!img.is_64bit_) {
    throw std::runtime_error("x64 only");
  }

  img.image_base_ = nt->OptionalHeader.ImageBase;
  img.size_of_image_ = nt->OptionalHeader.SizeOfImage;
  img.entry_point_rva_ = nt->OptionalHeader.AddressOfEntryPoint;

  const auto* sh = IMAGE_FIRST_SECTION(nt);
  for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
    SectionInfo si;
    si.name = trim_name(reinterpret_cast<const char*>(sh[i].Name), IMAGE_SIZEOF_SHORT_NAME);
    si.virtual_address = sh[i].VirtualAddress;
    si.virtual_size = sh[i].Misc.VirtualSize;
    si.raw_offset = sh[i].PointerToRawData;
    si.raw_size = sh[i].SizeOfRawData;
    si.characteristics = sh[i].Characteristics;
    img.sections_.push_back(si);
  }

  auto export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
  if (export_rva != 0) {
    auto export_off = img.va_to_offset(img.image_base_ + export_rva);
    if (export_off) {
      const auto* exp =
          reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(img.bytes_.data() + *export_off);
      auto names_off = img.va_to_offset(img.image_base_ + exp->AddressOfNames);
      auto ordinals_off = img.va_to_offset(img.image_base_ + exp->AddressOfNameOrdinals);
      auto funcs_off = img.va_to_offset(img.image_base_ + exp->AddressOfFunctions);

      if (names_off && ordinals_off && funcs_off) {
        const auto* names =
            reinterpret_cast<const std::uint32_t*>(img.bytes_.data() + *names_off);
        const auto* ords =
            reinterpret_cast<const std::uint16_t*>(img.bytes_.data() + *ordinals_off);
        const auto* funcs =
            reinterpret_cast<const std::uint32_t*>(img.bytes_.data() + *funcs_off);

        for (std::uint32_t i = 0; i < exp->NumberOfNames; i++) {
          auto name_off = img.va_to_offset(img.image_base_ + names[i]);
          if (!name_off) {
            continue;
          }
          const char* ename = reinterpret_cast<const char*>(img.bytes_.data() + *name_off);
          auto ord = ords[i];
          auto fn_rva = funcs[ord];
          img.export_rvas_.push_back(fn_rva);
          img.named_exports_.emplace_back(ename, fn_rva);
        }
      }
    }
  }

  return img;
}

std::optional<std::uint64_t> PeImage::rva_to_va(std::uint64_t rva) const {
  return image_base_ + rva;
}

std::optional<std::uint64_t> PeImage::va_to_rva(std::uint64_t va) const {
  if (va < image_base_) {
    return std::nullopt;
  }
  return va - image_base_;
}

std::optional<std::uint64_t> PeImage::va_to_offset(std::uint64_t va) const {
  auto rva = va_to_rva(va);
  if (!rva) {
    return std::nullopt;
  }
  for (const auto& sec : sections_) {
    auto sec_end = sec.virtual_address + (sec.virtual_size > sec.raw_size ? sec.virtual_size
                                                                            : sec.raw_size);
    if (*rva >= sec.virtual_address && *rva < sec_end) {
      auto delta = *rva - sec.virtual_address;
      auto off = sec.raw_offset + delta;
      if (off < bytes_.size()) {
        return off;
      }
    }
  }
  return std::nullopt;
}

std::optional<std::uint64_t> PeImage::offset_to_va(std::uint64_t offset) const {
  for (const auto& sec : sections_) {
    if (offset >= sec.raw_offset && offset < sec.raw_offset + sec.raw_size) {
      return image_base_ + sec.virtual_address + (offset - sec.raw_offset);
    }
  }
  return std::nullopt;
}

bool PeImage::contains_va(std::uint64_t va) const {
  auto rva = va_to_rva(va);
  if (!rva) {
    return false;
  }
  return *rva < size_of_image_;
}

const SectionInfo* PeImage::section_for_va(std::uint64_t va) const {
  auto rva = va_to_rva(va);
  if (!rva) {
    return nullptr;
  }
  for (const auto& sec : sections_) {
    if (*rva >= sec.virtual_address && *rva < sec.virtual_address + sec.virtual_size) {
      return &sec;
    }
  }
  return nullptr;
}

const SectionInfo* PeImage::section_by_name(const std::string& name) const {
  for (const auto& sec : sections_) {
    if (sec.name == name) {
      return &sec;
    }
  }
  return nullptr;
}

std::vector<std::uint8_t> PeImage::read_at_va(std::uint64_t va, std::size_t size) const {
  auto off = va_to_offset(va);
  if (!off) {
    return {};
  }
  if (*off + size > bytes_.size()) {
    return {};
  }
  return {bytes_.begin() + static_cast<std::ptrdiff_t>(*off),
          bytes_.begin() + static_cast<std::ptrdiff_t>(*off + size)};
}

std::optional<std::uint8_t> PeImage::read_u8(std::uint64_t va) const {
  auto d = read_at_va(va, 1);
  if (d.empty()) {
    return std::nullopt;
  }
  return d[0];
}

std::optional<std::uint32_t> PeImage::read_u32(std::uint64_t va) const {
  auto d = read_at_va(va, 4);
  if (d.size() != 4) {
    return std::nullopt;
  }
  return static_cast<std::uint32_t>(d[0]) | (static_cast<std::uint32_t>(d[1]) << 8) |
         (static_cast<std::uint32_t>(d[2]) << 16) | (static_cast<std::uint32_t>(d[3]) << 24);
}

std::optional<std::uint64_t> PeImage::read_u64(std::uint64_t va) const {
  auto d = read_at_va(va, 8);
  if (d.size() != 8) {
    return std::nullopt;
  }
  std::uint64_t v = 0;
  for (int i = 0; i < 8; i++) {
    v |= static_cast<std::uint64_t>(d[i]) << (8 * i);
  }
  return v;
}

std::vector<std::uint64_t> PeImage::export_rvas() const { return export_rvas_; }

std::vector<std::pair<std::string, std::uint64_t>> PeImage::named_exports() const {
  return named_exports_;
}

}
