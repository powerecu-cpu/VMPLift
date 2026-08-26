#pragma once

#include "handler_walker.hpp"
#include "ir_lifter.hpp"
#include "ir_optimizer.hpp"
#include "pe_image.hpp"
#include "vmenter.hpp"
#include "vmp_version.hpp"

#include <nlohmann/json.hpp>
#include <string>

namespace vmp {

struct DevirtOptions {
  std::uint64_t vmenter_va = 0;
  std::size_t max_handlers = 256;
  std::size_t max_insns_per_handler = 128;
  std::size_t max_callgraph_depth = 8;
  std::size_t max_vip_steps = 256;
  bool use_callgraph = true;
  bool emit_llvm = true;
  bool emit_pseudo_c = true;
  bool export_json = true;
  bool emit_devirt = true;
};

struct DevirtReport {
  VersionInfo version;
  std::vector<VmenterSite> vmenters;
  WalkResult walk;
  DiscoveryResult discovery;
  std::vector<IrFunction> functions;
  std::string llvm_ir;
  std::string pseudo_c;
  std::string vip_trace_text;
  std::string vasm;
  std::string native_pseudo;
  std::string native_l4;
  nlohmann::json summary;
  nlohmann::json vip_trace_json;
  nlohmann::json devirt_json;
};

class DevirtEngine {
public:
  explicit DevirtEngine(PeImage image);

  const PeImage& image() const { return image_; }
  VersionInfo version() const { return version_; }

  std::vector<VmenterSite> scan_vmenters() const;
  DevirtReport lift(const DevirtOptions& opts) const;
  std::string format_text_report(const DevirtReport& report) const;

private:
  PeImage image_;
  VersionInfo version_;
};

}
