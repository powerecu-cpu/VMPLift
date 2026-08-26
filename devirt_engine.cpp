#include "devirt_engine.hpp"

#include "handler_walker.hpp"
#include "handler_classify.hpp"
#include "indirect_dispatch.hpp"
#include "util.hpp"
#include "vip_context.hpp"

#include <sstream>

namespace vmp {

DevirtEngine::DevirtEngine(PeImage image)
    : image_(std::move(image)), version_(detect_version(image_)) {}

std::vector<VmenterSite> DevirtEngine::scan_vmenters() const {
  VmenterScanner sc(image_);
  return sc.scan_all();
}

static void do_lift(const std::vector<HandlerBlock>& blocks, const DevirtOptions& opts,
                    IrLifter& lifter, IrOptimizer& opt, DevirtReport& report,
                    std::ostringstream& llvm, std::ostringstream& pseudo) {
  int idx = 0;
  for (const auto& h : blocks) {
    auto fn = opt.optimize(lifter.lift_handler(h, idx++));
    report.functions.push_back(fn);
    if (opts.emit_llvm) {
      llvm << lifter.emit_llvm_text(fn);
    }
    if (opts.emit_pseudo_c) {
      pseudo << lifter.emit_pseudo_c(fn);
    }
  }
}

DevirtReport DevirtEngine::lift(const DevirtOptions& opts) const {
  DevirtReport report;
  report.version = version_;
  report.vmenters = scan_vmenters();

  std::uint64_t entry = opts.vmenter_va;
  if (entry == 0) {
    if (auto best = VmenterScanner::pick_best(report.vmenters)) {
      entry = *best;
    } else {
      throw std::runtime_error("no vmenter — pass --vmenter");
    }
  }

  HandlerWalker walker(image_, image_.image_base());

  std::vector<HandlerBlock> blocks;
  if (opts.use_callgraph) {
    DiscoveryOptions dopts;
    dopts.max_blocks = opts.max_handlers;
    dopts.max_depth = opts.max_callgraph_depth;
    dopts.max_insns_per_block = opts.max_insns_per_handler;
    dopts.vmp_sections_only = true;

    report.discovery = walker.discover(entry, dopts);
    blocks = report.discovery.blocks;

    report.walk.start_va = entry;
    report.walk.handlers = blocks;
    report.walk.truncated = report.discovery.truncated;
  } else {
    report.walk = walker.walk_from(entry, opts.max_handlers, opts.max_insns_per_handler);
    blocks = report.walk.handlers;
  }

  IrLifter lifter;
  IrOptimizer optimizer;

  std::ostringstream llvm;
  std::ostringstream pseudo;

  llvm << "; lift\n";
  llvm << "; " << image_.path() << "\n";
  llvm << "; " << report.version.label << "\n";
  llvm << "; entry " << hex_u64(entry) << "\n";
  llvm << "; mode " << (opts.use_callgraph ? "callgraph" : "chain") << "\n";
  llvm << "; blocks " << blocks.size() << "\n\n";

  do_lift(blocks, opts, lifter, optimizer, report, llvm, pseudo);

  report.llvm_ir = llvm.str();
  report.pseudo_c = pseudo.str();

  auto vip_tr = unicorn_vip_trace(image_, entry, std::min<std::size_t>(opts.max_handlers, 256),
                                  std::max<std::size_t>(opts.max_insns_per_handler * 16, 4096));
  report.vip_trace_text = format_vip_trace_text(vip_tr);
  report.vip_trace_json = {
      {"seed_note", vip_tr.seed.note},
      {"seeded", vip_tr.seeded},
      {"initial_vip", hex_u64(vip_tr.initial_vip)},
      {"key_candidate", hex_u64(vip_tr.rolling_key)},
      {"steps", vip_tr.steps.size()},
  };
  if (vip_tr.seed.enc_push_imm) {
    report.vip_trace_json["enc_push_imm"] = hex_u64(*vip_tr.seed.enc_push_imm);
  }
  nlohmann::json steps = nlohmann::json::array();
  for (const auto& s : vip_tr.steps) {
    nlohmann::json j = {{"handler", hex_u64(s.handler_va)},
                        {"vip", hex_u64(s.vip)},
                        {"fetch_enc", hex_u64(s.fetched_enc)},
                        {"note", s.note}};
    if (s.next_handler) j["next"] = hex_u64(*s.next_handler);
    if (!s.vip_reg.empty()) j["vip_reg"] = s.vip_reg;
    steps.push_back(j);
  }
  report.vip_trace_json["trace"] = steps;

  if (opts.emit_pseudo_c && !report.vip_trace_text.empty()) {
    report.pseudo_c = report.vip_trace_text + "\n" + report.pseudo_c;
  }

  if (opts.emit_devirt) {
    auto dv = run_devirt(image_, entry, blocks, opts.max_vip_steps);
    report.vasm = std::move(dv.vasm);
    report.native_pseudo = std::move(dv.native_pseudo);
    report.native_l4 = std::move(dv.native_l4);
    report.devirt_json = {
        {"classified", dv.classified},
        {"unknown", dv.unknown},
        {"stream_ops", dv.stream.size()},
        {"handlers", dv.handlers.size()},
        {"vip_seeded", dv.vip.seeded},
        {"vip_steps", dv.vip.steps.size()},
        {"rolling_key", hex_u64(dv.vip.rolling_key)},
        {"l4", dv.l4_summary},
    };
    nlohmann::json ops = nlohmann::json::array();
    for (const auto& op : dv.stream) {
      nlohmann::json j = {{"i", op.index},
                          {"op", op.mnemonic},
                          {"handler", hex_u64(op.handler_va)},
                          {"conf", op.confidence},
                          {"vip", hex_u64(op.vip)},
                          {"fetch_enc", hex_u64(op.fetch_enc)},
                          {"semantic", op.semantic},
                          {"comment", op.comment}};
      if (op.fetch_dec) j["fetch_dec"] = hex_u64(*op.fetch_dec);
      if (op.next) j["next"] = hex_u64(*op.next);
      ops.push_back(j);
    }
    report.devirt_json["ops"] = ops;

    auto vmfn = optimizer.optimize(lifter.lift_vm_stream(dv.stream, entry));
    report.functions.insert(report.functions.begin(), vmfn);
    if (opts.emit_llvm) {
      llvm.str("");
      llvm.clear();
      llvm << "; lift\n";
      llvm << "; " << image_.path() << "\n";
      llvm << "; " << report.version.label << "\n";
      llvm << "; entry " << hex_u64(entry) << "\n\n";
      llvm << lifter.emit_llvm_text(vmfn);
      for (std::size_t i = 1; i < report.functions.size(); i++) {
        llvm << lifter.emit_llvm_text(report.functions[i]);
      }
    }
    if (opts.emit_pseudo_c) {
      pseudo.str("");
      pseudo.clear();
      pseudo << lifter.emit_pseudo_c(vmfn);
      for (std::size_t i = 1; i < report.functions.size(); i++) {
        pseudo << lifter.emit_pseudo_c(report.functions[i]);
      }
    }
  }

  std::size_t insn_count = 0;
  for (const auto& b : blocks) {
    insn_count += b.insns.size();
  }

  report.summary = {
      {"binary", image_.path()},
      {"image_base", hex_u64(image_.image_base())},
      {"version", report.version.label},
      {"version_why", report.version.why},
      {"version_conf", report.version.confidence},
      {"merged_handlers", report.version.has_merged_handlers},
      {"rolling_key", report.version.uses_rolling_key},
      {"vmenter", hex_u64(entry)},
      {"mode", opts.use_callgraph ? "callgraph" : "chain"},
      {"handlers_discovered", blocks.size()},
      {"handlers_lifted", report.functions.size()},
      {"total_insns", insn_count},
      {"walk_truncated", report.walk.truncated},
      {"vmenter_candidates", report.vmenters.size()},
      {"vip_steps", vip_tr.steps.size()},
      {"vip_seeded", vip_tr.seeded},
      {"vip_initial", hex_u64(vip_tr.initial_vip)},
  };
  if (opts.emit_devirt && report.devirt_json.contains("classified")) {
    report.summary["devirt_classified"] = report.devirt_json["classified"];
    report.summary["devirt_unknown"] = report.devirt_json["unknown"];
    report.summary["devirt_ops"] = report.devirt_json["stream_ops"];
    if (report.devirt_json.contains("l4")) report.summary["l4"] = report.devirt_json["l4"];
  }

  report.summary["unicorn"] = unicorn_available();

  return report;
}

std::string DevirtEngine::format_text_report(const DevirtReport& report) const {
  std::ostringstream oss;
  oss << "vmp-lift report\n";
  oss << "==============\n";
  oss << "binary:      " << image_.path() << "\n";
  oss << "image base:  " << hex_u64(image_.image_base()) << "\n";
  oss << "version:     " << report.version.label << " (conf " << report.version.confidence
      << ")\n";
  if (!report.version.why.empty()) {
    oss << "version why: " << report.version.why << "\n";
  }
  oss << "mode:        " << report.summary.value("mode", "callgraph") << "\n";
  oss << "vmp sections:";
  for (const auto& sec : report.version.vmp_sections) {
    oss << " " << sec;
  }
  oss << "\n\n";

  oss << "VMENTER candidates (" << report.vmenters.size() << ", top 25):\n";
  auto show_n = report.vmenters.size();
  if (show_n > 25) {
    show_n = 25;
  }
  for (std::size_t i = 0; i < show_n; i++) {
    const auto& site = report.vmenters[i];
    oss << "  " << hex_u64(site.va) << " rva=" << hex_u64(site.rva) << " conf=" << site.confidence
        << " src=" << site.source;
    if (site.first_handler_va) {
      oss << " target=" << hex_u64(site.first_handler_va);
    }
    oss << "\n";
  }
  if (report.vmenters.size() > show_n) {
    oss << "  ... " << (report.vmenters.size() - show_n) << " more\n";
  }

  const auto& blocks =
      report.walk.handlers.empty() ? report.discovery.blocks : report.walk.handlers;
  oss << "\nHandlers lifted (" << blocks.size() << " blocks):\n";
  std::size_t block_show = blocks.size() > 40 ? 40 : blocks.size();
  for (std::size_t i = 0; i < block_show; i++) {
    const auto& h = blocks[i];
    oss << "  [" << i << "] " << hex_u64(h.entry_va) << " insns=" << h.insns.size();
    if (h.next_handler_va) {
      oss << " -> " << hex_u64(*h.next_handler_va);
    }
    if (h.is_exit) {
      oss << " (exit)";
    }
    if (!h.stop_reason.empty()) {
      oss << " {" << h.stop_reason << "}";
    }
    oss << "\n";
  }
  if (blocks.size() > block_show) {
    oss << "  ... " << (blocks.size() - block_show) << " more\n";
  }

  if (report.walk.truncated) {
    oss << "\n(note: hit handler cap — bump --max-handlers)\n";
  }

  return oss.str();
}

}
