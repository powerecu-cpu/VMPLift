#include "devirt_engine.hpp"
#include "dispatch_resolver.hpp"
#include "util.hpp"
#include "vmp_version.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>

namespace {

constexpr const char* kReset = "\033[0m";
constexpr const char* kCyan = "\033[96m";
constexpr const char* kGreen = "\033[92m";
constexpr const char* kYellow = "\033[93m";
constexpr const char* kDim = "\033[90m";

void enable_ansi() {
  auto hout = GetStdHandle(STD_OUTPUT_HANDLE);
  if (hout == INVALID_HANDLE_VALUE) {
    return;
  }
  DWORD mode = 0;
  if (!GetConsoleMode(hout, &mode)) {
    return;
  }
  SetConsoleMode(hout, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

void banner() {
  std::cout
      << kCyan
      << "                       _ _  __ _\n"
      << "__   ___ __ ___  _ __ | (_)/ _| |_\n"
      << "\\ \\ / / '_ ` _ \\| '_ \\| | | |_| __|\n"
      << " \\ V /| | | | | | |_) | | |  _| |_\n"
      << "  \\_/ |_| |_| |_| .__/|_|_|_|  \\__|\n"
      << "                |_|                \n"
      << kReset
      << kDim << "vmprotect 3.8 / 3.10 handler lifter\n"
      << kReset << "\n";
}

void ok(const std::string& msg) {
  std::cout << kGreen << "[+] " << kReset << msg << "\n";
}

std::string hex_pad(std::uint64_t v, int width) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "0x%0*llX", width, static_cast<unsigned long long>(v));
  return buf;
}

void print_scan(const vmp::DevirtEngine& engine, const std::string& binary,
                const std::vector<vmp::VmenterSite>& sites) {
  const auto& img = engine.image();
  const auto ver = engine.version();
  const auto fname = std::filesystem::path(binary).filename().string();

  banner();
  ok("Loading file: " + fname);
  ok("Read " + hex_pad(img.bytes().size(), 8) + " bytes");
  ok("PE parse ok");
  std::cout << "\n";
  std::cout << "    Image type:   " << (img.is_64bit() ? "PE32+" : "PE32") << "\n";
  std::cout << "    Machine:      AMD64\n";
  std::cout << "    Image base:   " << vmp::hex_u64(img.image_base()) << "\n";
  std::cout << "    Entry point:  "
            << vmp::hex_u64(img.image_base() + img.entry_point_rva()) << "\n";
  std::cout << "    Sections:     " << img.sections().size() << "\n\n";

  ok("Sections:");
  std::cout << "    " << std::left << std::setw(4) << "#" << std::setw(10) << "Name"
            << std::setw(14) << "VA" << std::setw(12) << "VSize" << "RawSize\n";
  int idx = 0;
  for (const auto& sec : img.sections()) {
    bool vmp_sec = vmp::is_vmp_section_name(sec.name);
    if (vmp_sec) {
      std::cout << kYellow;
    }
    std::cout << "    " << std::left << std::setw(4) << idx << std::setw(10) << sec.name
              << std::setw(14) << hex_pad(sec.virtual_address, 8) << std::setw(12)
              << hex_pad(sec.virtual_size, 8) << hex_pad(sec.raw_size, 8);
    if (vmp_sec) {
      std::cout << "  (VMP)";
    }
    std::cout << kReset << "\n";
    idx++;
  }
  std::cout << "\n";

  ok("Version detect: " + ver.label + "  conf=" + std::to_string(ver.confidence));
  if (!ver.why.empty()) {
    ok("Version why: " + ver.why);
  }
  if (ver.randomized_sections) {
    ok("Detected protection: VMProtect 3.x + randomized sections");
  }
  ok("Scanning for VM entrypoints (vmenter patterns) ...");
  ok("Found " + std::to_string(sites.size()) + " vmenter candidate(s):");
  std::cout << "\n";
  std::cout << "    " << std::left << std::setw(4) << "#" << std::setw(18) << "Address"
            << std::setw(10) << "Score" << "Notes\n";

  const auto best_va = vmp::VmenterScanner::pick_best(sites);
  for (std::size_t i = 0; i < sites.size(); i++) {
    const auto& s = sites[i];
    bool best = best_va && s.va == *best_va;
    if (best) {
      std::cout << kYellow;
    }
    std::cout << "    " << std::left << std::setw(4) << i << std::setw(18) << vmp::hex_u64(s.va)
              << std::setw(10) << s.confidence << s.source;
    if (s.first_handler_va) {
      std::cout << "  target=" << vmp::hex_u64(s.first_handler_va);
    }
    if (best) {
      std::cout << "  *";
    }
    std::cout << kReset << "\n";
  }
  if (best_va) {
    std::string src = "?";
    int conf = 0;
    for (const auto& s : sites) {
      if (s.va == *best_va) {
        src = s.source;
        conf = s.confidence;
        break;
      }
    }
    std::cout << "\n";
    ok("vmenter " + vmp::hex_u64(*best_va) + " score " + std::to_string(conf) + " " + src);
  }
}

void usage() {
  banner();
  std::cout
      << "usage:\n"
      << "  vmp-lift scan <binary>\n"
      << "  vmp-lift lift <binary> [--vmenter 0xVA] [--max-handlers N]\n"
      << "                   [--mode callgraph|chain] [--out-dir DIR]\n"
      << "  vmp-lift devirt <binary> [--vmenter 0xVA] [--max-handlers N]\n"
      << "                     [--mode callgraph|chain] [--out-dir DIR]\n"
      << "  vmp-lift test [--binary PATH]\n\n"
      << "example:\n"
      << "  vmp-lift lift WaveUIAuth_static_unpacked.dll --vmenter 0x18101da77\n"
      << "  vmp-lift lift ..\\samples\\adder.vmp.exe\n"
      << "  vmp-lift scan ..\\samples\\adder.vmp.exe\n";
}

struct Args {
  std::string command;
  std::string binary;
  std::uint64_t vmenter = 0;
  std::size_t max_handlers = 256;
  std::string mode = "callgraph";
  std::string out_dir = "devirt_out";
  bool emit_llvm = true;
  bool emit_pseudo_c = true;
  bool emit_json = true;
};

Args parse_args(int argc, char** argv) {
  if (argc < 2) {
    throw std::runtime_error("missing args");
  }

  Args a;
  a.command = argv[1];
  if (a.command != "test" && argc < 3) {
    usage();
    throw std::runtime_error("need binary path");
  }
  if (argc >= 3) {
    a.binary = argv[2];
  }

  for (int i = 3; i < argc; ++i) {
    const std::string flag = argv[i];
    auto next = [&](const char* name) {
      if (i + 1 >= argc) {
        throw std::runtime_error(std::string("need value for ") + name);
      }
      return std::string(argv[++i]);
    };

    if (flag == "--vmenter") {
      auto val = next("--vmenter");
      auto parsed = vmp::parse_hex_u64(val);
      if (!parsed) {
        throw std::runtime_error("bad --vmenter");
      }
      a.vmenter = *parsed;
    } else if (flag == "--max-handlers") {
      a.max_handlers = static_cast<std::size_t>(std::stoull(next("--max-handlers")));
    } else if (flag == "--mode") {
      a.mode = next("--mode");
    } else if (flag == "--out-dir") {
      a.out_dir = next("--out-dir");
    } else if (flag == "--no-llvm") {
      a.emit_llvm = false;
    } else if (flag == "--no-pseudo-c") {
      a.emit_pseudo_c = false;
    } else if (flag == "--no-json") {
      a.emit_json = false;
    } else if (flag == "--llvm" || flag == "--pseudo-c" || flag == "--json") {

    } else {
      throw std::runtime_error("unknown flag: " + flag);
    }
  }

  return a;
}

void dump_file(const std::filesystem::path& p, const std::string& text) {
  std::ofstream out(p, std::ios::binary);
  if (!out) {
    throw std::runtime_error("cant write " + p.string());
  }
  out << text;
}

}

int main(int argc, char** argv) {
  enable_ansi();
  if (argc < 2) {
    usage();
    return 0;
  }
  try {
    const auto args = parse_args(argc, argv);
    auto image = vmp::PeImage::load(args.binary);
    vmp::DevirtEngine engine(std::move(image));

    if (args.command == "scan") {
      auto sites = engine.scan_vmenters();
      print_scan(engine, args.binary, sites);
      return sites.empty() ? 2 : 0;
    }

    if (args.command == "lift" || args.command == "devirt") {
      banner();
      ok("Loading file: " + std::filesystem::path(args.binary).filename().string());
      vmp::DevirtOptions opts;
      opts.vmenter_va = args.vmenter;
      opts.max_handlers = args.max_handlers;
      opts.use_callgraph = (args.mode != "chain");
      opts.emit_llvm = args.emit_llvm;
      opts.emit_pseudo_c = args.emit_pseudo_c;
      opts.export_json = args.emit_json;
      opts.emit_devirt = true;

      const auto report = engine.lift(opts);
      const auto txt = engine.format_text_report(report);
      std::cout << txt;

      std::filesystem::create_directories(args.out_dir);
      auto base = std::filesystem::path(args.out_dir);
      dump_file(base / "report.txt", engine.format_text_report(report));
      if (args.emit_llvm) {
        dump_file(base / "lifted.ll", report.llvm_ir);
      }
      if (args.emit_pseudo_c) {
        dump_file(base / "lifted.c", report.pseudo_c);
      }
      if (args.emit_json) {
        dump_file(base / "summary.json", report.summary.dump(2));
        dump_file(base / "vip_trace.json", report.vip_trace_json.dump(2));
      }
      if (!report.vip_trace_text.empty()) {
        dump_file(base / "vip_trace.txt", report.vip_trace_text);
      }
      if (!report.vasm.empty()) {
        dump_file(base / "devirt.vasm", report.vasm);
      }
      if (!report.native_pseudo.empty()) {
        dump_file(base / "devirt_native.c", report.native_pseudo);
      }
      if (!report.native_l4.empty()) {
        dump_file(base / "devirt_l4.c", report.native_l4);
      }
      if (args.emit_json && !report.devirt_json.empty()) {
        dump_file(base / "devirt.json", report.devirt_json.dump(2));
      }

      std::cout << "\nwrote output -> " << args.out_dir << "\n";
      if (report.summary.contains("vip_steps")) {
        ok("vip trace steps: " + std::to_string(report.summary["vip_steps"].get<std::size_t>()) +
           (report.summary.value("vip_seeded", false) ? " (seeded)" : " (unseeded)"));
      }
      if (report.summary.contains("devirt_ops")) {
        ok("devirt ops: " + std::to_string(report.summary["devirt_ops"].get<std::size_t>()) +
           " classified=" +
           std::to_string(report.summary.value("devirt_classified", 0)) +
           " unknown=" + std::to_string(report.summary.value("devirt_unknown", 0)));
      }
      if (report.summary.contains("l4")) {
        ok("l4: " + report.summary["l4"].get<std::string>());
      }
      return report.functions.empty() ? 3 : 0;
    }

    if (args.command == "test") {
      std::string bin = args.binary;
      if (bin.empty()) {
        bin = "WaveUIAuth_static_unpacked.dll";
      }
      if (!std::filesystem::exists(bin)) {
        bin = (std::filesystem::path("..") / "WaveUIAuth_static_unpacked.dll").string();
      }
      if (!std::filesystem::exists(bin)) {
        throw std::runtime_error("test binary missing: " + bin);
      }

      auto test_img = vmp::PeImage::load(bin);
      int fails = 0;
      auto check = [&](bool ok, const std::string& name) {
        std::cout << (ok ? "[PASS] " : "[FAIL] ") << name << "\n";
        if (!ok) {
          ++fails;
        }
      };

      const auto version = vmp::detect_version(test_img);
      check(version.version == vmp::VmpVersion::Vmp38Plus, "version is VMP 3.8+");
      check(test_img.image_base() == 0x180000000ULL, "image base");

      vmp::DevirtEngine eng(std::move(test_img));
      const auto sites = eng.scan_vmenters();
      bool got_download = false;
      for (const auto& site : sites) {
        if (site.va == 0x18101DA77ULL && site.confidence >= 90) {
          got_download = true;
        }
      }
      check(got_download, "export Download VMENTER at 0x18101da77");

      vmp::DevirtOptions opts;
      opts.vmenter_va = 0x18101DA77ULL;
      opts.max_handlers = 256;
      opts.use_callgraph = true;
      opts.emit_llvm = false;
      opts.emit_pseudo_c = false;
      const auto report = eng.lift(opts);
      check(report.functions.size() >= 50, "callgraph discovers >= 50 handlers");
      check(report.summary.value("total_insns", 0) >= 500, "lifted >= 500 total insns");

      vmp::DispatchResolver resolver(eng.image());
      const auto insns = resolver.linear_disasm(0x18101DA77ULL, 20);
      check(insns.size() >= 5, "linear disasm at Download VMENTER");
      bool prologue = false;
      for (const auto& ins : insns) {
        if (ins.mnemonic == "pushfq" || ins.mnemonic == "push") {
          prologue = true;
        }
      }
      check(prologue, "Download VMENTER has VMP prologue");

      vmp::DevirtOptions chain = opts;
      chain.use_callgraph = false;
      chain.max_handlers = 16;
      const auto chain_report = eng.lift(chain);
      check(!chain_report.functions.empty(), "chain mode lifts at least one handler");

      std::cout << "\n" << fails << " failure(s)\n";
      return fails == 0 ? 0 : 1;
    }

    usage();
    return 1;
  } catch (const std::exception& ex) {
    std::cerr << "error: " << ex.what() << "\n";
    return 1;
  }
}
