#!/usr/bin/env python3
"""Execute production CLI and exit-policy bodies with isolated host dependencies."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess


PREFIX = r'''
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <getopt.h>
#define Info(...) printf(__VA_ARGS__)
bool enable_simjtag = false;
int remote_jtag_port = 0;
const char *difftest_ref_so = nullptr;
'''

CLI_MAIN = r'''
int main(int argc, char **argv) {
  std::vector<const char *> arguments(argv, argv + argc);
  const EmuArgs args = parse_args(argc, arguments.data());
  printf("CLI_RESULT {\"enabled_diff\":%s,\"has_image\":%s,\"has_reference\":%s,"
         "\"enable_ref_trace\":%s}\n", args.enable_diff ? "true" : "false",
         args.image ? "true" : "false", difftest_ref_so ? "true" : "false",
         args.enable_ref_trace ? "true" : "false");
}
'''

OUTCOME_DEPENDENCIES = r'''
namespace DasicsScalarAudit {
struct Audit {
  bool terminal_seen = true;
  uint64_t terminal_code = 0;
  bool reference_loaded = false;
};
Audit &state() { static Audit audit; return audit; }
}
int finalize_calls = 0;
int finalize_result = 0;
struct Difftest {
  int uit_finalize() { ++finalize_calls; return finalize_result; }
};
Difftest fake_reference_lifecycle;
Difftest *fake_harts[] = {&fake_reference_lifecycle};
Difftest **difftest = fake_harts;
class Emulator {
public:
  EmuArgs args;
  int trapCode = STATE_GOODTRAP;
  int is_good();
};
'''

OUTCOME_MAIN = r'''
int main(int argc, char **argv) {
  if (argc != 2) return 91;
  const std::string name(argv[1]);
  Emulator emulator;
  emulator.args.enable_diff = name.rfind("no-diff-", 0) != 0;
  if (name == "no-diff-max-cycles") {
    emulator.args.max_cycles = 123;
    emulator.trapCode = STATE_LIMIT_EXCEEDED;
  } else if (name == "no-diff-max-instr") {
    emulator.args.max_instr = 123;
    emulator.trapCode = STATE_LIMIT_EXCEEDED;
  } else if (name == "no-diff-no-terminal") {
    DasicsScalarAudit::state().terminal_seen = false;
  } else if (name == "no-diff-wrong-code") {
    DasicsScalarAudit::state().terminal_code = 1;
  } else if (name == "no-diff-reference-loaded") {
    DasicsScalarAudit::state().reference_loaded = true;
  } else if (name == "no-diff-bad-trap" || name == "diff-bad-trap") {
    emulator.trapCode = STATE_BADTRAP;
  } else if (name == "no-diff-sim-exit") {
    emulator.trapCode = STATE_SIM_EXIT;
  } else if (name == "diff-finalize-failed") {
    finalize_result = 1;
  } else if (name == "diff-limit") {
    emulator.trapCode = STATE_LIMIT_EXCEEDED;
  }
#ifdef DASICS_SCALAR_COMPARE
  // A raw-only test has no reference object at all. Accidental finalization
  // fails instead of silently succeeding through the fake lifecycle method.
  if (!emulator.args.enable_diff) difftest = nullptr;
#endif
  const int good = emulator.is_good();
  printf("OUTCOME_RESULT {\"good\":%s,\"finalize_calls\":%d,\"trap_code\":%d}\n",
         good ? "true" : "false", finalize_calls, emulator.trapCode);
}
'''


def exact_region(text, start, end):
    if text.count(start) != 1 or text.count(end) != 1:
        raise ValueError(f"production extraction anchor is ambiguous: {start!r} / {end!r}")
    first = text.index(start)
    last = text.index(end, first)
    return text[first:last], text.count("\n", 0, first) + 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--cxx", default="g++")
    args = parser.parse_args()
    root = args.source_root.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    emu_h = root / "src/test/csrc/verilator/emu.h"
    emu_cpp = root / "src/test/csrc/verilator/emu.cpp"
    dut_h = root / "src/test/csrc/common/dut.h"
    header = emu_h.read_text()
    implementation = emu_cpp.read_text()
    constants = dut_h.read_text()
    pieces = {
        "emu-args.inc": (emu_h, *exact_region(header, "struct EmuArgs {", "class Emulator final")),
        "parse-args.inc": (emu_cpp, *exact_region(implementation,
            "static inline long long int atoll_strict(", "Emulator::Emulator(int argc")),
        "is-good.inc": (emu_cpp, *exact_region(implementation,
            "int Emulator::is_good() {", "inline char *Emulator::timestamp_filename(")),
        "trap-codes.inc": (dut_h, *exact_region(constants, "enum {\n  STATE_GOODTRAP", "enum class SimExitCode")),
    }
    report = {"schema": 1, "evidence_kind": "exact_production_functions_with_fake_host_dependencies",
              "source_root": str(root), "dut_execution": False, "reference_model_execution": False,
              "whole_emulator_execution": False, "extractions": [], "builds": [], "cases": [],
              "started": datetime.now(timezone.utc).isoformat()}
    for name, (path, body, line) in pieces.items():
        (output / name).write_text(body)
        report["extractions"].append({"output": name, "source": str(path), "first_line": line,
                                      "verbatim": True, "bytes": len(body.encode())})
    (output / "cli-test.cpp").write_text(PREFIX + '\n#include "emu-args.inc"\n#include "parse-args.inc"\n' + CLI_MAIN)
    (output / "outcome-test.cpp").write_text(PREFIX + '\n#include "emu-args.inc"\n#include "trap-codes.inc"\n' +
                                            OUTCOME_DEPENDENCIES + '\n#include "is-good.inc"\n' + OUTCOME_MAIN)
    flags = [args.cxx, "-std=c++17", "-O1", "-Wall", "-Wextra", "-Werror",
             "-DCONFIG_DIFFTEST_USERTIMERACCESS", "-DNUM_CORES=1"]
    builds = []
    for mode in ("scalar", "legacy-uit"):
        for target in ("cli", "outcome"):
            command = flags + (["-DDASICS_SCALAR_COMPARE"] if mode == "scalar" else [])
            name = mode + "-" + target
            builds.append((name, command + [str(output / (target + "-test.cpp")), "-o", str(output / name)]))

    def build(item):
        name, command = item
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        (output / (name + ".build.stdout")).write_text(result.stdout)
        (output / (name + ".build.stderr")).write_text(result.stderr)
        return {"name": name, "command": command, "exit_code": result.returncode}

    with ThreadPoolExecutor(max_workers=4) as pool:
        report["builds"] = list(pool.map(build, builds))
    cases = []
    image = ["--image=/guest.bin"]
    reference = ["--diff=/reference.so"]

    def cli(name, mode, arguments, code, enabled_diff=None):
        expected = None if code else {"enabled_diff": enabled_diff, "has_image": True,
                                      "has_reference": enabled_diff, "enable_ref_trace": "--dump-ref-trace" in arguments}
        cases.append((name, mode + "-cli", arguments, code, "CLI_RESULT ", expected))

    cli("scalar-no-diff", "scalar", ["--no-diff"] + image, 0, False)
    cli("scalar-image-first-no-diff", "scalar", image + ["--no-diff"], 0, False)
    cli("scalar-no-diff-ref-last", "scalar", image + ["--no-diff"] + reference, 1)
    cli("scalar-no-diff-ref-first", "scalar", reference + image + ["--no-diff"], 1)
    cli("scalar-diff-missing-ref", "scalar", image, 1)
    cli("scalar-diff-explicit-ref", "scalar", reference + image, 0, True)
    cli("scalar-no-diff-ref-trace", "scalar", image + ["--no-diff", "--dump-ref-trace"], 1)
    cli("scalar-diff-ref-trace", "scalar", image + reference + ["--dump-ref-trace"], 0, True)
    cli("scalar-no-diff-missing-image", "scalar", ["--no-diff"], 1)
    cli("scalar-diff-missing-image", "scalar", reference, 1)
    cli("legacy-no-diff", "legacy-uit", image + ["--no-diff"], 1)
    cli("legacy-no-diff-with-ref", "legacy-uit", image + reference + ["--no-diff"], 1)
    cli("legacy-diff-missing-ref", "legacy-uit", image, 1)
    cli("legacy-diff-explicit-ref", "legacy-uit", image + reference, 0, True)
    restricted = {
        "snapshot": ["--load-snapshot=/saved"], "fork": ["--enable-fork"],
        "runahead": ["--sim-run-ahead"], "jtag": ["--enable-jtag"],
        "load-difftrace": ["--load-difftrace=/trace"], "footprint-input": ["--as-footprints"],
        "restore": ["--gcpt-restore=/restore"], "iotrace": ["--iotrace-name=/trace"],
    }
    for mode in ("scalar", "legacy-uit"):
        for name, option in restricted.items():
            cli(mode + "-reject-" + name, mode, image + reference + option, 1)
        cli(mode + "-bad-numeric", mode, image + reference + ["--max-cycles=12bad"], 22)
    cli("scalar-reject-dump-difftrace", "scalar", image + reference + ["--dump-difftrace=/trace"], 1)
    cli("legacy-allow-dump-difftrace", "legacy-uit", image + reference + ["--dump-difftrace=/trace"], 0, True)

    for name in ("pass", "max-cycles", "max-instr", "no-terminal", "wrong-code", "reference-loaded",
                 "bad-trap", "sim-exit"):
        scenario = "no-diff-" + name
        cases.append(("scalar-outcome-" + scenario, "scalar-outcome", [scenario], 0, "OUTCOME_RESULT ",
                      {"good": name == "pass", "finalize_calls": 0}))
    for mode in ("scalar", "legacy-uit"):
        for name in ("diff-pass", "diff-finalize-failed", "diff-bad-trap", "diff-limit"):
            cases.append((mode + "-outcome-" + name, mode + "-outcome", [name], 0, "OUTCOME_RESULT ",
                          {"good": name == "diff-pass", "finalize_calls": 1,
                           **({"trap_code": 2} if name == "diff-finalize-failed" else {})}))

    def run(item):
        name, binary, arguments, code, prefix, expected = item
        command = [str(output / binary)] + arguments
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        (output / (name + ".stdout")).write_text(result.stdout)
        (output / (name + ".stderr")).write_text(result.stderr)
        rows = [json.loads(line[len(prefix):]) for line in result.stdout.splitlines() if line.startswith(prefix)]
        passed = result.returncode == code
        if expected is not None:
            passed &= len(rows) == 1 and all(rows[0].get(key) == value for key, value in expected.items())
        else:
            passed &= not rows
        return {"name": name, "command": command, "exit_code": result.returncode,
                "expected_exit_code": code, "expected_result": expected, "actual_result": rows, "passed": bool(passed)}

    if all(item["exit_code"] == 0 for item in report["builds"]):
        with ThreadPoolExecutor(max_workers=16) as pool:
            report["cases"] = list(pool.map(run, cases))
    report["expected_cases"] = len(cases)
    report["passed"] = sum(item["passed"] for item in report["cases"])
    report["status"] = "PASS" if report["passed"] == len(cases) else "FAIL"
    report["finished"] = datetime.now(timezone.utc).isoformat()
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "passed": report["passed"],
                      "expected_cases": len(cases), "output": str(output)}))
    return int(report["status"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
