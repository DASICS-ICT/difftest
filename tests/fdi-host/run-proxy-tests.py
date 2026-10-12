#!/usr/bin/env python3
"""Check production host sources using explicitly synthetic observer declarations."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import subprocess


def make_fixture(root, original, output):
    text = original.read_text()
    scala = (root / "src/main/scala/Bundles.scala").read_text()
    classes = dict(re.findall(r"class (\w+)[^\n{]*\{(.*?)\n\}", scala, re.S))

    def fields(name, prefix=""):
        result = []
        for field, expression in re.findall(r"^  val (\w+) = (.+)$", classes[name], re.M):
            if expression.startswith("UInt("):
                width = int(re.fullmatch(r"UInt\((\d+)\.W\)", expression).group(1))
                result.append(f"  uint{max(8, width)}_t {prefix}{field};")
            elif expression == "Bool()":
                result.append(f"  uint8_t {prefix}{field};")
            elif expression.startswith("new "):
                result += fields(expression[4:], prefix + field + "_")
        return result

    declarations, members = [], []
    if "DifftestUserTimerAccess" not in text:
        for name in ("Access", "Response", "Snapshot", "Retire", "Cancel", "Uart", "Clock", "Terminal"):
            full = "UserTimer" + name
            declarations += ["#define CONFIG_DIFFTEST_" + full.upper(), "typedef struct {"]
            if name != "Clock":
                declarations.append("  uint8_t valid;")
            declarations += fields(full) + ["} Difftest" + full + ";"]
            members.append("  Difftest" + full + " uit_" + name.lower() +
                           ("[8]" if name == "Retire" else "[160]" if name == "Cancel" else "") + ";")
    if "DifftestFDIObservation" not in text:
        declarations += ["#define CONFIG_DIFFTEST_FDIOBSERVATION", "typedef struct {",
          "  uint8_t valid, kind, robFlag, readNeeded, writeNeeded, permitted, actualWrite;",
          "  uint8_t responseIllegal, responseVirtual, cancelReason;",
          "  uint64_t epoch, uid, cycle, pc, eventSeq, beforeCount;",
          "  uint32_t instruction;", "  uint16_t robIdx, csrAddress;", "  uint64_t words[52];",
          "} DifftestFDIObservation;"]
        members.append("  DifftestFDIObservation fdi_observation[4];")
    marker = "typedef struct {\n  DifftestArchIntRegState"
    if text.count(marker) != 1:
        raise ValueError("unsupported generated state declaration")
    text = text.replace(marker, "// Host-only synthetic observer declarations; not a generated ABI proof.\n" +
                        "\n".join(declarations) + "\n" + marker)
    text = text.replace("} DiffTestState;", "\n".join(members) + "\n} DiffTestState;")
    output.write_text(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generated-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--cxx", default="g++")
    parser.add_argument("--scalar-compare", action="store_true")
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    root = source.parents[1]
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    fixture = output / "fixture"
    fixture.mkdir()
    original = args.generated_dir.resolve() / "diffstate.h"
    make_fixture(root, original, fixture / "diffstate.h")
    flags = [args.cxx, "-std=c++17", "-O1", "-g", "-Werror", "-DREF_PROXY=NemuProxy"]
    if args.scalar_compare:
        flags += ["-DDASICS_SCALAR_COMPARE", "-DCPU_ROCKET_CHIP"]
    for directory in (fixture, root / "config", root / "src/test/csrc/common",
                      root / "src/test/csrc/difftest", root / "src/test/csrc/plugin/spikedasm"):
        flags += ["-I", str(directory)]
    builds = [("fake", flags + ["-shared", "-fPIC", str(source / "fake-reference.cpp"), "-o", str(output / "fake.so")]),
              ("proxy", flags + [str(source / "proxy-test.cpp"), str(root / "src/test/csrc/difftest/refproxy.cpp"),
                                  "-ldl", "-o", str(output / "proxy")]),
              ("production-syntax", flags + ["-fsyntax-only", str(root / "src/test/csrc/difftest/difftest.cpp")])]
    for missing in ("QUERY", "CAPTURE", "INITIALIZE", "STATE"):
        builds.append(("missing-" + missing, flags + ["-DOMIT_FDI_" + missing, "-shared", "-fPIC",
                      str(source / "fake-reference.cpp"), "-o", str(output / ("missing-" + missing + ".so"))]))

    def build(item):
        name, command = item
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        (output / (name + ".build.stdout")).write_text(result.stdout)
        (output / (name + ".build.stderr")).write_text(result.stderr)
        return {"name": name, "command": command, "exit_code": result.returncode}

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(build, builds))
    report = {"schema": 1, "evidence_kind": "production_host_fake_reference_synthetic_observer_declarations",
              "dut_execution": False, "reference_model_execution": False, "generated_abi_verified": False,
              "base_generated_header": str(original), "builds": results, "cases": []}

    def case(name, test="constructor", library="fake.so", overrides=None, expected=1, diagnostic=""):
        command = [str(output / "proxy"), str(output / library), test]
        env = {key: value for key, value in os.environ.items() if not key.startswith(("FAKE_FDI_", "FAKE_UIT_"))}
        env.update(overrides or {})
        if args.scalar_compare:
            env.update(DASICS_DEVELOPMENT_TRACE=str(output / (name + ".audit.jsonl")),
                       DASICS_DEVELOPMENT_RUN_ID=name)
        result = subprocess.run(command, capture_output=True, text=True, timeout=10, env=env)
        (output / (name + ".stdout")).write_text(result.stdout)
        (output / (name + ".stderr")).write_text(result.stderr)
        passed = result.returncode == expected and diagnostic in result.stderr and "FDI_FAKE_FORBIDDEN_IMPORT_REACHED" not in result.stderr
        report["cases"].append({"name": name, "command": command, "environment": overrides or {},
                                "exit_code": result.returncode, "expected_exit_code": expected,
                                "diagnostic": diagnostic, "passed": passed})

    if not any(item["exit_code"] for item in results):
        case("roundtrip", "roundtrip", expected=0)
        for test in ("import_before_dut_reset", "duplicate_startup_import", "runtime_import"):
            case(test, test, diagnostic="ordinary state import outside the single verified startup boundary")
        for missing in ("QUERY", "CAPTURE", "INITIALIZE", "STATE"):
            case("missing_" + missing, library="missing-" + missing + ".so", diagnostic="missing FDI reference symbol")
        case("disabled", overrides={"FAKE_FDI_DISABLED": "1"}, diagnostic="FDI capabilities do not match")
        case("dirty_reset", overrides={"FAKE_FDI_DIRTY_RESET": "1"}, diagnostic="reference natural reset is not zero")
        if args.scalar_compare:
            case("strict_csr", "strict_csr", expected=0)
    report["passed"] = sum(item["passed"] for item in report["cases"])
    report["scalar_compare"] = args.scalar_compare
    report["expected_cases"] = 11 if args.scalar_compare else 10
    report["status"] = "PASS" if report["passed"] == report["expected_cases"] else "FAIL"
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"FDI production proxy fake unit {report['status']}: {report['passed']}/{report['expected_cases']}; {output}")
    return int(report["status"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
