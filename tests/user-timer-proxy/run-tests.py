#!/usr/bin/env python3
"""Exercise RefProxy against fake libraries, without executing DUT or NEMU."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generated-dir", type=Path, required=True, help="Directory containing an actual diffstate.h")
    parser.add_argument("--output-dir", type=Path, required=True, help="New directory for unit binaries and evidence")
    parser.add_argument("--cxx", default="g++")
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    root = source.parent.parent
    generated = args.generated_dir.resolve()
    output = args.output_dir.resolve()
    if not (generated / "diffstate.h").is_file():
        parser.error("--generated-dir must contain diffstate.h")
    if output.exists():
        parser.error("--output-dir must be new to preserve previous evidence")
    output.mkdir(parents=True)
    includes = [root / "config", root / "src/test/csrc/common", root / "src/test/csrc/difftest", generated]
    flags = [args.cxx, "-std=c++17", "-O1", "-g", "-Werror", "-DCONFIG_DIFFTEST_USERTIMERACCESS"]
    for include in includes:
        flags += ["-I", str(include)]
    fake = source / "fake-reference.cpp"
    proxy_sources = [str(source / "proxy-test.cpp"), str(root / "src/test/csrc/difftest/refproxy.cpp")]
    missing = ["QUERY_CAPS", "INIT", "EXEC", "RAISE_EVENT", "GET_STATE", "READ_TX"]
    builds = [("fake-reference", flags + ["-shared", "-fPIC", str(fake), "-o", str(output / "fake-reference.so")])]
    for symbol in missing:
        builds.append(("missing-" + symbol.lower(), flags + ["-shared", "-fPIC", "-DOMIT_UIT_" + symbol,
                      str(fake), "-o", str(output / ("missing-" + symbol.lower() + ".so"))]))
    for cores in (1, 2):
        builds.append(("proxy-test-" + str(cores), flags + ["-DNUM_CORES=" + str(cores)] + proxy_sources +
                      ["-ldl", "-o", str(output / ("proxy-test-" + str(cores)))]))

    def build(item):
        name, command = item
        result = subprocess.run(command, text=True, capture_output=True, timeout=60)
        (output / (name + ".build.stdout")).write_text(result.stdout)
        (output / (name + ".build.stderr")).write_text(result.stderr)
        return {"name": name, "command": command, "exit_code": result.returncode}

    jobs = min(len(builds), len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else (os.cpu_count() or 1))
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        build_results = list(pool.map(build, builds))
    report = {"schema": 1, "evidence_kind": "proxy_abi_unit_fake_reference", "dut_execution": False,
              "reference_model_execution": False, "generated_header": str(generated / "diffstate.h"),
              "parallel_build_jobs": jobs, "builds": build_results, "cases": []}
    if any(result["exit_code"] for result in build_results):
        report["status"] = "FAIL"
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print("Proxy ABI unit build failed:", output)
        return 1

    def case(name, test="constructor", library="fake-reference.so", env=None, expected=1, diagnostic="", cores=1,
             reject_before_init=True):
        command = [str(output / ("proxy-test-" + str(cores))), str(output / library), test]
        environment = {key: value for key, value in os.environ.items() if not key.startswith("FAKE_UIT_")}
        environment.update(env or {})
        result = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=15)
        (output / (name + ".stdout")).write_text(result.stdout)
        (output / (name + ".stderr")).write_text(result.stderr)
        passed = result.returncode == expected and diagnostic in result.stderr
        if reject_before_init:
            passed = passed and "FAKE_REFERENCE_INITIALIZED" not in result.stdout
        if "runtime" in name:
            passed = passed and "FAKE_REFERENCE_RUNTIME_IMPORT_REACHED" not in result.stderr
        report["cases"].append({"name": name, "command": command, "environment_overrides": env or {},
                                "expected_exit_code": expected, "exit_code": result.returncode,
                                "expected_diagnostic": diagnostic, "passed": passed})

    case("roundtrip_and_wrappers", test="roundtrip", expected=0, reject_before_init=False)
    case("disabled_abi_init", test="disabled_init", env={"FAKE_UIT_DISABLED": "1"}, expected=0,
         reject_before_init=False)
    for block in ("gpr", "fp", "vector", "csr", "hcsr", "vcsr", "fcsr", "trigger"):
        case("compare_" + block, test="compare_" + block, expected=1,
             diagnostic="REAL_REFPROXY_COMPARE_REJECT: compare_" + block +
                        " sample_unchanged=true reference_unchanged=true", reject_before_init=False)
    for symbol in missing:
        case("missing_" + symbol.lower(), library="missing-" + symbol.lower() + ".so",
             diagnostic="UIT required reference symbol missing: difftest_uit_" + symbol.lower())
    caps = {"version": "version", "bytes": "caps bytes", "enabled_features": "enabled features",
            "supported_features": "supported features", "xlen": "XLEN", "vlen": "VLEN",
            "legacy_regcpy_bytes": "legacy regcpy bytes", "legacy_csrcpy_bytes": "legacy csrcpy bytes",
            "legacy_regcpy_arity": "legacy regcpy arity", "max_harts": "max harts",
            "exec_request_bytes": "exec request bytes", "event_request_bytes": "event request bytes",
            "state_bytes": "state bytes", "exec_result_bytes": "exec result bytes"}
    for field, diagnostic in caps.items():
        case("bad_cap_" + field, env={"FAKE_UIT_BAD_CAP": field}, diagnostic="UIT ABI mismatch: " + diagnostic)
    case("caps_query_failure", env={"FAKE_UIT_BAD_CAP": "query_rc"}, diagnostic="UIT capability query failed: rc=-1")
    case("bad_hart", test="bad_hart", diagnostic="UIT ABI mismatch: hart ID")
    case("multiple_harts", cores=2, diagnostic="UIT ABI mismatch: DUT harts")
    for entry in ("sync", "regcpy"):
        case("runtime_" + entry + "_import", test="runtime_" + entry + "_import",
             diagnostic="UIT runtime register import is forbidden", reject_before_init=False)
    report["passed"] = sum(case["passed"] for case in report["cases"])
    report["total"] = len(report["cases"])
    report["status"] = "PASS" if report["passed"] == report["total"] else "FAIL"
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Proxy ABI fake-reference unit {report['status']}: {report['passed']}/{report['total']}; {output}")
    return int(report["status"] != "PASS")


if __name__ == "__main__":
    sys.exit(main())
