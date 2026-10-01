#!/usr/bin/env python3
"""Host ABI/audit unit tests; fake libraries and frames are not DUT evidence."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generated-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    root = source.parents[1]
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    generated = output / "unit-generated"
    generated.mkdir()
    header = (args.generated_dir / "diffstate.h").read_text()
    # Keep the measured ordinary legacy layout while removing only UIT guards.
    # This derived header is explicitly a unit fixture, never a generated candidate.
    header = re.sub(r"^#define CONFIG_DIFFTEST_USERTIMER\w*[^\n]*\n", "", header, flags=re.M)
    (generated / "diffstate.h").write_text(header)
    for name in ("difftest-dpic.h", "difftest-dpic.cpp", "difftest-query.h"):
        (generated / name).write_bytes((args.generated_dir / name).read_bytes())
    flags = ["/usr/bin/g++", "-std=c++17", "-O1", "-Werror", "-DDASICS_DEVELOPMENT_AUDIT", "-DNUM_CORES=1",
             "-DREF_PROXY=NemuProxy"]
    for include in (root / "config", root / "src/test/csrc/common", root / "src/test/csrc/difftest",
                    root / "src/test/csrc/plugin/spikedasm", generated):
        flags += ["-I", str(include)]
    commands = [
        ("fake-reference", flags + ["-shared", "-fPIC", str(source / "fake-reference.cpp"), "-o", str(output / "reference.so")]),
        ("audit-test", flags + [str(source / "audit-test.cpp"), str(root / "src/test/csrc/difftest/refproxy.cpp"),
                               "-ldl", "-o", str(output / "audit-test")]),
        ("difftest-syntax", flags + ["-fsyntax-only", str(root / "src/test/csrc/difftest/difftest.cpp")]),
        ("buffer-test", flags + [str(source / "buffer-test.cpp"), str(generated / "difftest-dpic.cpp"),
                                "-o", str(output / "buffer-test")]),
    ]
    report = {"schema": 1, "kind": "host-unit-fake-reference-and-frames", "dut_execution": False,
              "generated_header_source": str(args.generated_dir), "unit_derived_header": str(generated),
              "started": datetime.now(timezone.utc).isoformat(), "builds": [], "cases": []}

    def execute_build(item):
        name, argv = item
        result = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        (output / (name + ".stdout")).write_text(result.stdout)
        (output / (name + ".stderr")).write_text(result.stderr)
        return {"name": name, "argv": argv, "exit_code": result.returncode}

    with ThreadPoolExecutor(max_workers=4) as pool:
        report["builds"] = list(pool.map(execute_build, commands))
    if not any(item["exit_code"] for item in report["builds"]):
        cases = [("difftest", {}, 0), ("no-diff", {}, 0), ("stale-compare", {}, 1),
                 ("runtime-import", {}, 1), ("state-adjusted", {}, 1), ("max-delay", {}, 0),
                 ("terminal-timeout", {}, 1), ("missing-terminal-exec", {}, 1),
                 ("wrong-terminal-pc", {}, 1), ("wrong-terminal-instruction", {}, 1),
                 ("terminal-skip", {}, 1), ("terminal-fused", {}, 1),
                 ("younger-retirement", {}, 1), ("duplicate-trap", {}, 1), ("missing-trap", {}, 1),
                 ("failed-compare", {}, 1), ("wrong-enabled", {"FAKE_DEVELOPMENT_ENABLED": "32"}, 1),
                 ("wrong-vlen", {"FAKE_UIT_BAD_CAP": "vlen"}, 1),
                 ("wrong-regcpy", {"FAKE_UIT_BAD_CAP": "legacy_regcpy_bytes"}, 1),
                 ("wrong-arity", {"FAKE_UIT_BAD_CAP": "legacy_regcpy_arity"}, 1),
                 ("query-failed", {"FAKE_UIT_BAD_CAP": "query_rc"}, 1)]
        for name, overrides, expected in cases:
            trace = output / (name + ".jsonl")
            env = {k: v for k, v in os.environ.items() if not k.startswith(("FAKE_", "DASICS_DEVELOPMENT_"))}
            env.update(overrides, DASICS_DEVELOPMENT_TRACE=str(trace), DASICS_DEVELOPMENT_RUN_ID=name)
            argv = [str(output / "audit-test"), str(output / "reference.so"), name]
            result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=10)
            (output / (name + ".stdout")).write_text(result.stdout)
            (output / (name + ".stderr")).write_text(result.stderr)
            rows = [json.loads(line) for line in trace.read_text().splitlines()]
            events = [row["event"] for row in rows]
            passed = result.returncode == expected and all(row["run_id"] == name for row in rows)
            if expected == 0:
                passed &= events[0] == "start" and events[-1] == "end" and "terminal" in events
                passed &= ("loaded" in events) == (name != "no-diff")
                latch = next(row for row in rows if row["event"] == "trap_latched")
                terminal = next(row for row in rows if row["event"] == "terminal")
                passed &= terminal["trap_frame"] == latch["frame"] == 1
                passed &= terminal["retire_frame"] == terminal["frame"] == (17 if name == "max-delay" else 4)
            else:
                passed &= "end" not in events and "Development audit rejected:" in result.stderr
            report["cases"].append({"name": name, "argv": argv, "environment": overrides,
                                    "exit_code": result.returncode, "expected_exit_code": expected, "passed": passed})
        # An existing trace must remain byte-for-byte intact after a second launch.
        trace = output / "difftest.jsonl"
        original = trace.read_bytes()
        env.update(DASICS_DEVELOPMENT_TRACE=str(trace), DASICS_DEVELOPMENT_RUN_ID="duplicate")
        result = subprocess.run([str(output / "audit-test"), str(output / "reference.so"), "no-diff"],
                                env=env, capture_output=True, text=True, timeout=10)
        report["cases"].append({"name": "existing-trace", "exit_code": result.returncode,
                                "passed": result.returncode == 1 and trace.read_bytes() == original})
        env = {k: v for k, v in os.environ.items() if not k.startswith(("FAKE_", "DASICS_DEVELOPMENT_"))}
        trace = output / "buffer-consumption.jsonl"
        env.update(DASICS_DEVELOPMENT_TRACE=str(trace), DASICS_DEVELOPMENT_RUN_ID="buffer-consumption")
        argv = [str(output / "buffer-test")]
        result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=10)
        (output / "buffer-consumption.stdout").write_text(result.stdout)
        (output / "buffer-consumption.stderr").write_text(result.stderr)
        rows = [json.loads(line) for line in trace.read_text().splitlines()]
        retires = [(row["frame"], row["slot"], row["pc"]) for row in rows if row["event"] == "retire"]
        passed = result.returncode == 0 and retires == [(1, 1, "0x80000004"), (4, 0, "0x80000000"),
                                                       (5, 0, "0x80000000"), (8, 0, "0x80000010")]
        passed &= rows[-1]["event"] == "end" and rows[-1]["terminal_seen"] is True
        report["cases"].append({"name": "actual-generated-buffer-consumption", "argv": argv,
                                "exit_code": result.returncode, "passed": passed,
                                "same_pc_distinct_frames": [4, 5], "terminal_frame": 8})
    report["finished"] = datetime.now(timezone.utc).isoformat()
    report["status"] = "PASS" if (not any(item["exit_code"] for item in report["builds"]) and
                                    all(item["passed"] for item in report["cases"])) else "FAIL"
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "cases": len(report["cases"]), "output": str(output)}))
    return int(report["status"] != "PASS")


if __name__ == "__main__":
    sys.exit(main())
