#!/usr/bin/env python3
"""Test scalar audit lifecycle with fake frames; no DUT or reference execution."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--cxx", default="g++")
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    root = source.parents[1]
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    flags = [args.cxx, "-std=c++17", "-O1", "-Wall", "-Wextra", "-Werror",
             "-DDASICS_SCALAR_COMPARE", "-DNUM_CORES=1", "-DCONFIG_DIFF_COMMIT_WIDTH=2",
             "-DCONFIG_DIFFTEST_USERTIMERACCESS", "-DCONFIG_DIFFTEST_FDIOBSERVATION",
             "-DCONFIG_DIFFTEST_HCSRSTATE", "-DCONFIG_DIFFTEST_STOREEVENT", "-DCONFIG_DIFF_STORE_WIDTH=2", "-I", str(root / "src/test/csrc/difftest")]
    command = flags + [str(source / "audit-test.cpp"), "-o", str(output / "audit-test")]
    build = subprocess.run(command, capture_output=True, text=True, timeout=60)
    (output / "build.stdout").write_text(build.stdout)
    (output / "build.stderr").write_text(build.stderr)
    report = {"schema": 1, "kind": "scalar-audit-host-fake-frames", "dut_execution": False,
              "reference_model_execution": False, "started": datetime.now(timezone.utc).isoformat(),
              "build": {"command": command, "exit_code": build.returncode}, "cases": [], "guards": []}
    good = ("difftest no-diff max-delay incomplete-diff incomplete-no-diff store-fields store-no-diff "
            "store-zero-mask store-two-slots store-identical-packets store-at-terminal store-zero-after-terminal").split()
    bad = ("observe-before-init load-before-init duplicate-init duplicate-load load-in-no-diff "
           "missing-trap commit-before-trap duplicate-trap event-during-terminal terminal-timeout "
           "wrong-terminal-pc wrong-terminal-instruction terminal-skip terminal-fused younger-retirement "
           "retire-after-terminal trap-after-terminal observe-after-finish duplicate-finish load-after-finish "
           "store-after-terminal").split()

    def run_case(name):
        trace = output / (name + ".jsonl")
        env = {key: value for key, value in os.environ.items() if not key.startswith("DASICS_DEVELOPMENT_")}
        env.update(DASICS_DEVELOPMENT_TRACE=str(trace), DASICS_DEVELOPMENT_RUN_ID=name)
        argv = [str(output / "audit-test"), name]
        result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=10)
        (output / (name + ".stdout")).write_text(result.stdout)
        (output / (name + ".stderr")).write_text(result.stderr)
        rows = [json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []
        expected = 0 if name in good else 1
        passed = result.returncode == expected
        passed &= all(row["schema"] == 1 and row["scope"] == "scalar-compare-v1" and
                      row["run_id"] == name and row["core"] == 0 for row in rows)
        passed &= all(row["event"] not in ("compare", "ref_exec", "state_import") for row in rows)
        if expected == 0:
            incomplete = name.startswith("incomplete-")
            diff = name not in ("no-diff", "incomplete-no-diff", "store-no-diff")
            passed &= rows[0]["event"] == "start" and rows[-1]["event"] == "end"
            passed &= rows[-1]["reference_loaded"] == diff and rows[-1]["terminal_seen"] != incomplete
            passed &= all(row["mode"] == ("difftest" if diff else "no-diff") for row in rows)
            if diff:
                loaded = next(row for row in rows if row["event"] == "loaded")
                passed &= loaded["path"] == 'fake-"reference\\\n'
            if not incomplete:
                terminal = next(row for row in rows if row["event"] == "terminal")
                arch = next(row for row in rows if row["event"] == "architectural_event")
                passed &= arch["pc"] == "0x800000ab" and arch["exception"] == 25 and not arch["interrupt"]
                passed &= terminal["trap_frame"] == 3 and terminal["retire_frame"] == (19 if name == "max-delay" else 6)
                passed &= terminal["compare_pass"] is False and terminal["observation_only"] is True
                passed &= terminal["code"] == 3 and terminal["gpr"][10] == "0xa70000000000000a"
                retirements = [row for row in rows if row["event"] == "retire"]
                passed &= len(retirements) == 2 and retirements[0]["robidx"] == 147 and retirements[1]["robidx"] == 0
            stores = [row for row in rows if row["event"] == "store"]
            expected_stores = (2 if name in ("store-two-slots", "store-identical-packets", "store-at-terminal",
                                            "store-zero-after-terminal") else 1) if name.startswith("store-") else 0
            passed &= len(stores) == expected_stores
            for index, store in enumerate(stores):
                expected_slot = 0 if name == "store-two-slots" and index == 0 else 1
                expected_cycle = 224 if name in ("store-identical-packets", "store-at-terminal") and index == 1 else 223
                expected_mask = 0 if name == "store-zero-mask" or name == "store-zero-after-terminal" and index == 1 else 0x30
                passed &= (store["slot"] == expected_slot and store["sample_cycle"] == expected_cycle and
                           store["pc"] == "0x80000024" and store["robidx"] == 147 and
                           store["address"] == "0x800006a0" and store["data"] == "0x0000221100000000" and
                           store["mask"] == expected_mask)
        else:
            passed &= "Scalar comparison audit rejected:" in result.stderr
        return {"name": name, "command": argv, "exit_code": result.returncode,
                "expected_exit_code": expected, "passed": bool(passed)}

    if build.returncode == 0:
        with ThreadPoolExecutor(max_workers=min(os.cpu_count() or 1, len(good + bad))) as pool:
            report["cases"] = list(pool.map(run_case, good + bad))
        original = (output / "no-diff.jsonl").read_bytes()
        for name in ("existing-file", "symlink", "relative-path", "invalid-run-id", "missing-path"):
            trace = output / (name + ".jsonl")
            if name == "existing-file":
                trace.write_bytes(original)
            elif name == "symlink":
                trace.symlink_to(output / "no-diff.jsonl")
            env = {key: value for key, value in os.environ.items() if not key.startswith("DASICS_DEVELOPMENT_")}
            env.update(DASICS_DEVELOPMENT_TRACE=str(trace), DASICS_DEVELOPMENT_RUN_ID=name)
            if name == "relative-path":
                env["DASICS_DEVELOPMENT_TRACE"] = "relative.jsonl"
            elif name == "invalid-run-id":
                env["DASICS_DEVELOPMENT_RUN_ID"] = "invalid id"
            elif name == "missing-path":
                del env["DASICS_DEVELOPMENT_TRACE"]
            result = subprocess.run([str(output / "audit-test"), "no-diff"], env=env,
                                    capture_output=True, text=True, timeout=10)
            (output / (name + ".stderr")).write_text(result.stderr)
            preserved = (output / "no-diff.jsonl").read_bytes() == original
            if name == "existing-file":
                preserved &= trace.read_bytes() == original
            report["cases"].append({"name": name, "exit_code": result.returncode,
                                    "passed": result.returncode == 1 and preserved})
        bad_macros = ("DASICS_DEVELOPMENT_AUDIT CONFIG_NO_DIFFTEST BASIC_DIFFTEST_ONLY CONFIG_DIFFTEST_SQUASH "
                      "CONFIG_DIFFTEST_REPLAY CONFIG_DIFFTEST_BATCH CONFIG_DIFFTEST_DELTA ENABLE_RUNAHEAD "
                      "ENABLE_RUNHEAD VM_SAVABLE DEBUG_MODE_DIFF LINKED_REFPROXY_LIB CONFIG_PLATFORM_FPGA").split()
        guards = [(macro, ["-D" + macro]) for macro in bad_macros]
        guards += [(macro, ["-U" + macro]) for macro in (
            "CONFIG_DIFFTEST_USERTIMERACCESS", "CONFIG_DIFFTEST_FDIOBSERVATION", "CONFIG_DIFFTEST_HCSRSTATE",
            "CONFIG_DIFFTEST_STOREEVENT")]
        guards += [("two-harts", ["-UNUM_CORES", "-DNUM_CORES=2"])]

        def guard(item):
            name, defines = item
            argv = flags + defines + ["-DSCALAR_AUDIT_GUARD_ONLY", "-fsyntax-only", str(source / "audit-test.cpp")]
            result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
            (output / ("guard-" + name + ".stderr")).write_text(result.stderr)
            return {"name": name, "command": argv, "exit_code": result.returncode,
                    "passed": result.returncode != 0 and "Scalar comparison audit requires" in result.stderr}

        with ThreadPoolExecutor(max_workers=min(os.cpu_count() or 1, len(guards))) as pool:
            report["guards"] = list(pool.map(guard, guards))
    report["finished"] = datetime.now(timezone.utc).isoformat()
    report["status"] = "PASS" if (build.returncode == 0 and len(report["cases"]) == len(good + bad) + 5 and
                                    all(item["passed"] for item in report["cases"] + report["guards"])) else "FAIL"
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "cases": len(report["cases"]),
                      "guards": len(report["guards"]), "output": str(output)}))
    return int(report["status"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
