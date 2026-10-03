#!/usr/bin/env python3
"""Check the FDI host lifecycle and ledger with fake APIs and observations."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
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
    command = [args.cxx, "-std=c++17", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
               "-I", str(root / "src/test/csrc/difftest"), str(source / "bridge-test.cpp"),
               "-o", str(output / "bridge-test")]
    build = subprocess.run(command, capture_output=True, text=True, timeout=60)
    (output / "build.stdout").write_text(build.stdout)
    (output / "build.stderr").write_text(build.stderr)
    report = {"schema": 1, "evidence_kind": "fdi_host_unit_fake_reference_and_observations",
              "dut_execution": False, "reference_model_execution": False, "generated_abi_verified": False,
              "build": {"command": command, "exit_code": build.returncode}, "cases": []}
    api = "roundtrip missing hart cores disabled caps_canary query_rc import_before_reset reference_reset_dirty reset_header reset_canary capture_rc duplicate_reset dut_reset_dirty epoch_zero init_before_import double_import startup_changes_fdi init_rc state_rc runtime_import double_init state_header state_alias state_reserved state_canary".split()
    api += ["cap_" + field for field in "version bytes state_bytes projection_words supported_features enabled_features xlen max_harts init_bytes projection_version machine_abi_major reserved32 reserved64".split()]
    ledger = "roundtrip both_reset_dirty no_reset duplicate_reset orphan_post wrong_epoch bad_read_obligation bad_write_obligation alias_pollution reserved_pollution readonly readonly_changed illegal illegal_retired sync_cancel duplicate_pre missing_post unfinished same_cycle_post wrong_rob wrong_pc wrong_uid missing_effect virtual_fault cancel duplicate_post cancel_after_write wrong_event saved_snapshots bad_retired_identity execute_twice single_word_mismatch full_pointer_mismatch reference_alias_pollution duplicate_retirement all_words_mismatch reason_seven event_before_cancel".split()
    ledger += ["interrupt_before_acceptance", "interrupt_canceled_read", "interrupt_before_cancel"]
    ledger += ["duplicate_event_uid", "trap_before_acceptance"]
    ledger += ["canceled_pre_pollution", "same_cycle_pre_post", "same_cycle_lane_disagreement", "interrupt_wrong_cancel_reason"]

    def run(case):
        result = subprocess.run([str(output / "bridge-test"), case], capture_output=True, text=True, timeout=10)
        (output / (case + ".stdout")).write_text(result.stdout)
        (output / (case + ".stderr")).write_text(result.stderr)
        return {"name": case, "exit_code": result.returncode, "passed": result.returncode == 0}

    if build.returncode == 0:
        with ThreadPoolExecutor(max_workers=8) as pool:
            report["cases"] = list(pool.map(run, ["api_" + case for case in api] + ledger))
    report["passed"] = sum(case["passed"] for case in report["cases"])
    report["total"] = len(api) + len(ledger)
    report["status"] = "PASS" if report["passed"] == report["total"] else "FAIL"
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"FDI host fake unit {report['status']}: {report['passed']}/{report['total']}; {output}")
    return int(report["status"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
