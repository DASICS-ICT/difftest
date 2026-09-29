#!/usr/bin/env python3
"""Test the production UIT host protocol with synthetic declarations and spies."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


def make_fixture(root, original, destination):
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

    names = ["Access", "Response", "Snapshot", "Retire", "Cancel", "Uart", "Clock", "Terminal"]
    declarations = ["// Synthetic host-unit fixture only; this does not certify the generated RTL ABI."]
    for name in names:
        full = "UserTimer" + name
        declarations += ["#define CONFIG_DIFFTEST_" + full.upper(), "typedef struct {"]
        if name != "Clock":
            declarations.append("  uint8_t valid;")
        declarations += fields(full)
        declarations.append("} Difftest" + full + ";")
    text = original.read_text()
    if "DifftestUserTimerAccess" in text:
        indexed = re.search(r"DifftestUserTimerCancel\s+uit_cancel\[(\d+)\]\s*;", text)
        if indexed and int(indexed.group(1)) != 160:
            raise ValueError("generated cancellation slot count differs from the UIT06 ROB contract")
        if not indexed:
            text, count = re.subn(r"(DifftestUserTimerCancel\s+uit_cancel)\s*;",
                                  r"\1[160]; // Synthetic host-only indexed cancellation shape delta.", text)
            if count != 1:
                raise ValueError("missing generated cancellation member")
            destination.write_text(text)
            return "provided_generated_header_with_synthetic_160_slot_cancel_shape"
        destination.write_text(text)
        return "provided_generated_header"
    text = text.replace("} DifftestArchEvent;", "  uint8_t irToHU;\n  uint64_t eventSeq;\n} DifftestArchEvent;")
    marker = "typedef struct {\n  DifftestArchIntRegState"
    if text.count(marker) != 1:
        raise ValueError("unsupported baseline DiffTestState declaration")
    text = text.replace(marker, "\n".join(declarations) + "\n\n" + marker)
    members = "\n".join("  DifftestUserTimer" + name + " uit_" + name.lower() +
                        ("[8]" if name == "Retire" else "[160]" if name == "Cancel" else "") + ";" for name in names)
    text = text.replace("} DiffTestState;", members + "\n} DiffTestState;")
    destination.write_text(text)
    return "synthetic_UIT_declarations_from_Bundles_scala"


def capture_census(header, destination):
    structs = {name: body for body, name in re.findall(r"typedef\s+struct\s*\{([^{}]*)\}\s*(\w+)\s*;", header.read_text(), re.S)}
    members = re.findall(r"^\s*(Difftest\w+)\s+(\w+)(?:\[(\d+)\])?\s*;", structs["DiffTestState"], re.M)
    flags, census = [], []
    for typename, member, array in members:
        if re.search(r"\buint8_t\s+valid\s*;", structs[typename]):
            count = int(array) if array else 1
            census.append({"member": member, "type": typename, "entries": count})
            flags += [f"state.{member}[{i}].valid" if array else f"state.{member}.valid" for i in range(count)]
    if not flags or "uint8_t  hasTrap;" not in structs["DifftestTrapEvent"]:
        raise ValueError("generated capture census is incomplete")
    flags.append("state.trap.hasTrap")
    body = ["// Derived from the generated struct declarations, independently of the production clear helper.",
            f"static constexpr size_t capture_census_count = {len(flags)};",
            "static void set_capture_census_flags(DiffTestState &state, uint8_t value) {"]
    body += [f"  {flag} = value;" for flag in flags]
    body += ["}"]
    destination.write_text("\n".join(body) + "\n")
    return {"packet_members": census, "flag_count_including_hasTrap": len(flags)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generated-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--cxx", default="g++")
    parser.add_argument("--exit-only", action="store_true", help="Run only the Emulator::is_good exit cases")
    parser.add_argument("--sticky-only", action="store_true", help="Run only repeated live-buffer capture cases")
    parser.add_argument("--ram-anchor-only", action="store_true", help="Run only RAM initialization boundary cases")
    parser.add_argument("--indexed-cancel-only", action="store_true", help="Run indexed cancellation and affected capture/queue cases")
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    root = source.parent.parent
    original = args.generated_dir.resolve() / "diffstate.h"
    output = args.output_dir.resolve()
    if not original.is_file():
        parser.error("--generated-dir must contain diffstate.h")
    if output.exists():
        parser.error("--output-dir must be new to preserve earlier evidence")
    fixture = output / "fixture"
    fixture.mkdir(parents=True)
    declaration_kind = make_fixture(root, original, fixture / "diffstate.h")
    census = capture_census(fixture / "diffstate.h", fixture / "capture-census.inc")
    production = root / "src/test/csrc/difftest"
    for name in ("user_timer_bridge.h", "user_timer_bridge.inc"):
        (fixture / name).write_bytes((production / name).read_bytes())
    retirement_source = (production / "difftest.cpp").read_text()
    symbol = retirement_source.index("static constexpr uint64_t reference_start_pc")
    begin = retirement_source.rindex("#ifdef", 0, symbol)
    finish = retirement_source.index("#endif", symbol) + len("#endif")
    (fixture / "production-reference-start.inc").write_text(retirement_source[begin:finish] + "\n")
    extracted = []
    for start, end in (("inline int Difftest::check_all()", "void Difftest::do_interrupt()"),
                       ("int Difftest::do_instr_commit(int i)", "void Difftest::do_first_instr_commit()"),
                       ("void Difftest::do_exception()", "int Difftest::do_instr_commit(int i)"),
                       ("void Difftest::do_first_instr_commit()", "#if defined(CONFIG_DIFFTEST_LOADEVENT) && defined(CONFIG_DIFFTEST_ARCHVECREGSTATE)")):
        begin = retirement_source.index(start)
        finish = retirement_source.index(end, begin)
        extracted.append(retirement_source[begin:finish])
    (fixture / "production-retirement.inc").write_text("\n".join(extracted))
    emulator_source = (root / "src/test/csrc/verilator/emu.cpp").read_text()
    begin = emulator_source.index("int Emulator::is_good()")
    finish = emulator_source.index("inline char *Emulator::timestamp_filename", begin)
    (fixture / "production-exit.inc").write_text(emulator_source[begin:finish])
    command = [args.cxx, "-std=c++17", "-O1", "-g", "-Werror"]
    for include in [fixture, root / "config", root / "src/test/csrc/common", root / "src/test/csrc/difftest"]:
        command += ["-I", str(include)]
    command += [str(source / "protocol-test.cpp"), "-o", str(output / "protocol-test")]
    build = subprocess.run(command, text=True, capture_output=True, timeout=60)
    (output / "build.stdout").write_text(build.stdout)
    (output / "build.stderr").write_text(build.stderr)
    report = {"schema": 1, "evidence_kind": "production_host_protocol_unit_with_spies", "dut_execution": False,
              "reference_model_execution": False, "generated_abi_verified": False,
              "declaration_kind": declaration_kind, "base_header": str(original),
              "capture_census": census,
              "production_functions": ["Difftest::check_all", "Difftest::do_instr_commit", "Difftest::do_exception",
                                       "Difftest::do_first_instr_commit", "Emulator::is_good", "user_timer_bridge.inc"],
              "stubbed_dependencies": ["reference ISA execution", "full architectural state comparison",
                                        "memory and TLB checks", "reference import and initialization API implementations",
                                        "flash and memory clone input data"],
              "source_snapshot_dir": str(fixture),
              "build_command": command, "build_exit_code": build.returncode, "cases": []}
    if build.returncode:
        report["status"] = "FAIL"
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print("Protocol unit build failed:", output)
        return 1
    if args.ram_anchor_only:
        baseline_source = fixture / "baseline-reference-start.cpp"
        baseline_source.write_text('#include "config.h"\n#undef CONFIG_DIFFTEST_USERTIMERACCESS\n'
                                   '#include "production-reference-start.inc"\n'
                                   'static_assert(reference_start_pc == FIRST_INST_ADDRESS, "baseline start PC remains configured");\n')
        baseline_command = [args.cxx, "-std=c++17", "-Werror", "-fsyntax-only", "-I", str(fixture),
                            "-I", str(root / "config"), str(baseline_source)]
        baseline = subprocess.run(baseline_command, text=True, capture_output=True, timeout=60)
        (output / "baseline-start.stdout").write_text(baseline.stdout)
        (output / "baseline-start.stderr").write_text(baseline.stderr)
        report["baseline_reference_start_check"] = {"command": baseline_command, "exit_code": baseline.returncode}
        if baseline.returncode:
            report["status"] = "FAIL"
            (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            return 1

    positives = ["initial_reset", "feature_off", "same_pc_distinct_uid", "same_pc_distinct_uid_execute", "out_of_order_samples_execute", "cancel_flush", "cancel_hu_keeps_source",
                 "readiness", "frame_fifo", "exec_valid", "exec_legal_exception", "exec_uret", "event_valid",
                 "uart_valid", "uart_wait", "uart_observe_replicated", "uart_observe_upper_lanes", "terminal_valid", "order_middle", "order_before_slot0", "order_after_last",
                 "status_early_marker", "status_delayed_good", "decode_off_no_access", "decode_on_missing_access",
                 "decode_off_timer_missing_access", "decode_off_wrong_cause", "decode_off_interrupt", "decode_off_with_access"]
    negatives = {
        "warm_reset": "warm reset is unsupported",
        "clock_epoch": "observation epoch mismatch",
        "feature_mismatch": "DUT and reference feature configuration mismatch",
        "duplicate_access": "duplicate or invalid access identity",
        "out_of_order_closed_duplicate": "duplicate or invalid access identity",
        "access_missing_sample": "missing or wrong-address sample",
        "access_wrong_csr": "access CSR metadata mismatch",
        "access_wrong_funct3": "access CSR metadata mismatch",
        "access_epoch": "duplicate or invalid access identity",
        "access_zero_uid": "duplicate or invalid access identity",
        "access_pending_payload": "invalid sample payload",
        "access_unexpected_sample": "unexpected sample",
        "access_wrong_sample_kind": "invalid sample payload",
        "access_overflow": "access queue overflow",
        "missing_response_access": "missing access or duplicate response",
        "duplicate_response": "missing access or duplicate response",
        "response_wrong_uid": "missing access or duplicate response",
        "response_epoch": "missing access or duplicate response",
        "snapshot_wrong_uid": "unmatched or duplicate access snapshot",
        "duplicate_snapshot": "unmatched or duplicate access snapshot",
        "snapshot_epoch": "snapshot identity mismatch",
        "duplicate_event_snapshot": "duplicate event snapshot or overflow",
        "cancel_after_effect": "cancellation after effect",
        "frame_overflow": "comparison frame FIFO overflow",
        "exec_missing": "missing controlled transaction",
        "exec_wrong_transaction": "wrong dynamic transaction",
        "exec_pc": "controlled execution PC or mode mismatch",
        "exec_mode": "controlled execution PC or mode mismatch",
        "exec_pre_bank": "ordinary user architectural state mismatch",
        "exec_post_bank": "ordinary user architectural state mismatch",
        "exec_result_uid": "controlled execution outcome mismatch",
        "exec_result_seq": "controlled execution outcome mismatch",
        "exec_sample_consumed": "controlled execution outcome mismatch",
        "exec_rejected": "reference rejected controlled execution",
        "exec_response_rdata": "DUT CSR response differs from its read sample",
        "exec_write_value": "DUT CSR write request differs from reference calculation",
        "exec_uret_target": "URET target mismatch",
        "event_missing": "missing architectural event snapshot",
        "event_pc": "reference PC differs from event boundary",
        "event_order": "architectural event order or identity mismatch",
        "event_retirement": "architectural event order or identity mismatch",
        "event_type": "invalid HU event type",
        "event_target": "architectural event target mismatch",
        "event_post_bank": "ordinary user architectural state mismatch",
        "event_rejected": "reference rejected HU event",
        "uart_mismatch": "UART output mismatch",
        "uart_observe_mismatch": "UART output mismatch",
        "uart_observe_length": "invalid UART observation",
        "uart_observe_address": "invalid UART observation",
        "uart_observe_epoch": "invalid UART observation",
        "terminal_uninitialized": "unclosed transactions or retirement mismatch at termination",
        "terminal_access": "unclosed transactions or retirement mismatch at termination",
        "terminal_retirement": "unclosed transactions or retirement mismatch at termination",
        "terminal_reference_uart": "unmatched reference UART output at termination",
        "terminal_pending_store": "uncompared DUT stores at termination",
        "order_boundary_behind": "architectural event arrived after its boundary",
        "order_boundary_ahead": "architectural event order or identity mismatch",
        "order_boundary_inside_group": "architectural event splits a retired instruction group",
        "order_retire_count": "retirement identity or count mismatch",
        "order_missing_uid": "retirement identity or count mismatch",
        "order_wrong_pc": "reference PC differs from retirement boundary",
        "order_skipped_controlled": "controlled instruction was skipped or fused",
        "order_fused_controlled": "controlled instruction was skipped or fused",
        "status_missing_commit": "terminal instruction has not been compared",
        "status_wrong_uid": "terminal retirement identity mismatch",
        "terminal_raw_pc_mismatch": "raw trap and terminal identity disagree",
        "terminal_duplicate_marker": "invalid or duplicate terminal identity",
        "exec_result_epoch": "controlled execution outcome mismatch",
        "exec_result_bytes": "controlled execution outcome mismatch",
        "exec_state_epoch": "reference state header mismatch",
        "exec_state_bytes": "reference state header mismatch",
        "exec_state_sequence": "reference state header mismatch",
        "uart_header_bytes": "UART output mismatch",
        "fault_ustatus": "ordinary user architectural state mismatch",
        "fault_uie": "ordinary user architectural state mismatch",
        "fault_utvec": "ordinary user architectural state mismatch",
        "fault_uscratch": "ordinary user architectural state mismatch",
        "fault_uepc": "ordinary user architectural state mismatch",
        "fault_ucause": "ordinary user architectural state mismatch",
        "fault_utval": "ordinary user architectural state mismatch",
        "fault_hu_boundary": "reference PC differs from event boundary",
        "fault_hu_target": "architectural event target mismatch",
        "fault_uret_target": "URET target mismatch",
        "decode_off_target_mismatch": "architectural event target mismatch",
        "decode_off_bank_mismatch": "ordinary user architectural state mismatch",
    }
    aborted = {"status_ref_end_without_marker": "reference ended before the terminal comparison",
               "status_ref_end_early": "reference ended before the terminal comparison",
               "status_missing_raw": "missing raw terminal marker",
               "status_dut_badtrap": "DUT or reference termination failed",
               "status_reference_running_at_terminal": "DUT or reference termination failed",
               "status_compare_failure": ""}
    cases = ([(name, 0, "") for name in positives] + [(name, 1, diag) for name, diag in negatives.items()] +
             [(name, 2, diag) for name, diag in aborted.items()])
    exit_cases = [("exit_good", 0, ""), ("exit_limit_mature", 1, ""),
                  ("exit_limit_without_terminal", 1, "terminal instruction has not been compared"),
                  ("exit_sim_exit_pending", 1, "terminal instruction has not been compared"),
                  ("exit_nonzero_trap", 1, "DUT or reference termination failed")]
    sticky_cases = [(name, 0, "") for name in ("sticky_controlled_frame", "sticky_event_frame", "sticky_terminal_frame",
                                               "capture_census", "capture_reset")]
    ram_cases = [(name, 0, "") for name in ("ram_anchor_enabled", "ram_anchor_disabled")]
    indexed_cases = [("indexed_cancel_mixed", 0, "")] + [
        (name, 1, "illegal or duplicate cancellation after effect") for name in
        ("indexed_cancel_duplicate", "indexed_cancel_effect_first", "indexed_cancel_effect_last")]
    indexed_affected = indexed_cases + sticky_cases + [("cancel_flush", 0, ""), ("cancel_hu_keeps_source", 0, ""),
        ("cancel_after_effect", 1, "cancellation after effect"), ("readiness", 0, ""), ("frame_fifo", 0, ""),
        ("frame_overflow", 1, "comparison frame FIFO overflow"),
        ("terminal_access", 1, "unclosed transactions or retirement mismatch at termination")]
    cases = indexed_affected if args.indexed_cancel_only else ram_cases if args.ram_anchor_only else sticky_cases if args.sticky_only else exit_cases if args.exit_only else cases + exit_cases + sticky_cases + ram_cases + indexed_cases
    for name, expected, diagnostic in cases:
        invocation = [str(output / "protocol-test"), name, str(output / (name + ".trace.jsonl"))]
        result = subprocess.run(invocation, text=True, capture_output=True, timeout=15)
        (output / (name + ".stdout")).write_text(result.stdout)
        (output / (name + ".stderr")).write_text(result.stderr)
        passed = result.returncode == expected and diagnostic in result.stderr
        report["cases"].append({"name": name, "command": invocation, "expected_exit_code": expected,
                                "exit_code": result.returncode, "expected_diagnostic": diagnostic, "passed": passed})
    report["passed"] = sum(case["passed"] for case in report["cases"])
    report["total"] = len(report["cases"])
    report["status"] = "PASS" if report["passed"] == report["total"] else "FAIL"
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Production protocol unit {report['status']}: {report['passed']}/{report['total']}; {output}")
    return int(report["status"] != "PASS")


if __name__ == "__main__":
    sys.exit(main())
