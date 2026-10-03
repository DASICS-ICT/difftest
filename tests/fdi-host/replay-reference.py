#!/usr/bin/env python3
"""Replay real local CSR observer records against an independently executing reference."""

import argparse
from collections import defaultdict
import json
from pathlib import Path
import shutil
import struct
import subprocess


def program():
    addresses = [0xBC4, 0x9E1, 0xBC5, 0xBC6, 0x9E2, 0x9E3, 0x880]
    addresses += list(range(0x890, 0x8B0)) + list(range(0x8B0, 0x8B4))
    addresses += [0x8C8] + list(range(0x8C0, 0x8C8))
    instructions = [(csr << 20) | (1 << 15) | (1 << 12) | (2 << 7) | 0x73 for csr in addresses]
    instructions += [(csr << 20) | (2 << 12) | (2 << 7) | 0x73 for csr in addresses]
    return {"schema": 1, "scope": "local_real_CSR_wrapper_and_shared_UID_observer",
            "initial_pc": 0x80000000, "initial_mode": 3, "initial_x1": (1 << 64) - 1,
            "instruction_count": 104, "csr_addresses": addresses, "instructions": instructions}


def number(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def records(text):
    active = False
    finished = False
    result = []
    for line in text.splitlines():
        if "FDI_REFERENCE_BEGIN" in line:
            if active or finished:
                raise ValueError("duplicate reference replay region")
            active = True
            continue
        if "FDI_REFERENCE_END" in line:
            if not active:
                raise ValueError("reference replay region ended before beginning")
            active = False
            finished = True
            continue
        if not active:
            continue
        for prefix, kind in (("FDI_RTL_OBSERVATION", "observation"), ("FDI_RTL_RETIRE", "retirement")):
            if prefix in line:
                payload = json.loads(line.split(prefix, 1)[1].strip())
                record = {key: [number(item) for item in value] if isinstance(value, list) else number(value)
                          for key, value in payload.items()}
                if kind == "observation" and (len(record["words"]) != 52 or record["kind"] not in (1, 2, 3)):
                    raise ValueError("unexpected observation shape or kind")
                result.append((kind, record))
    if not finished or active or sum(kind == "retirement" for kind, _ in result) != 104:
        raise ValueError("real replay region must finish with exactly 104 retirements")
    return result


def normalize(items, destination):
    frames = defaultdict(lambda: {"observation": [], "retirement": []})
    for kind, record in items:
        frames[record["cycle"]][kind].append(record)
    lines = []
    fields = "kind epoch uid cycle pc eventSeq beforeCount instruction robIdx csrAddress robFlag readNeeded writeNeeded permitted actualWrite responseIllegal responseVirtual cancelReason".split()
    retire_fields = "epoch uid pc instruction robIdx robFlag beforeCount afterCount".split()
    for cycle, frame in sorted(frames.items()):
        observations = sorted(frame["observation"], key=lambda item: item["lane"])
        if len({item["lane"] for item in observations}) != len(observations):
            raise ValueError("duplicate observation lane")
        lines.append(f"F {cycle} {len(observations)} {len(frame['retirement'])}")
        for item in observations:
            lines.append(" ".join(str(item[field]) for field in fields) + " " + " ".join(map(str, item["words"])))
        for item in frame["retirement"]:
            lines.append(" ".join(str(item[field]) for field in retire_fields))
    destination.write_text("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", type=Path, required=True, help="Persistent simulator log containing the real replay region")
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--generated-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--cxx", default="g++")
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    root = source.parents[1]
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    trace = args.trace.resolve()
    shutil.copyfile(trace, output / "real-producer.log")
    manifest = program()
    (output / "program.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (output / "program.bin").write_bytes(b"".join(struct.pack("<I", word) for word in manifest["instructions"]))
    actual = records(trace.read_text())
    normalize(actual, output / "observations.txt")
    mutant = json.loads(json.dumps(actual))
    target = next(record for kind, record in mutant if kind == "observation" and record["kind"] == 3 and record["actualWrite"])
    target["words"][39] ^= 1
    (output / "mutant-records.json").write_text(json.dumps(mutant, indent=2) + "\n")
    normalize(mutant, output / "mutant-observations.txt")
    flags = [args.cxx, "-std=c++17", "-O1", "-g", "-Werror"]
    generated_header = args.generated_dir.resolve() / "diffstate.h"
    generated = generated_header.read_text()
    for macro in ("CONFIG_DIFFTEST_FDIOBSERVATION", "CONFIG_DIFFTEST_USERTIMERACCESS"):
        if "#define " + macro not in generated:
            flags.append("-D" + macro)
    # RefProxy uses the actual ordinary register declaration. No synthetic DPI
    # declaration is needed by this persisted-observation replay executable.
    for directory in (args.generated_dir.resolve(), root / "config", root / "src/test/csrc/common",
                      root / "src/test/csrc/difftest"):
        flags += ["-I", str(directory)]
    command = flags + [str(source / "replay-reference.cpp"), str(root / "src/test/csrc/difftest/refproxy.cpp"),
                       "-ldl", "-o", str(output / "replay-reference")]
    build = subprocess.run(command, capture_output=True, text=True, timeout=60)
    (output / "build.stdout").write_text(build.stdout)
    (output / "build.stderr").write_text(build.stderr)
    report = {"schema": 1, "evidence_kind": "real_local_CSR_observer_and_reference_replay",
              "full_processor_execution": False, "source_trace": str(trace), "reference": str(args.reference.resolve()),
              "generated_header": str(args.generated_dir.resolve() / "diffstate.h"),
              "build": {"command": command, "exit_code": build.returncode}, "runs": []}
    if build.returncode == 0:
        for name, observations in (("positive", "observations.txt"), ("canonical-word-mutant", "mutant-observations.txt")):
            command = [str(output / "replay-reference"), str(args.reference.resolve()), str(output / observations),
                       str(output / "program.bin"), str(output / (name + ".jsonl"))]
            run = subprocess.run(command, capture_output=True, text=True, timeout=60)
            (output / (name + ".stdout")).write_text(run.stdout)
            (output / (name + ".stderr")).write_text(run.stderr)
            passed = run.returncode == 0 if name == "positive" else run.returncode == 1 and "FDI architectural state mismatch" in run.stderr
            report["runs"].append({"name": name, "command": command, "exit_code": run.returncode, "passed": passed})
    report["fault"] = {"kind": "single canonical DUT post word", "uid": target["uid"], "word": 39, "xor": 1,
                       "reference_input_unchanged": True, "original_trace_preserved": True}
    report["status"] = "PASS" if len(report["runs"]) == 2 and all(item["passed"] for item in report["runs"]) else "FAIL"
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"FDI real local replay {report['status']}: {output}")
    return int(report["status"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
