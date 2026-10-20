#!/usr/bin/env python3
"""Compare original tasks/properties and media flow against the actual Native worker.

Pointer/receiveSerial values are process-local: label first observations without
changing equality relationships. Repeated labels or changed old properties fail
the same comparison as Source. Successful normal receiver exit is required.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def execute(receiver, case):
    lines = []
    for batch in case["batches"]:
        lines.extend(" ".join(map(str, action)) for action in batch)
        lines.append("B")
    result = subprocess.run(
        [
            str(receiver.resolve()),
            str(ROOT / "app/tests/fixtures/video/sequential.h264"),
        ],
        input="\n".join(lines) + "\n",
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        case["name"],
        result.returncode,
        result.stderr[-2000:],
    )
    return [json.loads(line) for line in result.stdout.splitlines()]


def verify(receiver, case, rows=None):
    rows = execute(receiver, case) if rows is None else rows
    assert len(rows) == len(case["states"]), (case["name"], "batch count", len(rows))
    labels = {}
    for index, (native, source) in enumerate(zip(rows, case["states"])):
        value = {key: val for key, val in native.items() if key != "tracker_capacity"}
        value["tasks"] = [
            [labels.setdefault(task, len(labels)), fid, stamp]
            for task, fid, stamp in value["tasks"]
        ]
        value["flow"] = [
            (
                event[:3] + [hashlib.sha256(bytes.fromhex(event[3])).hexdigest()]
                if event[0] == "decode"
                else event
            )
            for event in value["flow"]
        ]
        assert value == source, (case["name"], index, value, source)
    return len(rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", required=True, type=Path)
    parser.add_argument("--stats-receiver", type=Path)
    parser.add_argument(
        "--reference",
        type=Path,
        default=ROOT / "scripts/fixtures/steam-decoder-identity-reference.json",
    )
    parser.add_argument(
        "--baseline-report",
        type=Path,
        help="Capture normal baseline differences without claiming alignment",
    )
    args = parser.parse_args()
    reference = json.loads(args.reference.read_text())
    mismatches, observations = [], []
    count = 0
    for case in reference["cases"]:
        rows = execute(args.receiver, case)
        observations.append(dict(name=case["name"], rows=rows))
        try:
            count += verify(args.receiver, case, rows)
        except AssertionError as error:
            if not args.baseline_report:
                raise
            mismatches.append(dict(name=case["name"], difference=str(error)))
    if args.baseline_report:
        args.baseline_report.write_text(
            json.dumps(
                dict(
                    normal_exit_cases=len(observations),
                    observations=observations,
                    mismatches=mismatches,
                ),
                indent=2,
            )
            + "\n"
        )
        print(
            "Baseline only:", len(mismatches), "differing cases; not an alignment pass"
        )
    else:
        print(
            "Decoder identity:",
            len(reference["cases"]),
            "cases,",
            count,
            "states match",
        )
        if args.stats_receiver:
            spec = importlib.util.spec_from_file_location(
                "identity_stats_check", ROOT / "scripts/check-steam-decoder-pressure.py"
            )
            check = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(check)
            count = sum(
                check.verify_stats(args.stats_receiver, case)
                for case in reference["stats_cases"]
            )
            print(
                "Cancellation stats projection:",
                len(reference["stats_cases"]),
                "cases,",
                count,
                "report states match",
            )
