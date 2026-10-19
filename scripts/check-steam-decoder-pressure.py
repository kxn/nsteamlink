#!/usr/bin/env python3
"""Compare original pressure input/submit behavior, preserving port guard differences.

Native tracker storage is a separate local resource invariant, never an official
capacity constant. Submitted payload SHA256 compares the actual complete bytes.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def execute(receiver, case):
    lines = []
    for batch in case["batches"]:
        lines.extend("F " + " ".join(map(str, frame)) for frame in batch)
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


def normalize(row):
    out = dict(row)
    out.pop("tracker_capacity")
    out["flow"] = [
        (
            event[:3] + [hashlib.sha256(bytes.fromhex(event[3])).hexdigest()]
            if event[0] == "decode"
            else event
        )
        for event in row["flow"]
    ]
    return out


def verify(receiver, case, rows=None):
    got = execute(receiver, case) if rows is None else rows
    want = case["states"]
    assert len(got) == len(want), (case["name"], "batch count", len(got), len(want))
    for index, (native, source) in enumerate(zip(got, want)):
        expected = dict(source)
        if case["native_guard"]:
            # Explicit local 256-partial protection: Source does not emit this.
            assert source["flow"][0] == ["flush", 0, 0, 0]
            expected["flow"] = [["lost", 0], ["flush", 0, 1, 0], *source["flow"][1:]]
        value = normalize(native)
        assert value == expected, (
            case["name"],
            index,
            "state/flow differs",
            value,
            expected,
        )
        capacity = native["tracker_capacity"]
        assert capacity in (256, 512), (
            case["name"],
            index,
            "unexpected resource growth",
            capacity,
        )
        if case["name"] == "300_key_inputs":
            assert (
                capacity == 256
            ), "Completed collected records must be reusable without growth"
        if case["name"] == "300_retained_outputs" and index == len(want) - 1:
            assert capacity == 512 and len(native["player"]) == 301
    return len(got)


def execute_stats(receiver, case):
    result = subprocess.run(
        [
            str(receiver.resolve()),
            "tracked-batched",
            str(int(case["full"])),
            "0",
            "0",
            *map(str, case["ids"]),
        ],
        input="\n".join(" ".join(map(str, action)) for action in case["actions"])
        + "\n",
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        "stats",
        case["full"],
        result.returncode,
        result.stderr[-2000:],
    )
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    return rows


def verify_stats(receiver, case, rows=None):
    spec = importlib.util.spec_from_file_location(
        "stats_check", ROOT / "scripts/check-steam-frame-stats.py"
    )
    check = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(check)
    rows = execute_stats(receiver, case) if rows is None else rows
    assert len(rows) == len(case["actions"])
    for observation in case["observed"]:
        index, original = observation["index"], observation["state"]
        expected = {
            key: original[key]
            for key in (
                "last_frame",
                "last_display",
                "displayed",
                "reported",
                "slots",
                "frames",
            )
        }
        expected["slots"] = [
            (
                None
                if slot is None
                else {
                    **{key: value for key, value in slot.items() if key != "extra"},
                    "deltas": slot["extra"][:16],
                }
            )
            for slot in original["slots"]
        ]
        expected["details"] = [
            value.hex()
            for frame in original["frames"]
            for field, kind, value, _ in check.wire.fields(bytes.fromhex(frame)[1:])
            if field == 2 and kind == 2
        ]
        assert rows[index] == expected, (
            "stats",
            case["full"],
            index,
            rows[index],
            expected,
        )
    return len(case["observed"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", required=True, type=Path)
    parser.add_argument(
        "--reference",
        type=Path,
        default=ROOT / "scripts/fixtures/steam-decoder-pressure-reference.json.gz",
    )
    parser.add_argument("--stats-receiver", required=True, type=Path)
    args = parser.parse_args()
    reference = json.loads(gzip.decompress(args.reference.read_bytes()))
    cases = reference["cases"]
    states = sum(verify(args.receiver, case) for case in cases)
    guards = sum(case["native_guard"] for case in cases)
    stats_states = sum(
        verify_stats(args.stats_receiver, case) for case in reference["stats_cases"]
    )
    print("Overflow statistics: 2 original-client cases/", stats_states, "flush states")
    print(
        f"Decoder pressure: {len(cases)} official cases/{states} states; {guards} explicit port guards"
    )


if __name__ == "__main__":
    main()
