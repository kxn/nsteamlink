#!/usr/bin/env python3
"""Compare real Native playback with the pinned official Linux AVCodec caller.

Codec API results, output metadata/availability, clocks and presentation return
metadata are declared boundary inputs. All delivered pixels are first real
FFmpeg output checked against independent framemd5. Original client functions,
not a rewritten queue model, supply expected stages, feedback, completion and
jitter state. This is not natural hardware/Steam/SDL failure or startup proof.
"""

import argparse
import gzip
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = 2147483647


def execute(receiver, commands):
    result = subprocess.run(
        [str(receiver), str(ROOT / "app/tests/fixtures/video/sequential.h264")],
        input="\n".join(commands) + "\n",
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert not result.returncode, (result.returncode, result.stderr[-3000:], commands)
    return [json.loads(line) for line in result.stdout.splitlines()]


def commands_for(case):
    commands = ["B " + str(case.get("budget", 0))]
    if case.get("present_status") is False:
        commands += ["V 0"]
    mapping = []
    now = 1000000
    sequence = 0
    for op, inp in case["actions"]:
        if op == "submit":
            fid = inp.get("id", 23)
            stamp = inp.get("timestamp", now)
            now = inp.get("now", now)
            commands += [f"Q {inp.get('input_ticks', 0)} {inp.get('output_ticks', 0)}"]
            dimensions = inp.get("dimensions", [-1, -1])
            args = [
                inp.get("send", DEFAULT),
                inp.get("receive", DEFAULT),
                inp.get("parse_delta", 0),
                inp.get("parsed_size", -1),
                *dimensions,
                inp.get("format", -1),
            ]
            commands += ["E " + " ".join(map(str, args))]
            commands += ["T " + str(inp.get("output_pts", -(1 << 63)))]
            flags = 24 if not sequence else 8
            sequence += 1
            commands += [
                f"P {fid} {sequence} {flags} {stamp} {now} 0 {inp.get('size', 2204)}"
            ]
            now += inp.get("input_ticks", 0) + inp.get("output_ticks", 0)
        else:
            if inp is not None:
                now = inp
            commands += ["D " + str(now)]
        mapping.append(len(commands) - 1)
    return commands, mapping


def verify(case, native, mapping):
    for index, (source, action) in enumerate(zip(case["states"], mapping, strict=True)):
        got = native[action]
        results = {
            str(row["id"]): row["result"] if row["complete"] else 0
            for row in got["tracker"]
        }
        assert results == source["stats"], (
            case["name"],
            index,
            "stats",
            results,
            source["stats"],
        )
        assert got["jitter"]["count"] == source["jitter_count"], (
            case["name"],
            index,
            "count",
        )
        assert got["jitter"]["budget"] == source["jitter_budget"], (
            case["name"],
            index,
            "budget",
            got["jitter"],
            source,
        )
        assert got["reset_feedback_applied"] == bool(source["reset_requested"]), (
            case["name"],
            index,
            "reset",
        )
        # Compare operations belonging to this action. Native cleanup can make
        # additional rejected completion attempts; effective first result above
        # is read from the actual one-time tracker publication history.
        events = [row for row in got["events"] if row[0] == action]
        stages = [[row[2], row[3], row[4]] for row in events if row[1] == 0]
        expected = [
            row[1:]
            for row in source["events"]
            if row[0] == "event" and row[2] in (14, 15)
        ]
        assert stages == expected, (
            case["name"],
            index,
            "decode stages",
            stages,
            expected,
        )
        feedback = [[row[2], format(row[3], "02x")] for row in events if row[1] == 2]
        assert feedback == [
            [row[1], row[2]] for row in source["events"] if row[0] == "feedback"
        ], (case["name"], index, "DataLost", feedback)
        samples = [[row[2], row[3]] for row in events if row[1] == 3]
        assert samples == [row[1:] for row in source["events"] if row[0] == "sample"], (
            case["name"],
            index,
            "sample",
        )
        sdk = [
            (row[1], row[2], row[3] if row[1] == 4 else 0)
            for row in events
            if row[1] in (4, 5)
        ]
        expected_sdk = [
            (4 if row[0] == "send" else 5, row[1], row[2] if row[0] == "send" else 0)
            for row in source["events"]
            if row[0] in ("send", "receive")
        ]
        assert sdk == expected_sdk, (
            case["name"],
            index,
            "SDK calls",
            sdk,
            expected_sdk,
        )
        if any(row[0] == "reset" for row in source["events"]):
            send = next(n for n, row in enumerate(events) if row[1] == 4)
            reset = next(
                n for n, row in enumerate(events) if row[1] == 7 and row[2] == 2
            )
            receive = next(n for n, row in enumerate(events) if row[1] == 5)
            assert send < reset < receive, (
                case["name"],
                index,
                "send/reset/receive order",
            )
        if feedback:
            loss = next(n for n, row in enumerate(events) if row[1] == 2)
            sample = next(n for n, row in enumerate(events) if row[1] == 3)
            end = next(
                n for n, row in enumerate(events) if row[1] == 0 and row[3] == 15
            )
            assert loss < sample < end, (case["name"], index, "feedback/Put/end order")
        if case["actions"][index][0] == "present":
            selected = next(
                (row[1] for row in got["selected"] if row[0] == action), None
            )
            new_task = next(
                (
                    row[1]
                    for row in source["events"]
                    if row[0] == "event" and row[2] == 16
                ),
                None,
            )
            expected_selected = source["previous"] if new_task is not None else None
            assert selected == expected_selected, (
                case["name"],
                index,
                "selection",
                selected,
                expected_selected,
            )
            prep = [row[1:] for row in got["prep"] if row[0] == action]
            expected_prep = [
                row[1:3]
                for row in source["events"]
                if row[0] == "event" and row[2] in (16, 17)
            ]
            assert prep == expected_prep, (
                case["name"],
                index,
                "prep",
                prep,
                expected_prep,
            )
            pixels = [row for row in got["physical_selected"] if row[0] == action]
            # Compare the returned object of a NEW task. Repainting an old SDL
            # texture may avoid a redundant copy in this port's GPU backend.
            expected_pixels = new_task is not None and any(
                row[0] == "pixel_upload" for row in source["events"]
            )
            assert bool(pixels) == expected_pixels, (
                case["name"],
                index,
                "physical object",
                pixels,
                expected_pixels,
            )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", type=Path, required=True)
    args = parser.parse_args()
    source = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-client-avcodec-player-reference.json.gz"
            ).read_bytes()
        )
    )
    states = 0
    for case in source["cases"]:
        commands, mapping = commands_for(case)
        native = execute(args.receiver.resolve(), commands)
        verify(case, native, mapping)
        states += len(mapping)
    keys = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-client-avcodec-key-reference.json.gz"
            ).read_bytes()
        )
    )
    for case in keys["cases"]:
        commands = ["B 0"]
        mapping = []
        for a in case["actions"]:
            if a[0] == "P":
                _, fid, seq, flags, offset, size = a
                commands += [f"P {fid} {seq} {flags} 1000000 1000000 {offset} {size}"]
            else:
                commands += ["D 1000000"]
            mapping.append(len(commands) - 1)
        native = execute(args.receiver.resolve(), commands)
        projected = dict(
            case,
            actions=[
                ["submit", None] if a[0] == "P" else ["present", None]
                for a in case["actions"]
            ],
        )
        verify(projected, native, mapping)
        assert not any(row[1] == 8 for row in native[-1]["events"]), (
            case["name"],
            "unofficial codec flush",
        )
        states += len(mapping)
    print(
        "Native AVCodec:",
        len(source["cases"]) + len(keys["cases"]),
        "official client cases,",
        states,
        "states passed",
    )


if __name__ == "__main__":
    main()
