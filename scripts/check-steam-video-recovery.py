#!/usr/bin/env python3
"""Compare Native config/EIO/actor policy against official client execution.

Real runtime/control/video worker/FFmpeg/media/owned config APIs run. SDK status
injection uses real independently hashed pixels, as in the existing AVCodec
oracle. Format-callback comparison declares the target HW unavailable; actual
SDK hardware capability absence is separately exercised by video_pipeline.
Compare complete config bytes, effective preference, reset epochs, DataLost and
absence of config notify/save/99. Source decoder-info 80's text/timing, physical
GPU/Nvtegra faults, full statistics and general network wire are outside this
projection. The original full source functions/terminals remain in its fixture.
"""

import argparse
import gzip
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "playback", ROOT / "scripts/check-steam-video-avcodec.py"
)
playback = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(playback)


def verify(receiver, case):
    commands = ["C " + (case["config"] or "-")]
    mapping = []
    seq = 0
    for op, value in case["actions"]:
        if op == "submit":
            commands += [f"E {value['send']} {value['receive']} 0 -1 -1 -1 -1"]
            seq += 1
            flags = 24 if seq == 1 or value.get("native_key") else 8
            commands += [f"P {value['id']} {seq} {flags} 1000000 1000000 0 2204"]
        elif op == "actor":
            commands += ["R"]
        else:
            assert op == "format"
            commands += [f"F {len(value)} " + " ".join(map(str, value))]
        mapping.append(len(commands) - 1)
    native = playback.execute(receiver, commands)
    assert native[0]["config"] == case["initial"]["config"]
    epoch = 1
    preference = case["initial"]["hardware"]
    for index, (source, position) in enumerate(
        zip(case["states"], mapping, strict=True)
    ):
        got = native[position]
        for row in source["events"]:
            if row[0] == "codec_preference":
                preference = bool(row[1])
        assert got["requested_hardware"] == preference, (
            case["name"],
            index,
            "actual backend request",
        )
        epoch += sum(
            row[:2] == ["actor", "decoder_restart"] for row in source["events"]
        )
        assert got["config"] == source["config"], (
            case["name"],
            index,
            "config",
            got["config"],
            source["config"],
        )
        assert got["hardware_preference"] == source["hardware"], (
            case["name"],
            index,
            "hardware preference",
        )
        assert got["epoch"] == epoch, (
            case["name"],
            index,
            "actual decoder epoch",
            got["epoch"],
            epoch,
        )
        events = [row for row in got["events"] if row[0] == position]
        losses = [[row[2], format(row[3], "02x")] for row in events if row[1] == 2]
        expected = [
            row[1:]
            for row in source["events"]
            if row[:1] == ["feedback"] and row[1] == 3
        ]
        assert losses == expected, (case["name"], index, "DataLost", losses, expected)
        assert not any(
            row[1] in (10, 11) or (row[1] == 9 and row[2] == 99) for row in events
        ), (case["name"], index, "unexpected config side effect", events)
        if case["actions"][index][0] == "format":
            selected = next(
                row[1] for row in source["events"] if row[0] == "format_return"
            )
            assert got["format_result"] & 0xFFFFFFFF == selected, (
                case["name"],
                index,
                "format",
            )
        if case["actions"][index][0] == "submit":
            feedback = next(
                (n for n, row in enumerate(events) if row[1] == 7 and row[2] & 4), None
            )
            if case["actions"][index][1]["send"] == -5:
                assert feedback is not None and events[feedback][2] == 6, (
                    case["name"],
                    index,
                    "disable before reset",
                )
                sent = next(n for n, row in enumerate(events) if row[1] == 4)
                received = next(n for n, row in enumerate(events) if row[1] == 5)
                assert sent < feedback < received
            else:
                assert feedback is None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", type=Path, required=True)
    args = parser.parse_args()
    source = json.loads(
        gzip.decompress(
            (
                ROOT
                / "scripts/fixtures/steam-client-avcodec-recovery-reference.json.gz"
            ).read_bytes()
        )
    )
    for case in source["cases"]:
        verify(args.receiver.resolve(), case)
    print(
        "Native recovery:",
        len(source["cases"]),
        "official cases,",
        sum(len(case["states"]) for case in source["cases"]),
        "states passed",
    )


if __name__ == "__main__":
    main()
