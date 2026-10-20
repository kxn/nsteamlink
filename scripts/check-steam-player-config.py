#!/usr/bin/env python3
"""Compare the production hardware-config delegate with official player traces.

The real Native runtime callback, complete config API/control FIFO, video reset
gate/actor, FFmpeg/media and current epochs run. SDK error injection still hashes
real decoded fixture pixels. Compare cache, complete config, reset notification
order, full submitted control plaintext and actual epoch changes. The Source
window/overlay/microphone cases remain Source-only; this hardware projection
does not claim those platform delegates, full SDK startup or real Steam/Switch.
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
    commands = ["C " + (case["initial_config"] or "-")]
    positions = []
    for op, value in case["actions"]:
        if op == "api":
            wire, local = value
            commands.append(f"U {local} {wire or '-'}")
        elif op == "peer99":
            commands.append(f"G {value}")
        elif op == "actor":
            commands.append("R")
        else:
            assert op == "eio"
            commands += ["E -5 -11 0 -1 -1 -1 -1", "P 23 1 24 1000000 1000000 0 2204"]
        positions.append(len(commands) - 1)
    native = playback.execute(receiver, commands)
    assert native[0]["config"] == case["initial"]["config"], (
        case["name"],
        "initial config",
    )
    assert native[0]["player_hardware_cache"] == case["initial"]["cache_hardware"], (
        case["name"],
        "initial player cache",
    )
    epoch = 1
    for source, position in zip(case["states"], positions, strict=True):
        got = native[position]
        epoch += sum(e[0] == "decoder_restart" for e in source["events"])
        assert got["epoch"] == epoch, (case["name"], position, "actual epoch")
        assert got["config"] == source["config"], (
            case["name"],
            position,
            "complete config",
        )
        assert got["player_hardware_cache"] == source["cache_hardware"], (
            case["name"],
            position,
            "player cache",
        )
        events = [e for e in got["events"] if e[0] == position]
        expected = []
        for event in source["events"]:
            if event[0] == "notify":
                expected.append([10, event[2]])
            elif event[0] == "save":
                expected.append([11, 0])
            elif event[0] == "reset_request" and any(
                e[0] == "notify" for e in source["events"]
            ):
                expected.append([12, 1])
        observed = [
            [e[1], e[3] if e[1] == 10 else (e[2] if e[1] == 12 else 0)]
            for e in events
            if e[1] in (10, 11, 12)
        ]
        assert observed == expected, (
            case["name"],
            position,
            "delegate/reset/save order",
            observed,
            expected,
        )
        bodies = [
            row[1]
            for row in got["control_bodies"]
            if row[0] == position and row[1].startswith("63")
        ]
        official = [
            e[3]
            for e in source["events"]
            if e[:1] == ["channel_send_terminal"]
            and e[2] == 1
            and e[3].startswith("63")
        ]
        assert bodies == official, (
            case["name"],
            position,
            "complete config 99 plaintext",
        )
        losses = [[e[2], format(e[3], "02x")] for e in events if e[1] == 2]
        expected_losses = [
            [e[2], e[3]]
            for e in source["events"]
            if e[:1] == ["channel_send_terminal"] and e[2] == 3 and e[3] == "02"
        ]
        assert losses == expected_losses, (case["name"], position, "DataLost")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    a = p.parse_args()
    report = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-client-player-config-reference.json.gz"
            ).read_bytes()
        )
    )
    cases = [case for case in report["cases"] if case["native_hardware_projection"]]
    for case in cases:
        verify(a.receiver.resolve(), case)
    print(
        "Native player hardware config:",
        len(cases),
        "official cases,",
        sum(len(c["states"]) for c in cases),
        "states passed",
    )


if __name__ == "__main__":
    main()
