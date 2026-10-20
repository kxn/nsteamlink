#!/usr/bin/env python3
"""Compare real Native AVCodec decoder-info reports to the official client.

The production callback table, media start/submit, real FFmpeg format callback,
epoch API/actor and full protobuf pack execute. Every decoded SDK picture still
passes the independent framemd5 check in the playback oracle before controlled
receive status. An SDK-open callback is explicitly injected at that SDK boundary.
The current one-thread, unavailable-HW/software projection covers six official
cases. Other SDK thread counts/unsupported offers/hardware success stay outside
this Native projection; all original Source cases remain frozen separately.
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


def verify(receiver, case, cache, prefix=()):
    commands = list(prefix) + [
        "C " + (case["config"] or "-"),
        f"I {int(case['send_ok'])}",
        "E 0 -11 0 -1 -1 -1 -1",
    ]
    positions = []
    expected = []
    seq = 0
    epoch = 1
    epochs = []
    for op, value in case["actions"]:
        if op in ("submit_format", "submit_plain"):
            seq += 1
            commands.append(f"P {22 + seq} {seq} 24 1000000 1000000 0 2204")
        elif op in ("restart", "restart_open_format"):
            if op == "restart_open_format":
                commands.append("O")
            commands.append("Z")
            epoch += 1
        else:
            raise AssertionError(op)
        positions.append(len(commands) - 1)
        epochs.append(epoch)
    native = playback.execute(receiver, commands)
    startup = len(prefix) + 2
    assert native[startup]["decoder_infos"] == [], (
        case["name"],
        "startup must not report before format",
    )
    assert native[startup]["decoder_info_cache"] == cache[0], (
        case["name"],
        "initial cache",
    )
    for index, (source, position, epoch, action) in enumerate(
        zip(case["states"], positions, epochs, case["actions"], strict=True)
    ):
        phase = 4 if action[0] == "restart_open_format" else 3
        expected += [[position, phase, body] for body in source["info_bodies"]]
        got = native[position]
        assert got["decoder_info_cache"] == cache[index + 1], (
            case["name"],
            position,
            "owned decoder-info cache",
        )
        assert got["decoder_infos"] == expected, (
            case["name"],
            position,
            "full info80 body and actual callback phase",
            got["decoder_infos"],
            expected,
        )
        assert got["epoch"] == epoch, (case["name"], position, "actual actor epoch")
        assert not got["reset_feedback_applied"], (
            case["name"],
            position,
            "info failure must not request reset",
        )
        assert got["config"] == source["config"], (
            case["name"],
            position,
            "complete config",
        )
    return native, positions


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    a = p.parse_args()
    report = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-client-decoder-info-reference.json.gz"
            ).read_bytes()
        )
    )
    cases = [c for c in report["cases"] if c.get("native_projection")]
    assert len(cases) == 6
    for case in cases:
        verify(a.receiver.resolve(), case, report["cached_info"][case["name"]])
    print(
        "Native decoder info:",
        len(cases),
        "official cases,",
        sum(len(c["states"]) for c in cases),
        "states passed",
    )


if __name__ == "__main__":
    main()
