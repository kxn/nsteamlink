#!/usr/bin/env python3
"""Observe actual Native AVCodec completion, feedback order and decoder timing.

The configured production oracle runs runtime/control/parser/worker/FFmpeg/media
and real tracker publication history. API results/elapsed ticks are declared
boundary inputs; every returned physical image is checked with framemd5 before
metadata/status injection. No natural hardware/Steam/loader parity is claimed.
The report records whether the original counterexamples still exist, without a
test requiring them to remain. Strategy expectations come from the pinned
original client, not a second hand-written recovery/queue implementation.
"""

import argparse
import gzip
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def observe(build, output):
    output.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["cmake", "--build", str(build), "--target", "nsl-video-timing-oracle", "-j2"],
        check=True,
        stdout=(output / "build.log").open("w"),
        stderr=subprocess.STDOUT,
    )
    exe = build / "app/nsl-video-timing-oracle"

    def run(name, commands):
        r = subprocess.run(
            [str(exe), str(ROOT / "app/tests/fixtures/video/sequential.h264")],
            input=commands,
            text=True,
            capture_output=True,
            timeout=20,
        )
        (output / (name + ".jsonl")).write_text(r.stdout)
        (output / (name + ".log")).write_text(r.stderr)
        assert not r.returncode, (r.returncode, r.stderr[-2500:])
        return json.loads(r.stdout.splitlines()[-1])

    native = run("native", "B 0\nX 1\nP 1 1 24 1000000 1000000 0 2204\nD 1000000\n")
    timed = run(
        "native-timing",
        "B 0\nQ 100 200\nP 23 23 24 1000000 1000000 0 2204\nD 1000300\n",
    )
    source = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-client-avcodec-player-reference.json.gz"
            ).read_bytes()
        )
    )
    no = next(c for c in source["cases"] if c["name"] == "no_output")["states"][0]
    reference = next(c for c in source["cases"] if c["name"] == "decoder_time")[
        "states"
    ][0]
    actual = next(r for r in native["tracker"] if r["id"] == 1)
    expected = [row[1:] for row in reference["events"] if row[0] == "event"]
    events = [row[1:] for row in timed["decode_events"]]
    loss = [[r[2], format(r[3], "02x")] for r in native["events"] if r[1] == 2]
    report = dict(
        scope=__doc__,
        native_head=subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        native_dirty=bool(
            subprocess.check_output(
                ["git", "status", "--porcelain"], cwd=ROOT, text=True
            ).strip()
        ),
        official_binary_sha256=source["binary_sha256"],
        native=actual,
        native_feedback=loss,
        completion_matches=actual["complete"] and actual["result"] == no["stats"]["23"],
        feedback_matches=loss
        == [[r[1], r[2]] for r in no["events"] if r[0] == "feedback"],
        decoder_timing=dict(
            original_events=expected,
            native_events=events,
            decode_events_match=events == expected,
        ),
        outstanding_selected_tasks=native["pending"],
    )
    (output / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--build", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    observe(a.build.resolve(), a.output.resolve())
