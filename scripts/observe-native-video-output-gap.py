#!/usr/bin/env python3
"""Observe official input-task/pixel ownership using the actual native receiver.

Both sides start with an explicit valid 10 ms jitter state. The observer uses
actual runtime/parser/worker/FFmpeg/media/SDL; its declared backend boundary
suppresses the first real decoder output and preserves the second. Returned
pixels are checked against independent framemd5 in the receiver. This compares
selected task, physical output and completion; it does not prove natural device
failure, NDK timeout/flush equivalence or a physical Steam/Switch session.
"""

import argparse
import gzip
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def observe(build, output):
    output.mkdir(parents=True, exist_ok=True)
    commands = (
        "B 10\nX 1\nP 1 1 24 998689 1000000 0 2204\n"
        "P 2 2 8 1001311 1000000 0 2204\nD 1000000\nD 1003000\n"
    )
    run = subprocess.run(
        [
            str(build / "app/nsl-video-timing-oracle"),
            str(ROOT / "app/tests/fixtures/video/sequential.h264"),
        ],
        input=commands,
        text=True,
        capture_output=True,
        timeout=20,
    )
    (output / "native-states.jsonl").write_text(run.stdout)
    (output / "native-stderr.log").write_text(run.stderr)
    assert not run.returncode, (run.returncode, run.stderr[-3000:])
    states = [json.loads(line) for line in run.stdout.splitlines()]
    fixture = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-video-output-reference.json.gz"
            ).read_bytes()
        )
    )
    source = next(
        c
        for c in fixture["cases"]
        if c["input"]["shape"] == "future_output_for_ready_job"
    )["states"][-1]
    output_pts = next(e[4] for e in source["io"] if e[1] == "dequeue" and e[3] == 7)
    source_pixel = next(e[1] for e in source["input_pts"] if e[3] == output_pts)
    source_job = source["held"][0][0]
    native_job = states[4]["selected"][-1][1]
    native_pixel = next(
        (e[1] for e in states[4]["physical_selected"] if e[0] == 4), None
    )
    report = dict(
        boundary=__doc__,
        official_binary_sha256=fixture["binary_sha256"],
        source_held_job_id=source_job,
        source_sdk_output_input_id=source_pixel,
        native_task_now=native_job,
        native_output_now=native_pixel,
        native_task_later=states[5]["selected"][-1][1],
        completed_now=states[4]["completed"],
        prep_now=states[4]["prep"],
        selection_matches=bool(
            native_job and native_job[0] == source_job and native_pixel == source_pixel
        ),
    )
    (output / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--build", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    observe(a.build.resolve(), a.output.resolve())
