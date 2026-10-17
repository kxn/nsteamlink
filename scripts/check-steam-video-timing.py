#!/usr/bin/env python3
"""Compare actual runtime/worker/FFmpeg timing queue against official execution.

Source device/Surface branches remain independent Source evidence. Projection
compares known-picture display/late completions; raw Source gap/reset/stat events
remain in the fixture and are not claimed as full statistics equivalence.
"""

import argparse
import gzip
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    p.add_argument(
        "--reference",
        type=Path,
        default=ROOT / "scripts/fixtures/steam-video-timing-reference.json.gz",
    )
    a = p.parse_args()
    resources = subprocess.run(
        [
            str(a.receiver.resolve()),
            str(ROOT / "app/tests/fixtures/video/sequential.h264"),
            "--resources",
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert (
        not resources.returncode and "Video timing resources passed" in resources.stdout
    ), resources.stderr[-2500:]
    reference = json.loads(gzip.decompress(a.reference.read_bytes()))
    for case in reference["empty_jobs"]:
        r = subprocess.run(
            [
                str(a.receiver.resolve()),
                str(ROOT / "app/tests/fixtures/video/sequential.h264"),
            ],
            input="\n".join(" ".join(str(y) for y in x) for x in case["actions"])
            + "\n",
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert not r.returncode, r.stderr[-2000:]
        states = [json.loads(line) for line in r.stdout.splitlines()]
        assert [s["jitter"] for s in states] == [s["jitter"] for s in case["states"]]
        assert [s["decode_events"] for s in states] == [
            s["decode_events"] for s in case["states"]
        ]
        assert all(
            not s["pictures"] and not s["pending"] and not s["completed"]
            for s in states
        )
    cases = reference["cases"]
    keys = (
        "jitter",
        "pending",
        "pictures",
        "submissions",
        "decode_events",
        "selected",
        "waits",
        "completed",
    )
    states = 0
    for n, c in enumerate(cases):
        r = subprocess.run(
            [
                str(a.receiver.resolve()),
                str(ROOT / "app/tests/fixtures/video/sequential.h264"),
            ],
            input="\n".join(" ".join(str(y) for y in x) for x in c["actions"]) + "\n",
            text=True,
            capture_output=True,
            timeout=20,
        )
        assert not r.returncode, (n, c["input"], r.returncode, r.stderr[-2500:])
        got = [json.loads(x) for x in r.stdout.splitlines()]
        want = [{k: s[k] for k in keys} for s in c["states"]]
        assert got == want, (
            n,
            c["input"],
            [(i, g, w) for i, (g, w) in enumerate(zip(got, want)) if g != w][:2],
            len(got),
            len(want),
        )
        states += len(got)
    print("Video timing:", len(cases), "official cases/", states, "states passed")


if __name__ == "__main__":
    main()
