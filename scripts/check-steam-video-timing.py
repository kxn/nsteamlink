#!/usr/bin/env python3
"""Check the shared no-SDK-delay timing projection from official Android evidence.

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
    # Empty AVCodec input and SDK-duration timing are covered by the Linux
    # client vectors. The old Android endpoints remain original Source evidence,
    # not mandatory FFmpeg behavior (protocol reference §91–93).
    cases = [
        c for c in reference["cases"] if c["input"]["shape"] != "accepted_before_output"
    ]
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
        got = [
            {k: s[k] for k in keys}
            for s in (json.loads(x) for x in r.stdout.splitlines())
        ]
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
