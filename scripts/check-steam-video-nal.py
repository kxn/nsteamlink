#!/usr/bin/env python3
"""Compare owned-context NAL byte assembly against original client execution.

Native uses real production consumer/tickets/actor/crypto and callback terminals.
Source-only asserts/out-of-allocation reads and HEVC capability/factory probe
remain explicit independent evidence. They are not normal byte expectations.
"""

import argparse
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
        default=ROOT / "scripts/fixtures/steam-video-nal-reference.json",
    )
    a = p.parse_args()
    guarded = subprocess.run(
        [str(a.receiver.resolve()), "--guards"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert not guarded.returncode and "NAL local guards passed" in guarded.stdout, (
        guarded
    )
    cases = json.loads(a.reference.read_text())["cases"]
    states = 0
    keys = ("strict", "soft", "request", "backend", "mode", "body", "flow", "player")
    for n, c in enumerate(cases):
        i = c["input"]
        r = subprocess.run(
            [
                str(a.receiver.resolve()),
                str(i["codec"]),
                str(ROOT / "app/tests/fixtures/video/sequential.h264"),
            ],
            input="\n".join(
                " ".join("-" if item == "" else str(item) for item in x)
                for x in c["actions"]
            )
            + "\n",
            text=True,
            capture_output=True,
            timeout=10,
        )
        assert not r.returncode, (n, i, r.returncode, r.stderr)
        got = [json.loads(x) for x in r.stdout.splitlines()]
        want = [{k: s[k] for k in keys} for s in c["states"]]
        assert got == want, (
            n,
            i,
            [(j, g, w) for j, (g, w) in enumerate(zip(got, want)) if g != w],
        )
        states += len(got)
    print("Video NAL:", len(cases), "official cases/", states, "states passed")


if __name__ == "__main__":
    main()
