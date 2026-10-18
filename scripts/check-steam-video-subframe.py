#!/usr/bin/env python3
"""Compare production subframe lists/range state/bytes/submit ID to official execution.

Original Wait delays remain Source evidence, not physical OS timing assertions.
Native uses its actual parser/consumer/tracker/actor/crypto; callbacks are terminals.
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
        default=ROOT / "scripts/fixtures/steam-video-subframe-reference.json",
    )
    a = p.parse_args()
    cases = json.loads(a.reference.read_text())["cases"]
    states = 0
    keys = (
        "strict",
        "soft",
        "request",
        "backend",
        "mode",
        "body",
        "flow",
        "player",
        "next_range",
        "next_seq",
        "overflow_span",
        "partial",
    )
    for n, c in enumerate(cases):
        i = c["input"]
        r = subprocess.run(
            [
                str(a.receiver.resolve()),
                str(i["codec"]),
                str(ROOT / "app/tests/fixtures/video/sequential.h264"),
                str(int(i["backend"])),
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
    print("Video subframe:", len(cases), "official cases/", states, "states passed")


if __name__ == "__main__":
    main()
