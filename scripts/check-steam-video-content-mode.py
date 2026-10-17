#!/usr/bin/env python3
"""Compare official bit6/submit gating, retained bytes and reset lifecycle.

Source executes original instructions through SDK input. Native runs production
assembly/tickets/actor with backend/player callbacks as recording terminals.
Q is an explicit pending-request input; OS scheduling, physical output, source
helper-only vectors and every upstream producer are independent boundaries.
"""

import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", required=True, type=Path)
    p.add_argument(
        "--reference",
        type=Path,
        default=ROOT / "scripts/fixtures/steam-video-content-mode-reference.json",
    )
    a = p.parse_args()
    cases = json.loads(a.reference.read_text())["cases"]
    keys = ("strict", "soft", "request", "backend", "mode", "body", "flow", "player")
    count = 0
    for index, c in enumerate(cases):
        i = c["input"]
        cmd = [
            str(a.receiver.resolve()),
            str(int(i["backend"])),
            str(-1 if i["initial"] is None else i["initial"]),
            str(int(i.get("ready", True))),
            str(ROOT / "app/tests/fixtures/video/sequential.h264"),
        ]
        proc = subprocess.run(
            cmd,
            input="\n".join(" ".join(map(str, op)) for op in c["actions"]) + "\n",
            text=True,
            capture_output=True,
            timeout=10,
        )
        assert not proc.returncode, (index, i, proc.returncode, proc.stderr)
        got = [json.loads(x) for x in proc.stdout.splitlines()]
        want = [{k: s[k] for k in keys} for s in c["states"]]
        assert got == want, (
            index,
            i,
            [(n, g, w) for n, (g, w) in enumerate(zip(got, want)) if g != w],
        )
        count += len(got)
    print(f"Video content mode: {len(cases)} official cases/{count} states passed")


if __name__ == "__main__":
    main()
