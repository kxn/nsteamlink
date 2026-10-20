#!/usr/bin/env python3
"""Compare Native actual Stop/Reset ownership phases and clock with official code.

Original-client fixtures control SDK/init delays. Native executes its production
video TU/assembly/tracker/worker join/Reset and DataLost paths; platform callbacks
record the matching phase inputs. Other factories, all producers, hardware and
wall-clock/OS scheduling equivalence are not asserted.
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
        default=ROOT / "scripts/fixtures/steam-video-stop-phases-reference.json",
    )
    args = p.parse_args()
    cases = json.loads(args.reference.read_text())["cases"]
    for index, case in enumerate(cases):
        i = case["input"]
        d = i.get("delays", {})
        s = case["after"]
        cmd = [
            str(args.receiver.resolve()),
            str(i.get("tick", 1000000)),
            str(int(i["mode"] == "reset")),
            str(int(i["old_backend"])),
            str(int(i["init_success"])),
            str(d.get("flush", 0)),
            str(d.get("delete", 0)),
            str(d.get("init", 0)),
            str(int(i.get("escape", False))),
        ]
        result = subprocess.run(cmd, text=True, capture_output=True, timeout=10)
        assert not result.returncode, (
            index,
            i,
            result.returncode,
            result.stdout,
            result.stderr,
        )
        actual = json.loads(result.stdout)
        want = dict(
            active=bool(s["active"]),
            backend=bool(s["backend"]),
            strict=s["strict"],
            soft=s["soft"],
            mark=s["last_request"],
            tick=case["tick"],
            lost=case["lost"],
            phase_order=case["phase_order"],
        )
        assert actual == want, (index, i, actual, want)
    print(f"Video Stop phases: {len(cases)} official inputs passed")


if __name__ == "__main__":
    main()
