#!/usr/bin/env python3
"""Compare key-fragment flush timing, complete SDK input bytes and decoder gates.

Native runs its production consumer/assembly/tracker and callback phases. Source
executes the original decode/assembly/FinalDecode/Android SDK submission chain.
SDK bodies are observed at each actual boundary; physical output and all stats,
other factories/producers and OS scheduling remain independent.
"""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", required=True, type=Path)
    p.add_argument(
        "--reference",
        type=Path,
        default=ROOT / "scripts/fixtures/steam-keyframe-flush-reference.json",
    )
    a = p.parse_args()
    cases = json.loads(a.reference.read_text())["cases"]
    count = 0
    for index, c in enumerate(cases):
        i = c["input"]
        cmd = [
            str(a.receiver.resolve()),
            str(int(i["backend"])),
            str(i["strict"]),
            str(i["soft"]),
            i["pending"],
            str(ROOT / "app/tests/fixtures/video/sequential.h264"),
        ]
        proc = subprocess.run(
            cmd,
            input="\n".join(" ".join(map(str, op)) for op in c["actions"]) + "\n",
            text=True,
            capture_output=True,
            timeout=10,
        )
        assert not proc.returncode, (
            index,
            i,
            proc.returncode,
            proc.stdout,
            proc.stderr,
        )
        got = [json.loads(x) for x in proc.stdout.splitlines()]
        want = [
            {k: s[k] for k in ("strict", "soft", "request", "flow")}
            for s in c["states"]
        ]
        assert got == want, (index, i, [(g, w) for g, w in zip(got, want) if g != w])
        count += len(got)
    print(f"Keyframe flush: {len(cases)} official cases/{count} states passed")


if __name__ == "__main__":
    main()
