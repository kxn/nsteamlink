#!/usr/bin/env python3
"""Compare original crypto outputs and video protocol policy with production code.

Native uses its real mbedTLS crypto/assembly/tracker/actor. The backend/player are
recording callbacks. Source-only protected-content fields/calls terminate in the
original Android no-ops; they are retained as evidence, not a new Native API.
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
        default=ROOT / "scripts/fixtures/steam-video-crypto-reference.json",
    )
    a = p.parse_args()
    reference = json.loads(a.reference.read_text())
    receiver = str(a.receiver.resolve())
    for index, c in enumerate(reference["helpers"]):
        i = c["input"]
        proc = subprocess.run(
            [
                receiver,
                "D",
                str(i["keylen"]),
                i["iv"],
                i["cipher"],
                str(i["capacity"]),
                str(int(i["inplace"])),
            ],
            text=True,
            capture_output=True,
            timeout=10,
        )
        assert not proc.returncode, (index, i, proc.returncode, proc.stderr)
        got = json.loads(proc.stdout)
        assert got == c["result"], ("helper", index, i, got, c["result"])
    states = 0
    for index, c in enumerate(reference["videos"]):
        i = c["input"]
        proc = subprocess.run(
            [
                receiver,
                "V",
                str(i["keylen"]),
                str(int(i["backend"])),
                str(ROOT / "app/tests/fixtures/video/sequential.h264"),
            ],
            input="\n".join(" ".join(map(str, x)) for x in c["actions"]) + "\n",
            text=True,
            capture_output=True,
            timeout=10,
        )
        assert not proc.returncode, (index, i, proc.returncode, proc.stderr)
        got = [json.loads(x) for x in proc.stdout.splitlines()]
        want = [
            {
                k: s[k]
                for k in (
                    "strict",
                    "soft",
                    "request",
                    "backend",
                    "mode",
                    "body",
                    "flow",
                    "player",
                )
            }
            for s in c["states"]
        ]
        assert got == want, (
            "video",
            index,
            i,
            [(n, g, w) for n, (g, w) in enumerate(zip(got, want)) if g != w],
        )
        states += len(got)
    print(
        "Video crypto:",
        len(reference["helpers"]),
        "official helper cases;",
        len(reference["videos"]),
        "video cases/",
        states,
        "states passed",
    )


if __name__ == "__main__":
    main()
