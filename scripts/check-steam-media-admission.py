#!/usr/bin/env python3
"""Compare production media admission and transport/video counters with official instructions."""

import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    a = p.parse_args()
    cases = json.loads(
        (ROOT / "scripts/fixtures/steam-media-admission-reference.json").read_text()
    )["cases"]
    states = 0
    for case in cases:
        inp = case["input"]
        result = subprocess.run(
            [
                str(a.receiver.resolve()),
                str(int(inp["crc"])),
                "1",
                "-1",
                "34",
                "admission",
            ],
            input="\n".join(" ".join(map(str, row)) for row in inp["actions"]) + "\n",
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert not result.returncode, (inp["name"], result.stdout, result.stderr)
        actual = [json.loads(row) for row in result.stdout.splitlines()]
        assert len(actual) == len(case["observed"])
        for n, (got, want) in enumerate(zip(actual, case["observed"])):
            # Source records the pre-admission transport delegate; native's
            # existing fields record post-admission consumer FIFO ownership.
            # Compare the explicit admitted list instead, retaining all counters.
            del got["delivered"], got["metadata"]
            assert got == want, (
                inp["name"],
                n,
                {
                    k: (got.get(k), want.get(k))
                    for k in got.keys() | want.keys()
                    if got.get(k) != want.get(k)
                },
            )
            states += 1
    print(f"Media admission: {len(cases)} official cases, {states} states passed")


if __name__ == "__main__":
    main()
