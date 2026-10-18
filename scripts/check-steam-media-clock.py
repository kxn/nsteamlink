#!/usr/bin/env python3
"""Compare RX clock/sampling and delayed native consumer with official terminal history."""

import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    args = p.parse_args()
    cases = json.loads(
        (ROOT / "scripts/fixtures/steam-media-clock-reference.json").read_text()
    )["cases"]
    states = 0
    for case in cases:
        inp = case["input"]
        r = subprocess.run(
            [
                str(args.receiver.resolve()),
                str(int(inp["crc"])),
                "1",
                str(int(inp["full"])) if "full" in inp else "-1",
                "34",
                "media-clock",
            ],
            input="\n".join(" ".join(map(str, x)) for x in inp["actions"]) + "\n",
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert not r.returncode, (inp["name"], r.stdout, r.stderr)
        actual = [json.loads(s) for s in r.stdout.splitlines()]
        assert len(actual) == len(case["observed"])
        for n, (got, want) in enumerate(zip(actual, case["observed"])):
            del got["delivered"], got["metadata"], got["admitted"]
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
    print(f"Media clock: {len(cases)} official cases, {states} states passed")


if __name__ == "__main__":
    main()
