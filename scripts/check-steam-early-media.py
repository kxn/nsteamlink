#!/usr/bin/env python3
"""Compare actual early transport/windows/complete pending with official client instructions."""

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
        (ROOT / "scripts/fixtures/steam-early-media-reference.json").read_text()
    )["cases"]
    states = 0
    for case in cases:
        inp = case["input"]
        run = subprocess.run(
            [
                str(args.receiver.resolve()),
                str(int(inp["crc"])),
                "1",
                "-1",
                "34",
                "early-closing" if inp.get("closing") else "early",
            ],
            input="\n".join(" ".join(map(str, op)) for op in inp["actions"]) + "\n",
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert not run.returncode, (inp["name"], run.stdout, run.stderr)
        actual = [json.loads(s) for s in run.stdout.splitlines()]
        assert len(actual) == len(case["observed"])
        for i, (got, want) in enumerate(zip(actual, case["observed"])):
            # Pre-client transport and post-client FIFO observers are different
            # ownership boundaries. The explicit decoder IDs/pending and all
            # transport/sample counters are compared instead.
            del got["delivered"], got["metadata"]
            assert got == want, (
                inp["name"],
                i,
                {
                    k: (got.get(k), want.get(k))
                    for k in got.keys() | want.keys()
                    if got.get(k) != want.get(k)
                },
            )
            states += 1
    print(f"Early media: {len(cases)} official cases, {states} states passed")


if __name__ == "__main__":
    main()
