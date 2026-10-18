#!/usr/bin/env python3
"""Compare real stalled media workers with original decoder-terminal metadata.

The first worker cannot start consuming until D; its first callback then holds
it until the second D. RX changes clock offsets while the frames wait. This is
an explicit native scheduling barrier, not official OS or hardware scheduling.
"""

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
    runs = 0
    for case in cases:
        inp = case["input"]
        if "full" in inp:
            continue
        lines = []
        metadata = []
        wires = 0
        for op, observed in zip(inp["actions"], case["observed"]):
            lines.append(
                " ".join(map(str, op))
                if op[0] != "D"
                else f"D {len(metadata) + len(observed['decoded'])}"
            )
            metadata += observed["decoded"]
            wires += len(observed["wires"])
        for repeat in range(2):
            run = subprocess.run(
                [str(args.receiver.resolve()), str(int(inp["crc"])), "clock"],
                input="\n".join(lines) + "\n",
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert not run.returncode, (inp["name"], repeat, run.stdout, run.stderr)
            got = json.loads(run.stdout)
            assert got["metadata"] == metadata, (inp["name"], got, metadata)
            assert (
                got["decoded"] == [v["id"] for v in metadata]
                and got["feedbacks"] == wires
                and got["goodbyes"] == 0
            ), (inp["name"], got, wires)
            assert got["started"] == got["stopped"] == 1, (inp["name"], got)
            runs += 1
    print(f"Media clock real workers: {runs} launches passed")


if __name__ == "__main__":
    main()
