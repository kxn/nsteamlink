#!/usr/bin/env python3
"""Drive official early media schedules through real native media workers.

Source decoder-terminal outputs supply the IDs. Explicit D barriers wait for the
native worker after Source's synchronous terminal boundary; this compares queue
ownership/lifetime and stop/join, not official OS scheduling or hardware decode.
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
        (ROOT / "scripts/fixtures/steam-early-media-reference.json").read_text()
    )["cases"]
    runs = 0
    for case in cases:
        inp = case["input"]
        lines, ids, wires, goodbyes = [], [], 0, 0
        for op, observed in zip(inp["actions"], case["observed"]):
            lines.append(" ".join(map(str, op)))
            ids += observed["admitted"]
            for wire in observed["wires"]:
                if int(wire[:2], 16) & 127 == 9:
                    goodbyes += 1
                else:
                    wires += 1
            if observed["admitted"]:
                lines.append(f"D {len(ids)}")
        for repeat in range(2):
            run = subprocess.run(
                [str(args.receiver.resolve()), str(int(inp["crc"]))],
                input="\n".join(lines) + "\n",
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert not run.returncode, (inp["name"], repeat, run.stdout, run.stderr)
            got = json.loads(run.stdout)
            assert got["goodbyes"] == goodbyes, (inp["name"], got, goodbyes)
            assert got["decoded"] == ids and got["feedbacks"] == wires, (
                inp["name"],
                got,
                ids,
                wires,
            )
            count = sum(op[0] == "C" for op in inp["actions"])
            assert got["started"] == got["stopped"] == count, (inp["name"], got, count)
            runs += 1
    print(
        f"Early media real workers: {runs} launches, {len(cases)} official schedules passed"
    )


if __name__ == "__main__":
    main()
