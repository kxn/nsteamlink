#!/usr/bin/env python3
"""Compare production reliable frame transactions with original client vectors.

The native dispatcher is the actual worker step, not an oracle FIFO re-enactment.
Frame returns are not compared with async bool admission. Compared fields are
full wire, retained count and next ID for each ordered trigger stage.
"""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", type=Path, required=True)
    args = parser.parse_args()
    fixture = json.loads(
        (ROOT / "scripts/fixtures/steam-initial-send-reference.json").read_text()
    )
    for number, case in enumerate(fixture["cases"]):
        inp = case["input"]
        trigger = {"update": 0, "new_frame": 1, "ack_update": 2}[inp["trigger"]]
        result = subprocess.run(
            [
                str(args.receiver.resolve()),
                *map(str, (inp["crc"], inp["fail_index"], inp["error"], trigger)),
            ],
            text=True,
            capture_output=True,
            timeout=10,
        )
        assert result.returncode == 0, (number, result.stderr)
        got = json.loads(result.stdout)
        want = [
            {k: v for k, v in stage.items() if k != "result"}
            for stage in case["observed"]
        ]
        assert got == want, (number, inp, got, want)
    print(
        f"Production initial reliable transactions: {len(fixture['cases'])} vectors passed"
    )


if __name__ == "__main__":
    main()
