#!/usr/bin/env python3
"""Compare native network collector states/float bits with original ARM64 output.

This tests sample queues and arithmetic, not Socket/decoder caller reachability.
The source's controlled PacketSample padding is zero; no wire padding is implied.
"""

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
        (ROOT / "scripts/fixtures/steam-network-collectors-reference.json").read_text()
    )["cases"]
    count = 0
    for case in cases:
        i = case["input"]
        result = subprocess.run(
            [str(a.receiver.resolve())],
            input="\n".join(" ".join(map(str, action)) for action in i["actions"])
            + "\n",
            text=True,
            capture_output=True,
            timeout=10,
        )
        assert result.returncode == 0, (i, result.stdout, result.stderr)
        actual = [json.loads(line) for line in result.stdout.splitlines()]
        assert len(actual) == len(case["observed"])
        for n, (got, expected) in enumerate(zip(actual, case["observed"])):
            assert got == expected, (i["name"], n, got, expected)
            count += 1
    print(
        f"Network collectors: {len(cases)} official cases, {count} states/float bit patterns passed"
    )


if __name__ == "__main__":
    main()
