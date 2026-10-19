#!/usr/bin/env python3
"""Compare actual Native worker/FIFO/submit order to original-client batches."""

import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    p.add_argument(
        "--reference",
        type=Path,
        default=ROOT / "scripts/fixtures/steam-decoder-queue-reference.json",
    )
    a = p.parse_args()
    cases = json.loads(a.reference.read_text())["cases"]
    states = 0
    for case in cases:
        lines = []
        for batch in case["batches"]:
            lines.extend("F " + " ".join(map(str, f)) for f in batch)
            lines.append("B")
        result = subprocess.run(
            [
                str(a.receiver.resolve()),
                str(ROOT / "app/tests/fixtures/video/sequential.h264"),
            ],
            input="\n".join(lines) + "\n",
            text=True,
            capture_output=True,
            timeout=15,
        )
        assert result.returncode == 0, (case["name"], result.returncode, result.stderr)
        got = [json.loads(line) for line in result.stdout.splitlines()]
        assert got == case["states"], (case["name"], got, case["states"])
        states += len(got)
    print(f"Decoder queue: {len(cases)} official cases/{states} states passed")


if __name__ == "__main__":
    main()
