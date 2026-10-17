#!/usr/bin/env python3
"""Compare production ordinary-channel loss events against pinned client execution.

Native actual CRC RX, channel insertion, reliable update, window Pop and live
collectors are used. Media polling drives the production worker step explicitly;
scheduling, decoder, final feedback I/O, early-media and FEC are outside scope.
Optional report cases compare full original FrameEvents bodies.
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
        (ROOT / "scripts/fixtures/steam-network-loss-reference.json").read_text()
    )["cases"]
    count = bodies = 0
    for c in cases:
        i = c["input"]
        full = str(int(i["full"])) if "full" in i else "-1"
        result = subprocess.run(
            [str(a.receiver.resolve()), str(int(i["crc"])), "1", full, "34", "loss"],
            input="\n".join(" ".join(map(str, v)) for v in i["actions"]) + "\n",
            text=True,
            capture_output=True,
            timeout=10,
        )
        assert result.returncode == 0, (i, result.stdout, result.stderr)
        actual = [json.loads(line) for line in result.stdout.splitlines()]
        assert len(actual) == len(c["observed"])
        for n, (got, expected) in enumerate(zip(actual, c["observed"])):
            assert got == expected, (i["name"], n, got, expected)
            count += 1
            bodies += len(got.get("frames", []))
    print(
        f"Network loss: {len(cases)} official client cases, {count} states, {bodies} full bodies passed"
    )


if __name__ == "__main__":
    main()
