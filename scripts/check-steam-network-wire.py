#!/usr/bin/env python3
"""Compare native actual CRC RX/send collectors with original Socket sampling.

Addresses/I/O results are controlled. Source body consumers/connect/disconnect
and unclaimed replies are adapters; native RX-generated final sends are rejected
and excluded. Appended report cases compare real global stage -> live network
snapshot -> stats producer -> reliable admission with original complete bodies.
No complete channel/handshake/UDP errno equivalence is implied.
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
        (ROOT / "scripts/fixtures/steam-network-wire-reference.json").read_text()
    )["cases"]
    states = bodies = 0
    for case in cases:
        i = case["input"]
        command = [
            str(a.receiver.resolve()),
            str(int(i["crc"])),
            str(int(i["address"])),
        ]
        if "full" in i or "remote" in i:
            command.append(str(int(i["full"])) if "full" in i else "-1")
        if "remote" in i:
            command.append(str(i["remote"]))
        result = subprocess.run(
            command,
            input="\n".join(" ".join(map(str, v)) for v in i["actions"]) + "\n",
            text=True,
            capture_output=True,
            timeout=10,
        )
        assert result.returncode == 0, (i, result.stdout, result.stderr)
        actual = [json.loads(line) for line in result.stdout.splitlines()]
        assert len(actual) == len(case["observed"])
        for n, (got, expected) in enumerate(zip(actual, case["observed"])):
            assert got == expected, (i, n, got, expected)
            states += 1
            bodies += len(got.get("frames", []))
    print(
        f"Socket network sampling: {len(cases)} official cases, {states} states, {bodies} full bodies passed"
    )


if __name__ == "__main__":
    main()
