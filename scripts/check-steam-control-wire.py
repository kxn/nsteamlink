#!/usr/bin/env python3
"""Compare actual production control/frame wire bytes with official client vectors.

Native protobuf, fragmentation, admission/retention and Socket serialization run;
only time/final UDP are controlled. Queue admission is separate from Socket's
result. Original factory creation is recorded but not claimed equivalent here.
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
        (ROOT / "scripts/fixtures/steam-control-wire-reference.json").read_text()
    )
    for number, case in enumerate(fixture["cases"]):
        group, inp, want = case["group"], case["input"], case["observed"]
        kind = {"frame": 0, "control": 1, "connected": 2}[group]
        code = inp.get("socket_result", 0)
        completed = subprocess.run(
            [
                str(args.receiver.resolve()),
                *map(str, (inp["crc"], inp["mtu"], kind, inp.get("type", 6), code)),
                inp.get("payload", ""),
            ],
            text=True,
            capture_output=True,
            timeout=10,
        )
        assert completed.returncode == 0, (number, completed.stderr)
        got = json.loads(completed.stdout)
        assert got["admitted"]
        assert got["socket_result"] == code
        assert got["wire"] == want["wire"], (number, group, inp, got, want)
        assert got["next_id"] == want["next_id"], (number, got, want)
    print(f"Production control wire: {len(fixture['cases'])} official vectors passed")


if __name__ == "__main__":
    main()
