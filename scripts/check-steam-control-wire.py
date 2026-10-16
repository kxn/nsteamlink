#!/usr/bin/env python3
"""Compare actual production control/frame wire bytes with official client vectors.

Native protobuf, fragmentation, admission/retention and Socket serialization run;
only time/final UDP are controlled. Queue admission is separate from completion.
Original factory creation is recorded but not claimed equivalent here.
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
    cpp = json.loads(
        (ROOT / "scripts/fixtures/steam-discovery-protobuf-reference.json").read_text()
    )
    assert cpp["binary_sha256"] == fixture["binary_sha256"]
    cpp_cases = {
        (case["input"]["requested"], case["input"]["presence"]): case["observed"]
        for case in cpp["cases"]
    }
    cpp_checked = set()
    for number, case in enumerate(fixture["cases"]):
        group, inp, want = case["group"], case["input"], case["observed"]
        kind = {"frame": 0, "control": 1, "connected": 2, "stats": 3, "discovery": 4}[
            group
        ]
        code = inp.get("socket_result", 0)
        completed = subprocess.run(
            [
                str(args.receiver.resolve()),
                *map(
                    str,
                    (
                        inp["crc"],
                        inp["mtu"],
                        kind,
                        inp.get("presence", 3)
                        if group == "discovery"
                        else inp.get("type", 6),
                        code,
                    ),
                ),
                str(
                    inp.get("text_length", inp.get("requested", inp.get("payload", "")))
                ),
            ],
            text=True,
            capture_output=True,
            timeout=10,
        )
        assert completed.returncode == 0, (number, completed.stderr)
        got = json.loads(completed.stdout)
        assert got["admitted"]
        assert got["attempts"] == len(want["wire"])
        assert got["wire"] == want["wire"], (number, group, inp, got, want)
        assert got["next_id"] == want["next_id"], (number, got, want)
        key = (inp.get("requested"), inp.get("presence", 3))
        if group == "discovery" and not inp["crc"] and not code and key in cpp_cases:
            # Full wire above matches the first harness. Also compare the real
            # generated C++ protobuf/Frame output from an independent harness.
            assert got["wire"][0][28:] == cpp_cases[key]["frame_body"], (number, got)
            cpp_checked.add(key)
    assert cpp_checked == set(cpp_cases)
    print(f"Production control wire: {len(fixture['cases'])} official vectors passed")
    print(f"Independent C++ discovery body projections: {len(cpp_checked)} passed")


if __name__ == "__main__":
    main()
