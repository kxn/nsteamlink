#!/usr/bin/env python3
"""Compare reliable receive events, states, frame delivery and full feedback wire.

Source assertions are diagnostic/release adapters, not native protocol state.
All other observations, including the initial state, must match exactly.
"""

import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def projection(state):
    return {k: v for k, v in state.items() if k != "asserts"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", type=Path, required=True)
    args = parser.parse_args()
    fixture = json.loads(
        (ROOT / "scripts/fixtures/steam-reliable-feedback-reference.json").read_text()
    )
    for index, case in enumerate(fixture["cases"]):
        inp = case["input"]
        run = subprocess.run(
            [
                str(args.receiver.resolve()),
                *map(str, (inp["crc"], inp["rtt"], inp["start"])),
            ],
            input="".join(" ".join(map(str, op)) + "\n" for op in inp["ops"]),
            text=True,
            capture_output=True,
            timeout=10,
        )
        assert run.returncode == 0, (index, case["case"], run.stderr)
        got = json.loads(run.stdout)
        assert got["initial"] == projection(case["initial"]), (
            index,
            "initial",
            got["initial"],
            case["initial"],
        )
        assert len(got["observed"]) == len(case["observed"])
        for step, (actual, expected) in enumerate(
            zip(got["observed"], case["observed"])
        ):
            assert actual == projection(expected), (
                index,
                case["case"],
                step,
                inp,
                actual,
                expected,
            )
    print(
        f"Production reliable receive/feedback: {len(fixture['cases'])} official vectors passed"
    )


if __name__ == "__main__":
    main()
