#!/usr/bin/env python3
"""Compare production overflow consumer with pinned original-client vectors.

The endpoints, client phase and transition at feedback delivery are explicit
inputs. The receiver executes production range/recovery/gating and protobuf;
control delivery and packet queueing are observation terminals, not wire ACKs.
No session worker, real scheduling, sockets or physical decoder is exercised.
"""
import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", required=True, type=Path)
    parser.add_argument(
        "--reference",
        type=Path,
        default=ROOT / "scripts/fixtures/steam-video-overflow-reference.json",
    )
    args = parser.parse_args()
    reference = json.loads(args.reference.read_text())
    assert (
        reference["binary_sha256"]
        == "95482ca6120f90bb90798b27206b7946ab732e079f008d7fc90ea58a8b0074e1"
    )
    count = 0
    for case in reference["cases"]:
        commands = []
        for action in case["input"]:
            commands.append(
                " ".join(
                    str(value)
                    for value in [
                        action.get("phase", 6),
                        action.get("waiting_key", 0),
                        action.get("syncing", 0),
                        action.get("count", 2),
                        action.get("first", 100),
                        action.get("last", 102),
                        action.get("ticks", 5000),
                        action.get("previous_span", 0),
                        int("previous_span" in action),
                        action.get("phase_after_feedback", 0xFFFFFFFF),
                    ]
                )
            )
        result = subprocess.run(
            [str(args.receiver.resolve())],
            input="\n".join(commands) + "\n",
            text=True,
            capture_output=True,
            timeout=10,
        )
        assert result.returncode == 0, (case["name"], result.stderr)
        actual = [json.loads(line) for line in result.stdout.splitlines()]
        expected = [
            {key: value for key, value in state.items() if key != "assertions"}
            for state in case["states"]
        ]
        assert actual == expected, (case["name"], actual, expected)
        count += len(actual)
    print(
        f"Video overflow: {len(reference['cases'])} original cases/{count} states passed"
    )


if __name__ == "__main__":
    main()
