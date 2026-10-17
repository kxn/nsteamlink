#!/usr/bin/env python3
"""Compare actual generic receive/consumer ingress and final packets with the client."""

import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def clean(state):
    return (
        {k: v for k, v in state.items() if k != "asserts"}
        if state is not None
        else None
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    args = p.parse_args()
    fixture = json.loads(
        (ROOT / "scripts/fixtures/steam-reliable-channels-reference.json").read_text()
    )
    for index, case in enumerate(fixture["cases"]):
        inp = case["input"]
        run = subprocess.run(
            [
                str(args.receiver.resolve()),
                *map(
                    str,
                    (
                        inp["crc"],
                        inp["channel"],
                        inp["state"],
                        inp["payload"],
                        int(inp["configured"]),
                    ),
                ),
            ],
            input="".join(" ".join(map(str, op)) + "\n" for op in inp["ops"]),
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert run.returncode == 0, (index, inp, run.stderr)
        got = json.loads(run.stdout)
        assert got["initial"] == clean(case["initial"]), (
            index,
            "initial",
            got["initial"],
            case["initial"],
        )
        assert len(got["observed"]) == len(case["observed"])
        for step, (a, e) in enumerate(zip(got["observed"], case["observed"])):
            want = dict(e, state=clean(e["state"]))
            assert a == want, (index, step, inp, a, want)
    print(
        f"Production generic reliable channels: {len(fixture['cases'])} official vectors passed"
    )


if __name__ == "__main__":
    main()
