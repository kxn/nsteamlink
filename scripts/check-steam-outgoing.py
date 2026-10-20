#!/usr/bin/env python3
"""Check reliable retry wire bytes against original Android sender instructions.

Consumes only the retained reliable RTO/failure cases. Full socket shaping,
unreliable windows and connection priority scheduling remain separate contracts.
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
        (ROOT / "scripts/fixtures/steam-outgoing-reference.json").read_text()
    )
    checked = 0
    for case in fixture["cases"]:
        group, inp = case["group"], case["input"]
        if group not in ("rto", "failure"):
            continue
        count = inp["count"]
        now = inp.get("now", 1000000)
        stamp = 0 if inp.get("zero") else (now - inp.get("age", 1000)) & 0xFFFFFFFF
        times = (
            [(now, 0)]
            if group == "rto"
            else [
                (now + delta, inp["transport"] if delta == 0 else 0)
                for delta in (0, 1, 125, 126)
            ]
        )
        expected = [case["observed"]] if group == "rto" else case["observed"]
        result = subprocess.run(
            [
                str(args.receiver.resolve()),
                str(count),
                str(stamp),
                str(1 if group == "rto" else 2),
                str(inp.get("srtt", 100)),
            ],
            input="".join(f"{time} {ret}\n" for time, ret in times),
            text=True,
            capture_output=True,
            timeout=10,
        )
        assert result.returncode == 0, (case["case"], result.stderr)
        actual = [json.loads(line) for line in result.stdout.splitlines()]
        assert len(actual) == len(expected)
        for got, wanted in zip(actual, expected):
            assert got["sent"] == wanted["sent"], (case["case"], got, wanted["sent"])
            assert got["attempts"] == len(wanted["sent"])
        checked += 1
    assert checked == 50
    print(f"Production reliable retry: {checked} original-reference scenarios passed")


if __name__ == "__main__":
    main()
