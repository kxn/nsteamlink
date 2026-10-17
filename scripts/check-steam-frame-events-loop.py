#!/usr/bin/env python3
"""Compare native session stages and complete frame bodies with official OnThink.

Native runs real report production/serialization/reliable admission; source runs
original OnThink with an empty RX queue. Network processing/locks and socket
scheduling are not compared. Controlled admission rejection verifies retirement,
not equivalent errno semantics. Metrics are zero seed values in both programs.
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
        (ROOT / "scripts/fixtures/steam-frame-events-loop-reference.json").read_text()
    )["cases"]
    states = bodies = 0
    for case in cases:
        i = case["input"]
        result = subprocess.run(
            [
                str(a.receiver.resolve()),
                str(i["state"]),
                str(int(i["full"])),
                str(i["send_result"]),
            ],
            input="\n".join(" ".join(map(str, action)) for action in i["actions"])
            + "\n",
            text=True,
            capture_output=True,
            timeout=10,
        )
        assert result.returncode == 0, (i, result.stdout, result.stderr)
        got = [json.loads(line) for line in result.stdout.splitlines()]
        assert len(got) == len(case["observed"]), (i, got)
        for n, (actual, expected) in enumerate(zip(got, case["observed"])):
            assert actual == expected, (i, n, actual, expected)
            states += 1
            bodies += len(actual["frames"])
    print(
        f"Session frame-events: {len(cases)} official cases, {states} stages, {bodies} full bodies passed"
    )


if __name__ == "__main__":
    main()
