#!/usr/bin/env python3
"""Compare native reliable ring fill/growth, frame digests and feedback to original code."""

import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    a = p.parse_args()
    fixture = json.loads(
        (
            ROOT / "scripts/fixtures/steam-reliable-large-frame-reference.json"
        ).read_text()
    )
    for index, c in enumerate(fixture["cases"]):
        i = c["input"]
        run = subprocess.run(
            [
                str(a.receiver.resolve()),
                str(i["crc"]),
                str(i["count"]),
                str(int(i.get("missing_first", False))),
            ],
            text=True,
            capture_output=True,
            timeout=15,
        )
        assert run.returncode == 0, (index, i, run.stderr)
        got = json.loads(run.stdout)
        want = dict(
            before=c["before"],
            observed={k: v for k, v in c["observed"].items() if k != "asserts"},
        )
        assert got == want, (index, i, got, want)
    print(
        f"Production reliable full-ring/large-frame: {len(fixture['cases'])} original vectors passed"
    )


if __name__ == "__main__":
    main()
