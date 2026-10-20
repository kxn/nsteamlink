#!/usr/bin/env python3
"""Compare the application wait predicate with original SDL/client/player paths.

This component gate compares source phase inputs and exact tick boundaries, not
actual packet scheduling, UI/renderer state or complete session cleanup. The
runtime loopback test independently covers the production caller and workers.
"""

import argparse
import gzip
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    a = p.parse_args()
    source = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-connection-wait-reference.json.gz"
            ).read_bytes()
        )
    )
    assert (
        source["binary_sha256"]
        == "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"
    )
    assert len(source["cases"]) == 55
    assert source["mutation"]["hits"] == ["0x75cec4"]
    assert source["mutation"]["original"] != source["mutation"]["mutant"]
    assert all(
        not source["mutation"][key]["source_assertions"]
        for key in ("original", "mutant")
    )
    lines, expected = [], []
    for case in source["cases"]:
        i, r = case["input"], case["observed"]
        assert not r["source_assertions"] and r["phase"] == i["phase"]
        expired = ["error", 4] in r["events"]
        assert ("quit_boundary" in r["events"]) == (expired or i["phase"] == 0)
        if i["phase"] == 6:
            assert not expired and "session_continue" in r["events"]
            assert r["entered"] == [
                "0x76817c",
                "0x7a5ff8",
                "0x7a7140",
                "0x7b76e8",
                "0x7b782c",
            ]
        lines.append(f"{int(i['phase'] == 1)} {i['start']} {i['now']}")
        expected.append(int(expired))
    process = subprocess.run(
        [str(a.receiver.resolve())],
        input="\n".join(lines) + "\n",
        text=True,
        capture_output=True,
        timeout=15,
    )
    assert process.returncode == 0, (process.returncode, process.stderr)
    assert [int(v) for v in process.stdout.splitlines()] == expected
    print(
        "Official connection wait: 55 exact loop/tick comparisons, empty-video continuation and public phase getter passed"
    )


if __name__ == "__main__":
    main()
