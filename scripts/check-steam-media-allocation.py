#!/usr/bin/env python3
"""Compare actual ordinary RX/FIFO/consumer bytes to fixed official window outputs.

Native Thread::Create(video) is an explicit failed-start adapter. Production
queue admission, FIFO ownership/poll and generic consumer dispatch execute;
there is no OS decoder-worker, codec, network peer or Switch claim.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", required=True, type=Path)
    args = parser.parse_args()
    fixture = json.loads(
        (ROOT / "scripts/fixtures/steam-media-allocation-reference.json").read_text()
    )
    for name, digest in fixture["helpers"].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest, name
    for case in fixture["cases"]:
        inp, want = case["input"], case["observed"]
        run = subprocess.run(
            [str(args.receiver.resolve()), str(inp["bytes"]), str(inp["chunk"])],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert run.returncode == 0, (inp, run.returncode, run.stderr)
        got = json.loads(run.stdout)
        assert got["body"] == want["bytes"] and got["fragments"] == case["fragments"], (
            inp,
            got,
        )
        assert got["raw_sha256"] == want["sha256"], (inp, got)
        assert got["consumer_sha256"] == want["consumer_projection_sha256"], (inp, got)
        assert (
            got["large_consumed"]
            and got["following_consumed"]
            and not got["window_remaining"]
        ), (inp, got)
        assert (
            got["fifo_count"] == 1
            and 0 < got["fifo_bytes"] <= got["fifo_limit"] == 4194304
        ), (inp, got)
        assert (
            got["retained_capacity"] >= inp["bytes"]
            and got["fifo_bytes"] > got["retained_capacity"]
        ), (inp, got)
        assert got["failed_start_adapter"] == 1
    print(
        f"Production media allocation: {len(fixture['cases'])} original byte outputs matched"
    )


if __name__ == "__main__":
    main()
