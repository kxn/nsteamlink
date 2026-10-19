#!/usr/bin/env python3
"""Actual UDP/RX/deferred owner respects original read-before-due ordering.

The Native fixture holds the idle gap before forwarding a real condition wait,
temporarily releases Base so main can pump, then restores ownership. No epochs
are forged. Wall time is controlled; reply uses the original-source response
fixture and real Native protobuf/AES/callbacks. Source BProcess dispatch is a
declared adapter; no natural Qt/network or Switch timing proof.
"""
import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def check(receiver, reference):
    source = json.loads(reference.read_text())
    require(source["binary_sha256"] == "15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2", "source identity")
    results = []
    for case in source["cases"]:
        reply = case["reply"]
        expected = [1, 1, 1, 1] if reply else [1, 1, 2, 2]
        require(case["request_counts"] == expected, "original no-update / due-update request counts")
        require(case["steps"][-1]["state"] == (6 if reply else 5), "original terminal state")
        require(any(row[0] == "response_handler" for row in case["order"]) == reply, "actual original handler reached")
        commands = ["g 1000 1", "n 1000", "n 1001", "n 1001"]
        if reply:
            commands.append("w 1001 6 123 " + case["response"])
        commands += ["g 1001 0", "n 1001", "c 1001"]
        process = subprocess.run([str(receiver.resolve()), "0"], input="\n".join(commands) + "\n",
                                 text=True, capture_output=True, timeout=12)
        require(process.returncode == 0, f"native exit {process.returncode}: {process.stderr}")
        rows = [json.loads(line) for line in process.stdout.splitlines()]
        require(len(rows) == len(commands) + 1, "native complete command observations")
        counts = [sum(m["tag"] == 5 for m in row["messages"]) for row in rows]
        # Initial, held gap, consume completed RX at1000, then two idle pumps
        # at due1001. No new original Update means no due retransmission.
        require(counts[:5] == [1] * 5, "idle pumps retransmitted before a new receive update")
        resume = 6 if reply else 5
        require(counts[resume] == (1 if reply else 2), "reply-before-due vs empty-input retry")
        require(counts[resume + 1] == counts[resume], "same completed batch consumed twice")
        require(rows[resume]["state"] == (6 if reply else 5), "native state after actual receive update")
        require(rows[resume]["successes"] == int(reply), "real native ticket callback")
        if reply:
            require(rows[resume]["accepted"] == bytes(range(32)).hex(), "real AES-decrypted ticket")
        results.append(dict(reply=reply, commands=commands, request_counts=counts, observed=rows))
    require(len(results) == 2, "both source branches")
    return dict(scope=__doc__, source_binary_sha256=source["binary_sha256"], cases=results)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", required=True, type=Path)
    parser.add_argument("--reference", type=Path, default=ROOT / "scripts/fixtures/steam-discovery-order-reference.json")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = check(args.receiver, args.reference)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print("Discovery order: idle pumps, empty-input retry, queued real ticket before due passed")


if __name__ == "__main__":
    main()
