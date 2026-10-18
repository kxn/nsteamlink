#!/usr/bin/env python3
"""Compare original transaction semantics with real Native client/timer/UDP."""
import argparse
import gzip
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def projection(step):
    messages = []
    for m in step["messages"]:
        row = {k: m[k] for k in ["tag", "request_id", "target"]}
        row["network_test" if m["tag"] == 5 else "body"] = m[
            "network_test" if m["tag"] == 5 else "body"
        ]
        messages.append(row)
    return dict(
        label=step["label"],
        state=step["state"],
        request_id=step["request_id"],
        target=step["target"],
        messages=messages,
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", required=True, type=Path)
    a = p.parse_args()
    source = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-streaming-transaction-reference.json.gz"
            ).read_bytes()
        )
    )
    assert len(source["cases"]) == 16 and len(source["functions"]) == 21
    for c in source["cases"]:
        assert not c["source_assertions"]
        r = subprocess.run(
            [
                str(a.receiver.resolve()),
                c["input"]["path"],
                str(int(c["input"]["test"])),
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert r.returncode == 0, (c["input"], r.returncode, r.stderr[-2000:])
        actual = [json.loads(line) for line in r.stdout.splitlines()]
        expected = [projection(s) for s in c["steps"]]
        assert actual == expected, (c["input"], actual, expected)
        if c["input"]["path"] == "failure_dialog":
            failed = next(s for s in c["steps"] if s["label"] == "failed_dialog")
            assert failed["test_status"] == 4 and len(failed["messages"]) == 1
            assert (
                dict(signal="2finished( int )", slot="1OnActionCancel()")
                in failed["actions"]
            )
    m = source["mutation"]
    assert (
        m["mutant"]["patch_hits"] == [m["pc"]] and not m["mutant"]["source_assertions"]
    )
    assert (
        m["mutant"]["steps"][-1]["request_id"] == 17
        and m["original"]["steps"][-1]["request_id"] == 0
    )
    print(
        "Streaming transactions: 16 Source/Native state/ID/target/5-test-flag/complete-cancel-body traces, real client/timers/UDP; Source failure UI/slot, 1 executed counterfactual. Native UI is tested by the product runtime gate."
    )


if __name__ == "__main__":
    main()
