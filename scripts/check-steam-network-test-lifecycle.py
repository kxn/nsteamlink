#!/usr/bin/env python3
"""Compare dedicated Native test-mode protocol/recording with original run-loop.

The Native component runs production admission/window/control, actual HMAC,
mode producer/consumer/metrics and owner stage. Identity frame cipher and final
frame admission match the original instruction driver's explicit boundaries.
This does not acquire a discovery ticket or prove real Steam/UI/OS scheduling.
"""

import argparse
import gzip
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
KEYS = (
    "status",
    "state",
    "last_data",
    "previous_kbps",
    "current_kbps",
    "tx_sequence",
    "rx_sequence",
    "total",
    "batch",
    "latencies",
    "samples",
    "average",
    "full_count",
    "full",
    "frame_count",
)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    a = p.parse_args()
    report = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-network-test-lifecycle-reference.json.gz"
            ).read_bytes()
        )
    )
    checkpoints = 0
    assert report["binary_sha256"] == "15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2"
    assert len(report["cases"]) == 29
    assert sum(len(c["trace"]) for c in report["cases"]) == 248
    assert len(report["functions"]) == 59
    assert "_ZN7CCrypto15GenerateHMAC256EPKvmS1_mPA32_h" in report["functions"]
    mutation = report["mutation"]
    assert mutation["mutant"]["patch_hits"] == [mutation["pc"]]
    assert not mutation["mutant"]["source_assertions"]
    assert len(mutation["mutant"]["trace"]) == 5 and len(mutation["original"]["trace"]) == 7
    for c in report["cases"]:
        assert not c["source_assertions"], c["input"]
        assert all(s["receive_delay"] == 65 for s in c["trace"])
    for c in report["cases"]:
        i = c["input"]
        if not i.get("connect", True):
            continue  # BConnect bool is a separate original OS boundary.
        mode = 2 if i.get("bitrate", 20000) <= 0 else 1
        target = 15000 if mode == 2 else i.get("bitrate", 20000)
        start = i.get("start", 1000000)
        actions = []
        for delta, op, *args in i["events"]:
            actions.append(
                " ".join(
                    map(
                        str,
                        [(start + delta) & 0xFFFFFFFF, op]
                        + (args or [0])
                        + (["-"] if op == "C" and len(args) == 1 else []),
                    )
                )
            )
        # Empty proto bodies need one explicit placeholder in the command ABI.
        actions = [
            line.rstrip() + " -"
            if line.split()[1] == "C" and len(line.split()) == 3
            else line
            for line in actions
        ]
        result = subprocess.run(
            [
                str(a.receiver.resolve()),
                str(mode),
                str(target),
                str(start),
                str(i.get("key_length", 32)),
            ],
            input="\n".join(actions) + "\n",
            text=True,
            capture_output=True,
            timeout=15,
        )
        assert result.returncode == 0, (
            i,
            result.returncode,
            result.stdout[-3000:],
            result.stderr[-3000:],
        )
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        expected = {s["label"]: s for s in c["trace"]}
        assert len(rows) == len(i["events"]) + 2, (i["name"], len(rows))
        for row in rows:
            src = expected[row["label"]]
            actual = {k: row[k] for k in KEYS}
            want = {k: src[k] for k in KEYS}
            assert actual == want, (i["name"], row["label"], actual, want)
            assert row["frames"] == c["frames"][: src["frame_count"]], (
                i["name"],
                row["label"],
                "complete frame bodies",
                row["frames"],
                c["frames"][: src["frame_count"]],
            )
            checkpoints += 1
        assert rows[-1]["frames"] == c["frames"], i["name"]
        if c["completed_scores"]:
            assert rows[-1]["result"] == c["completed_scores"][-1], i["name"]
    assert checkpoints == 136, checkpoints
    print(
        f"Network-test lifecycle: {len(report['cases'])} original scenarios; {checkpoints} Native producer/consumer checkpoints passed (BConnect failure remains original OS boundary)"
    )


if __name__ == "__main__":
    main()
