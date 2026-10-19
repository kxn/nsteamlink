#!/usr/bin/env python3
"""Compare actual FEC bytes and allocation observations to original outputs.

This intentionally returns nonzero while any original delivery remains missing;
known local resource limits are recorded as gaps, not normalized into equality.
Native requested-live bytes exclude input/helper scratch, allocator overhead,
other session owners, GPU and RSS. Original tracked terminals are not a peak.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SHA = "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"


def wires(spec):
    if "fixed_wires" in spec:
        return spec["fixed_wires"]
    payload = bytes((i * 37 + 11) & 255 for i in range(spec["length"]))
    count = (len(payload) + spec["shard"] - 1) // spec["shard"]
    return [
        (
            struct.pack("<BBBBBHHI", 11, 0, 7, 1, 3, index, 1, 1000000)
            + struct.pack("<IHH", len(payload), spec["shard"], spec["parity"])
            + payload[index * spec["shard"] : (index + 1) * spec["shard"]].ljust(
                spec["shard"], b"\0"
            )
        ).hex()
        for index in range(count)
    ]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    fixture = json.loads(
        (ROOT / "scripts/fixtures/steam-fec-resources-reference.json").read_text()
    )
    assert fixture["binary_sha256"] == SHA
    probe = fixture["sender_probe"]
    assert (
        probe["controlled_mtu"],
        probe["injected_percentage"],
        probe["length"],
        probe["data_shards"],
        probe["parity"],
        probe["shard"],
    ) == (1472, 5, 2097172, 1457, 0, 1440)
    assert not probe["rs_calls"]
    assert probe["source_body_sha256"] == probe["source_received_sha256"]
    for name, digest in fixture["helpers"].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest
    rows = []
    for case in fixture["cases"]:
        sequence = wires(case["input"])
        run = subprocess.run(
            [str(args.receiver.resolve()), "--observe"],
            input="\n".join(sequence) + "\n",
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert run.returncode == 0, (case["input"]["name"], run.stderr, run.returncode)
        got = json.loads(run.stdout)
        assert got["packets"] == len(sequence) and not got["live_after_destroy"]
        want = case["observed"]
        matched = (
            got["delivered"] == 1
            and got["bytes"] == want["bytes"]
            and got["sha256"] == want["sha256"]
            and not got["resource_errors"]
        )
        rows.append(
            dict(input=case["input"], original=want, native=got, matched=matched)
        )
    report = dict(
        scope=__doc__,
        binary_sha256=SHA,
        cases=rows,
        matched=sum(row["matched"] for row in rows),
        unmatched=[row["input"]["name"] for row in rows if not row["matched"]],
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"FEC resources: {report['matched']}/{len(rows)} original deliveries matched; "
        f"unresolved={report['unmatched']}"
    )
    return 1 if report["unmatched"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
