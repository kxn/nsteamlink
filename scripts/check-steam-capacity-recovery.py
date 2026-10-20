#!/usr/bin/env python3
"""Verify capacity-retained input recovery against the actual official decoder.

The complete-source control and Native UDP retirement capture remain separate
from the retained-input projection. Compare the persistent Native worker at SDK
gates; do not reinterpret the projection as an official memory/drop policy.
"""

import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


overlap = module("capacity_check_overlap", "check-steam-decoder-overlap.py")
stim = module("capacity_check_stim", "media-pressure-stimuli.py")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_reference(report):
    assert (
        report["binary_sha256"]
        == "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"
    )
    assert {"DecodeFrame", "OnThink", "RunDecodeLoop", "_ZN13CStreamPacketD1Ev"} <= {
        f["name"] for f in report["functions"]
    }
    for path, sha in report["programs"].items():
        assert digest(ROOT / path) == sha, path
    assert report["native_observer_sha256"] == digest(
        ROOT / "app/tests/udp_video_load.h"
    )
    assert report["pressure_reference_sha256"] == digest(
        ROOT / "scripts/fixtures/steam-client-pressure-process-reference.json.gz"
    )
    assert len(report["cases"]) == 2
    payloads = stim.aus()
    for case in report["cases"]:
        native = case["native_capture"]["native"]
        load = native["load"]
        consumed, retired = load["consumed_ids"], load["retired_ids"]
        assert len(retired) == load["retired"] > 0 and not set(consumed) & set(retired)
        assert sorted(consumed + retired) == load["rx_ids"] == list(range(100, 402))
        assert all(s["result"] == 0 and s["size"] == 65536 for s in load["sdk"])
        assert (
            native["phase"] == 6 and not native["closed"] and native["video"]["stopped"]
        )
        actual = [
            {k: r[k] for k in ("id", "consumed")}
            for r in case["source_recovery_inputs"]
        ]
        assert actual == load["recovery_inputs"] and len(actual) == load["datalost"] > 0
        delivered = case["initial"] + [f for wave in case["waves"] for f in wave]
        assert [f[0] for f in delivered] == consumed
        for fid, sequence, flags, stamp, raw in delivered:
            index = fid - 100
            assert [sequence, flags, stamp, raw] == [
                index,
                24 if index % 6 == 0 else 8,
                1000000 + index * 1092,
                payloads[index % 6].hex(),
            ]
        for key in ("source", "source_full"):
            result = case[key]
            assert not result["end"]["closed"] and not result["end"]["queue"]
            assert [g["id"] for g in result["gates"]] == [s["id"] for s in load["sdk"]]
            assert [g["payload"] for g in result["gates"]] == [
                s["sha256"] for s in load["sdk"]
            ]
            assert [v[1] for v in result["end"]["dequeued"]] == (
                consumed if key == "source" else list(range(100, 402))
            )
            lost = [e for e in result["end"]["flow"] if e[0] == "lost"]
            assert len(lost) == (len(actual) if key == "source" else 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-capacity-recovery-reference.json.gz"
            ).read_bytes()
        )
    )
    verify_reference(report)
    results = []
    for case in report["cases"]:
        got = overlap.execute(args.receiver, case)
        gates = overlap.verify(args.receiver, case, got)
        results.append(dict(name=case["name"], gates=gates, native=got))
        print(
            case["name"],
            gates,
            "SDK gates; exact retained bytes/flow/task ownership matched",
            flush=True,
        )
    if args.output:
        args.output.write_text(json.dumps(results, indent=2) + "\n")
    print(
        "Capacity recovery: 2 actual UDP captures, 4 original executions, 2 Native worker replays"
    )


if __name__ == "__main__":
    main()
