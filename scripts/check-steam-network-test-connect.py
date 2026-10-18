#!/usr/bin/env python3
"""Compare real public Connect/owners with official test Run/BConnect (§123)."""
import argparse
import gzip
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", required=True, type=Path)
    a = p.parse_args()
    source = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-network-test-connect-reference.json.gz"
            ).read_bytes()
        )
    )
    assert (
        source["binary_sha256"]
        == "15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2"
    )
    assert len(source["cases"]) == 24 and len(source["functions"]) == 27
    for c in source["cases"]:
        i, o = c["input"], c["observed"]
        assert (
            not o["source_assertions"]
            and o["connection_cleared"]
            and o["transport_cleared"]
        )
        if not i["activate"]:
            assert o["status"] == 4 and o["phase"] == 0 and not o["wires"]
            continue  # Backend activation is a Source adapter, not a Native errno equivalence.
        assert o["budget_writes"] == [[3, 6553]] and o["at_network"][0]["delay"] == 6553
        wire = bytearray.fromhex(o["wires"][0])
        wire[2] = 0
        r = subprocess.run(
            [
                str(a.receiver.resolve()),
                str(i["mode"]),
                str(i["start"]),
                str(i["send_result"]),
            ],
            text=True,
            capture_output=True,
            timeout=10,
        )
        assert r.returncode == 0, (i, r.returncode, r.stderr[-1500:])
        assert json.loads(r.stdout) == dict(
            delay=o["at_network"][0]["delay"],
            status=o["status"],
            phase=o["phase"],
            wire=wire.hex(),
        ), (i, r.stdout, o)
    guard = subprocess.run(
        [str(a.receiver.resolve()), "1", "1000000", "0", "fail-receiver"],
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert guard.returncode == 0 and json.loads(guard.stdout) == dict(
        local_failure_guard=True, status=4, worker=False, valid=False
    ), (guard.returncode, guard.stdout, guard.stderr)
    m = source["mutation"]
    assert m["mutant"]["observed"]["patch_hits"] == [m["pc"]]
    assert not m["mutant"]["observed"]["source_assertions"]
    assert m["mutant"]["observed"]["at_network"][0]["delay"] == 65
    assert m["original"]["observed"]["at_network"][0]["delay"] == 6553
    print(
        "Dedicated Connect: 24 Source thread-body cases; 18 real Native public-Connect/owner cases, first wire and channel3 budget, joined cancel; 1 executed Source counterfactual"
    )


if __name__ == "__main__":
    main()
