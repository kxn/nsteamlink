#!/usr/bin/env python3
"""Compare original UI transaction PIN bytes with actual Native owner/AES/UDP.

Only field8 and its transaction lifetime are projected. IV is a controlled
provider, crypto executes unchanged. Native secret replacement is explicit input,
not an implemented automatic authorization path. SDK metadata/token, UI, save
ordering and real Steam/Switch are not claimed by this component comparison.
"""
import argparse
import gzip
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def pin_field(body):
    wire = bytes.fromhex(body)

    def read(pos):
        value = shift = 0
        while True:
            b = wire[pos]
            pos += 1
            value |= (b & 127) << shift
            if b < 128:
                return value, pos
            shift += 7
            assert shift < 70

    pos = 0
    while pos < len(wire):
        tag, pos = read(pos)
        if tag & 7 == 0:
            _, pos = read(pos)
        else:
            assert tag & 7 == 2
            n, pos = read(pos)
            v = wire[pos : pos + n]
            pos += n
            if tag >> 3 == 8:
                return v.hex()
    raise AssertionError("missing PIN field8")


def run(receiver, pin, fail=False):
    r = subprocess.run(
        [str(receiver.resolve()), pin, str(int(fail))],
        text=True,
        capture_output=True,
        timeout=15,
    )
    assert r.returncode == 0, (pin, fail, r.returncode, r.stderr[-2500:])
    return [json.loads(s) for s in r.stdout.splitlines()]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    a = p.parse_args()
    source = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-authorization-ui-reference.json.gz"
            ).read_bytes()
        )
    )
    assert len(source["cases"]) == 24
    expected = {}
    for c in source["cases"]:
        if c["input"]["path"] == "cancel":
            continue
        s = c["steps"][2]
        initial, resumed = s["messages"][0], s["messages"][3]
        assert (
            initial["tag"] == resumed["tag"] == 5 and initial["body"] == resumed["body"]
        )
        pin = c["input"].get("pin", "9876")
        value = pin_field(initial["body"])
        if pin in expected:
            assert expected[pin] == value
        expected[pin] = value
    assert sorted(map(len, expected)) == [0, 1, 4, 15, 16]
    for pin, cipher in expected.items():
        rows = run(a.receiver, pin)
        assert rows[0] == dict(started=True)
        assert rows[1:] == [dict(tag=5, pin=cipher, encryptions=int(bool(pin)))] * 2, (
            pin,
            rows,
            cipher,
        )
    failed = run(a.receiver, "9876", True)
    assert failed == [dict(started=False), dict(tag=10, pin="", encryptions=1)]
    assert source["negative"]["mutant"]["patch_hits"] == [source["negative"]["site"]]
    assert not source["negative"]["mutant"]["source_assertions"]
    print(
        "Streaming PIN: 5 official/Native IV-controlled AES vectors, cached retry after secret replacement, producer failure/cancel; original UI/storage/consumer traces remain separately scoped"
    )


if __name__ == "__main__":
    main()
