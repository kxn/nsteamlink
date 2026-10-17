#!/usr/bin/env python3
"""Compare complete negotiation output for the platform's supported codec subset.

The source's mandatory Raw-video capability is a declared platform difference.
Only that single caps entry is removed from expected bytes; cases that actually
select unsupported video codecs are source-only and counted separately. No other output fields
are filtered. Native ciphertext is really reassembled and decrypted by the oracle.
"""

import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def varint(data, pos):
    value = shift = 0
    while True:
        byte = data[pos]
        pos += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, pos
        shift += 7
        assert shift < 70


def encode(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def fields(data):
    pos = 0
    while pos < len(data):
        start = pos
        tag, pos = varint(data, pos)
        kind = tag & 7
        value = None
        if kind == 0:
            value, pos = varint(data, pos)
        elif kind == 1:
            pos += 8
        elif kind == 5:
            pos += 4
        else:
            assert kind == 2
            size, pos = varint(data, pos)
            value = data[pos : pos + size]
            pos += size
        yield tag >> 3, kind, value, data[start:pos]
    assert pos == len(data)


def platform_frame(encoded):
    raw = bytes.fromhex(encoded)
    assert raw[0] == 4
    body = bytearray()
    for number, kind, value, record in fields(raw[1:]):
        if number != 3:
            body.extend(record)
            continue
        assert kind == 2
        caps = bytearray()
        removed = 0
        for n, k, v, r in fields(value):
            if n == 15 and k == 0 and v == 1:
                removed += 1
            else:
                caps.extend(r)
        assert removed == 1
        body.extend(encode(3 * 8 + 2) + encode(len(caps)) + caps)
    return (bytes([4]) + body).hex()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    args = p.parse_args()
    fixture = json.loads(
        (ROOT / "scripts/fixtures/steam-negotiation-reference.json").read_text()
    )
    tested = source_only = 0
    for index, case in enumerate(fixture["cases"]):
        inp = case["input"]
        if not inp["native_compatible"]:
            source_only += 1
            continue
        run = subprocess.run(
            [
                str(args.receiver.resolve()),
                inp["initial_config"] or "-",
                str(int(5 in inp["available"])),
            ],
            input="".join((body or "-") + "\n" for body in inp["packets"]),
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert run.returncode == 0, (index, case["case"], run.stderr)
        got = json.loads(run.stdout)
        assert len(got) == len(case["observed"])
        for step, (actual, expected) in enumerate(zip(got, case["observed"])):
            want = {k: expected[k] for k in actual}
            want["frames"] = [platform_frame(frame) for frame in expected["frames"]]
            assert actual == want, (index, case["case"], step, actual, want)
        tested += 1
    print(
        f"Production negotiation: {tested} official supported-codec cases passed; {source_only} unsupported-video cases source-only"
    )


if __name__ == "__main__":
    main()
