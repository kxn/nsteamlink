#!/usr/bin/env python3
"""Compare production config/crypto/session behavior with fixed official results.

No ELF, emulator or Python protobuf package is required. The wire comparison
retains field presence, repeated ordering, nested messages and unknown fields.
"""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def varint(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
    raise AssertionError("bad varint")


def fields(data, kind="config"):
    result, offset = {}, 0
    nested = {
        "config": {21: "limit", 22: "limit", 23: "limit", 24: "limit"},
        "limit": {2: "mode"},
        "message": {1: "config"},
    }
    while offset < len(data):
        tag, offset = varint(data, offset)
        number, wire_type = tag >> 3, tag & 7
        assert number > 0
        if wire_type == 0:
            value, offset = varint(data, offset)
        elif wire_type in (1, 5):
            size = 8 if wire_type == 1 else 4
            value, offset = data[offset : offset + size], offset + size
        elif wire_type == 2:
            size, offset = varint(data, offset)
            value, offset = data[offset : offset + size], offset + size
            if number in nested.get(kind, {}):
                value = fields(value, nested[kind][number])
        else:
            raise AssertionError(f"unsupported fixture wire type {wire_type}")
        result.setdefault(number, []).append((wire_type, value))
    assert offset == len(data)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", type=Path, required=True)
    args = parser.parse_args()
    fixture = json.loads(
        (ROOT / "scripts/fixtures/steam-client-config-reference.json").read_text()
    )
    count = 0

    def run(commands):
        nonlocal count
        count += 1
        result = subprocess.run(
            [str(args.receiver.resolve())],
            input="\n".join(commands) + "\n",
            text=True,
            capture_output=True,
            timeout=10,
        )
        assert result.returncode == 0, (commands[:2], result.stderr)
        return [json.loads(line) for line in result.stdout.splitlines()]

    for case in fixture["cases"]:
        entry, inp, expected = case["entry"], case["input"], case["observed"]
        if (
            entry == "player_delegate"
            or entry == "setter"
            and inp["local_only"] not in (0, 1)
        ):
            # Native application player effects are a separate contract; C bool
            # callers also cannot supply the noncanonical ABI values 2/3.
            continue
        phase = {2: 2, 3: 3, 4: 4, 6: 6}[inp["state"]]
        command = (
            f"SET {inp['local_only']} {inp['config'] or '-'}"
            if entry == "setter"
            else f"RX {inp['message'] or '-'}"
        )
        actual = run([f"SEED {inp['initial']}", f"PHASE {phase}", command])[-1]
        assert fields(bytes.fromhex(actual["config"])) == fields(
            bytes.fromhex(expected["config"])
        ), case["case"]
        assert len(actual["events"]) == len(expected["events"]), (
            case["case"],
            actual,
            expected,
        )
        for got, wanted in zip(actual["events"], expected["events"]):
            assert got.keys() == wanted.keys(), (case["case"], got, wanted)
            for key in got:
                if key in ("notify", "save", "payload"):
                    kind = "message" if key == "payload" else "config"
                    assert fields(bytes.fromhex(got[key]), kind) == fields(
                        bytes.fromhex(wanted[key]), kind
                    ), (case["case"], key)
                else:
                    assert got[key] == wanted[key], (case["case"], key)
        config = fields(bytes.fromhex(expected["config"]))
        for name, tag in (("video", 9), ("audio", 10), ("input", 11)):
            assert actual[f"{name}_enabled"] == bool(
                config.get(tag, [(0, 1)])[-1][1]
            ), case["case"]

    # Initial message 4 must use the retained full config, including fields
    # outside the legacy configuring callback, exact fractional FPS and -1 bitrate.
    rich_case = next(c for c in fixture["cases"] if c["case"] == "incoming_s6_rich")
    base_wire = bytes.fromhex(rich_case["observed"]["config"])

    def encode(value):
        result = bytearray()
        value &= (1 << 64) - 1
        while value > 127:
            result.append((value & 127) | 128)
            value >>= 7
        return bytes(result + bytes([value]))

    large_case = next(
        c for c in fixture["cases"] if c["case"] == "incoming_s6_large_string"
    )
    fraction = (
        b"\x20"
        + encode(60000)
        + b"\x28"
        + encode(1001)
        + b"\x30"
        + encode(-1)
        + b"\x58\x00"
    )
    for wire in (
        base_wire,
        base_wire + fraction,
        bytes.fromhex(large_case["observed"]["config"]),
    ):
        actual = run([f"SEED {wire.hex()}", "PHASE 4", "NEGOTIATE -"])[-1]
        expected_fields = fields(wire)
        # Repeated test input fields are absent here; the retained unknown tag
        # and decoder-limit ordering remain part of the comparison.
        actual_fields = fields(bytes.fromhex(actual["config"]))
        for tag, value in expected_fields.items():
            assert actual_fields[tag] == value, (tag, actual_fields, expected_fields)
        assert len(actual["events"]) == 1 and actual["events"][0]["send"] == 4
        message = fields(bytes.fromhex(actual["events"][0]["payload"]), "negotiation")
        assert fields(message[2][0][1]) == actual_fields

    # Full protobuf absence means the official optional defaults, rather than
    # a request to materialize legacy 15 Mbps/overlay/hotkey conveniences.
    for payload in ("", "c80101"):
        actual = run([f"SEED {payload or '-'}", "PHASE 4", "NEGOTIATE -"])[-1]
        expected_fields = fields(bytes.fromhex(payload))
        assert fields(bytes.fromhex(actual["config"])) == expected_fields
        assert len(actual["events"]) == 1 and actual["events"][0]["send"] == 4
        message = fields(bytes.fromhex(actual["events"][0]["payload"]), "negotiation")
        assert fields(message[2][0][1]) == expected_fields

    # Invalid API input is not a valid C++ message argument. These are native
    # parser guards, not invented official setter observations.
    for payload in ("0a08", "80", "aa0103120100"):
        actual = run(["SEED c801015800", "PHASE 5", f"SET 0 {payload}"])[-1]
        assert not actual["result"] and not actual["events"]
        assert fields(bytes.fromhex(actual["config"])) == fields(
            bytes.fromhex("c801015800")
        )
    print(
        f"Production client config: {count} official-reference and parser scenarios passed"
    )


if __name__ == "__main__":
    main()
