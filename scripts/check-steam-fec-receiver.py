#!/usr/bin/env python3
"""Compare the production type-11 receiver against fixed official wire bytes.

No ELF is needed for ordinary CI. The k3/m2 codewords come from original
Android AddPacket/RS instructions, pinned in steam-fec-reference.json.
The tests deliberately require safe handling of the original duplicate bug.
"""

import argparse
import itertools
import json
import struct
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def crc32c(data):
    value = 0xFFFFFFFF
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
    return value ^ 0xFFFFFFFF


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", type=Path, required=True)
    args = parser.parse_args()
    reference = json.loads(
        (ROOT / "scripts/fixtures/steam-fec-reference.json").read_text()
    )
    assert reference["binary_sha256"] == (
        "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"
    )
    vector = reference["vector"]
    wires = [bytes.fromhex(w) for w in vector["wires"]]
    payload = vector["payload"]
    requests, expected, labels = [], [], []
    cases = 0

    def reset():
        nonlocal cases
        cases += 1
        requests.append("R")
        expected.append("reset")
        labels.append(f"reset {cases}")

    def output(first, body=payload):
        shard, group, stamp = struct.unpack_from("<HHI", first, 5)
        return f"11 {group} {stamp} {shard} {body}"

    def send(wire, result="-", label="packet"):
        requests.append(wire.hex())
        expected.append(result)
        labels.append(f"case {cases}: {label}")

    def scenario(sequence, name, body=payload):
        reset()
        for i, wire in enumerate(sequence):
            send(
                wire,
                output(
                    min(sequence[:3], key=lambda w: struct.unpack_from("<H", w, 5)[0]),
                    body,
                )
                if i == 2
                else "-",
                name,
            )

    # Every 2-erasure pattern, all orders of the three surviving distinct shards.
    for chosen in itertools.combinations(wires, 3):
        for order in itertools.permutations(chosen):
            scenario(order, "two erasures")
    # All five shards in every order. Deliver once, as soon as three arrive.
    for order in itertools.permutations(wires):
        scenario(order, "five-shard permutation")
    for count in range(3):
        for chosen in itertools.combinations(wires, count):
            reset()
            for wire in chosen:
                send(wire, label="insufficient unique shards")
    reset()
    for wire in [wires[0]] * 5 + [wires[3]] * 5:
        send(wire, label="duplicates cannot satisfy k")
    send(wires[4], output(wires[0]), "third unique shard restores exact payload")
    reset()
    send(wires[0])
    for changed in (
        wires[1][:13],
        wires[1][:13] + struct.pack("<I", 0x80000000) + wires[1][17:],
        wires[1][:17] + bytes(2) + wires[1][19:],
        wires[1][:19] + struct.pack("<H", 254) + wires[1][21:],
        wires[1][:5] + struct.pack("<H", 5) + wires[1][7:],
        wires[1][:-1],
        wires[1][:13] + struct.pack("<I", 81) + wires[1][17:],
        wires[1][:13] + struct.pack("<I", 2 * 1024 * 1024 + 1) + wires[1][17:],
    ):
        send(changed, label="malformed shard must not poison current group")
    send(wires[3])
    send(wires[4], output(wires[0]))

    def group(wire, number):
        return wire[:7] + struct.pack("<H", number) + wire[9:]

    reset()
    send(wires[0])
    send(group(wires[0], 2))
    send(wires[3])  # late group 1 replaces unfinished group 2, as official does
    send(wires[0])
    send(wires[4], output(wires[0]))
    for i, wire in enumerate(wires[:3]):
        changed = group(wire, 2)
        send(changed, output(group(wires[0], 2)) if i == 2 else "-")
    reset()
    for number in (32766, 65533, 65535, 0):
        for i, wire in enumerate(wires[:3]):
            send(
                group(wire, number), output(group(wires[0], number)) if i == 2 else "-"
            )
    for number in (0, 65535, 32768):
        for wire in wires:
            send(group(wire, number), label="duplicate, stale or half-range")
    reset()
    crc_wires = []
    for wire in wires:
        raw = bytes([wire[0] | 0x80]) + wire[1:]
        crc_wires.append(raw + struct.pack("<I", crc32c(raw)))
    damaged = crc_wires[0][:-1] + bytes([crc_wires[0][-1] ^ 1])
    send(damaged, "invalid", "CRC checked before FEC")
    for i, wire in enumerate(crc_wires[:3]):
        send(
            wire, output(crc_wires[0]) if i == 2 else "-", "CRC-wrapped official shards"
        )
    reset()
    send(bytes([12]) + wires[0][1:], "-", "type12 is not FEC")
    # Sender m=0 bypasses RS; non-aligned payload and >255 data shards remain valid.
    for count in (1, 256, 65536):
        reset()
        data = bytes(i & 255 for i in range(count * 16 - 3))
        for i in range(count):
            wire = (
                struct.pack("<BBBBBHHI", 11, 0, 12, 34, 3, i, 1, 123456)
                + struct.pack("<IHH", len(data), 16, 0)
                + data[i * 16 : (i + 1) * 16].ljust(16, b"\0")
            )
            send(wire, f"11 1 123456 0 {data.hex()}" if i == count - 1 else "-")
    result = subprocess.run(
        [str(args.receiver.resolve())],
        input="\n".join(requests) + "\n",
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    actual = result.stdout.splitlines()
    assert len(actual) == len(expected), (len(actual), len(expected), result.stderr)
    for label, want, got in zip(labels, expected, actual):
        assert got == want, f"{label}: expected {want[:200]}, got {got[:200]}"
    print(
        f"Production FEC receiver: {cases} scenarios, {len(expected) - cases} datagrams passed"
    )


if __name__ == "__main__":
    main()
