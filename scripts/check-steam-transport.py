#!/usr/bin/env python3
"""Compare actual session ingress/lifecycle against fixed official ARM64 cases.

Runs the production C oracle. It does not reinterpret raw datagrams as a model
of the local protocol. The final disconnect/decoder actions and clock are doubles.
"""

import argparse
import json
import struct
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def varint(value):
    result = bytearray()
    value &= (1 << 64) - 1
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    return bytes(result + bytes([value]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", type=Path, required=True)
    args = parser.parse_args()
    fixture = json.loads(
        (ROOT / "scripts/fixtures/steam-protocol-trigger-reference.json").read_text()
    )
    inventory = json.loads(
        (ROOT / "scripts/fixtures/steam-protocol-inventory.json").read_text()
    )
    count = 0

    def run(
        commands,
        phase=1,
        paused=False,
        last_receive=1000000,
        last_echo=200,
        update_time=123456,
    ):
        nonlocal count
        count += 1
        completed = subprocess.run(
            [
                str(args.receiver.resolve()),
                str(phase),
                str(int(paused)),
                str(last_receive),
                str(last_echo),
                str(update_time),
            ],
            input="\n".join(commands) + "\n",
            text=True,
            capture_output=True,
            timeout=10,
            check=True,
        )
        return [json.loads(line) for line in completed.stdout.splitlines()]

    for case in fixture["cases"]:
        group, entry, observed = case["group"], case["input"], case["observed"]
        if group == "connected":
            actual = run([f"WIRE 1000000 1 {entry['datagram']}"])[-1]
            connected = "connected" in observed["actions"]
            assert actual["phase"] == (2 if connected else 1), case["case"]
            assert actual["crc"] == observed["crc_required"], case["case"]
            assert actual["actions"].split() == (["C6"] if connected else []), case[
                "case"
            ]
        elif group in ("crc_requirement", "crc_policy", "transport_lease"):
            commands = [
                f"WIRE 1000000 1 {entry['datagrams'][0]}",
                f"WIRE 1000100 {int(entry['peer_address_matches'])} {entry['datagrams'][1]}",
            ]
            actual = run(commands)[-1]
            if group == "transport_lease":
                # Official harness substitutes channel lookup/delegates; local
                # channel 31 is absent. Compare connection lease/handshake only.
                assert actual["last_receive"] == observed["last_receive"], case["case"]
                assert actual["phase"] == 2 and "C6" not in actual["actions"].split()
                continue
            expected_actions = [
                "D" if action == "disconnect" else action
                for action in observed["actions"]
            ]
            assert actual["host_stop"] == ("D" in expected_actions), case["case"]
            # Transport Disconnect is now a distinct operation. Its wrapper
            # observes dispatch; the shutdown oracle checks the real reply/close.
            assert actual["actions"].split() == expected_actions, case["case"]
            assert actual["last_receive"] == observed["last_receive"], case["case"]
        elif group == "mtu":
            phase = 2 if entry["client_state"] == 2 else 3
            actual = run(
                [
                    f"MTU {entry['initial_mtu']}",
                    f"WIRE 1000000 1 {entry['reassembled_plaintext_packet']}",
                ],
                phase=phase,
            )[-1]
            assert actual["mtu"] == observed["mtu"], case["case"]
            auth = "start_authentication" in observed["actions"]
            assert ("C1" in actual["actions"].split()) == auth, case["case"]
            assert actual["phase"] == (3 if auth else phase), case["case"]
        elif group == "pause_resume":
            conn, client = entry["connection_state"], entry["client_state"]
            phase = (6 if client == 6 else 2) if conn == 1 else 1 if conn == 0 else 0
            actual = run(
                [f"FOREGROUND {int(entry['action'] == 'resume')}", "UPDATE 123456"],
                phase=phase,
                paused=entry["client_paused"],
                last_receive=100,
            )[-1]
            expected_actions = [
                f"C{x['control']}" if "control" in x else f"L{x['data_lost']}"
                for x in observed["actions"]
            ]
            assert actual["actions"].split() == expected_actions, case["case"]
            for key in (
                "client_paused",
                "connection_paused",
                "last_receive",
                "last_echo",
            ):
                assert actual[key] == observed[key], (
                    case["case"],
                    key,
                    actual,
                    observed,
                )

    for case in inventory["mtu_cases"]:
        value = b"\x08" + varint(case["input"]) if case["mtu_field_present"] else b""
        body = b"\x07\x0a" + varint(len(value)) + value
        wire = struct.pack("<BBBBBHHI", 5, 0, 34, 12, 1, 0, 0, 900000) + body
        actual = run([f"WIRE 1000000 1 {wire.hex()}", "FRAGMENT 4000"], phase=2)
        assert actual[0]["mtu"] == case["output"] and actual[0]["phase"] == 3, case
        assert actual[1]["max_wire"] <= case["output"] and actual[1]["payload"] == 4000
        assert actual[1]["fragments"] == (4000 + case["output"] - 18) // (
            case["output"] - 17
        )

    for crc in (False, True):
        connected = next(
            x for x in fixture["cases"] if x["case"] == f"connected_crc{int(crc)}_body4"
        )
        actual = run(
            [
                f"WIRE 1000000 1 {connected['input']['datagram']}",
                "SEND",
                "MTU 512",
                "FRAGMENT 4000 0",
            ]
        )
        assert actual[1]["sent_crc"] == crc and actual[1]["sent_bytes"] == (
            20 if crc else 16
        )
        # Official AddToOutgoingPacketWindow always reserves the four bytes;
        # Socket appends them only with CRC. Full producer/wire proof: §42.
        limit = 512 - 17
        assert actual[2]["max_wire"] == (512 if crc else 508)
        assert actual[2]["fragments"] == (4000 + limit - 1) // limit

    # Actual worker callback, controlled clock, no real-time 15/180-second sleeps.
    for paused in (False, True):
        threshold = (180 if paused else 15) * 65536
        for start in (1000000, 0xFFFF0000):
            for offset in (-1, 0, 1):
                now = (start + threshold + offset) & 0xFFFFFFFF
                actual = run(
                    [f"BEGIN {start}", f"UPDATE {now}"], phase=6, paused=paused
                )[-1]
                assert actual["timed_out"] == (offset >= 0)
                assert actual["actions"].split() == (["D"] if offset >= 0 else [])
                assert not actual["host_stop"]
    actual = run(
        [
            "BEGIN 1000000",
            "FOREGROUND 0",
            "FOREGROUND 1",
            "FOREGROUND 0",
            "UPDATE 1000100",
            "FOREGROUND 1",
            "UPDATE 1000200",
            "FEEDBACK 999900 1000300 1000400",
            "FEEDBACK 999970 1000300 1000400",
        ],
        phase=6,
        update_time=1000000,
    )
    assert actual[0]["actions"].split() == ["C122", "C123", "L0", "L1", "C122"]
    assert actual[1]["actions"].split() == ["C123", "L0", "L1"]
    assert actual[1]["last_receive"] == actual[1]["last_echo"] == 1000100
    # Resume must update the actual ProcessTimestamp watermark, not a shadow
    # field: echo older by 200 is rejected; the -130 boundary is accepted.
    assert actual[2]["last_echo"] == 1000100
    assert actual[3]["last_echo"] == 999970
    print(
        f"Production transport: {count} official-reference and boundary scenarios passed"
    )


if __name__ == "__main__":
    main()
