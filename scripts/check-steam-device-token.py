#!/usr/bin/env python3
"""Project official token/PIN bytes onto actual Native producers and UDP output.

This component projection replaces the Native secret explicitly; §132's automatic
same-owner path is checked separately by check-steam-auto-authorization.py. Source metadata, OS,
Qt and unselected message kinds are not claimed equal. SDK encrypt failure is
compared with Source's helper-bool failure at the caller, not inside the crypto.
"""
import argparse
import gzip
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def fields(body):
    b, pos, out = bytes.fromhex(body), 0, {}

    def varint():
        nonlocal pos
        n = shift = 0
        while True:
            value = b[pos]
            pos += 1
            n |= (value & 127) << shift
            if value < 128:
                return n
            shift += 7
            assert shift < 70

    while pos < len(b):
        tag = varint()
        if tag & 7 == 0:
            value = varint()
        else:
            assert tag & 7 == 2
            n = varint()
            value = b[pos : pos + n]
            pos += n
        out[tag >> 3] = value
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    a = p.parse_args()
    source = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-device-token-reference.json.gz"
            ).read_bytes()
        )
    )
    assert len(source["cases"]) == 36
    for case in source["cases"]:
        inp, last = case["input"], case["steps"][-1]
        mode = (
            "auth"
            if inp["path"] == "auth_retry" or inp.get("fail_token") == 1
            else "stream"
        )
        tag = 3 if mode == "auth" else 5
        wires = [row for row in last["messages"] if row["tag"] in (3, 5)]
        selected = []
        args = [
            str(a.receiver.resolve()),
            mode,
            str(inp.get("device_id", 0x1122334455667788)),
            inp.get("pin", "9876"),
            str(int(inp.get("test", False))),
        ]
        for i, call in enumerate(last["token_calls"]):
            row = wires[i] if not call["failed"] else last["messages"][-1]
            if row["tag"] not in (tag, 9 if mode == "auth" else 10):
                continue
            iv = "!" if call["failed"] else last["ivs"][call["iv_before"]]
            args.append(call["secret"] + ":" + iv)
            selected.append((call, row))
        assert selected
        run = subprocess.run(args, text=True, capture_output=True, timeout=15)
        assert run.returncode == 0, (inp, mode, run.returncode, run.stderr[-2500:])
        native = [json.loads(row) for row in run.stdout.splitlines()]
        assert len(native) == len(selected)
        for i, (row, (call, wire)) in enumerate(zip(native, selected)):
            assert row["tag"] == wire["tag"], (inp, i, "caller failure", row, wire)
            assert row["attempts"] == row["encryptions"] == i + 1, (
                inp,
                i,
                "fresh per-send encryption",
                row,
            )
            assert row["pin_encryptions"] == int(
                mode == "stream" and bool(inp.get("pin", "9876"))
            ), (inp, i, row)
            assert row["pending"] == (not call["failed"]) and row["failed"] == int(
                call["failed"]
            ), (inp, i, row)
            if mode == "auth":
                assert row["ticket_secret"] == call["secret"], (
                    inp,
                    i,
                    "ticket/token snapshot",
                    row,
                )
            if call["failed"]:
                assert row["body"] == wire["body"] and row["failure_code"] == (
                    7 if mode == "auth" else 3
                ), (inp, i, row)
            else:
                body = fields(wire["body"])
                expected = body[1 if tag == 3 else 7].hex()
                assert row["token"] == expected, (inp, i, "token", row, expected)
                if mode == "stream":
                    assert row["pin"] == body[8].hex() and row["test"] == bool(
                        inp.get("test", False)
                    ), (inp, i, "PIN cache", row)
    negative = source["negative"]
    assert (
        negative["mutant"]["patch_hits"] == [negative["site"]] * 3
        and not negative["mutant"]["source_assertions"]
    )
    print(
        "Device tokens: 36 official/Native per-send token/PIN/secret/producer-failure projections, actual AES/RSA/UDP; automatic stream ownership remains separately scoped"
    )


if __name__ == "__main__":
    main()
