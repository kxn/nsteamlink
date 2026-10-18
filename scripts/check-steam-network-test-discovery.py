#!/usr/bin/env python3
"""Check discovery test flag, original credentials/error/cancel and retry vectors.

The oracle executes the production producer, raw-envelope parser, AES/HMAC and
actual UDP sends. Ingress is explicitly driven. Peer identity and endpoint are
fixtures; the independent full worker UDP test is still not a real Steam host.
Platform/version/token/transport/gamepad details are not byte-equal Android
capabilities. Unauthorized enters the same stream owner; full crypto/continuation is checked
separately against §132 by check-steam-auto-authorization.py.
"""
import argparse
import gzip
import hashlib
import hmac
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def fields(wire):
    def read(pos):
        value = shift = 0
        while True:
            byte = wire[pos]
            pos += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value, pos
            shift += 7
            assert shift < 70

    result, pos = {}, 0
    while pos < len(wire):
        tag, pos = read(pos)
        if tag & 7 == 0:
            value, pos = read(pos)
        else:
            assert tag & 7 == 2
            size, pos = read(pos)
            value = wire[pos : pos + size].hex()
            pos += size
        result.setdefault(str(tag >> 3), []).append(value)
    return result


def run(receiver, test, gamepads, response, repeat=1, callbacks=None):
    command = [
        str(receiver.resolve()),
        str(int(test)),
        str(gamepads),
        response,
        str(repeat),
    ]
    if callbacks is not None:
        command.append(str(callbacks))
    result = subprocess.run(command, text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, (
        result.returncode,
        result.stdout[-2000:],
        result.stderr[-2000:],
    )
    return json.loads(result.stdout)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    a = p.parse_args()
    report = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-network-test-discovery-reference.json.gz"
            ).read_bytes()
        )
    )
    assert (
        report["binary_sha256"]
        == "15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2"
    )
    assert (
        len(report["requests"]) == 8
        and len(report["responses"]) == 43
        and len(report["functions"]) == 16
    )
    assert "_ZN7CCrypto16SymmetricDecryptEPKhjPhPjS1_j" in report["functions"]
    mutation = report["mutation"]
    assert mutation["mutant"]["patch_hits"] == [mutation["pc"]]
    assert not mutation["mutant"]["source_assertions"]
    assert mutation["original"]["fields"]["12"] == [1] and mutation["mutant"]["fields"][
        "12"
    ] == [0]
    success = report["responses"][0]
    assert success["key"] == bytes(range(32)).hex() and success["test_auth_tokens"] == [
        success["key"]
    ]
    assert set(success["crypto_hits"]) == {
        "0xcdc27c",
        "0xcdc2b4",
        "0x102f05c",
        "0x102f5d4",
        "0xcdc558",
    }
    producers = matched = handoffs = 0
    for c in report["requests"]:
        assert not c["source_assertions"]
        i = c["input"]
        if i["restricted"]:
            continue  # Switch currently requests false, never copy an Android policy bit.
        row = run(a.receiver, i["network_test"], i["gamepads"], success["response"])
        actual = fields(bytes.fromhex(row["request"]))
        for key in ("1", "2", "3", "4", "9", "10", "11", "12", "13", "15", "16", "20"):
            assert actual.get(key) == c["fields"][key], (
                i,
                key,
                actual.get(key),
                c["fields"][key],
            )
        assert actual.get("17", [0]) == c["fields"]["17"]
        producers += 1
    for c in report["responses"]:
        i = c["input"]
        assert c["source_assertions"] == (
            [524, 526] if i["name"] in ("short_0", "missing_cipher") else []
        ), i
        if i.get("has_ip", True) is False or i.get("peer_port", 27036) == 0:
            continue  # Original address/peer-port guard is an explicit source boundary.
        row = run(a.receiver, True, 0, c["response"], i.get("repeat", 1))
        assert row["cancels"] == [m["body"] for m in c["messages"] if m["tag"] == 10], (
            i,
            row,
            c["messages"],
        )
        if i.get("result", 0) == 1:
            # This Source audit stops at its producer boundary; compare entry
            # only here. §132 separately checks actual full owner continuation.
            assert row["failures"] == 0 and row["authorizing"] and not row["success"]
            handoffs += 1
            continue
        if c["state"] == 6:
            assert (
                row["success"] == 1
                and not row["failures"]
                and row["key"] == c["key"]
                and row["port"] == c["port"]
            ), (i, row, c)
            assert row["configured"] == (c["key_length"] in (16, 32)), (i, row)
            if row["configured"]:
                expected = hmac.new(
                    bytes.fromhex(c["key"]), b"Steam In-Home Streaming", hashlib.sha256
                ).hexdigest()
                assert row["hmac"] == expected, (i, row)
        elif c["errors"]:
            expected = i.get("result", 0) or 3
            assert (
                row["failures"] == 1
                and row["failure_result"] == expected
                and not row["success"]
            ), (i, row, c)
        else:
            assert not row["success"] and not row["failures"], (i, row, c)
            assert bool(row["progress"]) == (
                i.get("result", 0) in (4, 5) and i.get("request_id", 17) == 17
            ), (i, row)
        matched += 1
    retry = run(a.receiver, True, 0, "-")
    assert retry == dict(
        sends=[s["sends"] for s in report["retry"]["observations"]], failures=0
    ), retry
    assert producers == 4 and matched == 40 and handoffs == 1, (
        producers,
        matched,
        handoffs,
    )
    bad = next(c for c in report["responses"] if c["input"]["name"] == "bad_padding")
    for callback_mode in (1, 2):
        row = run(a.receiver, True, 0, bad["response"], callbacks=callback_mode)
        assert row["cancels"] == ["0811"] and not row["success"], row
        assert row["failures"] == (callback_mode == 1), row
    print(
        f"Discovery: {producers} Native request producers, {matched} credential/error/cancel vectors, 7 original retry checkpoints; {handoffs} same-owner authorization entry"
    )


if __name__ == "__main__":
    main()
