#!/usr/bin/env python3
"""Compare production config/HMAC/control crypto with original client evidence.

Four original credential/auth/dispatch chains and their exact encrypted outputs
are inspected. The Native oracle exercises real config/HMAC/frame crypto at
component boundaries; network_test_udp independently exercises full loopback
discovery, two workers, handshake, authentication, control and joined teardown.
Neither gate proves actual Steam identity, natural ticket lengths or a device.
"""

import argparse
import gzip
import hashlib
import hmac
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def run(receiver, length, vectors):
    lines = [f"{v['op']} {v['sequence']} {v['input'] or '-'}" for v in vectors]
    process = subprocess.run(
        [str(receiver), str(length)],
        input="\n".join(lines) + "\n",
        text=True,
        capture_output=True,
        timeout=15,
    )
    assert process.returncode == 0, (length, process.returncode, process.stderr)
    rows = [
        json.loads(line) for line in process.stdout.splitlines() if line.startswith("{")
    ]
    assert rows, (length, process.stdout)
    assert rows[0]["configured"] == (length in (16, 32)), rows[0]
    assert len(rows) == len(vectors) + 1, (length, rows)
    if length in (16, 32):
        assert (
            rows[0]["hmac"]
            == hmac.new(
                bytes(range(length)), b"Steam In-Home Streaming", hashlib.sha256
            ).hexdigest()
        )
    for vector, row in zip(vectors, rows[1:]):
        expected = dict(ok=vector.get("ok", True), output=vector["output"])
        assert row == expected, (length, vector, row)
    return len(vectors)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    a = p.parse_args()
    reference = json.loads(
        gzip.decompress(
            (ROOT / "scripts/fixtures/steam-session-key-reference.json.gz").read_bytes()
        )
    )
    assert (
        reference["binary_sha256"]
        == "15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2"
    )
    assert len(reference["chains"]) == 4 and len(reference["functions"]) == 48
    assert reference["mutation"]["hits"] == [reference["mutation"]["pc"]]
    assert not reference["mutation"]["source_assertions"]
    count = 0
    for chain in reference["chains"]:
        length = chain["key_length"]
        assert (
            not chain["source_assertions"]
            and chain["key"] == bytes(range(length)).hex()
        )
        assert (
            chain["target"] == 100000
            and chain["tx_sequence"] == 4
            and chain["rx_sequence"] == 1
        )
        assert all(
            chain["crypto_visits"][s] > 0
            for s in ("aes_decrypt_schedule", "aes_decrypt_block", "cbc_decrypt")
        )
        frames = chain["transmitted"]
        assert [int(f["body"][:2], 16) for f in frames] == [6, 1, 9, 9, 9, 8]
        assert all(f["channel"] == 1 for f in frames)
        assert frames[1]["body"] == chain["authentication"]
        assert len(chain["encrypted_inputs"]) == 4
        vectors = [
            dict(v, op="E", output=f["body"][2:])
            for v, f in zip(chain["encrypted_inputs"], frames[2:])
        ]
        vectors.append(
            dict(
                op="D",
                sequence=0,
                input=chain["incoming_target"],
                ok=True,
                output="08a08d06",
            )
        )
        count += run(a.receiver.resolve(), length, vectors)
    assert len(reference["cases"]) == 2
    assert sum(len(c["vectors"]) for c in reference["cases"]) == 250
    for case in reference["cases"]:
        count += run(a.receiver.resolve(), case["key_length"], case["vectors"])
    # Local admission guard, not claims about official behavior for other lengths.
    for length in (0, 1, 15, 17, 24, 31):
        run(a.receiver.resolve(), length, [])
    print(
        f"Official 16/32-byte session keys: 4 source chains, {count} Native crypto comparisons and 6 local guards passed"
    )


if __name__ == "__main__":
    main()
