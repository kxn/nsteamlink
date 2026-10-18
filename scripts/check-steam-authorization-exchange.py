#!/usr/bin/env python3
"""Compare complete official crypto/cache vectors with real Native UDP workers.

The explicit LAN authorization API is compared at authorization completion,
confirmation/cancel bytes, secret and derivation count. Official automatic stream
resumption, repeat Unauthorized ownership, Qt/persistence and foreign-source
admission are not claimed by this component projection.
"""
import argparse
import gzip
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def varint(value):
    out = bytearray()
    while value > 127:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def key_field(wire):
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
            data, pos = wire[pos : pos + n], pos + n
            if tag >> 3 == 4:
                return data.hex()
    raise AssertionError("auth_key missing")


def response(row):
    key, token = bytes.fromhex(row["auth_key"]), bytes.fromhex(row["device_token"])
    return (
        b"\x08"
        + varint(row["result"])
        + b"\x11"
        + (76561198000000001).to_bytes(8, "little")
        + b"\x1a"
        + varint(len(key))
        + key
        + b"\x22"
        + varint(len(token))
        + token
    ).hex()


def execute(receiver, args):
    r = subprocess.run(
        [str(receiver.resolve()), *args], capture_output=True, text=True, timeout=15
    )
    assert r.returncode == 0, (args[0], r.returncode, r.stderr[-3000:])
    return [json.loads(s) for s in r.stdout.splitlines()]


def expected(step):
    messages = []
    for m in step["messages"]:
        if m["tag"] == 5:
            continue
        messages.append(
            dict(
                tag=m["tag"],
                body=(
                    key_field(bytes.fromhex(m["body"])) if m["tag"] == 3 else m["body"]
                ),
            )
        )
    return dict(
        pending=step["state"] == 4,
        derived=step["derived"],
        success=len(step["saved"]),
        failed=int(bool(step["errors"])),
        secret=step["secret"],
        messages=messages,
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    p.add_argument("--deferred", action="store_true")
    a = p.parse_args()
    source = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-authorization-exchange-reference.json.gz"
            ).read_bytes()
        )
    )
    assert len(source["cases"]) == 34
    compared = 0
    for c in source["cases"]:
        assert not c["source_assertions"]
        if c["input"]["path"] == "cached_success_reauthorization":
            # This requires retaining the original streaming transaction and
            # cache across automatic Unauthorized. The standalone API does not.
            continue
        mode = (
            c["input"]["path"]
            if "clocks" in c
            else ("pump" if a.deferred else "normal")
        )
        actual = execute(a.receiver, [mode, *[response(r) for r in c["responses"]]])
        assert len(actual) == len(c["steps"])
        for observed, step in zip(actual, c["steps"]):
            projected = {k: observed[k] for k in expected(step)}
            assert projected == expected(step), (
                c["input"],
                step["label"],
                projected,
                expected(step),
            )
        if a.deferred:
            assert actual[-1]["persist"] == len(c["steps"][-1]["saved"])
            stages = []
            for step in c["steps"]:
                count = sum(m["tag"] == 14 for m in step["messages"])
                stages.extend([len(step["saved"])] * (count - len(stages)))
            assert actual[-1]["persist_at_confirm"] == stages, (
                c["input"],
                stages,
                actual[-1],
            )
        compared += 1
    retry = execute(a.receiver, ["retry"])
    assert [len(s["messages"]) for s in retry] == [1, 1, 1, 1, 2, 2, 2, 3, 4]
    assert all(s["pending"] and not s["failed"] and not s["success"] for s in retry)
    for mode in ("universe", "rsa"):
        failed = execute(a.receiver, [mode])
        assert (
            len(failed) == 1 and failed[0]["failed"] == 1 and not failed[0]["pending"]
        )
        assert failed[0]["messages"] == [dict(tag=9, body="")]
    if a.deferred:
        valid = source["cases"][0]["responses"][0]
        dropped = execute(a.receiver, ["drop", response(valid)])
        assert len(dropped) == 1 and dropped[0]["pending"] and not dropped[0]["derived"]
        denied = next(
            c
            for c in source["cases"]
            if c["input"] == dict(path="result", result=1, test=False)
        )["responses"][0]
        full = execute(a.receiver, ["queue_full", response(denied)])
        assert (
            len(full) == 2
            and not full[-1]["pending"]
            and not full[-1]["derived"]
            and full[-1]["failed"] == 1
        )
        assert [m["tag"] for m in full[-1]["messages"]] == [3, 9] + [14] * 31
        assert all(m["body"] == "0808" for m in full[-1]["messages"] if m["tag"] == 14)
    n = source["negative"]
    assert (
        n["mutant"]["patch_hits"] == [n["site"]]
        and not n["mutant"]["source_assertions"]
    )
    assert (
        n["original"]["steps"][-1]["derived"] == 1
        and n["mutant"]["steps"][-1]["derived"] == 2
    )
    print(
        f"Authorization exchange: {compared} official/Native complete crypto/cache/cancel/secret UDP traces, 3-second retries, 2 producer failures; automatic streaming reauthorization remains a separate product path"
    )


if __name__ == "__main__":
    main()
