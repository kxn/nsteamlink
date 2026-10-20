#!/usr/bin/env python3
"""Compare full official authorization frames with real routed IHS UDP owners.

Compare each state, request ID, current secret, latest key/result cache, crypto
calls, key-save identity/order and all outgoing body bytes/selected crypto fields.
IHS parser/RX/deferred actor/timers/crypto are real. The endpoint/metadata lookup,
identity/PIN/private/IV entropy and persistence callback are explicit providers.
Original persistent SteamID promotion/subscription and Qt are not this projection.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("token", ROOT / "scripts/check-steam-device-token.py")
token = importlib.util.module_from_spec(spec)
spec.loader.exec_module(token)


def check(receiver, case):
    commands = ["p 1000 6 123 08111001"]  # Real Unauthorized for request_id 17.
    commands += ["c 1000" if packet is None else "r 1000 " + packet["wire"]
                 for packet in case["packets"]]
    run = subprocess.run([str(receiver.resolve()), str(int(case["input"]["test"])), "0", "routed"],
                         input="\n".join(commands) + "\n", text=True,
                         capture_output=True, timeout=15)
    assert run.returncode == 0, (case["input"], run.returncode, run.stderr[-3000:])
    rows = [json.loads(line) for line in run.stdout.splitlines()]
    assert len(rows) == len(commands) + 1
    for actual, expected in zip(rows[1:], case["steps"]):
        for field in ("state", "rid", "secret", "cache", "cached_result", "derived"):
            assert actual[field] == expected[field], (case["input"], expected["label"], field,
                                                       actual, expected)
        saved = [{k: item[k] for k in ("client", "steamid", "secret")}
                 for item in expected["timeline"] if item["op"] == "save_key"]
        assert actual["saved_keys"] == saved, (case["input"], actual["saved_keys"], saved)
        assert actual["send_states"] == expected["send_states"], (
            case["input"], actual["send_states"], expected["send_states"])
        assert actual["persist_states"] == expected["persist_states"], (
            case["input"], actual["persist_states"], expected["persist_states"])
        assert actual["keypairs"] == expected["keypair_generations"]
        assert len(actual["messages"]) == len(expected["messages"]), (case["input"], actual, expected)
        saves = 0
        order = []
        for item in expected["timeline"]:
            saves += item["op"] == "save_key"
            if item["op"] == "send":
                order.append(saves)
        for index, (a, e) in enumerate(zip(actual["messages"], expected["messages"])):
            assert a["tag"] == e["tag"] and a["saves"] == order[index], (case["input"], a, e)
            if a["tag"] in (3, 5):
                ap, ep = token.fields(a["body"]), token.fields(e["body"])
                fields = (1, 4, 5) if a["tag"] == 3 else (1, 7, 8, 12)
                assert all(ap.get(k) == ep.get(k) for k in fields), (case["input"], ap, ep)
            else:
                assert a["body"] == e["body"], (case["input"], a, e)


def main():
    if not __debug__:
        raise SystemExit("Original comparison requires assertions; do not use Python -O")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", type=Path, required=True)
    parser.add_argument("--reference", type=Path,
                        default=ROOT / "scripts/fixtures/steam-authorization-admission-reference.json.gz")
    args = parser.parse_args()
    reference = json.loads(gzip.decompress(args.reference.read_bytes()))
    assert reference["schema"] == 1
    assert reference["binary_sha256"] == "15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2"
    for name, sha in reference["helpers"].items():
        assert hashlib.sha256((ROOT / "scripts" / name).read_bytes()).hexdigest() == sha, name
    assert len(reference["cases"]) == 72
    for case in reference["cases"]:
        assert not case["source_assertions"]
        check(args.receiver, case)
    print(f'PASS {len(reference["cases"])} original BProcess/native routed UDP admission traces')


if __name__ == "__main__":
    main()
