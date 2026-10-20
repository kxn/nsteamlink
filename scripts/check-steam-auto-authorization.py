#!/usr/bin/env python3
"""Compare actual same-owner Native automatic authorization with §132 Source.

Every input runs through UDP/RX, owned FIFO, the runtime-style Pump, real shared
crypto/cache/producers and callbacks. Time/entropy/IV and peer are controlled.
Compare whole transaction sequences, not an explicit secret replacement/new
PAIR request. Qt and platform metadata/RSA ciphertext are not projected; real
Steam, natural scheduling and Switch execution remain separate gates.
"""
import argparse
import gzip
import json
from pathlib import Path
import subprocess
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "token", ROOT / "scripts/check-steam-device-token.py"
)
token = importlib.util.module_from_spec(spec)
spec.loader.exec_module(token)


def main():
    if not __debug__:
        raise SystemExit("Assertions required")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    a = p.parse_args()
    source = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-auto-authorization-reference.json.gz"
            ).read_bytes()
        )
    )
    assert len(source["cases"]) == 42
    errors = json.loads(
        gzip.decompress(
            (
                ROOT
                / "scripts/fixtures/steam-auto-authorization-errors-reference.json.gz"
            ).read_bytes()
        )
    )
    assert len(errors["cases"]) == 2
    for case in source["cases"] + errors["cases"]:
        commands = []
        positions = {0: 0}
        for index, e in enumerate(case["events"]):
            if not isinstance(e, dict):
                assert e == "load-settings", ("Unmodeled Source observer", e)
                positions[index + 1] = len(commands)
                continue  # This inherited settings observer is not a peer input.
            assert e.get("kind") in ("packet", "update", "cancel"), e
            if e["kind"] == "packet":
                commands.append(f"p {e['wall']} {e['tag']} {e['host']} {e['body']}")
            else:
                commands.append(f"{'c' if e['kind']=='cancel' else 'u'} {e['wall']}")
            positions[index + 1] = len(commands)
        run = subprocess.run(
            [str(a.receiver.resolve()), str(int(case["input"]["test"]))],
            input="\n".join(commands) + "\n",
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert run.returncode == 0, (case["input"], run.returncode, run.stderr[-4000:])
        rows = [json.loads(x) for x in run.stdout.splitlines()]
        assert len(rows) == len(commands) + 1
        for step in case["steps"]:
            got = rows[positions[step["event_count"]]]
            for k in ("state", "rid", "secret", "cache", "cached_result", "derived"):
                assert got[k] == step[k], (case["input"], step["label"], k, got, step)
            assert got["keypairs"] == step["keypair_generations"]
            assert got["saves"] == len(
                [x for x in step["timeline"] if x["op"] == "save_key"]
            )
            assert len(got["messages"]) == len(step["messages"]), (
                case["input"],
                step["label"],
                "message count",
                got["messages"],
                step["messages"],
            )
            source_saves = []
            saved = 0
            for item in step["timeline"]:
                if item["op"] == "save_key":
                    saved += 1
                elif item["op"] == "send":
                    source_saves.append(saved)
            assert len(source_saves) == len(step["messages"])
            for at, (actual, expected) in enumerate(
                zip(got["messages"], step["messages"])
            ):
                assert actual["tag"] == expected["tag"]
                if actual["tag"] in (3, 5):
                    ap, ep = token.fields(actual["body"]), token.fields(
                        expected["body"]
                    )
                    selected = (1, 4, 5) if actual["tag"] == 3 else (1, 7, 8, 12)
                    assert all(ap[k] == ep[k] for k in selected), (
                        case["input"],
                        step["label"],
                        "wire fields",
                        ap,
                        ep,
                    )
                else:
                    assert actual["body"] == expected["body"]
                assert actual["saves"] == source_saves[at], (
                    case["input"],
                    step["label"],
                    "persistence order",
                    at,
                )
            assert got["tickets"] == [token.fields(t)[3].hex() for t in step["tickets"]]
            if step["state"] == 6:
                expected_key = bytes(range(case["input"]["length"])).hex()
                assert got["successes"] == 1 and got["accepted"] == expected_key
                consumer = (
                    step["network_tokens"]
                    if case["input"]["test"]
                    else step["ordinary_launches"]
                )
                if consumer:
                    assert consumer == [expected_key]
            else:
                assert got["successes"] == 0
        print(case["input"], "same-owner transaction verified", flush=True)
    unauthorized = source["cases"][0]["events"][1]["body"]
    progress_case = next(c for c in source["cases"] if c["input"].get("result") == 5)
    success_case = next(
        c for c in source["cases"] if c["input"]["path"] == "credentials_after_auth"
    )
    progress = next(
        e["body"]
        for e in progress_case["events"]
        if isinstance(e, dict) and e.get("tag") == 4
    )
    success = next(
        e["body"]
        for e in success_case["events"]
        if isinstance(e, dict) and e.get("tag") == 4
    )
    commands = f"p 1000 6 123 {unauthorized}\nq 1003 4 123 {progress}\nq 1003 4 123 {success}\nb 1003 0\nb 1003 1\nb 1003 1\n"
    run = subprocess.run(
        [str(a.receiver.resolve()), "0"],
        input=commands,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert run.returncode == 0, ("FIFO receiver", run.returncode, run.stderr)
    rows = [json.loads(line) for line in run.stdout.splitlines()]
    assert [r["queued"] for r in rows] == [0, 0, 1, 2, 2, 1, 0]
    assert [len(r["messages"]) for r in rows] == [
        1,
        2,
        2,
        2,
        2,
        2,
        4,
    ], "FIFO deadline ordering"
    assert [r["state"] for r in rows] == [5, 4, 4, 4, 4, 4, 5]
    assert rows[-1]["keypairs"] == rows[-1]["derived"] == rows[-1]["saves"] == 1
    print(
        "44 official/Native complete automatic authorization transactions; same request/keypair/PIN, real RX/actor/crypto, persistence-before-confirm and ordinary/test credentials"
    )


if __name__ == "__main__":
    main()
