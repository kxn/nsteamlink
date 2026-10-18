#!/usr/bin/env python3
"""Compare complete official Proof transactions with actual Native RX/actor.

Only two Source host-zero direct-handler cases use Native direct dispatch;
BProcess rejects that identity before handler entry. Other inputs use UDP/RX,
FIFO, crypto and owned timers. File failures in Source are projected onto the
SDK observer contract; product filesystem/readbacks are tested separately.
Selected server identity is an explicit request input, not a natural selector.
"""
import argparse
import gzip
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "token", ROOT / "scripts/check-steam-device-token.py"
)
token = importlib.util.module_from_spec(spec)
spec.loader.exec_module(token)


def compare(got, step, inp):
    for key in ("state", "rid", "secret"):
        assert got[key] == step[key], (inp, step["label"], key, got[key], step[key])
    assert got["keypairs"] == step["keypair_generations"], (
        inp,
        step["label"],
        "keypairs",
    )
    assert got["saves"] == len([x for x in step["timeline"] if x["op"] == "save_key"])
    ops = []
    for item in step["proof_ops"]:
        keys = {
            "hash": ("op", "plain"),
            "encrypt": ("op", "plain", "secret"),
            "save": ("op", "client", "steamid"),
            "send": ("op", "tag"),
        }[item["op"]]
        ops.append({k: item[k] for k in keys})
    assert len(got["proof_ops"]) == len(ops), (
        inp,
        step["label"],
        "operation count",
        got,
        step,
    )
    for actual, expected in zip(got["proof_ops"], ops):
        assert all(actual[k] == v for k, v in expected.items()), (
            inp,
            step["label"],
            actual,
            expected,
        )
    assert len(got["messages"]) == len(step["messages"]), (
        inp,
        step["label"],
        "messages",
        got,
        step,
    )
    source_saves, saved = [], 0
    for item in step["timeline"]:
        if item["op"] == "save_key":
            saved += 1
        elif item["op"] == "send":
            source_saves.append(saved)
    for index, (actual, expected) in enumerate(zip(got["messages"], step["messages"])):
        assert actual["tag"] == expected["tag"]
        if actual["tag"] in (3, 5):
            ap, ep = token.fields(actual["body"]), token.fields(expected["body"])
            selected = (1, 4, 5) if actual["tag"] == 3 else (1, 7, 8, 12)
            assert all(ap.get(k) == ep.get(k) for k in selected), (
                inp,
                step["label"],
                ap,
                ep,
            )
        else:
            assert actual["body"] == expected["body"], (
                inp,
                step["label"],
                actual,
                expected,
            )
        assert actual["saves"] == source_saves[index], (
            inp,
            step["label"],
            "save-before-send",
        )
    if step["state"] == 6:
        length = inp.get("length", 32)
        assert got["successes"] == 1 and got["accepted"] == bytes(range(length)).hex()
    assert got["failures"] == len(step["errors"]), (
        inp,
        step["label"],
        "terminal callback",
    )


def check(receiver, case):
    commands, positions = [], {0: 0}
    for index, event in enumerate(case["events"]):
        kind, wall = event["kind"], event["wall"]
        if kind == "packet":
            if event["tag"] == 7:
                commands.append(f"f {wall} {int(event['encrypt_failure'])}")
            # Same direct boundary as the two zero-host Source handler inputs.
            op = "d" if event["host"] == 0 else "p"
            commands.append(
                f"{op} {wall} {event['tag']} {event['host']} {event['body']}"
            )
        else:
            commands.append(f"{dict(start='s', cancel='c', update='u')[kind]} {wall}")
        positions[index + 1] = len(commands)
    inp = case["input"]
    account = inp.get("account", inp.get("server_account", 0))
    run = subprocess.run(
        [str(receiver.resolve()), str(int(inp.get("test", False))), str(account)],
        input="\n".join(commands) + "\n",
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert run.returncode == 0, (inp, run.returncode, run.stderr[-3000:])
    rows = [json.loads(line) for line in run.stdout.splitlines()]
    assert len(rows) == len(commands) + 1
    for step in case["steps"]:
        compare(rows[positions[step["event_count"]]], step, inp)


def check_ingress(receiver, case):
    commands = []
    for event in case["events"]:
        if event["kind"] == "raw":
            commands.append(f"r {event['wall']} {event['wire']}")
        elif event["kind"] == "packet":
            commands.append(
                f"p {event['wall']} {event['tag']} {event['host']} {event['body']}"
            )
        else:
            assert event["kind"] == "cancel"
            commands.append(f"c {event['wall']}")
    run = subprocess.run(
        [str(receiver.resolve()), "0", "0"],
        input="\n".join(commands) + "\n",
        text=True,
        capture_output=True,
        timeout=15,
    )
    assert run.returncode == 0, (case["input"], run.returncode, run.stderr[-3000:])
    rows = [json.loads(line) for line in run.stdout.splitlines()]
    assert len(rows) == len(commands) + 1
    for step in (case["before"], case["after"]):
        compare(rows[step["event_count"]], step, case["input"])


def main():
    if not __debug__:
        raise SystemExit("Assertions required")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    a = p.parse_args()
    source = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-proof-transaction-reference.json.gz"
            ).read_bytes()
        )
    )
    assert len(source["cases"]) == 63
    for index, case in enumerate(source["cases"]):
        check(a.receiver, case)
        print(
            index,
            case["input"].get("path", "requests"),
            "Proof transaction verified",
            flush=True,
        )
    ingress = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-proof-ingress-reference.json.gz"
            ).read_bytes()
        )
    )
    assert len(ingress["cases"]) == 14
    for case in ingress["cases"]:
        check_ingress(a.receiver, case)
        print(case["input"], "raw Proof ingress verified", flush=True)
    print(
        "63 official/Native Proof transactions + 14 complete ingress cases; two host-zero transaction cases explicitly at direct handler boundary; empty-body Source assertion excluded"
    )


if __name__ == "__main__":
    main()
