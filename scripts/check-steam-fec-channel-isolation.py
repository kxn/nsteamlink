#!/usr/bin/env python3
"""Compare original client channel isolation with two actual Native RX executions.

The existing collector oracle checks each action's bytes/counters. The separate
header oracle checks actual channel/group/body delegates and stable distinct FEC
receivers. Both use production CRC/Base/session/FEC/RS and controlled final I/O,
time and delivery delegates. Neither executes media workers/decoders/real UDP.
Counterexamples are corrupted evidence records, not production semantic mutants.
"""
import argparse
import copy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CLIENT_SHA = "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"
ADDRESSES = {
    0x7FF3E0,
    0x7FACFC,
    0x7FBA34,
    0x7F8630,
    0x7F9250,
    0x7F9940,
    0x7F7FCC,
    0x7F7EEC,
    0x7F84DC,
    0x7F609C,
    0x7F9C9C,
}


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


stim = module("channel_stimuli", "fec-channel-stimuli.py")
norm = module("channel_crc", "check-steam-retry-process.py")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_reference(ref):
    assert ref["binary_sha256"] == CLIENT_SHA
    assert len(ref["functions"]) == len(ADDRESSES)
    assert {f["address"] for f in ref["functions"]} == ADDRESSES
    for f in ref["functions"]:
        assert f["size"] > 0 and f["names"] and len(f["sha256"]) == 64
        assert len(bytes.fromhex(f["sha256"])) == 32
    helpers = ref["helpers"]
    assert len(helpers) >= 10
    for name, sha in helpers.items():
        assert name.startswith("scripts/") and digest(ROOT / name) == sha, (
            "Source helper changed",
            name,
        )
    assert {
        "scripts/audit-steam-fec-channel-isolation.py",
        "scripts/fec-channel-stimuli.py",
        "scripts/audit-steam-fec.py",
        "scripts/audit-steam-video-recovery.py",
    } <= helpers.keys()
    bank = ref["bank"]
    assert len(bank) == 2 and bank[0]["body"] != bank[1]["body"]
    assert all(
        len(bytes.fromhex(b["body"])) == 80 and len(b["wires"]) == 5 for b in bank
    )
    assert [c["input"] for c in ref["cases"]] == stim.schedules(bank)
    covered = set()
    for c in ref["cases"]:
        stim.verify(c, bank)
        covered.update(int(k) for k, v in c["function_hits"].items() if v > 0)
        assert c["created_channels"] == list(range(5))
        assert len(c["observed"]) == len(c["input"]["actions"])
        wire_actions = [
            (i, op) for i, op in enumerate(c["input"]["actions"]) if op[0] == "W"
        ]
        assert len(c["wire_inputs"]) == len(wire_actions)
        for row, (index, op) in zip(c["wire_inputs"], wire_actions, strict=True):
            assert row["action"] == index
            raw = bytes.fromhex(row["wire"])
            assert bool(raw[0] & 128) == c["input"]["crc"]
            plain = norm.without_crc(raw)
            assert plain == struct.pack(
                "<BBBBBHHI",
                op[2] | (128 if c["input"]["crc"] else 0),
                op[5],
                34,
                12,
                op[3],
                op[6],
                op[4],
                op[7],
            ) + bytes.fromhex(op[8])
    assert covered == ADDRESSES, covered


def compare_states(actual, case):
    assert actual == case["observed"], (
        case["input"]["name"],
        "per-action collector/body mismatch",
    )


def compare_headers(actual, case):
    actions = case["input"]["actions"]
    assert actual[-1] == dict(
        done=True,
        distinct=True,
        parsed=sum(op[0] == "W" for op in actions),
        fec_calls=sum(op[0] == "W" and op[2] == 11 for op in actions),
    )
    assert actual[:-1] == case["deliveries"], (
        case["input"]["name"],
        "header/body mismatch",
    )


def run_case(case, receiver, channel_receiver):
    inp = case["input"]
    crc = str(int(inp["crc"]))
    command = [str(receiver.resolve()), crc, "1", "-1", "34", "loss"]
    r = subprocess.run(
        command,
        input="".join(" ".join(map(str, op)) + "\n" for op in inp["actions"]),
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert r.returncode == 0, (inp["name"], r.stderr)
    states = [json.loads(line) for line in r.stdout.splitlines()]
    compare_states(states, case)
    wires = {v["action"]: v["wire"] for v in case["wire_inputs"]}
    lines = [
        f"W {n} {op[1]} {wires[n]}" if op[0] == "W" else f"U {n} {op[1]} {op[2]}"
        for n, op in enumerate(inp["actions"])
    ]
    command2 = [str(channel_receiver.resolve()), crc]
    r2 = subprocess.run(
        command2,
        input="\n".join(lines) + "\n",
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert r2.returncode == 0, (inp["name"], r2.stderr)
    headers = [json.loads(line) for line in r2.stdout.splitlines()]
    compare_headers(headers, case)
    return dict(
        name=inp["name"], states=states, headers=headers, commands=[command, command2]
    )


def counterexamples(ref, results):
    checks = []

    def rejected(name, fn):
        try:
            fn()
        except (AssertionError, ValueError, KeyError):
            checks.append(name)
        else:
            raise AssertionError("corrupted evidence accepted: " + name)

    for name, modify in (
        ("wrong client", lambda r: r.update(binary_sha256="0" * 64)),
        ("missing case", lambda r: r["cases"].pop()),
        (
            "changed input channel",
            lambda r: r["cases"][0]["input"]["actions"][0].__setitem__(3, 4),
        ),
        ("Source channel", lambda r: r["cases"][0]["deliveries"][0].update(channel=3)),
        ("Source reconstruction skipped", lambda r: r["cases"][0]["rs"].pop()),
        (
            "Source function not executed",
            lambda r: [c["function_hits"].pop(str(0x7F609C), None) for c in r["cases"]],
        ),
        (
            "Source wire changed",
            lambda r: r["cases"][0]["wire_inputs"][0].update(wire="00"),
        ),
        (
            "Source helper identity",
            lambda r: r["helpers"].update({"scripts/fec-channel-stimuli.py": "0" * 64}),
        ),
    ):
        bad = copy.deepcopy(ref)
        modify(bad)
        rejected(name, lambda: validate_reference(bad))
    case = ref["cases"][0]
    result = results[0]
    for name, modify in (
        ("Native receiver alias", lambda a: a[-1].update(distinct=False)),
        ("Native wrong header channel", lambda a: a[0].update(channel=3)),
        ("Native wrong group", lambda a: a[0].update(group=2)),
        ("Native wrong body", lambda a: a[0].update(body="00")),
        ("Native missing delivery", lambda a: a.pop(0)),
        ("Native input not parsed", lambda a: a[-1].update(parsed=0)),
        ("Native bypassed FEC", lambda a: a[-1].update(fec_calls=0)),
    ):
        bad = copy.deepcopy(result["headers"])
        modify(bad)
        rejected(name, lambda: compare_headers(bad, case))
    bad = copy.deepcopy(result["states"])
    bad[-1]["packets"]["lost"] += 1
    rejected("Native collector changed", lambda: compare_states(bad, case))
    return checks


def main():
    if not __debug__:
        raise SystemExit("Evidence comparator requires Python assertions")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    p.add_argument("--channel-receiver", type=Path, required=True)
    p.add_argument(
        "--reference",
        type=Path,
        default=ROOT / "scripts/fixtures/steam-fec-channel-isolation-reference.json.gz",
    )
    p.add_argument("--output", type=Path)
    a = p.parse_args()
    ref = json.loads(gzip.decompress(a.reference.read_bytes()))
    validate_reference(ref)
    results = [run_case(c, a.receiver, a.channel_receiver) for c in ref["cases"]]
    checks = counterexamples(ref, results)
    report = dict(
        scope=__doc__,
        passed=True,
        cases=results,
        counterexamples=checks,
        receiver_sha256=digest(a.receiver),
        channel_receiver_sha256=digest(a.channel_receiver),
    )
    if a.output:
        a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"PASS: {len(results)} official channel schedules / two Native executions each, {len(checks)} evidence counterexamples"
    )


if __name__ == "__main__":
    main()
