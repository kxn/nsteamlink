#!/usr/bin/env python3
"""Compare actual Native worker/Opus Stop schedules with pinned original code.

The Source OS/IO boundaries and Native fixture gates are declared in the audit.
Complete-frame input is controlled, not natural network traffic or a Switch test.
Source releases consumed+purged references; Native separately observes consumed
release calls and asserts empty FIFO/budget after actual purge and worker join.
"""
import argparse
import copy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "stop_stim", ROOT / "scripts/decoder-stop-stimuli.py"
)
stim = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stim)
SHA = "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"


def validate(ref):
    assert ref["binary_sha256"] == SHA and ref["descriptor"] == stim.DESCRIPTOR
    assert [c["input"] for c in ref["cases"]] == stim.plans()
    assert [f["name"] for f in ref["functions"]] == list(stim.FUNCTIONS)
    addresses = {str(f["address"]) for f in ref["functions"]}
    for f in ref["functions"]:
        assert f["size"] > 0 and len(bytes.fromhex(f["sha256"])) == 32
    assert len(ref["helpers"]) >= 12
    for file, sha in ref["helpers"].items():
        assert hashlib.sha256((ROOT / file).read_bytes()).hexdigest() == sha, file
    coverage = set()
    for case in ref["cases"]:
        p = case["input"]
        assert set(case["function_hits"]) <= addresses
        assert all(n > 0 for n in case["function_hits"].values())
        coverage |= case["function_hits"].keys()
        all_ids = [f["id"] for f in p["initial"] + p["pending"]]
        consumed = [r[0] for r in case["consumed"]]
        if p["stage"] == "decode":
            assert (
                consumed == all_ids and not case["remaining"] and case["thinks"] == [0]
            )
        elif p["stage"] == "think":
            assert consumed == [f["id"] for f in p["initial"]]
            assert case["remaining"] == [f["id"] for f in p["pending"]]
            assert case["thinks"] == [1]
        else:
            assert not consumed and case["remaining"] == all_ids and not case["thinks"]
        assert case["released"] == all_ids == consumed + case["remaining"]
        assert case["codec_after"] is False
        assert case["events"] == (
            ["join_enter"]
            + ([] if p["stage"] == "entry" else ["wait_return"])
            + ["consumer_return", "join_return", "purge", "stop_codec"]
        )
        assert case["outputs"] == [[s[0], s[1], s[-1]] for s in case["decoded"]]
        assert all(s[-1] == 480 and len(s) == 6 for s in case["decoded"])
    assert coverage == addresses


def compare(actual, case):
    for key in ["consumed", "decoded", "outputs", "thinks", "codec_after"]:
        assert actual[key] == case[key], (
            case["input"]["name"],
            key,
            actual[key],
            case[key],
        )
    assert actual["released"] == [r[0] for r in case["consumed"]]
    assert actual["admitted_count"] == len(case["admitted"])
    assert actual["queue_after"] == actual["bytes_after"] == 0
    assert actual["player_retained"] is True and actual["device_closed"] == 1
    assert actual["queued_audio"] == sum(r[2] for r in case["outputs"]) * 4
    assert actual["events"] == [
        e for e in case["events"] if e not in ("wait_return", "purge")
    ]


def run(receiver, case):
    p = case["input"]
    lines = "".join(
        f'{tag} {f["id"]} {f["timestamp"]} {f["payload"]}\n'
        for tag, frames in [
            ("I", p["initial"]),
            ("P", p["pending"]),
            ("A", [p["after_stop"]]),
        ]
        for f in frames
    )
    r = subprocess.run(
        [str(receiver.resolve()), p["stage"]],
        input=lines,
        text=True,
        capture_output=True,
        timeout=25,
    )
    assert r.returncode == 0, (p["name"], r.stdout, r.stderr)
    return json.loads(r.stdout)


def negatives(ref, results):
    checks = []

    def reject(name, fn):
        try:
            fn()
        except (AssertionError, ValueError, KeyError):
            checks.append(name)
        else:
            raise AssertionError("Corrupted evidence accepted: " + name)

    for name, change in [
        ("wrong client", lambda x: x.update(binary_sha256="0" * 64)),
        ("missing schedule", lambda x: x["cases"].pop()),
        ("Source early drop", lambda x: x["cases"][1]["consumed"].pop()),
        ("Source late idle drain", lambda x: x["cases"][6]["remaining"].clear()),
        ("Source missing release", lambda x: x["cases"][8]["released"].clear()),
        (
            "Source helper",
            lambda x: x["helpers"].update(
                {"scripts/decoder-stop-stimuli.py": "0" * 64}
            ),
        ),
    ]:
        bad = copy.deepcopy(ref)
        change(bad)
        reject(name, lambda: validate(bad))
    for name, index, change in [
        ("Native skipped queued frame", 1, lambda x: x["consumed"].pop()),
        ("Native skipped final think", 0, lambda x: x["thinks"].clear()),
        ("Native entry drain", 8, lambda x: x["consumed"].append([0, 1100000, 0])),
        ("Native leaked FIFO", 8, lambda x: x.update(queue_after=1)),
        ("Native leaked budget", 8, lambda x: x.update(bytes_after=64)),
        ("Native early player close", 0, lambda x: x.update(player_retained=False)),
        ("Native Stop before join", 0, lambda x: x["events"].reverse()),
    ]:
        bad = copy.deepcopy(results[index])
        change(bad)
        reject(name, lambda: compare(bad, ref["cases"][index]))
    return checks


def main():
    if not __debug__:
        raise SystemExit("Evidence comparison requires Python assertions")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    ref = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-decoder-stop-queue-reference.json.gz"
            ).read_bytes()
        )
    )
    validate(ref)
    results = []
    for case in ref["cases"]:
        actual = run(args.receiver, case)
        compare(actual, case)
        results.append(actual)
    out = dict(cases=results, rejected_records=negatives(ref, results))
    if args.output:
        args.output.write_text(json.dumps(out, indent=2) + "\n")
    print(
        f"PASS: {len(results)} worker stop schedules, {len(out['rejected_records'])} corrupt records rejected"
    )


if __name__ == "__main__":
    main()
