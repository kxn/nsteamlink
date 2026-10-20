#!/usr/bin/env python3
"""Compare Source recovery-call identity with the actual Native policy function.

Source codec decode was a declared API terminal; the policy oracle's callbacks
also only record arguments. A separate real Native FIFO/worker/Opus/jitter run
covers the full half-range burst and bounded ring with a paused dummy SDL device.
Neither proves Source PCM, Switch timing, natural media loss or stop preemption.
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
spec = importlib.util.spec_from_file_location(
    "audio_gap_stimuli", ROOT / "scripts/audio-gap-stimuli.py"
)
stim = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stim)
SHA = "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(ref):
    assert ref["binary_sha256"] == SHA
    assert ref["descriptor"] == stim.DESCRIPTOR
    assert [c["input"] for c in ref["cases"]] == stim.plans()
    assert {f["name"] for f in ref["functions"]} == set(stim.FUNCTIONS)
    assert len(ref["functions"]) == 7
    addresses = {str(f["address"]) for f in ref["functions"]}
    for f in ref["functions"]:
        assert f["address"] and f["size"] > 0 and len(bytes.fromhex(f["sha256"])) == 32
    assert len(ref["helpers"]) >= 5
    for file, sha in ref["helpers"].items():
        assert digest(ROOT / file) == sha, ("Source helper changed", file)
    assert {
        "scripts/audit-steam-audio-gap-policy.py",
        "scripts/audio-gap-stimuli.py",
        "scripts/audit-steam-opus-recovery.py",
    } <= ref["helpers"].keys()
    for case in ref["cases"]:
        inp = case["input"]
        obs = case["observed"]
        assert len(obs) == len(inp["actions"])
        assert set(case["function_hits"]) == addresses and all(
            v > 0 for v in case["function_hits"].values()
        )
        assert case["state_write_pcs"] and all(
            0x7B134C <= int(pc) < 0x7B1770 and n > 0
            for pc, n in case["state_write_pcs"].items()
        )
        for op, count, s in zip(inp["actions"], inp["counts"], obs, strict=True):
            assert (
                set(s)
                == {"first", "next", "steps", "trace_sha256", "first_step", "last_step"}
                and s["steps"] == count
            )
            assert len(bytes.fromhex(s["trace_sha256"])) == 32
            assert isinstance(s["first"], bool) and 0 <= s["next"] <= 65535
            if count:
                first = struct.unpack("<HIIBB", bytes.fromhex(s["first_step"]))
                last = struct.unpack("<HIIBB", bytes.fromhex(s["last_step"]))
                assert (
                    op[0] == "F"
                    and first[1] == last[1] == op[2]
                    and last == (op[1], op[2], 5760, 1, 0)
                )
                assert s["first"] is False and s["next"] == (op[1] + 1) & 65535
            else:
                assert (
                    s["first_step"] == s["last_step"] == ""
                    and s["trace_sha256"] == hashlib.sha256(b"").hexdigest()
                )
            if op[0] == "R":
                assert s["first"] is True and s["next"] == 0


def compare(actual, case):
    assert actual == case["observed"], (
        case["input"]["name"],
        "recovery argument/state mismatch",
    )


def check_case(case, receiver):
    lines = "".join(" ".join(map(str, op)) + "\n" for op in case["input"]["actions"])
    r = subprocess.run(
        [str(receiver.resolve())],
        input=lines,
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert r.returncode == 0, (case["input"]["name"], r.stderr)
    actual = [json.loads(line) for line in r.stdout.splitlines()]
    compare(actual, case)
    return dict(name=case["input"]["name"], observed=actual)


def runtime(media):
    # Two complete frames, not two UDP packets. Keep the existing real dispatcher,
    # worker, app callback, libopus and jitter code; the SDL callback stays paused.
    r = subprocess.run(
        [str(media.resolve()), "2", "guard"],
        input="F 0 1100000 f0fffe\nF 32769 1101000 f0fffe\n",
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert r.returncode == 0, (r.stdout, r.stderr)
    s = json.loads(r.stdout)
    assert (
        s["frames"] == 32770
        and s["queued"] == 16383 * 2 * 2
        and s["drops"] > 0
        and s["errors"] == 0
    ), s
    return s


def negatives(ref, results):
    checks = []

    def reject(name, fn):
        try:
            fn()
        except (AssertionError, ValueError, KeyError):
            checks.append(name)
        else:
            raise AssertionError("Corrupted evidence accepted: " + name)

    for name, modify in (
        ("wrong client", lambda r: r.update(binary_sha256="0" * 64)),
        ("missing case", lambda r: r["cases"].pop()),
        (
            "changed input",
            lambda r: r["cases"][0]["input"]["actions"][0].__setitem__(1, 1),
        ),
        ("Source count", lambda r: r["cases"][4]["observed"][1].update(steps=1)),
        (
            "Source frame ID",
            lambda r: r["cases"][4]["observed"][1].update(last_step="00" * 12),
        ),
        (
            "external state write",
            lambda r: r["cases"][0]["state_write_pcs"].update({"1": 1}),
        ),
        (
            "Source method not executed",
            lambda r: r["cases"][0]["function_hits"].popitem(),
        ),
        (
            "Source helper",
            lambda r: r["helpers"].update({"scripts/audio-gap-stimuli.py": "0" * 64}),
        ),
    ):
        bad = copy.deepcopy(ref)
        modify(bad)
        reject(name, lambda: validate(bad))
    case = ref["cases"][4]
    for name, change in (
        ("Native truncated burst", {"steps": 100}),
        ("Native trace", {"trace_sha256": "0" * 64}),
        ("Native stale next", {"next": 1}),
        ("Native wrong first flag", {"first": True}),
        ("Native last FEC flag", {"last_step": "00" * 12}),
    ):
        bad = copy.deepcopy(results[4]["observed"])
        bad[1].update(change)
        reject(name, lambda: compare(bad, case))
    return checks


def main():
    if not __debug__:
        raise SystemExit("Evidence comparator requires Python assertions")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    p.add_argument("--media-receiver", type=Path, required=True)
    p.add_argument("--output", type=Path)
    a = p.parse_args()
    ref = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-audio-gap-policy-reference.json.gz"
            ).read_bytes()
        )
    )
    validate(ref)
    results = [check_case(c, a.receiver) for c in ref["cases"]]
    bad = negatives(ref, results)
    media = runtime(a.media_receiver)
    r = dict(
        passed=True,
        scope=__doc__,
        cases=results,
        counterexamples=bad,
        actual_media=media,
        receiver_sha256=digest(a.receiver),
        media_receiver_sha256=digest(a.media_receiver),
    )
    if a.output:
        a.output.write_text(json.dumps(r, indent=2) + "\n")
    print(
        f"PASS: {len(results)} original policy cases / full step identity traces, {len(bad)} evidence faults; real Native half-range Opus burst and bounded ring"
    )


if __name__ == "__main__":
    main()
