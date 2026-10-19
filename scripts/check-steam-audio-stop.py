#!/usr/bin/env python3
"""Compare threaded Stop ordering and full recovery trace against original code.

Original OS/codec API terminals are explicit in the reference. Native uses the
real FIFO, pthread worker, Opus and jitter; a fixture gate holds one real codec
call while another joined controller removes the channel. No product timer or
policy is changed. Record-corruption negatives are not semantic code mutations.
"""
import argparse
import copy
import gzip
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PAUSES = (0, 16384, 32767, 32768)


def read_fixture(name):
    return json.loads(gzip.decompress((ROOT / "scripts/fixtures" / name).read_bytes()))


def validate(ref):
    base = read_fixture("steam-audio-gap-policy-reference.json.gz")
    assert ref["binary_sha256"] == base["binary_sha256"]
    assert ref["descriptor"] == base["descriptor"]
    assert ref["functions"][:-1] == base["functions"]
    f = ref["functions"][-1]
    assert (
        f["name"] == "_ZN14IStreamDecoder15OnStreamStoppedEv"
        and f["address"] == 0x767160
        and f["size"] == 80
        and len(bytes.fromhex(f["sha256"])) == 32
    )
    assert set(ref["helpers"]) == set(base["helpers"]) | {
        "scripts/audit-steam-audio-stop.py"
    }
    for file, sha in ref["helpers"].items():
        assert hashlib.sha256((ROOT / file).read_bytes()).hexdigest() == sha
    assert [c["pause_index"] for c in ref["cases"]] == list(PAUSES)
    expected = next(c for c in base["cases"] if c["input"]["name"] == "halfspace")[
        "observed"
    ][1]
    addresses = {str(f["address"]) for f in ref["functions"]}
    for case in ref["cases"]:
        assert case["recovery"] == expected
        assert case["active_after"] is False and case["codec_after"] is False
        assert case["events"] == [
            ["signal", False, True],
            ["join_enter", case["pause_index"], True],
            ["join_return", 32769, True],
            ["empty_purge", 32769, True],
            ["stop_codec", 32769, True],
        ]
        assert set(case["function_hits"]) == addresses and all(
            n > 0 for n in case["function_hits"].values()
        )
        assert case["state_write_pcs"] and all(
            0x7B134C <= int(pc) < 0x7B1770 and n > 0
            for pc, n in case["state_write_pcs"].items()
        )


def compare(actual, case):
    assert actual == dict(
        pause_index=case["pause_index"],
        steps=32769,
        frames=32770,
        errors=0,
        joined=1,
        destroyed=1,
        trace_sha256=case["recovery"]["trace_sha256"],
    ), ("Native stop ordering or recovery identity mismatch", actual)


def negatives(ref, results):
    rejected = []

    def reject(name, fn):
        try:
            fn()
        except (AssertionError, ValueError, KeyError, IndexError):
            rejected.append(name)
        else:
            raise AssertionError("Corrupted record accepted: " + name)

    for name, change in (
        ("wrong client", lambda x: x.update(binary_sha256="0" * 64)),
        ("missing pause", lambda x: x["cases"].pop()),
        (
            "stop before join",
            lambda x: x["cases"][0]["events"].reverse(),
        ),
        (
            "codec already destroyed at join",
            lambda x: x["cases"][0]["events"][1].__setitem__(2, False),
        ),
        (
            "truncated Source recovery",
            lambda x: x["cases"][0]["recovery"].update(steps=16384),
        ),
        (
            "Stop never executed",
            lambda x: x["cases"][0]["function_hits"].pop(str(0x767160)),
        ),
        (
            "adapter recovery write",
            lambda x: x["cases"][0]["state_write_pcs"].update({"1": 1}),
        ),
        (
            "Source helper changed",
            lambda x: x["helpers"].update(
                {"scripts/audit-steam-audio-stop.py": "0" * 64}
            ),
        ),
    ):
        bad = copy.deepcopy(ref)
        change(bad)
        reject(name, lambda: validate(bad))
    for name, changes in (
        ("Native skipped current frame", dict(frames=32769)),
        ("Native partial recovery", dict(steps=16384)),
        ("Native missing join", dict(joined=0)),
        ("Native leaked decoder", dict(destroyed=0)),
        ("Native reordered callbacks", dict(trace_sha256="0" * 64)),
    ):
        bad = results[0] | changes
        reject(name, lambda: compare(bad, ref["cases"][0]))
    return rejected


def main():
    if not __debug__:
        raise SystemExit("Evidence comparison requires Python assertions")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    ref = read_fixture("steam-audio-stop-reference.json.gz")
    validate(ref)
    results = []
    for case in ref["cases"]:
        run = subprocess.run(
            [str(args.receiver.resolve()), "2", f"stop-{case['pause_index']}"],
            input="F 0 1100000 f0fffe\nF 32769 1101000 f0fffe\n",
            text=True,
            capture_output=True,
            timeout=30,
        )
        assert run.returncode == 0, (case["pause_index"], run.stdout, run.stderr)
        actual = json.loads(run.stdout)
        compare(actual, case)
        results.append(actual)
    result = dict(cases=results, rejected_records=negatives(ref, results))
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(
        f"PASS: {len(results)} concurrent Stop gates, {len(result['rejected_records'])} corrupt records rejected"
    )


if __name__ == "__main__":
    main()
