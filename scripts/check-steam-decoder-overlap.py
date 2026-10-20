#!/usr/bin/env python3
"""Compare original SDK-overlap/event evidence with the actual Native worker.

Three resource-limit cases retain full official output plus an explicitly trimmed
input replay. Only that replay predicts Native; it is not an official drop rule.
"""
import argparse
import gzip
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def execute(receiver, case):
    lines = ["F " + " ".join(map(str, f)) for f in case["initial"]] + ["S"]
    for n in range(len(case["source"]["gates"])):
        if n == case.get("idle_gate"):
            lines += ["A " + " ".join(map(str, f)) for f in case["after_idle"]]
        if n < len(case["waves"]):
            lines += ["F " + " ".join(map(str, f)) for f in case["waves"][n]]
        lines += ["R"]
    if case.get("spurious"):
        lines += ["E" if case.get("wake_result") == 4 else "U"]
    p = subprocess.run(
        [
            str(receiver.resolve()),
            str(ROOT / "app/tests/fixtures/video/sequential.h264"),
        ],
        input="\n".join(lines) + "\n",
        text=True,
        capture_output=True,
        timeout=45,
    )
    assert p.returncode == 0, (case["name"], p.returncode, p.stderr[-2000:])
    return json.loads(p.stdout)


def normalize(snapshot, gate, labels):
    s = snapshot["state"]
    out = {k: s[k] for k in ("player", "flow", "dequeued", "waits")}
    out["flow"] = [
        (
            e[:3] + [hashlib.sha256(bytes.fromhex(e[3])).hexdigest()]
            if e[0] == "decode"
            else e
        )
        for e in out["flow"]
    ]
    out["waits"] = [w[1] for w in out["waits"]]
    out["tasks"] = [
        [labels.setdefault(serial, len(labels)), fid, stamp]
        for serial, fid, stamp in snapshot["tasks"]
    ]
    out["queue"] = snapshot["queue"]
    out["thinks"] = snapshot["thinks"]
    if gate:
        out.update(
            id=snapshot["id"],
            payload=hashlib.sha256(bytes.fromhex(snapshot["payload"])).hexdigest(),
        )
    else:
        out.update({k: s[k] for k in ("strict", "soft", "request", "body", "closed")})
    return out


def verify(receiver, case, got=None):
    got = execute(receiver, case) if got is None else got
    expected = case["port_projection"] or case["source"]
    if case["port_projection"]:
        full = case["source"]["gates"][0]["queue"]
        retained = expected["gates"][0]["queue"]
        assert len(full) > case["keep"] and retained == full[-case["keep"] :]
    assert got["joined"] is True, (case["name"], "worker join")
    assert got["interrupted_returns"] == int(case.get("wake_result") == 4), (
        case["name"],
        "OS EINTR terminal was not exercised",
    )
    assert len(got["gates"]) == len(expected["gates"]), (
        case["name"],
        "gates",
        len(got["gates"]),
        len(expected["gates"]),
    )
    labels = {}
    for n, (row, want) in enumerate(zip(got["gates"], expected["gates"])):
        actual = normalize(row, True, labels)
        assert actual == want, (case["name"], "gate", n, actual, want)
    actual = normalize(got["end"], False, labels)
    assert actual == expected["end"], (case["name"], "end", actual, expected["end"])
    return len(got["gates"])


def verify_stop(receiver):
    raw = (ROOT / "app/tests/fixtures/video/sequential.h264").read_bytes()[:2204].hex()
    lines = [f"F 1 1 24 1000100 {raw}", "S"]
    lines += [f"F {i} {i} 8 {1000000+i*100} {raw}" for i in range(2, 1102)]
    lines += ["T"]
    p = subprocess.run(
        [
            str(receiver.resolve()),
            str(ROOT / "app/tests/fixtures/video/sequential.h264"),
            "--stop",
        ],
        input="\n".join(lines) + "\n",
        text=True,
        capture_output=True,
        timeout=45,
    )
    assert p.returncode == 0, ("stop", p.returncode, p.stderr[-2000:])
    assert json.loads(p.stdout) == dict(
        gates=[], stopped=True, joined=True, released=True
    )


def execute_deadline(receiver):
    raw = (ROOT / "app/tests/fixtures/video/sequential.h264").read_bytes()[:2204].hex()
    commands = [
        f"F {i} {i} {24 if i == 1 else 8} {1000000+i*100} {raw}" for i in range(1, 4)
    ]
    result = subprocess.run(
        [
            str(receiver.resolve()),
            str(ROOT / "app/tests/fixtures/video/sequential.h264"),
            "--deadline",
        ],
        input="\n".join(commands + ["S", "R", "R", "R"]) + "\n",
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        "deadline",
        result.returncode,
        result.stderr[-2000:],
    )
    return json.loads(result.stdout)


def verify_deadline(receiver, result=None):
    result = execute_deadline(receiver) if result is None else result
    assert (
        result["joined"] and result["budget_calls"] == result["budget_elapsed"] == 1
    ), (
        "spurious wake renewed the finite budget",
        result["budget_calls"],
        result["budget_elapsed"],
    )
    assert [e[2] for e in result["end"]["state"]["flow"] if e[0] == "decode"] == [
        1,
        2,
        3,
    ]


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    p.add_argument("--baseline-report", type=Path)
    a = p.parse_args()
    ref = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-decoder-overlap-reference.json.gz"
            ).read_bytes()
        )
    )
    rows = []
    failures = []
    count = 0
    for c in ref["cases"]:
        got = execute(a.receiver, c)
        rows.append(dict(name=c["name"], observed=got))
        try:
            count += verify(a.receiver, c, got)
        except AssertionError as e:
            if not a.baseline_report:
                raise
            failures.append(dict(name=c["name"], difference=str(e)))
    if a.baseline_report:
        a.baseline_report.write_text(
            json.dumps(
                dict(normal_exit_cases=len(rows), failures=failures, rows=rows),
                indent=2,
            )
            + "\n"
        )
        print("Baseline only, not an alignment pass:", len(failures), "different cases")
    else:
        verify_stop(a.receiver)
        verify_deadline(a.receiver)
        print(
            "Decoder overlap:",
            len(rows),
            "cases,",
            count,
            "SDK gates; 3 explicit local input projections",
        )
