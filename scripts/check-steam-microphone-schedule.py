#!/usr/bin/env python3
"""Compare complete controlled microphone scheduling states with official code.

Identity encryption, clock and final I/O match the explicit Source adapters.
The real producer, dispatch and retained sender run. This does not prove OS
scheduling, full network-loop interleaving or physical microphone operation.
"""

import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def verify_process_report(report):
    spec = importlib.util.spec_from_file_location(
        "mic_check", ROOT / "scripts/check-steam-microphone-process.py"
    )
    mic = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mic)
    prior = json.loads(
        gzip.decompress(
            (
                ROOT
                / "scripts/fixtures/steam-client-microphone-process-reference.json.gz"
            ).read_bytes()
        )
    )
    for key in (
        "client_sha256",
        "codec_sha256",
        "util_sha256",
        "runner_sha256",
        "qt_dependency_sha256",
    ):
        assert report[key] == prior[key], key
    assert len(report["cases"]) == 4 and len(report["source_functions"]) == 60
    assert len(report["helpers"]) == 5
    for name, digest in report["helpers"].items():
        assert (
            hashlib.sha256((ROOT / "scripts" / name).read_bytes()).hexdigest() == digest
        )
    assert (
        hashlib.sha256(
            (ROOT / "scripts/steam-client-microphone-schedule-driver.c").read_bytes()
        ).hexdigest()
        == report["driver_source_sha256"]
    )
    assert {(c["crc"], c["lock_network_thread"]) for c in report["cases"]} == {
        (crc, locked) for crc in (False, True) for locked in (False, True)
    }

    def controls(case):
        result = []
        for item in case["received"]:
            wire = mic.without_crc(bytes.fromhex(item["data"]))
            if wire[0] & 127 == 5 and wire[4] == 1 and wire[13] in (4, 5, 107, 108):
                if wire[13:].hex() not in result:
                    result.append(wire[13:].hex())
        assert len(result) == 7
        return result

    for case in report["cases"]:
        r = case["process"]
        assert (
            case["reliable"]
            and r["exit_code"] == 0
            and r["cleanup_complete"]
            and not r["source_assertions"]
        )
        assert r["schedule_lock_network"] == case["lock_network_thread"]
        assert r["settings_reads"] == [dict(loaded=True, bytes=case["settings"])]
        assert r["module_refs"] == [0, 5]
        assert [
            (e["value"], e["phase"])
            for e in r["module_events"]
            if e["name"].startswith("module_force")
        ] == [(5, "original_exit"), (0, "original_exit")]
        assert any(e[0] == "join_completed" and e[2] == 0 for e in r["trace"])
        assert not {
            pid
            for pid, value in r["tasks_after_shutdown"].items()
            if value not in ("X", "Z")
        } - set(r["tasks_before"])
        assert set(r["mic_peer_returns"]) == {4, 5, 6}
        baseline = next(
            c
            for c in prior["cases"]
            if c["crc"] == case["crc"] and c["reliable"] and c["fec"]
        )
        assert controls(case) == controls(baseline)
        assert [
            mic.normalize(bytes.fromhex(w)) for w in case["mic_initial_wires"]
        ] == mic.expected_wires(case)
        assert r["mapped_sdk"] == baseline["process"]["mapped_sdk"]
        trace = r["schedule_trace"]
        assert len(trace) == 8 and [v[3] for v in trace] == [3, 0, 4, 4, 5, 5, 5, 5]
        assert [v[4] for v in trace] == [3, 3, 0, 1, 0, 0, 1, 1]
        assert trace[0][2] == trace[-1][2] == 625000
        assert all(v[2] == 16384 for v in trace[1:-1])
        assert r["mic_states"][-1] == dict(
            label="duplicate_stop", phase=6, channel=0, sequence=1, gate=0, rx=5, tx=7
        )
        if case["lock_network_thread"]:
            events = case["events"]
            assert (
                events.index("data:5:0")
                < events.index("control:107:4")
                < events.index("control:107:5")
            )
            assert all(((v[0] - v[1]) & 0xFFFFFFFF) >= 0x80000000 for v in trace[2:5])
            assert ((trace[5][0] - trace[5][1]) & 0xFFFFFFFF) < 0x80000000
    print(
        "Official UDP schedule: four original processes, byte identity and controlled counterexamples verified"
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    p.add_argument("--process-report", type=Path)
    args = p.parse_args()
    process_report = (
        json.loads(args.process_report.read_text())
        if args.process_report
        else json.loads(
            gzip.decompress(
                (
                    ROOT
                    / "scripts/fixtures/steam-client-microphone-schedule-process-reference.json.gz"
                ).read_bytes()
            )
        )
    )
    verify_process_report(process_report)
    reference = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-microphone-schedule-reference.json.gz"
            ).read_bytes()
        )
    )
    assert (
        reference["binary_sha256"]
        == "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"
    )
    assert len(reference["functions"]) == 23 and len(reference["cases"]) == 36
    assert {
        (i["crc"], i["reliable"], i["rate"], i["delta"])
        for i in (c["input"] for c in reference["cases"])
    } == {
        (crc, reliable, rate, delta)
        for crc in (False, True)
        for reliable in (False, True)
        for rate in (0, 625000, 65536)
        for delta in (-1, 0, 1)
    }
    states = 0
    for case in reference["cases"]:
        inputs = case["input"]
        result = subprocess.run(
            [
                str(args.receiver.resolve()),
                str(int(inputs["crc"])),
                str(int(inputs["reliable"])),
                str(inputs["rate"]),
            ],
            input="".join(" ".join(map(str, a)) + "\n" for a in inputs["actions"]),
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, (inputs, result.stderr)
        actual = [json.loads(s) for s in result.stdout.splitlines()]
        assert len(actual) == len(case["observed"])
        for n, (got, want) in enumerate(zip(actual, case["observed"])):
            assert got == want, (
                inputs,
                n,
                {
                    k: (got.get(k), want.get(k))
                    for k in set(got) | set(want)
                    if got.get(k) != want.get(k)
                },
            )
            states += 1
    print(
        f"Official microphone schedule: {len(reference['cases'])} cases, {states} complete states passed"
    )


if __name__ == "__main__":
    main()
