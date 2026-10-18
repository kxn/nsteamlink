#!/usr/bin/env python3
"""Official network-test media fixture -> Native actual CRC/window/FEC statistics.

Native raw ingress, windows/FEC and complete-frame preparation run; this checker
compares their default collector with original NetworkTest CNetworkStats at each
checkpoint. It separately checks original score inputs in the production helper
and bridges identical saved configs through the existing real UDP negotiation
checker. Native network-test mode, timer/complete/result UI are NOT implemented
or claimed by these foundation comparisons. Qt full samples/callbacks remain
original-client observations, not Native functionality.
"""

import argparse
import gzip
import importlib.util
import json
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "flow_check", ROOT / "scripts/check-steam-network-test-fec-flow.py"
)
flow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flow)


def load(name):
    return json.loads(gzip.decompress((ROOT / "scripts/fixtures" / name).read_bytes()))


def invoke(command, actions):
    p = subprocess.run(
        command,
        input="\n".join(" ".join(map(str, a)) for a in actions) + "\n",
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert p.returncode == 0, (
        command,
        p.returncode,
        p.stdout[-1500:],
        p.stderr[-1500:],
    )
    return [json.loads(line) for line in p.stdout.splitlines()]


def verify_source(report):
    assert (
        report["binary_sha256"]
        == "15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2"
    )
    assert len(report["cases"]) == 56 and len(report["functions"]) == 61
    assert sum(len(c["states"]) for c in report["cases"]) == 410
    assert sum(len(c["accepted"]) for c in report["cases"]) == 6246
    assert sum(len(c["wires"]) for c in report["cases"]) == 6339
    for c in report["cases"]:
        i = c["input"]
        mode = 2 if i["bitrate"] <= 0 else 1
        assert not c["source_assertions"]
        assert len(c["completed_scores"]) == 1
        assert [s["observed"] for s in c["scores"] if s["caller"] == 0xCAA358] == c[
            "completed_scores"
        ]
        assert all(s["observed"] in (0, 1, 2) for s in c["scores"])
        assert c["states"][0]["state"] == 4 and c["states"][0]["status"] == 1
        states = {s["label"]: s for s in c["states"]}
        if "timeout_equal" in states:
            assert states["timeout_equal"]["state"] == 4
            assert states["timeout_after"]["state"] == 5
        assert states["complete"]["state"] == 0 and states["complete"]["status"] == 2
        assert all(
            s["gate"] == 0 and all(ch[2] == 0 for ch in s["channels"])
            for s in c["states"]
        )
        for s in c["states"]:
            total = s["quality"]["total"]
            assert s["accepted"] <= len(c["accepted"]) and s["wire_count"] <= len(
                c["wires"]
            )
            # Original progress is raw span/600; Qt presentation is an adapter.
            expected_bits = struct.unpack(
                "<I", struct.pack("<f", total * 100.0 / 600.0)
            )[0]
            assert s["progress_bits"] == expected_bits, (i["name"], s["label"])
        request = bytes.fromhex(c["control_frames"][4]["body"])
        assert request[0] == 8 and flow.fields(request[1:], "test") == {
            1: [(0, 600)],
            2: [(0, 60)],
            3: [
                (
                    0,
                    20000
                    if mode == 1
                    else (10000, 15000, 30000)[i.get("quality", 2) - 1],
                )
            ],
            4: [(0, 0)],
            5: [(0, int(mode == 2))],
        }
        initial = flow.fields(bytes.fromhex(c["initial"]))
        final = flow.fields(bytes.fromhex(c["final"]))
        assert initial[25] == [(0, int(i.get("before", False)))]
        rec = states["result_page"]["recommendation"]
        previous = states["result_page"]["previous_kbps"]
        expected_rec = (
            0
            if mode == 1
            else (
                (1 if i.get("quality", 2) != 1 else 0)
                if previous < 100000
                else (2 if i.get("quality", 2) != 3 else 0)
            )
        )
        assert rec == expected_rec
        save = bool(i.get("accepted", 0) and rec)
        assert len(c["saved"]) == int(save)
        if save:
            assert final[25] == [(0, 1)] and final[1] == [(0, 1 if rec == 1 else 3)]
        else:
            assert c["final"] == c["initial"]
        assert states["user_result"]["saves"] == int(save)
        full = states["complete"]["full"]
        # Graph receives missing spans, full samples record accepted unique IDs.
        assert len(c["graph"]) == states["complete"]["quality"]["total"]
        assert len(full) == sum(row[1] == 0 for row in c["graph"])
    for c in report["cases"]:
        if c["input"]["name"].startswith("wire_gap_"):
            assert [s["quality"]["total"] for s in c["states"][:5]] == [0, 0, 0, 0, 601]
            assert c["accepted"] == [[600, 1007000, 1007065]]
            assert c["states"][4]["state"] == (5 if c["input"]["bitrate"] > 0 else 4)
            assert c["completed_scores"] == [2]
    single = next(c for c in report["cases"] if c["input"]["name"] == "gaps_(599,)")
    assert (
        single["states"][1]["quality"]["total"] == 600 and len(single["accepted"]) == 1
    )
    assert single["states"][1]["state"] == 5 and single["completed_scores"] == [2]
    assert (
        struct.unpack(
            "<f", bytes.fromhex(single["states"][-1]["quality"]["average"])[:4]
        )[0]
        > 99
    )
    for m in report["mutations"]:
        assert m["hits"] == [m["pc"]] and not m["mutant"]["source_assertions"]
        assert (
            m["mutant"]["states"][1]["quality"] == m["original"]["states"][1]["quality"]
        )
    count, score = report["mutations"]
    assert (
        count["name"] == "count_received_instead_of_span"
        and count["original"]["states"][1]["state"] == 5
        and count["mutant"]["states"][1]["state"] == 4
    )
    assert (
        score["name"] == "score_with_internal_batch_loss"
        and score["original"]["completed_scores"] == [2]
        and score["mutant"]["completed_scores"] == [0]
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    p.add_argument("--collector", type=Path, required=True)
    p.add_argument("--negotiator", type=Path, required=True)
    a = p.parse_args()
    report = load("steam-network-test-media-reference.json.gz")
    verify_source(report)
    states = scores = 0
    for c in report["cases"]:
        i = c["input"]
        actions = [["Z"]]
        checkpoints = [0]
        cursor = 0
        if i.get("offset"):
            actions.append(["O", i["offset"]])
        for s in c["states"][1:]:
            for now, wire, _ in c["wires"][cursor : s["wire_count"]]:
                actions.append(["J", now, wire])
            cursor = s["wire_count"]
            if s["label"] == "U":
                actions.append(["U", s["transport_update"], 3])
            # Source Complete calls Stop once. Other checkpoint probes are read-only.
            actions.append(
                ["E"] if s["label"] == "complete" else ["O", i.get("offset", 0)]
            )
            checkpoints.append(len(actions) - 1)
        got = invoke(
            [
                str(a.receiver.resolve()),
                str(int(i.get("crc", False))),
                "1",
                "-1",
                "34",
                "quality",
            ],
            actions,
        )
        assert len(got) == len(actions), i["name"]
        for index, expected in zip(checkpoints, c["states"]):
            actual = got[index]["quality"]
            assert actual == expected["quality"], (
                i["name"],
                expected["label"],
                actual,
                expected["quality"],
            )
            states += 1
        result = invoke(
            [str(a.collector.resolve())], [["T"] + s["input"] for s in c["scores"]]
        )
        assert result == [s["observed"] for s in c["scores"]], i["name"]
        scores += len(result)
    previous = load("steam-network-test-fec-flow-reference.json.gz")
    settings = {c["observed"]["final"] for c in previous["cases"]}
    produced = {c["final"] for c in report["cases"]}
    assert produced <= settings, (len(produced), len(settings), produced - settings)
    # Exact protobuf byte identity bridges to the existing original Linux 24
    # process references; repeat current Native files/UDP/crypto/worker checks.
    subprocess.run(
        [
            "python3",
            str(ROOT / "scripts/check-steam-network-test-fec-flow.py"),
            "--receiver",
            str(a.negotiator.resolve()),
        ],
        check=True,
    )
    print(
        f"Network-test media foundations: {len(report['cases'])} official cases, {states} Native raw RX/stat checkpoints, {scores} original score inputs, {len(produced)} exact saved configs passed; Native test-mode/UI outside scope"
    )


if __name__ == "__main__":
    main()
