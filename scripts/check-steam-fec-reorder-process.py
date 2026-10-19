#!/usr/bin/env python3
"""Original client cross-group FEC schedules vs real Native UDP/RS/decoder.

All admitted datagrams, completed/consumed frame IDs, strict recovery, wire
requests, SDK bytes and every observed pixel are checked. Pacing/headless drain
remain fixture conditions. No Switch/Steam-host/performance equivalence claim.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


stim = module("reorder_stim", "media-fec-reorder-stimuli.py")
common = module("pressure", "check-steam-pressure-process.py")
large = module("large", "check-steam-large-process.py")


def initial_check(case, bank):
    rows = [[bytes.fromhex(h) for h in group] for group in case["initial"]]
    plan = stim.batches(case, bank)
    assert len(rows) == len(plan) == 26
    for row, expected in zip(rows, plan):
        assert len(row) == len(expected)
        for wire, original in zip(row, expected):
            raw = bytearray(common.plain(wire))
            raw[0] &= 127
            assert bytes(raw) == original and bool(wire[0] & 128) == case["crc"]
    return rows


def verify_source(case):
    r = case["process"]
    common.verify_flow(r)
    expected = stim.expected_ids(case["profile"])
    assert r["exit_code"] == 0 and r["cleanup_complete"] and not r["source_assertions"]
    assert r["load_frames"] == expected and r["load_receive_count"] == len(expected)
    assert (
        r["large_ready"] == dict(active=1, phase=6) and r["large_socket"]["drops"] == 0
    )
    assert r["load_table_restored"] and r["load_adapter_closed"]
    assert r["media_final"] == dict(phase=6, decoder=0, rx=4, tx=3)
    assert len(r["large_derived_sha256"]) == 2 and len(r["reorder_derived_sha256"]) == 3
    assert [
        (e["value"], e["phase"])
        for e in r["module_events"]
        if e["name"].startswith("module_force")
    ] == [(7, "original_exit"), (0, "original_exit")]
    assert not {
        pid
        for pid, state in r["tasks_after_shutdown"].items()
        if state not in ("X", "Z")
    } - set(r["tasks_before"])
    assert [e["result"] for e in r["media_events"] if e["name"] == "decoder_join"] == [
        0
    ]
    pictures = r["pictures"]
    sdk = [e for e in r["media_events"] if e["name"] == "sdk_send"]
    sdk_ids = [p["id"] for p in pictures]
    assert sdk_ids == sorted(set(sdk_ids)) and sdk_ids[-2:] == [124, 125]
    assert set(sdk_ids) <= set(expected) and len(sdk) == len(pictures)
    lost = len(expected) != 26
    if lost:
        assert not set(sdk_ids) & set(range(101, 106))
    payloads = stim.pressure.payloads()
    md5 = [
        s.split(",")[-1].strip()
        for s in (ROOT / "app/tests/fixtures/video/sequential.framemd5")
        .read_text()
        .splitlines()
        if not s.startswith("#")
    ]
    for packet, picture in zip(sdk, pictures):
        assert (packet["size"], packet["sha256"]) == (
            payloads[(picture["id"] - 100) % 6]["size"],
            payloads[(picture["id"] - 100) % 6]["sha256"],
        )
        assert picture["md5"] == md5[(picture["id"] - 100) % 6]
    for kind in ("sdk_send_return", "sdk_receive_return"):
        assert [e["result"] for e in r["media_events"] if e["name"] == kind] == [
            0
        ] * len(sdk)
    assert r["load_adapter_final"] == [0, len(sdk), len(sdk), 0]
    assert [e["id"] for e in r["gap_states"]] == expected
    transitions = [
        e["id"]
        for e in r["gap_states"]
        if e["before"]["strict"] == 0 and e["after"]["strict"] == 1
    ]
    assert transitions == (
        [102 if case["profile"] == "late_old" else 103] if lost else []
    )
    if lost:
        key = next(e for e in r["gap_states"] if e["id"] == 106)
        assert key["before"]["strict"] == 1 and key["after"]["strict"] == 0
    wires = [e for e in r["gap_sends"]]
    # At this explicit 5Hz cadence, each later non-key input is >100ms after
    # the preceding recovery request. The original re-requests while strict;
    # it does not send only when the strict flag transitions. No idle timer
    # or universal per-input request policy is inferred from this schedule.
    requests = list(range(transitions[0], 106)) if lost else []
    assert [e["input_id"] for e in wires] == requests
    for index, event in enumerate(wires):
        wire = bytes.fromhex(event["wire"])
        raw = large.recovery_wire(wire, case["crc"])
        assert event["return"] == len(wire) and event["phase"] == 6
        assert int.from_bytes(raw[7:9], "little") == index
        assert any(p["data"] == wire.hex() for p in case["received"])
    peer_media = [
        common.plain(bytes.fromhex(p["data"]))
        for p in case["received"]
        if common.plain(bytes.fromhex(p["data"]))[4] == 3
    ]
    assert len(peer_media) == len(wires)
    assert len(case["producer_times"]) == 26 and case["producer_times"][-1] >= 4.99
    return expected, payloads, md5, requests


def verify(receiver, case, bank):
    expected, payloads, md5, transitions = verify_source(case)
    rows = initial_check(case, bank)
    with tempfile.TemporaryDirectory(prefix="native-fec-reorder-") as td:
        directory = Path(td)
        (directory / "streaming_settings.bin").write_bytes(
            bytes.fromhex(case["settings"])
        )
        media = directory / "media.bin"
        media.write_bytes(
            b"".join(
                b"".join(struct.pack("<I", len(w)) + w for w in row) + bytes(4)
                for row in rows
            )
        )
        process = subprocess.run(
            [
                str(receiver.resolve()),
                "--pressure-fec-reorder",
                str(int(case["crc"])),
                td,
                "080010031804",
                "0",
                str(media),
                "0",
                "26",
                "5",
                case["profile"],
                "-1",
                "250",
                "250",
            ],
            capture_output=True,
            text=True,
            timeout=25,
        )
        assert process.returncode == 0, (
            case["name"],
            process.returncode,
            process.stderr[-5000:],
        )
        got = json.loads(process.stdout)
    data = got["load"]
    assert got["phase"] == 6 and not got["closed"] and got["video"]["stopped"]
    assert got["peer_socket"]["drops"] == got["udp_socket"]["drops"] == 0
    # Count all input, including stale/duplicate indices; they are not assumed
    # to be FEC-admitted fragments just because PacketParse admitted them.
    counts, unique = Counter(), {}
    for row in rows:
        for wire in row:
            shard, group = struct.unpack_from("<HH", wire, 5)
            counts[group] += 1
            unique.setdefault(group, set()).add(shard)
    assert len(got["fec_admitted"]) == 26
    for row in got["fec_admitted"]:
        assert row["packets"] == counts[row["group"]]
        assert row["unique"] == len(unique[row["group"]])
    assert data["rx_ids"] == data["consumed_ids"] == expected
    assert (
        data["received"] == len(expected)
        and not data["retired"]
        and not data["retired_capacity"]
    )
    assert not data["nacks"] and not data["repaired"]
    assert got["recovery_calls"] == data["datalost"] == len(transitions)
    assert [e["id"] for e in data["recovery_inputs"]] == transitions
    assert len(got["socket_sends"]) == len(got["outgoing_media"]) == len(transitions)
    for index, row in enumerate(got["socket_sends"]):
        assert (
            row["result"]
            and row["port"] == got["peer_socket"]["port"]
            and row["family"] == 0
        )
        assert row["wire"] == got["outgoing_media"][index]
        raw = large.recovery_wire(bytes.fromhex(row["wire"]), case["crc"])
        assert int.from_bytes(raw[7:9], "little") == index
    sdk_ids = [s["id"] for s in data["sdk"]]
    assert sdk_ids == sorted(set(sdk_ids)) and sdk_ids[-2:] == [124, 125]
    assert set(sdk_ids) <= set(expected)
    if transitions:
        assert not set(sdk_ids) & set(range(101, 106))
    assert data["pictures"][-1]["id"] == 125 and got["video"]["submits"] == len(sdk_ids)
    for row in data["sdk"]:
        assert row["size"] == 65536 and row["result"] == 0
        assert row["sha256"] == payloads[(row["id"] - 100) % 6]["sha256"]
    for row in data["pictures"]:
        assert row["id"] in sdk_ids and row["md5"] == md5[(row["id"] - 100) % 6]
    return dict(
        name=case["name"],
        received=len(expected),
        source_sdk=len(case["process"]["pictures"]),
        native_sdk=len(sdk_ids),
        datalost=len(transitions),
        native=got,
    )


def metadata(report):
    assert (
        report["client_sha256"]
        == "95482ca6120f90bb90798b27206b7946ab732e079f008d7fc90ea58a8b0074e1"
    )
    assert (
        report["codec_sha256"]
        == "c53a7e3d32a986323ec6bedd28df73a6e5842c4753b67b1d2aa0d6e4f524472f"
    )
    assert (
        report["util_sha256"]
        == "6df6556b6026144eb545dd95c0e2cc8c4568f462c9bd7e036531207d4172db34"
    )
    for file, sha in report["fixture_programs"].items():
        assert hashlib.sha256((ROOT / file).read_bytes()).hexdigest() == sha, file
    assert len(report["cases"]) == 10
    assert [
        {k: c[k] for k in p} for c, p in zip(report["cases"], stim.plans())
    ] == stim.plans()
    stim.bank_check(report["fec_encoder"])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", required=True, type=Path)
    p.add_argument(
        "--source-report",
        type=Path,
        default=ROOT
        / "scripts/fixtures/steam-client-fec-reorder-process-reference.json.gz",
    )
    p.add_argument("--output", type=Path)
    a = p.parse_args()
    raw = a.source_report.read_bytes()
    report = json.loads(gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw)
    metadata(report)
    results = []
    for case in report["cases"]:
        result = verify(a.receiver, case, report["fec_encoder"])
        results.append(result)
        print(
            json.dumps({k: v for k, v in result.items() if k != "native"}), flush=True
        )
    if a.output:
        a.output.write_text(json.dumps(results, indent=2) + "\n")
    print(
        "PASS: 10 original-client/Native UDP FEC cross-group schedules, bytes, recovery and pixels"
    )


if __name__ == "__main__":
    main()
