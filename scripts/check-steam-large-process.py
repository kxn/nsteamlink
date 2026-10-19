#!/usr/bin/env python3
"""Real UDP no-parity large groups, with kernel loss separated from FEC loss.

Paced cases require complete delivery. Burst cases retain actual per-socket
drops and parsed unique-shard counts; every complete admitted group must reach
the decoder. The final key/P tail has declared pacing, not a fabricated result.
"""

import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


large = module("large", "media-large-stimuli.py")
common = module("pressure", "check-steam-pressure-process.py")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def recovery_wire(wire, crc):
    assert len(wire) == 14 + 4 * int(crc)
    assert bool(wire[0] & 128) == crc
    if crc:
        value = 0xFFFFFFFF
        for byte in wire[:-4]:
            value ^= byte
            for _ in range(8):
                value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
        assert int.from_bytes(wire[-4:], "little") == (value ^ 0xFFFFFFFF)
    raw = common.plain(wire)
    assert raw[0] & 127 == 3 and raw[1] == 0 and raw[4:7] == bytes((3, 0, 0))
    assert raw[13:] == b"\x02"
    return raw


def verify_source(case):
    expected, payloads, md5 = common.verify_source(
        case, large.payloads(), allow_missing=case["burst"]
    )
    r = case["process"]
    assert r["large_ready"] == dict(active=1, phase=6)
    assert r["media_final"]["decoder"] == 0 and r["media_final"]["phase"] == 6
    assert len(r["large_derived_sha256"]) == 2
    assert [
        (v["value"], v["phase"])
        for v in r["module_events"]
        if v["name"].startswith("module_force")
    ] == [(7, "original_exit"), (0, "original_exit")]
    assert not {
        p for p, state in r["tasks_after_shutdown"].items() if state not in ("X", "Z")
    } - set(r["tasks_before"])
    drops = r["large_socket"]["drops"]
    if case["burst"]:
        assert len(expected - set(r["load_frames"])) <= drops
    else:
        assert drops == 0 and set(r["load_frames"]) == expected
    feedback = [bytes.fromhex(p["data"]) for p in case["received"]]
    feedback = [wire for wire in feedback if wire[4] == 3]
    for wire in feedback:
        recovery_wire(wire, case["crc"])
    if case["profile"] == "fec_drop":
        assert feedback
    elif not case["burst"]:
        assert not feedback
    assert len(case["producer_times"]) == 26 and case["producer_times"][-1] >= 5
    return expected, payloads, md5


def verify(receiver, case, bank):
    expected, payloads, md5 = verify_source(case)
    initial = [[bytes.fromhex(w) for w in group] for group in case["initial"]]
    wanted = large.frames(case, bank)
    for group, want in zip(initial, wanted):
        assert len(group) == len(want)
        for wire, canonical in zip(group, want):
            assert bool(wire[0] & 128) == case["crc"]
            raw = bytearray(common.plain(wire))
            raw[0] &= 127
            assert bytes(raw) == canonical
    with tempfile.TemporaryDirectory(prefix="native-large-fec-") as td:
        folder = Path(td)
        (folder / "streaming_settings.bin").write_bytes(bytes.fromhex(case["settings"]))
        media = folder / "media.bin"
        media.write_bytes(
            b"".join(
                b"".join(struct.pack("<I", len(w)) + w for w in group) + bytes(4)
                for group in initial
            )
        )
        process = subprocess.run(
            [
                str(receiver.resolve()),
                "--pressure-ready",
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
                str(case["spacing_us"]),
                str(case["tail_spacing_us"]),
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
    # These peers ACK actual reliable control receipts. Verify the peer itself
    # lost no datagrams before using its feedback count as receiver evidence.
    assert got["peer_socket"]["drops"] == 0
    sent = got["socket_sends"]
    assert [r["wire"] for r in sent] == got["outgoing_media"]
    assert got["recovery_calls"] == data["datalost"] == len(sent)
    for index, row in enumerate(sent):
        assert row["result"] and row["port"] == got["peer_socket"]["port"]
        assert row["family"] == 0
        wire = bytes.fromhex(row["wire"])
        raw = recovery_wire(wire, case["crc"])
        assert (
            raw[0] & 127 == 3
            and raw[1] == 0
            and raw[2]
            and raw[3:7] == bytes((7, 3, 0, 0))
        )
        assert int.from_bytes(raw[7:9], "little") == index and raw[13:] == b"\x02"
    admitted = got["fec_admitted"]
    assert len(admitted) == 26 and [r["group"] for r in admitted] == list(range(1, 27))
    assert all(
        r["packets"] == r["unique"] and 0 <= r["unique"] <= len(wires)
        for r, wires in zip(admitted, initial)
    )
    complete = [99 + row["group"] for row in admitted if row["unique"] == large.SHARDS]
    missing = sum(len(wires) - row["unique"] for row, wires in zip(admitted, initial))
    drops = got["udp_socket"]["drops"]
    assert isinstance(drops, int) and 0 <= missing <= drops
    if not case["burst"]:
        assert drops == missing == 0 and complete == sorted(expected)
    assert data["rx_ids"] == data["consumed_ids"] == complete
    assert (
        data["received"] == len(complete)
        and not data["retired"]
        and not data["retired_capacity"]
    )
    assert not data["nacks"] and not data["repaired"]
    if case["profile"] == "fec_drop":
        assert 101 not in complete and data["datalost"] > 0
    elif not case["burst"]:
        assert not data["datalost"]
    assert got["phase"] == 6 and not got["closed"] and got["video"]["stopped"]
    sdk, pictures = data["sdk"], data["pictures"]
    ids = [r["id"] for r in sdk]
    assert ids == sorted(set(ids)) and set(ids) <= set(complete)
    assert ids[-2:] == [124, 125] and pictures[-1]["id"] == 125
    assert got["video"]["submits"] == len(sdk)
    for row in sdk:
        assert row["size"] == large.SIZE and row["result"] == 0
        assert row["sha256"] == payloads[(row["id"] - 100) % 6]["sha256"]
    for row in pictures:
        assert row["id"] in ids and row["md5"] == md5[(row["id"] - 100) % 6]
    return dict(
        name=case["name"],
        received=len(complete),
        sdk=len(sdk),
        socket_drops=drops,
        missing_admitted=missing,
        datalost=data["datalost"],
        native=got,
    )


def verify_metadata(report):
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
    assert len(report["source_functions"]) == 53
    for path, sha in report["fixture_programs"].items():
        assert digest(ROOT / path) == sha, path
    assert report["payloads"] == large.payloads()
    bank = report["fec_encoder"]
    assert (
        bank["binary_sha256"]
        == "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"
    )
    assert (bank["k"], bank["m"], bank["shard"], bank["percentage"], bank["mtu"]) == (
        337,
        0,
        1168,
        5,
        1200,
    )
    for key, file in (
        ("generator_sha256", "audit-steam-large-fec-encode.py"),
        ("helper_sha256", "audit-steam-fec.py"),
        ("recovery_helper_sha256", "audit-steam-video-recovery.py"),
        ("stimulus_sha256", "media-large-stimuli.py"),
    ):
        assert bank[key] == digest(ROOT / "scripts" / file)
    assert len(bank["groups"]) == 26
    for index, group in enumerate(bank["groups"]):
        assert (
            group["index"] == index
            and len(group["wires"]) == 337
            and not group["coding_calls"]
        )
        assert group["body_sha256"] == hashlib.sha256(large.body(index)).hexdigest()
    assert [
        {k: c[k] for k in plan} for c, plan in zip(report["cases"], large.plans())
    ] == large.plans()
    assert len(report["cases"]) == 6


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", required=True, type=Path)
    parser.add_argument(
        "--source-report",
        type=Path,
        default=ROOT / "scripts/fixtures/steam-client-large-process-reference.json.gz",
    )
    parser.add_argument("--burst", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    raw = args.source_report.read_bytes()
    report = json.loads(
        gzip.decompress(raw) if args.source_report.suffix == ".gz" else raw
    )
    verify_metadata(report)
    results = []
    for case in report["cases"]:
        if case["burst"] != args.burst:
            continue
        result = verify(args.receiver, case, report["fec_encoder"])
        results.append(result)
        print(
            json.dumps({k: v for k, v in result.items() if k != "native"}), flush=True
        )
    assert len(results) == (2 if args.burst else 4)
    if args.output:
        args.output.write_text(json.dumps(results, indent=2) + "\n")
    print("Large no-parity actual UDP:", len(results), "processes verified")


if __name__ == "__main__":
    main()
