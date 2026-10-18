#!/usr/bin/env python3
"""Compare actual UDP NACK-gated repair and SDK pixels with official CLIENT.

Controlled peer supplies a missing fragment only after receiving actual matching
feedback. This proves neither Steam host retry timing nor automatic FEC policy.
Only connection IDs/outer timestamp and mandatory Raw capability are projected.
"""

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
INITIAL_GAP_ASSERTION = dict(
    file="../../src/streaming/common/streamnetwork.cpp",
    line=1139,
    expression="STREAM_OLDER_PACKET_ID( m_ReliableState.m_nPendingAckID, nPendingAckID )",
    phase="probe",
)


def without_crc(raw):
    if raw[0] & 128:
        value = 0xFFFFFFFF
        for byte in raw[:-4]:
            value ^= byte
            for _ in range(8):
                value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
        assert struct.unpack("<I", raw[-4:])[0] == value ^ 0xFFFFFFFF
        return raw[:-4]
    return raw


def normalize(raw):
    value = bytearray(without_crc(raw))
    assert len(value) >= 13
    value[2:4] = bytes(2)
    value[9:13] = bytes(4)
    return bytes(value)


def expected_feedback(case):
    head = case["missing"] == 0
    return struct.pack(
        "<BBBBBhHI",
        (8 if case["reliable"] else 10) | (128 if case["crc"] else 0),
        0,
        0,
        0,
        3,
        0,
        1 if head else 2,
        0,
    ) + struct.pack("<IHB", 1000000, 65535 if head else 0, 3 if head else 1)


def verify_source(case, payload, golden):
    r = case["process"]
    expected_assertions = (
        [INITIAL_GAP_ASSERTION] if case["reliable"] and case["missing"] == 0 else []
    )
    assert r["exit_code"] == 0 and r["cleanup_complete"]
    assert r["source_assertions"] == expected_assertions
    assert r["media_final"] == dict(phase=6, decoder=0, rx=4, tx=3)
    assert r["settings_reads"] == [dict(loaded=True, bytes=case["settings"])]
    assert r["pictures"] and len(r["pictures"]) == 1
    assert {k: v for k, v in r["pictures"][0].items() if k != "timestamp"} == dict(
        id=23, shape=[128, 72, 0], md5=golden
    )
    events = r["media_events"]
    assert [(e["size"], e["sha256"]) for e in events if e["name"] == "sdk_send"] == [
        (len(payload), hashlib.sha256(payload).hexdigest())
    ]
    for name in ("sdk_send_return", "sdk_receive_return", "decoder_join"):
        assert [e["result"] for e in events if e["name"] == name] == [0]
    assert [
        (e["value"], e["phase"])
        for e in r["module_events"]
        if e["name"] == "module_force_return"
    ] == [(0, "original_exit")]
    assert r["module_refs"] == [0, 7]
    assert not {
        pid
        for pid, state in r["tasks_after_shutdown"].items()
        if state not in ("X", "Z")
    } - set(r["tasks_before"])
    assert any(e[0] == "join_completed" and e[2] == 0 for e in r["trace"])
    feedback = bytes.fromhex(case["repair_feedback"])
    assert normalize(feedback) == expected_feedback(case)
    assert any(item["data"] == feedback.hex() for item in case["received"])
    observed = [e for e in r["feedback_sends"] if e["wire"] == feedback.hex()]
    assert len(observed) == 1
    entry = observed[0]
    assert entry["return"] == len(feedback)
    assert (entry["phase"], entry["pictures"], entry["sdk_packets"]) == (6, 0, 0)
    assert entry["thread"] != 1
    assert sum(p["source_relative"] is not None for p in entry["stack"]) >= 8
    wires = [bytes.fromhex(item["data"]) for item in case["media_input"]]
    assert len(wires) == 3 and case["repair_sent_index"] >= 2
    assert [struct.unpack_from("<H", w, 7)[0] for w in wires] == case["order"]
    assert [w[1] for w in wires] == [0, 0, 1]
    for index, wire in zip(case["order"], wires, strict=True):
        wire = without_crc(wire)
        assert bool(wire[0] & 128) == case["crc"] and wire[4] == 3
        assert wire[0] & 127 == (
            (5 if index == 0 else 6) if case["reliable"] else (3 if index == 0 else 4)
        )
        assert struct.unpack_from("<h", wire, 5)[0] == (2 if index == 0 else index - 1)
    body = b"".join(without_crc(wires[case["order"].index(i)])[13:] for i in range(3))
    expected_body = (
        bytes([1])
        + struct.pack("<HIHI", 23, 1000000, 0, 0)
        + struct.pack("<HBHH", 0, 24, 0, 0)
        + payload
    )
    assert body == expected_body
    withheld = bytearray(without_crc(wires[-1]))
    withheld[0] &= 127
    withheld[1] = 0
    assert case["withheld"] == withheld.hex()
    assert case["sent"][case["repair_sent_index"]] == case["media_input"][-1]
    assert (
        sum(
            without_crc(bytes.fromhex(p["data"]))[4] == 3
            for p in case["sent"][: case["repair_sent_index"]]
        )
        == 2
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    p.add_argument("--source-report", type=Path)
    args = p.parse_args()
    report = (
        json.loads(args.source_report.read_text())
        if args.source_report
        else json.loads(
            gzip.decompress(
                (
                    ROOT
                    / "scripts/fixtures/steam-client-retry-process-reference.json.gz"
                ).read_bytes()
            )
        )
    )
    assert (
        report["client_sha256"]
        == "95482ca6120f90bb90798b27206b7946ab732e079f008d7fc90ea58a8b0074e1"
    )
    codec_sha = "c53a7e3d32a986323ec6bedd28df73a6e5842c4753b67b1d2aa0d6e4f524472f"
    util_sha = "6df6556b6026144eb545dd95c0e2cc8c4568f462c9bd7e036531207d4172db34"
    assert report["codec_sha256"] == codec_sha and report["util_sha256"] == util_sha
    assert len(report["cases"]) == 8 and len(report["helpers"]) == 5
    for name, digest in report["helpers"].items():
        assert (
            digest == hashlib.sha256((ROOT / "scripts" / name).read_bytes()).hexdigest()
        )
    previous = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-client-media-process-reference.json.gz"
            ).read_bytes()
        )
    )
    functions = report["source_functions"]
    assert len(functions) == 59
    assert {k: functions[k] for k in previous["source_functions"]} == previous[
        "source_functions"
    ]
    assert {
        v["address"] for k, v in functions.items() if k.startswith("feedback_caller_")
    } == {
        0x1A39D0,
        0x1A0190,
        0x19C010,
        0x19D100,
        0x19D170,
        0x1A0760,
        0x1A1020,
        0x1A47B0,
        0x1A9990,
        0x19C960,
    }
    payload = (ROOT / "app/tests/fixtures/video/sequential.h264").read_bytes()[:2204]
    golden = (
        (ROOT / "app/tests/fixtures/video/sequential.framemd5")
        .read_text()
        .splitlines()[10]
        .split(",")[-1]
        .strip()
    )
    assert report["fixture_sha256"] == hashlib.sha256(payload).hexdigest()
    assert report["pixel_md5"] == golden
    assert {(c["reliable"], c["crc"], c["missing"]) for c in report["cases"]} == {
        (r, c, m) for r in (False, True) for c in (False, True) for m in (0, 1)
    }
    for case in report["cases"]:
        verify_source(case, payload, golden)
        mapped = case["process"]["mapped_sdk"]
        assert set(mapped) == {"0", "10", "17"}
        for index, name, sha in (
            ("0", "libavcodec.so.61", codec_sha),
            ("10", "libavcodec.so.61", codec_sha),
            ("17", "libavutil.so.59", util_sha),
        ):
            assert (
                Path(mapped[index]["path"]).name == name
                and mapped[index]["sha256"] == sha
            )
        for entry in case["process"]["feedback_sends"]:
            for frame in entry["stack"]:
                pc = frame["source_relative"]
                if pc is not None:
                    assert any(
                        f["address"] <= pc - 1 < f["address"] + f["size"]
                        for f in report["source_functions"].values()
                    )
        with tempfile.TemporaryDirectory(prefix="native-udp-retry-") as d:
            directory = Path(d)
            settings = directory / "streaming_settings.bin"
            settings.write_bytes(bytes.fromhex(case["settings"]))
            wires = [bytes.fromhex(item["data"]) for item in case["media_input"]]

            def record(wire):
                return struct.pack("<I", len(wire)) + wire

            media = directory / "media.bin"
            media.write_bytes(
                b"".join(record(w) for w in wires[:2])
                + bytes(4)
                + record(normalize(bytes.fromhex(case["repair_feedback"])))
                + record(wires[2])
            )
            result = subprocess.run(
                [
                    str(args.receiver.resolve()),
                    "--recover",
                    str(int(case["crc"])),
                    d,
                    "080110031804" if case["reliable"] else "080010031804",
                    "0",
                    str(media),
                ],
                text=True,
                capture_output=True,
                timeout=10,
            )
            assert result.returncode == 0, (
                case["name"],
                result.returncode,
                result.stderr[-3000:],
            )
            native = json.loads(result.stdout)
            assert settings.read_bytes() == bytes.fromhex(case["settings"])
        expected = dict(
            phase=6,
            closed=False,
            mtu=1472,
            goodbyes=0,
            receive_sequence=4,
            send_sequence=3,
            frames=case["native_projection"],
            sdk_packets_before_repair=0,
            video=dict(
                id=23,
                shape=[128, 72, 0],
                md5=golden,
                sdk_size=len(payload),
                sdk_sha256=report["fixture_sha256"],
                starts=1,
                submits=1,
                stopped=True,
            ),
        )
        assert {k: native[k] for k in expected} == expected, (
            case["name"],
            native,
            expected,
        )
        assert normalize(bytes.fromhex(native["repair_feedback"])) == expected_feedback(
            case
        )
    print(
        "Native/original real UDP repair: 8 NACK-gated fragment/SDK/pixel/Stop cases passed; 2 exact original release diagnostics preserved"
    )


if __name__ == "__main__":
    main()
