#!/usr/bin/env python3
"""Actual Native UDP unrepaired-gap/strict/key/P recovery vs official CLIENT.

Explicit pixel/feedback barriers only schedule controlled peer input and Stop.
Reliable observation is bounded; no host timeout/FEC/physical-renderer claim.
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
SPEC = importlib.util.spec_from_file_location(
    "retry", ROOT / "scripts/check-steam-retry-process.py"
)
retry = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(retry)
normalize, without_crc = retry.normalize, retry.without_crc


def expected_feedback(case):
    if case["reliable"]:
        kind, packet_id, body = 8, 4, struct.pack("<IHB", 1040000, 2, 15)
    else:
        kind, packet_id, body = 3, 0, b"\x02"
    return (
        struct.pack(
            "<BBBBBhHI", kind | (128 if case["crc"] else 0), 0, 0, 0, 3, 0, packet_id, 0
        )
        + body
    )


def expected_pictures(reliable):
    rows = (
        (ROOT / "app/tests/fixtures/video/sequential.framemd5").read_text().splitlines()
    )
    return [
        dict(id=fid, md5=rows[10 + au].split(",")[-1].strip())
        for fid, au in ([(23, 0)] if reliable else [(23, 0), (29, 6), (30, 7)])
    ]


def expected_inputs(reliable):
    data = (ROOT / "app/tests/fixtures/video/sequential.h264").read_bytes()
    return [
        dict(size=size, sha256=hashlib.sha256(data[start : start + size]).hexdigest())
        for start, size in (
            [(0, 2204)] if reliable else [(0, 2204), (4552, 1953), (6505, 501)]
        )
    ]


def state(strict, sequence):
    return dict(strict=strict, soft=0, sequence=sequence)


def verify_source(case):
    r = case["process"]
    reliable = case["reliable"]
    count = 1 if reliable else 3
    assert r["exit_code"] == 0 and r["cleanup_complete"] and not r["source_assertions"]
    assert r["media_final"] == dict(phase=6, decoder=0, rx=4, tx=3)
    assert r["settings_reads"] == [dict(loaded=True, bytes=case["settings"])]
    assert [dict(id=p["id"], md5=p["md5"]) for p in r["pictures"]] == expected_pictures(
        reliable
    )
    assert all(p["shape"] == [128, 72, 0] for p in r["pictures"])
    events = r["media_events"]
    assert [
        dict(size=e["size"], sha256=e["sha256"])
        for e in events
        if e["name"] == "sdk_send"
    ] == expected_inputs(reliable)
    for name in ("sdk_send_return", "sdk_receive_return"):
        assert [e["result"] for e in events if e["name"] == name] == [0] * count
    for name in (
        "start_video",
        "stop_video",
        "decoder_ctor",
        "decoder_dtor",
        "decoder_join",
    ):
        assert sum(e["name"] == name for e in events) == 1
    assert [e["result"] for e in events if e["name"] == "decoder_join"] == [0]
    assert [
        (e["value"], e["phase"])
        for e in r["module_events"]
        if e["name"].startswith("module_force")
    ] == [(7, "original_exit"), (0, "original_exit")]
    assert r["module_refs"] == [0, 7]
    assert any(e[0] == "join_completed" and e[2] == 0 for e in r["trace"])
    assert not {
        pid
        for pid, value in r["tasks_after_shutdown"].items()
        if value not in ("X", "Z")
    } - set(r["tasks_before"])
    expected_states = [dict(id=23, before=state(0, 0), after=state(0, 1))]
    if not reliable:
        expected_states += [
            dict(id=26, before=state(0, 1), after=state(1, 4)),
            dict(id=29, before=state(1, 4), after=state(0, 5)),
            dict(id=30, before=state(0, 5), after=state(0, 6)),
        ]
    assert r["gap_states"] == expected_states
    assert r["gap_before_stop"] == dict(
        pictures=count,
        sdk_packets=count,
        state=state(0, 1 if reliable else 6),
        after_feedback_updates=30 if reliable else 0,
    )
    raw = bytes.fromhex(case["gap_feedback"])
    assert normalize(raw) == expected_feedback(case)
    assert any(p["data"] == raw.hex() for p in case["received"])
    observations = [e for e in r["gap_sends"] if e["wire"] == raw.hex()]
    assert len(observations) == 1
    observed = observations[0]
    assert (
        observed["phase"],
        observed["pictures"],
        observed["sdk_packets"],
        observed["return"],
    ) == (6, 1, 1, len(raw))
    assert observed["thread"] != 1
    assert sum(f["source_relative"] is not None for f in observed["stack"]) >= 6
    wires = [without_crc(bytes.fromhex(p["data"])) for p in case["media_input"]]
    ids = [struct.unpack_from("<H", w, 7)[0] for w in wires]
    assert ids == ([0, 1, 2, 4, 5, 6, 7] if reliable else [0, 1, 2, 4, 5, 6, 7, 8])
    assert all(
        w[1] == 0 and w[4] == 3 and bool(w[0] & 128) == case["crc"] for w in wires
    )
    assert [struct.unpack_from("<I", w, 9)[0] for w in wires] == [
        1000000,
        1000000,
        1005000,
        1010000,
        1030000,
        1040000,
        1040000,
    ] + ([] if reliable else [1040100])
    assert [w[0] & 127 for w in wires] == (
        [5, 6, 5, 5, 5, 5, 6] if reliable else [3, 4, 3, 3, 3, 3, 4, 3]
    )
    assert [struct.unpack_from("<h", w, 5)[0] for w in wires] == (
        [1, 0, 1, 0, 0, 1, 0] + ([] if reliable else [0])
    )
    video = (ROOT / "app/tests/fixtures/video/sequential.h264").read_bytes()

    def body(fid, seq, timestamp, start, size, flags):
        return (
            bytes([1])
            + struct.pack("<HIHI", fid, timestamp, 0, 0)
            + struct.pack("<HBHH", seq, flags, 0, 0)
            + video[start : start + size]
        )

    assert wires[0][13:] + wires[1][13:] == body(23, 0, 1000000, 0, 2204, 24)
    assert wires[2][13:] + bytes.fromhex(case["withheld_tail"]) == body(
        24, 1, 1005000, 2204, 411, 8
    )
    assert wires[3][13:] == body(25, 2, 1010000, 2615, 425, 8)
    assert wires[4][13:] == body(26, 3, 1030000, 3040, 486, 8)
    assert wires[5][13:] + wires[6][13:] == body(29, 4, 1040000, 4552, 1953, 24)
    if not reliable:
        assert wires[7][13:] == body(30, 5, 1040100, 6505, 501, 8)
        assert case["sent"][case["post_key_sent_index"]] == case["media_input"][7]
    assert case["sent"][case["fault_sent_index"]] == case["media_input"][2]
    assert case["sent"][case["key_sent_index"]] == case["media_input"][5]
    callbacks = [
        e
        for e in events
        if e["name"] == "packet_callback"
        and "body_prefix" in e
        and int.from_bytes(bytes.fromhex(e["body_prefix"])[1:3], "little") != 23
    ]
    assert [
        struct.unpack_from("<H", bytes.fromhex(e["packet_header"]), 7)[0]
        for e in callbacks
    ] == ([] if reliable else [5, 6, 8])
    expected_bodies = (
        []
        if reliable
        else [wires[4][13:], wires[5][13:] + wires[6][13:], wires[7][13:]]
    )
    assert [e["body_sha256"] for e in callbacks] == [
        hashlib.sha256(b).hexdigest() for b in expected_bodies
    ]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    p.add_argument("--source-report", type=Path)
    args = p.parse_args()
    source = (
        json.loads(args.source_report.read_text())
        if args.source_report
        else json.loads(
            gzip.decompress(
                (
                    ROOT / "scripts/fixtures/steam-client-gap-process-reference.json.gz"
                ).read_bytes()
            )
        )
    )
    assert (
        source["client_sha256"]
        == "95482ca6120f90bb90798b27206b7946ab732e079f008d7fc90ea58a8b0074e1"
    )
    assert (
        source["codec_sha256"]
        == "c53a7e3d32a986323ec6bedd28df73a6e5842c4753b67b1d2aa0d6e4f524472f"
    )
    assert (
        source["util_sha256"]
        == "6df6556b6026144eb545dd95c0e2cc8c4568f462c9bd7e036531207d4172db34"
    )
    assert len(source["cases"]) == 4 and len(source["helpers"]) == 5
    assert {(c["reliable"], c["crc"]) for c in source["cases"]} == {
        (r, c) for r in (False, True) for c in (False, True)
    }
    for name, digest in source["helpers"].items():
        assert (
            digest == hashlib.sha256((ROOT / "scripts" / name).read_bytes()).hexdigest()
        )
    assert (
        source["runner_sha256"]
        == hashlib.sha256(
            (ROOT / "scripts/audit-steam-client-udp-process.py").read_bytes()
        ).hexdigest()
    )
    assert (
        source["fixture_sha256"]
        == hashlib.sha256(
            (ROOT / "app/tests/fixtures/video/sequential.h264").read_bytes()
        ).hexdigest()
    )
    baseline = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-client-media-process-reference.json.gz"
            ).read_bytes()
        )
    )
    assert {
        k: source["source_functions"][k] for k in baseline["source_functions"]
    } == baseline["source_functions"]
    assert len(source["source_functions"]) == 65
    assert source["source_functions"]["decode_frame"]["address"] == 0x3260D0
    boundaries = source["au_boundaries"]
    assert [(int(p["pos"]), int(p["size"])) for p in boundaries[:8]] == [
        (0, 2204),
        (2204, 411),
        (2615, 425),
        (3040, 486),
        (3526, 461),
        (3987, 565),
        (4552, 1953),
        (6505, 501),
    ]
    assert [i for i, p in enumerate(boundaries) if p["flags"].startswith("K")] == [0, 6]
    for case in source["cases"]:
        verify_source(case)
        old = next(
            c
            for c in baseline["cases"]
            if c["name"]
            == f"ordinary_reliable{int(case['reliable'])}_crc{int(case['crc'])}_reverse0"
        )
        assert (
            case["outputs"] == old["outputs"]
            and case["native_projection"] == old["native_projection"]
        )
        mapped = case["process"]["mapped_sdk"]
        assert set(mapped) == {"0", "10", "17"}
        for index, name, sha in (
            ("0", "libavcodec.so.61", source["codec_sha256"]),
            ("10", "libavcodec.so.61", source["codec_sha256"]),
            ("17", "libavutil.so.59", source["util_sha256"]),
        ):
            assert (
                Path(mapped[index]["path"]).name == name
                and mapped[index]["sha256"] == sha
            )
        for event in case["process"]["gap_sends"]:
            for frame in event["stack"]:
                pc = frame["source_relative"]
                if pc is not None:
                    assert any(
                        f["address"] <= pc - 1 < f["address"] + f["size"]
                        for f in source["source_functions"].values()
                    )
        with tempfile.TemporaryDirectory(prefix="native-udp-gap-") as d:
            directory = Path(d)
            settings = directory / "streaming_settings.bin"
            settings.write_bytes(bytes.fromhex(case["settings"]))
            wires = [bytes.fromhex(p["data"]) for p in case["media_input"]]

            def record(wire):
                return struct.pack("<I", len(wire)) + wire

            if case["reliable"]:
                staged = [wires[:2], wires[2:]]
            else:
                staged = [wires[:2], wires[2:5], wires[5:7], wires[7:]]
            payload = bytes(4).join(
                b"".join(record(w) for w in stage) for stage in staged
            )
            media = directory / "media.bin"
            media.write_bytes(payload)
            result = subprocess.run(
                [
                    str(args.receiver.resolve()),
                    "--gap",
                    str(int(case["crc"])),
                    d,
                    "080110031804" if case["reliable"] else "080010031804",
                    "0",
                    str(media),
                    expected_feedback(case).hex(),
                ],
                text=True,
                capture_output=True,
                timeout=10,
            )
            assert result.returncode == 0, (
                case["name"],
                result.returncode,
                result.stderr[-4000:],
            )
            native = json.loads(result.stdout)
            assert settings.read_bytes() == bytes.fromhex(case["settings"])
        pictures, inputs = (
            expected_pictures(case["reliable"]),
            expected_inputs(case["reliable"]),
        )
        expected = dict(
            phase=6,
            closed=False,
            mtu=1472,
            goodbyes=0,
            receive_sequence=4,
            send_sequence=3,
            frames=case["native_projection"],
            pictures=pictures,
            sdk_inputs=inputs,
            sdk_packets_before_feedback=1,
            video=dict(
                id=pictures[-1]["id"],
                shape=[128, 72, 0],
                md5=pictures[-1]["md5"],
                sdk_size=inputs[-1]["size"],
                sdk_sha256=inputs[-1]["sha256"],
                starts=1,
                submits=len(inputs),
                stopped=True,
            ),
        )
        assert {k: native[k] for k in expected} == expected, (
            case["name"],
            native,
            expected,
        )
        assert normalize(bytes.fromhex(native["gap_feedback"])) == expected_feedback(
            case
        )
    print(
        "Native/original UDP unrepaired gap: 4 bounded reliable-block/strict-wait/key/P-pixel/Stop cases passed"
    )


if __name__ == "__main__":
    main()
