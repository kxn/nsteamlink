#!/usr/bin/env python3
"""Compare Native local microphone APIs and encrypted/UDP wire with CLIENT.

No microphone device, capture or encoder is substituted into the official app;
encoded bytes are API inputs. Only IDs/outer timestamps/mandatory Raw capability
are projected. FEC request does not imply own upstream FEC activation.
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


def payloads():
    return [
        bytes.fromhex("11223344"),
        bytes.fromhex("55667788"),
        bytes(i & 255 for i in range(4000)),
    ]


def event_channels(events):
    """Keep exact per-channel order; process clocks/quota phases differ."""
    assert len(events) == 12
    keys = ("control:", "data:3:", "data:4:", "data:5:")
    return [[event for event in events if event.startswith(key)] for key in keys]


def expected_wires(case):
    crc, reliable = case["crc"], case["reliable"]
    result = []
    frames = [
        (3, 0, payloads()[0]),
        (3, 1, payloads()[1]),
        (3, 2, payloads()[2]),
        (4, 0, bytes(range(4))),
        (5, 0, bytes(range(4))),
    ]
    next_id = {3: 0, 4: 0, 5: 0}
    for channel, frame, data in frames:
        body = bytes([1]) + struct.pack("<HIHI", frame, 0, 0, 0) + data
        pieces = [body[i : i + 1455] for i in range(0, len(body), 1455)]
        for i, piece in enumerate(pieces):
            kind = (5 if i == 0 else 6) if reliable else (3 if i == 0 else 4)
            result.append(
                struct.pack(
                    "<BBBBBhHI",
                    kind | (128 if crc else 0),
                    0,
                    0,
                    0,
                    channel,
                    len(pieces) - 1 if i == 0 else i - 1,
                    next_id[channel],
                    0,
                )
                + piece
            )
            next_id[channel] += 1
    return result


def verify_source(case):
    r = case["process"]
    assert r["exit_code"] == 0 and r["cleanup_complete"] and not r["source_assertions"]
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
    assert r["mic_priorities"] == [[3, 1], [3, 0], [4, 1], [5, 1], [5, 0]]
    expected = [
        ("before", 0, 0, 2),
        ("start", 3, 0, 3),
        ("send0", 3, 1, 3),
        ("send1", 3, 2, 3),
        ("send2", 3, 3, 3),
        ("before_local_stop", 3, 3, 3),
        ("stop", 0, 3, 4),
        ("after_stop_send", 0, 3, 4),
        ("restart", 4, 0, 5),
        ("restart_send", 4, 1, 5),
        ("replace", 5, 0, 6),
        ("replace_send", 5, 1, 6),
        ("final_stop", 0, 1, 7),
        ("duplicate_stop", 0, 1, 7),
    ]
    assert [
        (s["label"], s["channel"], s["sequence"], s["tx"]) for s in r["mic_states"]
    ] == expected
    assert all(s["phase"] == 6 and s["gate"] == 0 for s in r["mic_states"])
    for s in r["mic_states"]:
        assert s["rx"] in (
            (4, 5)
            if s["label"].startswith("send")
            else (4,)
            if s["label"] in ("before", "start")
            else (5,)
        )
    actual = [bytes.fromhex(w) for w in case["mic_initial_wires"]]
    assert event_channels(case["events"]) == event_channels(
        [
            "control:107:2",
            "data:3:0",
            "data:3:1",
            "data:3:2",
            "data:3:3",
            "data:3:4",
            "control:108:3",
            "control:107:4",
            "data:4:0",
            "control:107:5",
            "data:5:0",
            "control:108:6",
        ]
    )
    assert [normalize(w) for w in actual] == expected_wires(case)
    assert [len(w) for w in actual] == [
        n + (4 if case["crc"] else 0) for n in (30, 30, 1468, 1468, 1116, 30, 30)
    ]
    for wire in actual:
        sends = [e for e in r["mic_sends"] if e["wire"] == wire.hex()]
        assert (
            len(sends) == 1
            and sends[0]["return"] == len(wire)
            and sends[0]["phase"] == 6
        )
        assert any(p["data"] == wire.hex() for p in case["received"])
        assert sum(f["source_relative"] is not None for f in sends[0]["stack"]) >= 5
    assert [o["sequence"] for o in case["outputs"]] == list(range(7))
    assert [bytes.fromhex(o["plain"]) for o in case["outputs"]][2:] == [
        bytes.fromhex(x)
        for x in (
            "6b100318032880f7023002",
            "6c",
            "6b100418032880f7023002",
            "6b100518032880f7023002",
            "6c",
        )
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
                    ROOT
                    / "scripts/fixtures/steam-client-microphone-process-reference.json.gz"
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
    assert len(source["cases"]) == 8 and len(source["helpers"]) == 4
    assert len(source["source_functions"]) == 56
    assert {(c["crc"], c["reliable"], c["fec"]) for c in source["cases"]} == {
        (c, r, f) for c in (False, True) for r in (False, True) for f in (False, True)
    }
    for name, sha in source["helpers"].items():
        assert hashlib.sha256((ROOT / "scripts" / name).read_bytes()).hexdigest() == sha
    assert (
        source["runner_sha256"]
        == hashlib.sha256(
            (ROOT / "scripts/audit-steam-client-udp-process.py").read_bytes()
        ).hexdigest()
    )
    baseline = json.loads(
        gzip.decompress(
            (
                ROOT
                / "scripts/fixtures/steam-client-negotiation-process-reference.json.gz"
            ).read_bytes()
        )
    )
    assert {
        k: source["source_functions"][k] for k in baseline["source_functions"]
    } == baseline["source_functions"]
    for case in source["cases"]:
        verify_source(case)
        prior = next(
            c
            for c in baseline["cases"]
            if c["name"]
            == f"fec_c801{int(case['fec']):02x}_reliable{int(case['reliable'])}_crc{int(case['crc'])}"
        )
        assert (
            case["outputs"][:2] == prior["outputs"]
            and case["native_projection"][:2] == prior["native_projection"]
        )
        mapped = case["process"]["mapped_sdk"]
        assert set(mapped) == {"0", "10", "17"}
        for index, name, digest in (
            ("0", "libavcodec.so.61", source["codec_sha256"]),
            ("10", "libavcodec.so.61", source["codec_sha256"]),
            ("17", "libavutil.so.59", source["util_sha256"]),
        ):
            assert (
                Path(mapped[index]["path"]).name == name
                and mapped[index]["sha256"] == digest
            )
        for e in case["process"]["mic_sends"]:
            for frame in e["stack"]:
                pc = frame["source_relative"]
                if pc is not None:
                    assert any(
                        f["address"] <= pc - 1 < f["address"] + f["size"]
                        for f in source["source_functions"].values()
                    )
        with tempfile.TemporaryDirectory(prefix="native-udp-microphone-") as d:
            path = Path(d) / "streaming_settings.bin"
            path.write_bytes(bytes.fromhex(case["settings"]))
            result = subprocess.run(
                [
                    str(args.receiver.resolve()),
                    "--microphone",
                    str(int(case["crc"])),
                    d,
                    "080110031804" if case["reliable"] else "080010031804",
                    "0",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert result.returncode == 0, (
                case["name"],
                result.returncode,
                result.stderr[-4000:],
            )
            native = json.loads(result.stdout)
            assert path.read_bytes() == bytes.fromhex(case["settings"])
        expected = dict(
            phase=6,
            closed=False,
            mtu=1472,
            goodbyes=0,
            receive_sequence=5,
            send_sequence=7,
            frames=case["native_projection"],
        )
        assert {k: native[k] for k in expected} == expected, (
            case["name"],
            native,
            expected,
        )
        mic = native["microphone"]
        assert (mic["starts"], mic["stops"], mic["peer_messages"]) == (3, 3, 3)
        assert event_channels(mic["events"]) == event_channels(case["events"]), (
            case["name"],
            mic["events"],
            case["events"],
        )
        assert [normalize(bytes.fromhex(w)) for w in mic["wires"]] == expected_wires(
            case
        )
    print(
        "Native/original microphone UDP: 8 direction/CRC/reliability/FEC-request/restart/replacement cases passed"
    )


if __name__ == "__main__":
    main()
