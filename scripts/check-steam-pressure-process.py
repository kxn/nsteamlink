#!/usr/bin/env python3
"""Actual Native large-AU RX/queue/NACK/FEC/SDK/pixels against original evidence.

Compare all bytes actually decoded and final key/P recovery. Natural schedules,
NACK counts and bounded FIFO retirement may differ; retained body accounting is
checked independently. Original RS codewords come only from the pinned encoder.
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
spec = importlib.util.spec_from_file_location(
    "stim", ROOT / "scripts/media-pressure-stimuli.py"
)
stim = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stim)


def plain(wire):
    return wire[:-4] if wire[0] & 128 else wire


def verify_flow(report):
    """Check observed worker order without predicting its natural schedule."""
    consumed, inputs, sdk_ids = 0, [], []
    in_input, in_think, sdk_in_think = False, False, 0
    for event in report["pressure_flow"]:
        kind = event["kind"]
        if kind == "input":
            assert not in_input and not in_think
            consumed += 1
            inputs.append(event["id"])
            in_input = True
        elif kind == "input_return":
            assert in_input and not in_think
            in_input = False
        elif kind == "think":
            assert not in_input and not in_think and event["target"] == 0x326F30
            in_think, sdk_in_think = True, 0
        elif kind == "sdk":
            assert in_think and not in_input and not sdk_in_think
            sdk_in_think += 1
            picture_id = report["pictures"][len(sdk_ids)]["id"]
            assert picture_id in inputs
            sdk_ids.append(picture_id)
        else:
            assert kind == "think_return" and in_think and not in_input
            assert event["timeout"] in (0, 1, 0xFFFFFFFF)
            in_think = False
        assert event["consumed"] == consumed
        assert event["strict"] in (0, 1) and event["soft"] in (0, 1)
    assert not in_input and not in_think
    assert inputs == report["load_frames"]
    assert sdk_ids == [p["id"] for p in report["pictures"]]


def verify_source(case):
    r = case["process"]
    verify_flow(r)
    count = case["frames"]
    last = 100 + count - 1
    ids = r["load_frames"]
    expected = set(range(100, last + 1))
    assert r["exit_code"] == 0 and r["cleanup_complete"] and not r["source_assertions"]
    assert (
        r["load_table_restored"]
        and r["load_adapter_closed"]
        and r["load_receive_count"] == len(ids)
    )
    if case["profile"] in ("drop", "fec_drop"):
        expected.remove(101)
    assert ids == sorted(set(ids)) and ids[-2:] == [last - 1, last]
    if case["profile"] == "drop":
        assert set(ids) <= expected
    else:
        assert set(ids) == expected
    if case["profile"] == "repair":
        assert case.get("repaired") and stim.requested(
            plain(bytes.fromhex(case["repair_feedback"])), case["hole_pid"]
        )
    if case["profile"].startswith("fec_"):
        assert not case["feedback"]
    if case["profile"] in ("repair", "drop"):
        assert case["feedback"]
    pixels = r["pictures"]
    assert [p["id"] for p in pixels[-2:]] == [last - 1, last]
    assert r["load_adapter_final"] == [
        0,
        len(pixels),
        len(pixels),
        case["delay_us"] * len(pixels),
    ]
    md5 = [
        line.split(",")[-1].strip()
        for line in (ROOT / "app/tests/fixtures/video/sequential.framemd5")
        .read_text()
        .splitlines()
        if not line.startswith("#")
    ]
    payloads = stim.payloads()
    sdk = [e for e in r["media_events"] if e["name"] == "sdk_send"]
    assert len(sdk) == len(pixels)
    for e, p in zip(sdk, pixels):
        assert (
            e["size"] == 65536
            and e["sha256"] == payloads[(p["id"] - 100) % 6]["sha256"]
            and p["md5"] == md5[(p["id"] - 100) % 6]
        )
    for name in ("sdk_send_return", "sdk_receive_return"):
        assert [e["result"] for e in r["media_events"] if e["name"] == name] == [
            0
        ] * len(pixels)
    assert [e["result"] for e in r["media_events"] if e["name"] == "decoder_join"] == [
        0
    ]
    return expected, payloads, md5


def verify_plan(case, bank):
    initial = [[bytes.fromhex(w) for w in group] for group in case["initial"]]
    assert len(initial) == case["frames"]
    for index, group in enumerate(initial):
        if case["profile"].startswith("fec_"):
            expected = set(range(60)) - stim.erasures(case["profile"], index)
            assert {struct.unpack_from("<H", w, 5)[0] for w in group} == expected
            assert all(
                w[0] & 127 == 11
                and struct.unpack_from("<H", w, 7)[0] == index + 1
                and struct.unpack_from("<IHH", w, 13) == (65556, 1168, 3)
                for w in group
            )
            for wire in group:
                shard_index = struct.unpack_from("<H", wire, 5)[0]
                want = bytearray.fromhex(bank["groups"][index]["wires"][shard_index])
                want[2:4] = bytes([7, 0])
                struct.pack_into("<I", want, 9, 1000000 + index * 1092)
                got = bytearray(plain(wire))
                got[0] &= 127
                assert got == want
        else:
            raw = stim.ordinary(index)
            assert len(group) == len(raw) == 55
            for wire, want in zip(group, raw):
                got = bytearray(plain(wire))
                got[0] &= 127
                assert bytes(got) == want
        assert all(
            bool(w[0] & 128) == case["crc"] and w[2:5] == bytes([7, 0, 3])
            for w in group
        )
    return initial


def verify(receiver, case, bank):
    expected, payloads, md5 = verify_source(case)
    initial = verify_plan(case, bank)
    count = case["frames"]
    last = 100 + count - 1
    with tempfile.TemporaryDirectory(prefix="native-byte-pressure-") as d:
        directory = Path(d)
        (directory / "streaming_settings.bin").write_bytes(
            bytes.fromhex(case["settings"])
        )
        media = directory / "media.bin"
        media.write_bytes(
            b"".join(
                b"".join(struct.pack("<I", len(w)) + w for w in group) + bytes(4)
                for group in initial
            )
        )
        completed = subprocess.run(
            [
                str(receiver.resolve()),
                "--pressure",
                str(int(case["crc"])),
                d,
                "080010031804",
                "0",
                str(media),
                str(case["delay_us"]),
                str(count),
                str(case["rate"]),
                case["profile"],
                str(case["hole_pid"]),
            ],
            capture_output=True,
            text=True,
            timeout=25,
        )
        assert completed.returncode == 0, (
            case["name"],
            completed.returncode,
            completed.stderr[-4000:],
        )
        got = json.loads(completed.stdout)
    load = got["load"]
    rx = load["rx_ids"]
    consumed = load["consumed_ids"]
    sdk = load["sdk"]
    pictures = load["pictures"]
    assert (
        got["phase"] == 6
        and not got["closed"]
        and got["video"]["stopped"]
        and got["video"]["starts"] == 1
    )
    assert (
        load["received"] == len(rx)
        and rx == sorted(set(rx))
        and consumed == sorted(set(consumed))
    )
    if case["profile"] == "drop":
        assert set(rx) <= expected
    else:
        assert set(rx) == expected, (case["name"], "actual complete RX", rx)
    assert set(consumed) <= set(rx) and len(consumed) + load["retired"] == len(rx)
    assert [s["id"] for s in sdk[-2:]] == [last - 1, last] and pictures[-1][
        "id"
    ] == last
    ids = [s["id"] for s in sdk]
    assert ids == sorted(set(ids)) and set(ids) <= set(consumed)
    assert got["video"]["submits"] == len(sdk)
    for s in sdk:
        assert (
            s["size"] == 65536
            and s["result"] == 0
            and s["sha256"] == payloads[(s["id"] - 100) % 6]["sha256"]
        )
        assert (
            s["elapsed_ns"] >= case["delay_us"] * 1000
            and s["queued_bytes"] <= 4194304
            and s["consumed"] <= len(consumed)
        )
    for picture in pictures:
        assert picture["id"] in ids and picture["md5"] == md5[(picture["id"] - 100) % 6]
    if case["profile"] == "capacity":
        assert (
            load["retired"] > 0
            and load["retired_capacity"] > 4194304
            and load["received_while_sdk"] > 0
        )
        assert max(s["queued_bytes"] for s in sdk) > 3000000
    else:
        assert not load["retired"] and not load["retired_capacity"]
    if case["profile"] == "repair":
        assert load["repaired"] and any(
            stim.requested(plain(bytes.fromhex(w)), case["hole_pid"])
            for w in load["feedback"]
        )
        assert not load["datalost"]
    elif case["profile"] == "drop":
        assert not load["repaired"] and load["nacks"] > 0
    elif case["profile"] == "fec_drop":
        assert not load["nacks"] and load["datalost"] > 0
    elif case["profile"] == "fec_recover":
        assert not load["nacks"] and not load["datalost"]
    elif case["profile"] == "full":
        assert not load["nacks"] and not load["datalost"]
    return dict(
        name=case["name"],
        source_rx=case["process"]["load_receive_count"],
        native_rx=len(rx),
        consumed=len(consumed),
        retired=load["retired"],
        source_sdk=len(case["process"]["pictures"]),
        native_sdk=len(sdk),
        nacks=load["nacks"],
        datalost=load["datalost"],
        queue_bytes=max(s["queued_bytes"] for s in sdk),
        native=got,
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", required=True, type=Path)
    p.add_argument("--source-report", type=Path)
    p.add_argument("--output", type=Path)
    a = p.parse_args()
    report = (
        json.loads(a.source_report.read_text())
        if a.source_report
        else json.loads(
            gzip.decompress(
                (
                    ROOT
                    / "scripts/fixtures/steam-client-pressure-process-reference.json.gz"
                ).read_bytes()
            )
        )
    )
    assert (
        report["client_sha256"]
        == "95482ca6120f90bb90798b27206b7946ab732e079f008d7fc90ea58a8b0074e1"
    )
    assert (
        report["codec_sha256"]
        == "c53a7e3d32a986323ec6bedd28df73a6e5842c4753b67b1d2aa0d6e4f524472f"
        and report["util_sha256"]
        == "6df6556b6026144eb545dd95c0e2cc8c4568f462c9bd7e036531207d4172db34"
        and len(report["source_functions"]) == 53
    )
    for name, sha in report["helpers"].items():
        assert hashlib.sha256((ROOT / "scripts" / name).read_bytes()).hexdigest() == sha
    assert (
        report["stimulus_sha256"]
        == hashlib.sha256(
            (ROOT / "scripts/media-pressure-stimuli.py").read_bytes()
        ).hexdigest()
    )
    assert report["payloads"] == stim.payloads()
    bank = report["fec_encoder"]
    for key, path in (
        ("runner_sha256", "scripts/audit-steam-client-udp-process.py"),
        ("generator_sha256", "scripts/audit-steam-client-pressure-process.py"),
        ("adapter_source_sha256", "app/tests/fixtures/transport/sdk_delay.c"),
        ("crc_source_sha256", "third_party/ihslib/src/crc32c.c"),
    ):
        assert report[key] == hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
    assert (
        bank["binary_sha256"]
        == "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"
    )
    for key, path in (
        ("generator_sha256", "audit-steam-pressure-fec-encode.py"),
        ("helper_sha256", "audit-steam-fec.py"),
        ("recovery_helper_sha256", "audit-steam-video-recovery.py"),
        ("stimulus_sha256", "media-pressure-stimuli.py"),
    ):
        assert (
            bank[key]
            == hashlib.sha256((ROOT / "scripts" / path).read_bytes()).hexdigest()
        )
    assert len(bank["groups"]) == 26 and (bank["k"], bank["m"], bank["shard"]) == (
        57,
        3,
        1168,
    )
    for group in bank["groups"]:
        assert (
            group["body_sha256"]
            == hashlib.sha256(stim.body(group["index"])).hexdigest()
        )
    assert len(report["cases"]) == 12
    results = []
    for case in report["cases"]:
        result = verify(a.receiver, case, bank)
        results.append(result)
        print(
            json.dumps({k: v for k, v in result.items() if k != "native"}), flush=True
        )
    if a.output:
        a.output.write_text(json.dumps(results, indent=2) + "\n")
    print(
        "Byte pressure: 12 real Native processes verified; input, retirement, feedback, exact AU/pixel and key/P"
    )


if __name__ == "__main__":
    main()
