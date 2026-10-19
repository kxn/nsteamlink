#!/usr/bin/env python3
"""Verify actual Native UDP/SDK/pixels under the official paced load stimuli.

Natural receive/consumer schedules differ. Submission counts and exact wall times
are observations, not equality fields. Compare every submitted AU and observed
pixel, all complete RX, SDK-busy RX progress, final recovery and clean stop.
The old exact component/batch oracles remain separate; no projection of observed
counts is presented as an official dropping threshold.
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
CLIENT = "95482ca6120f90bb90798b27206b7946ab732e079f008d7fc90ea58a8b0074e1"
CODEC = "c53a7e3d32a986323ec6bedd28df73a6e5842c4753b67b1d2aa0d6e4f524472f"
UTIL = "6df6556b6026144eb545dd95c0e2cc8c4568f462c9bd7e036531207d4172db34"


def groups(case):
    result = []
    for p in case["sent"]:
        wire = bytes.fromhex(p["data"])
        if wire[4] != 3 or wire[0] & 127 not in (3, 4):
            continue
        if wire[0] & 127 == 3:
            result.append([])
        result[-1].append(wire)
    assert len(result) == case["frames"]
    return result


def verify(receiver, case):
    r = case["process"]
    count = case["frames"]
    last = 100 + count - 1
    assert (
        count == 302
        and case["rate"] == 60
        and r["load_frames"] == list(range(100, last + 1))
    )
    assert r["exit_code"] == 0 and r["cleanup_complete"] and not r["source_assertions"]
    assert (
        r["load_table_restored"]
        and r["load_adapter_closed"]
        and r["load_receive_count"] == count
    )
    assert r["load_adapter_final"] == [
        0,
        len(r["pictures"]),
        len(r["pictures"]),
        case["delay_us"] * len(r["pictures"]),
    ]
    assert (
        r["pictures"][-1]["id"] == last
        and len(case["producer_times"]) == count
        and case["producer_times"][-1] >= 4.9
    )
    assert [picture["id"] for picture in r["pictures"][-2:]] == [last - 1, last]
    if case["delay_us"]:
        assert r["load_receive_busy"] > 0
    fixture = (ROOT / "app/tests/fixtures/video/sequential.h264").read_bytes()
    au = [
        fixture[a : a + n]
        for a, n in [
            (0, 2204),
            (2204, 411),
            (2615, 425),
            (3040, 486),
            (3526, 461),
            (3987, 565),
        ]
    ]
    md5s = [
        line.split(",")[-1].strip()
        for line in (ROOT / "app/tests/fixtures/video/sequential.framemd5")
        .read_text()
        .splitlines()
        if not line.startswith("#")
    ]
    for picture in r["pictures"]:
        assert picture["md5"] == md5s[(picture["id"] - 100) % 6]
    with tempfile.TemporaryDirectory(prefix="native-paced-load-") as d:
        path = Path(d)
        (path / "streaming_settings.bin").write_bytes(bytes.fromhex(case["settings"]))
        media = path / "media.bin"
        media.write_bytes(
            b"".join(
                b"".join(struct.pack("<I", len(w)) + w for w in group) + bytes(4)
                for group in groups(case)
            )
        )
        completed = subprocess.run(
            [
                str(receiver.resolve()),
                "--load",
                str(int(case["crc"])),
                d,
                "080010031804",
                "0",
                str(media),
                str(case["delay_us"]),
                str(count),
                str(case["rate"]),
            ],
            capture_output=True,
            text=True,
            timeout=25,
        )
        assert completed.returncode == 0, (
            case["name"],
            completed.returncode,
            completed.stderr[-3000:],
        )
        got = json.loads(completed.stdout)
    load = got["load"]
    sdk = load["sdk"]
    pictures = load["pictures"]
    assert (
        got["phase"] == 6
        and not got["closed"]
        and got["video"]["stopped"]
        and got["video"]["starts"] == 1
    )
    assert load["received"] == count and load["datalost"] == 0
    if case["delay_us"]:
        assert load["received_while_sdk"] > 0
    assert sdk and pictures and sdk[-1]["id"] == pictures[-1]["id"] == last
    ids = [s["id"] for s in sdk]
    assert ids == sorted(set(ids)) and all(100 <= i <= last for i in ids)
    assert ids[-2:] == [last - 1, last], (case["name"], ids[-2:])
    assert got["video"]["submits"] == len(sdk)
    for s in sdk:
        payload = au[(s["id"] - 100) % 6]
        assert (
            s["result"] == 0
            and s["size"] == len(payload)
            and s["sha256"] == hashlib.sha256(payload).hexdigest()
        )
        assert s["elapsed_ns"] >= case["delay_us"] * 1000
    picture_ids = [p["id"] for p in pictures]
    assert picture_ids == sorted(set(picture_ids))
    for p in pictures:
        assert p["id"] in ids and p["md5"] == md5s[(p["id"] - 100) % 6]
    return dict(
        name=case["name"],
        source_sdk=len(r["pictures"]),
        native_sdk=len(sdk),
        native_pictures=len(pictures),
        received=count,
        sdk_busy_rx=load["received_while_sdk"],
        max_sampled_queue=max(s["queued"] for s in sdk),
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
                    / "scripts/fixtures/steam-client-load-process-reference.json.gz"
                ).read_bytes()
            )
        )
    )
    assert (
        report["client_sha256"] == CLIENT
        and report["codec_sha256"] == CODEC
        and report["util_sha256"] == UTIL
    )
    assert len(report["cases"]) == 6 and len(report["source_functions"]) == 52
    for name, sha in report["helpers"].items():
        assert hashlib.sha256((ROOT / "scripts" / name).read_bytes()).hexdigest() == sha
    assert (
        report["adapter_source_sha256"]
        == hashlib.sha256(
            (ROOT / "app/tests/fixtures/transport/sdk_delay.c").read_bytes()
        ).hexdigest()
    )
    assert (
        report["fixture_sha256"]
        == hashlib.sha256(
            (ROOT / "app/tests/fixtures/video/sequential.h264").read_bytes()
        ).hexdigest()
    )
    results = [verify(a.receiver, c) for c in report["cases"]]
    if a.output:
        a.output.write_text(json.dumps(results, indent=2) + "\n")
    print(
        "Paced UDP load: six real processes; full RX, exact submitted AUs/pixels and final recovery; natural counts not equated"
    )


if __name__ == "__main__":
    main()
