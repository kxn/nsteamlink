#!/usr/bin/env python3
"""Native real file/UDP/crypto/video pipeline vs original client processes.

Generic/headless decoder endpoint, without SDL/runtime/rendering/Steam/device.
Compare full negotiated control and encrypted DecoderInfo, exact SDK packet and
independent pixel MD5. Only mandatory Raw capability is a platform projection.
Two known original duplicate-count counterexamples explicitly require Native's
existing unique-shard guard to recover; they are not claimed byte-equivalent.
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
                    / "scripts/fixtures/steam-client-media-process-reference.json.gz"
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
    )
    assert (
        report["util_sha256"]
        == "6df6556b6026144eb545dd95c0e2cc8c4568f462c9bd7e036531207d4172db34"
    )
    assert len(report["cases"]) == 18 and len(report["source_functions"]) == 49
    assert len(report["helpers"]) == 4
    for name, digest in report["helpers"].items():
        assert (
            digest == hashlib.sha256((ROOT / "scripts" / name).read_bytes()).hexdigest()
        )
    payload = (ROOT / "app/tests/fixtures/video/sequential.h264").read_bytes()[:2204]
    assert report["fixture_sha256"] == hashlib.sha256(payload).hexdigest()
    golden = (
        (ROOT / "app/tests/fixtures/video/sequential.framemd5")
        .read_text()
        .splitlines()[10]
        .split(",")[-1]
        .strip()
    )
    assert report["pixel_md5"] == golden
    results = []
    for case in report["cases"]:
        r = case["process"]
        decode = case.get("source_decode", True)
        assert (
            r["exit_code"] == 0 and r["cleanup_complete"] and not r["source_assertions"]
        )
        assert (
            sum(
                e["name"] == "decoder_join" and e["result"] == 0
                for e in r["media_events"]
            )
            == 1
        )
        assert [
            (e["value"], e["phase"])
            for e in r["module_events"]
            if e["name"] == "module_force_return"
        ] == [(0, "original_exit")]
        assert len(r["pictures"]) == int(decode)
        frames = case["native_projection"].copy()
        if not decode:
            assert case["name"].startswith("fec_duplicate_guard_") and case[
                "order"
            ] == [2, 2, 1]
            # Explicit existing safety divergence (§26.4/33), not broad filtering.
            # The actual original successful sibling supplies its genuine Info.
            sibling = next(
                c
                for c in report["cases"]
                if c["name"] == f"ordinary_reliable0_crc{int(case['crc'])}_reverse0"
            )
            assert case["outputs"] == sibling["outputs"][:2]
            assert len(frames) == 2
            frames.append(sibling["native_projection"][2])
        with tempfile.TemporaryDirectory(prefix="native-udp-media-") as d:
            directory = Path(d)
            settings = directory / "streaming_settings.bin"
            settings.write_bytes(bytes.fromhex(case["settings"]))
            wires = [bytes.fromhex(item["data"]) for item in case["media_input"]]
            assert len(wires) == len(case["order"])
            media = directory / "media.bin"
            media.write_bytes(
                b"".join(struct.pack("<I", len(wire)) + wire for wire in wires)
            )
            result = subprocess.run(
                [
                    str(args.receiver.resolve()),
                    "--video",
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
            frames=frames,
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
        results.append(case["name"])
    assert sum(not c.get("source_decode", True) for c in report["cases"]) == 2
    print(
        "Native/original real UDP video: 16 fragment/FEC/SDK/pixel/Stop cases and 2 explicit duplicate guards passed"
    )


if __name__ == "__main__":
    main()
