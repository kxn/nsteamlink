#!/usr/bin/env python3
"""Observe video codec_data through original encrypted control/factory/SDK.

Pinned genuine client and bundled SDK; original StartVideo handler stores the
bytes. Input control carrier header/auth token and parsed media are explicit
boundaries, with no authenticated Steam/SDL/renderer/hardware claim. No SDK result,
async flag, client phase, codec context or original body is replaced. These
field inputs do not prove a natural host producer or the user's freeze cause.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import re
import socket
import hashlib

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "start", ROOT / "scripts/audit-steam-client-video-start-process.py"
)
start = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(start)
process = start.process


def inputs(fixture):
    raw = fixture.read_bytes()
    markers = list(re.finditer(b"\x00\x00\x00?\x01", raw))
    nals = [
        raw[m.end() : markers[i + 1].start() if i + 1 < len(markers) else len(raw)]
        for i, m in enumerate(markers)
    ]
    sps = next(n for n in nals if n[0] & 31 == 7)
    pps = next(n for n in nals if n[0] & 31 == 8)
    avcc = (
        bytes([1, sps[1], sps[2], sps[3], 255, 225])
        + len(sps).to_bytes(2, "big")
        + sps
        + bytes([1])
        + len(pps).to_bytes(2, "big")
        + pps
    )
    annexb = b"\0\0\0\1" + sps + b"\0\0\0\1" + pps
    return dict(
        empty=b"",
        opaque=b"abcd",
        truncated=b"\1",
        annexb=annexb,
        avcc=avcc,
        avcc_reset=avcc,
    )


def verify(report, name, codec_data, fixture):
    s = report["original_start"]
    assert (
        report["original_process_exit_code"] == 0 and report["probe_cleanup_complete"]
    )
    assert not report["source_assertions"] and not s["assertions"]
    assert s["cleanup_complete"] and s["network_shutdown_before_main"]
    assert report["client_sha256"] == process.boundary.codec.SHA
    assert report["sdk_sha256"] == process.boundary.CODEC_SHA
    assert (
        len(report["source_functions"]) == 54 and len(report["start_functions"]) == 20
    )
    assert len(report["codec_data_functions"]) == 1
    count = 2 if name == "avcc_reset" else 1
    assert s["codec_data_input"] == codec_data.hex()
    assert (
        s["codec_data_states"]
        == [dict(stored=codec_data.hex(), sdk_size=0, sdk_has_pointer=False)] * count
    )
    data = fixture.read_bytes()[:2204]
    assert (
        s["codec_packets"]
        == [dict(size=len(data), sha256=hashlib.sha256(data).hexdigest(), sdk_size=0)]
        * count
    )
    trace = s["trace"]
    for label in ("sdk_open", "sdk_send", "sdk_receive", "sdk_get_format"):
        assert [e[2] for e in trace if e[0] == label + "_return"] == [0] * count
    assert s["control"] == [dict(channel=1, type=80)] * count
    assert [e[2] for e in trace if e[0] == "frame_send_return"] == [3] * count
    assert sum(e[0] == "data_lost" for e in trace) == count - 1
    assert s["pictures"] == [
        dict(id=23 + i, timestamp=1000000, md5=report["contexts"][0]["pixel_md5"])
        for i in range(count)
    ]
    controls = s["control_inputs"]
    assert [c["type"] for c in controls] == [52, 53]
    assert (
        controls[0]["plain"]
        == (
            bytes.fromhex("080310042080012848")
            + bytes([26, len(codec_data)])
            + codec_data
        ).hex()
    )
    assert [e[2] & 255 for e in trace if e[0] == "decrypt_control_return"] == [1, 1]
    assert ["decoder_pthread_join_completed", "main", 0] in trace
    assert ["manager_pthread_join_completed", "main", 0] in trace
    before = set(s["thread_ids_before_start"])
    assert set(s["thread_ids_after_stop"]) <= before
    assert set(s["thread_ids_after_resources"]) <= before
    assert report["loopback_packets"]
    assert all(len(bytes.fromhex(p["data"])) == 17 for p in report["loopback_packets"])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--sdk-directory", type=Path, required=True)
    p.add_argument("--qt-library-directory", type=Path, action="append", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    fixture = ROOT / "app/tests/fixtures/video/sequential.h264"
    cases = []
    for name, data in inputs(fixture).items():
        path = a.output.with_name(a.output.stem + "-" + name + ".json")
        packets = []
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.bind(("127.0.0.1", 0))
            peer.settimeout(0.1)
            r = process.audit(
                a.binary.resolve(),
                a.sdk_directory.resolve(),
                [q.resolve() for q in a.qt_library_directory],
                path,
                client_bootstrap="udp",
                endpoint="127.0.0.1:" + str(peer.getsockname()[1]),
                start_mode="reset_ready" if name == "avcc_reset" else "decode",
                video_codec_data=data,
            )
            try:
                while True:
                    packet, sender = peer.recvfrom(65536)
                    packets.append(dict(data=packet.hex(), peer=list(sender)))
            except socket.timeout:
                pass
        r["codec_case"] = name
        r["loopback_packets"] = packets
        r["start_functions"] = process.boundary.inventory(
            a.binary.read_bytes(), start.FUNCTIONS
        )
        r["codec_data_functions"] = process.boundary.inventory(
            a.binary.read_bytes(), {0x319360: "request_video_reset"}
        )
        path.write_text(json.dumps(r, indent=2) + "\n")
        verify(r, name, data, fixture)
        cases.append(r)
        print(
            name,
            len(data),
            "stored bytes; original SDK extradata empty; decoded",
            len(r["original_start"]["pictures"]),
            flush=True,
        )
    a.output.write_text(json.dumps(dict(scope=__doc__, cases=cases), indent=2) + "\n")
    print("Original video codec_data: six encrypted-control/SDK cases passed")


if __name__ == "__main__":
    main()
