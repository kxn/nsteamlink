#!/usr/bin/env python3
"""Run original encrypted control RX/FIFO/StartVideo/factory/SDK/StopVideo.

Pinned genuine Client/CStreamPlayer and SDK, real threads/allocators/crypto/UDP
Init; loopback only receives Connect. The fixed auth token, parsed control carrier
header and parsed media Frame are explicit inputs, not handshake/CRC/socket RX,
Qt/SDL startup or physical renderer/hardware proof. No decoder owner/async flag,
client phase, method body, SDK status or callback is overwritten.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "process", ROOT / "scripts/audit-steam-client-sdk-process.py"
)
process = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(process)
FUNCTIONS = {
    0x2D9010: "sdl_streaming_main",
    0x337610: "stream_player_constructor",
    0x336550: "stream_player_destructor",
    0x336EF0: "stream_player_deleting_destructor",
    0x327D50: "stream_player_prepare",
    0x317A10: "set_use_threads",
    0x317B30: "set_auth_token",
    0x317AB0: "set_player",
    0x31BBD0: "on_stream_packet",
    0x194B60: "frame_encrypt",
    0x194E60: "frame_decrypt",
    0x3212E0: "on_start_video",
    0x3214D0: "on_stop_video",
    0x318640: "start_video_factory",
    0x318910: "stop_video_owner",
    0x1945E0: "outgoing_frame_constructor",
    0x194730: "frame_put_bytes",
    0x31AA00: "client_shutdown",
    0x1A0170: "shutdown_network_processing",
    0x1A5610: "assertion",
}


def verify(report):
    s = report["original_start"]
    mode = s["mode"]
    trace = s["trace"]
    names = [e[0] for e in trace]
    assert (
        report["original_process_exit_code"] == 0 and report["probe_cleanup_complete"]
    )
    assert (
        len(report["source_functions"]) == 54 and len(report["start_functions"]) == 20
    )
    assert (
        not s["assertions"] and s["cleanup_complete"] and s["source_callback_installed"]
    )
    assert not report["source_assertions"]
    assert s["network_shutdown_before_main"]
    before = set(s["thread_ids_before_start"])
    assert set(s["thread_ids_after_stop"]) <= before
    assert set(s["thread_ids_after_resources"]) <= before
    assert ["manager_pthread_join_completed", "main", 0] in trace
    assert ["decoder_pthread_join_completed", "main", 0] in trace
    packets = report["loopback_packets"]
    assert packets
    assert all(
        len(bytes.fromhex(p["data"])) == 17 and bytes.fromhex(p["data"])[0] == 1
        for p in packets
    )
    assert s["decoder_generations"] == (2 if mode == "replace_pending" else 1)
    assert [e[2] for e in trace if e[0] == "sdk_open_return"] == [0] * s[
        "decoder_generations"
    ]
    controls = s["control_inputs"]
    assert [c["type"] for c in controls] == (
        [52, 52, 53] if mode == "replace_pending" else [52, 53]
    )
    for i, c in enumerate(controls):
        assert c["sequence"] == i
        assert c["plain"] == ("080310042080012848" if c["type"] == 52 else "")
        assert c["encrypted"] != f"{c['type']:02x}" + c["plain"]
    assert [e[2] & 255 for e in trace if e[0] == "decrypt_control_return"] == [1] * len(
        controls
    )
    assert names.count("start_video_handler") == s["decoder_generations"]
    assert names.count("player_prepare") == s["decoder_generations"]
    assert names.count("avcodec_deleting_destructor") == s["decoder_generations"]
    assert names.count("stop_video_handler") == 1

    def statuses(n):
        return [e[2] for e in trace if e[0] == n + "_return"]

    assert statuses("sdk_send") == (
        [0]
        if mode == "decode"
        else [-1094995529, 0]
        if mode == "replace_pending"
        else [-1094995529]
    )
    assert statuses("sdk_receive") == (
        [0] if mode == "decode" else [-11, 0] if mode == "replace_pending" else [-11]
    )
    assert statuses("sdk_get_format") == (
        [0] if mode == "decode" else [-1, 0] if mode == "replace_pending" else [-1]
    )
    infos = 0 if mode == "stop_pending" else 1
    assert s.get("control", []) == [{"channel": 1, "type": 80}] * infos
    assert statuses("frame_send") == [3] * infos
    assert names.count("data_lost") == (0 if mode == "decode" else 1)
    if infos:
        assert (
            s["cached_info_before_stop"]
            == "libavcodec software decoding with 4 threads"
        )
        assert s["picture"] == dict(
            id=23 if mode == "decode" else 24,
            timestamp=1000000,
            md5=report["contexts"][0]["pixel_md5"],
        )
    order = [
        names.index(n)
        for n in (
            "player_constructor",
            "set_use_threads",
            "set_auth_token",
            "packet_callback",
            "client_think",
            "control_dispatch",
            "start_video_handler",
            "player_prepare",
            "start_video_factory",
            "avcodec_constructor",
            "public_start",
        )
    ]
    assert order == sorted(order)
    for e in trace:
        if e[0] in (
            "sdk_send",
            "sdk_receive",
            "final_decode",
            "decode_frame",
            "player_put",
        ):
            assert e[1].startswith("background"), e
        elif e[0] in (
            "start_video_handler",
            "stop_video_handler",
            "decoder_info",
            "format_selector",
            "public_stop",
        ):
            assert e[1] == "main", e


def legacy_boundary(binary, sdk, qt, output):
    """Observe the historical fixture; do not suppress its real assertions."""
    revision = "41569f2ad79a81cda69df6d4559d55305f09e48b"
    worker = subprocess.check_output(
        ["git", "show", revision + ":scripts/steam-client-worker-gdb.py"], cwd=ROOT
    )
    assert (
        hashlib.sha256(worker).hexdigest()
        == "961fc5f88d0d983efb88597d964332f50e4e8506b7ff77ef9bcbbac703aac9c7"
    )
    original_root = process.ROOT
    with tempfile.TemporaryDirectory(prefix="original-legacy-fixture-") as directory:
        directory = Path(directory)
        (directory / "scripts").mkdir()
        (directory / "app").symlink_to(ROOT / "app", target_is_directory=True)
        (directory / "scripts/steam-client-sdk-gdb.py").write_bytes(
            (ROOT / "scripts/steam-client-sdk-gdb.py").read_bytes()
        )
        (directory / "scripts/steam-client-worker-gdb.py").write_bytes(worker)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.bind(("127.0.0.1", 0))
            process.ROOT = directory
            try:
                report = process.audit(
                    binary,
                    sdk,
                    qt,
                    output,
                    worker_mode="decode",
                    client_bootstrap="udp",
                    endpoint="127.0.0.1:" + str(peer.getsockname()[1]),
                )
            finally:
                process.ROOT = original_root
    assertions = report["source_assertions"]
    observed = [(a["line"], a["expression"], a["phase"]) for a in assertions]
    assert observed == [
        (250, "m_eSessionState == k_ESessionStateIdle", "probe"),
        (284, "pubKey", "probe"),
        (285, "cubKey > 0", "probe"),
        (5424, "Failed to set thread local value", "original_exit"),
    ], observed
    assert report["original_process_exit_code"] == 0
    report["historical_worker_revision"] = revision
    report["boundary_correction"] = (
        "Exit0/SDK pixels do not prove valid player registration, HMAC input or global TLS teardown; see recorded assertions."
    )
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        "Historical boundary: real exit0 with three probe assertions and one original-exit TLS assertion",
        flush=True,
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--sdk-directory", type=Path, required=True)
    p.add_argument("--qt-library-directory", type=Path, action="append", required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--legacy-boundary-output", type=Path)
    a = p.parse_args()
    cases = []
    for mode in ("decode", "replace_pending", "stop_pending"):
        path = a.output.with_name(a.output.stem + "-" + mode + ".json")
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
                start_mode=mode,
            )
            try:
                while True:
                    data, sender = peer.recvfrom(65536)
                    packets.append(dict(data=data.hex(), peer=list(sender)))
            except socket.timeout:
                pass
        r["loopback_packets"] = packets
        r["start_functions"] = process.boundary.inventory(
            a.binary.read_bytes(), FUNCTIONS
        )
        path.write_text(json.dumps(r, indent=2) + "\n")
        verify(r)
        cases.append(r)
        print(
            mode,
            "original owner generations",
            r["original_start"]["decoder_generations"],
            "no Source assertions",
            flush=True,
        )
    a.output.write_text(json.dumps(dict(scope=__doc__, cases=cases), indent=2) + "\n")
    print(
        "Original encrypted RX/FIFO/StartVideo/factory/SDK/StopVideo: three modes passed"
    )
    if a.legacy_boundary_output:
        legacy_boundary(
            a.binary.resolve(),
            a.sdk_directory.resolve(),
            [q.resolve() for q in a.qt_library_directory],
            a.legacy_boundary_output,
        )


if __name__ == "__main__":
    main()
