#!/usr/bin/env python3
"""Observe original official client UDP Connect/ConnectACK/ClientHandshake.

The fixed genuine ELF, real OS sockets/threads and original constructors, RX,
CRC, delegate, protobuf and reliable sender execute. A loopback fixture sends
explicit ConnectACKs, including CRC, duplicates or a bad-length first ACK. No
parsed Packet/Frame, client phase or original return value is injected. The
fixture auth token is supplied by original API. This stops at client Handshake;
there is no Steam server, ServerHandshake/authentication, Qt/SDL or media proof.
"""

import argparse
import gzip
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "process", ROOT / "scripts/audit-steam-client-sdk-process.py"
)
process = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(process)
FUNCTIONS = {
    0x31A6F0: "client_constructor",
    0x31AAB0: "client_destructor",
    0x31AC40: "client_deleting_destructor",
    0x337610: "player_constructor",
    0x336EF0: "player_deleting_destructor",
    0x317A10: "use_threads",
    0x317AB0: "set_player",
    0x317B30: "set_auth_token",
    0x3181A0: "transport_init_connect",
    0x3230A0: "client_think",
    0x31AA60: "client_shutdown",
    0x19BD00: "connection_factory",
    0x19BB80: "connection_constructor",
    0x19AA40: "connection_connect",
    0x19A8D0: "send_connect_packet",
    0x19B720: "handle_connected",
    0x3203B0: "client_on_connected",
    0x31AF60: "send_control",
    0x1947A0: "frame_send",
    0x1A0170: "network_shutdown",
    0x1A0C10: "network_manager_update",
}


def crc32c(data):
    value = 0xFFFFFFFF
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
    return value ^ 0xFFFFFFFF


def without_crc(raw):
    if raw[0] & 128:
        assert struct.unpack("<I", raw[-4:])[0] == crc32c(raw[:-4])
        return raw[:-4]
    return raw


def verify(case):
    r = case["process"]
    assert r["exit_code"] == 0 and r["cleanup_complete"] and not r["source_assertions"]
    assert r["module_refs"] == [0, 0]
    assert not {
        pid
        for pid, state in r["tasks_after_shutdown"].items()
        if state not in ("X", "Z")
    } - set(r["tasks_before"])
    trace = r["trace"]
    handlers = [e for e in trace if e[0] == "connected_handler"]
    assert len(handlers) == (4 if case["duplicate"] else 2 if case["bad_length"] else 1)
    assert [e[3] for e in handlers] == (
        [0, 1, 1, 1] if case["duplicate"] else [0, 0] if case["bad_length"] else [0]
    )
    assert [e[4] for e in handlers] == (
        [1, 2, 2, 2] if case["duplicate"] else [1, 1] if case["bad_length"] else [1]
    )
    assert all(e[6] == 0 for e in handlers)
    # Read exact bytes from the real admitted packet in the original handler.
    assert [e[2] for e in handlers] == [
        without_crc(bytes.fromhex(p["data"])).hex() for p in case["sent"]
    ]
    delegates = [e for e in trace if e[0] == "connected_delegate"]
    assert len(delegates) == 1 and delegates[0][1] != r["main_thread"]
    assert [e[2] for e in trace if e[0] == "send_control"] == [6]
    assert [e[2] for e in trace if e[0] == "frame_send"] == [6]
    assert any(e[0] == "join_completed" and e[2] == 0 for e in trace)
    state = r["connected_state"]
    local = bytes.fromhex(state["ids"])[0]
    assert state == dict(
        client_phase=2,
        transport_state=1,
        crc=int(case["crc"]),
        outgoing_fec=0,
        ids=bytes([local, 7]).hex(),
        callback=0x3203B0,
    )
    assert local
    packets = [bytes.fromhex(p["data"]) for p in case["received"]]
    connects = [p for p in packets if p[0] == 1]
    assert connects and all(
        len(p) == 17
        and p[1:9] == bytes([0, local, 0, 0, 0, 0, 0, 0])
        and p[13:] == bytes.fromhex("c73d8f3c")
        for p in connects
    )
    handshake = [p for p in packets if p[0] & 127 == 5]
    assert handshake and handshake[0][1] == 0
    for wire in handshake:
        raw = without_crc(wire)
        assert bool(raw[0] & 128) == case["crc"]
        assert raw[2:9] == bytes([local, 7, 1, 0, 0, 0, 0])
        assert raw[13:] == bytes.fromhex("060a00")
    assert any(p[0] & 127 == 9 for p in packets)
    first = without_crc(handshake[0])
    case["projection"] = dict(
        phase=state["client_phase"],
        transport=state["transport_state"],
        crc=bool(state["crc"]),
        outgoing_fec=bool(state["outgoing_fec"]),
        control_body=first[13:].hex(),
        control_channel=first[4],
        reliable=(first[0] & 127) == 5,
        duplicate_callbacks=len(delegates) - 1,
    )


def audit(binary, sdk, qt, output, case):
    helper = ROOT / "scripts/steam-client-udp-gdb.py"
    bootstrap = ROOT / "scripts/steam-client-sdk-gdb.py"
    received, sent, errors = [], [], []
    stop = threading.Event()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.bind(("127.0.0.1", 0))
        peer.settimeout(0.1)

        def serve():
            connected = False
            bad_sent = False
            duplicates_sent = False
            try:
                while not stop.is_set():
                    try:
                        raw, address = peer.recvfrom(65536)
                    except socket.timeout:
                        continue
                    received.append(dict(data=raw.hex(), peer=list(address)))
                    if len(raw) == 17 and raw[0] == 1 and not connected:
                        reply = (
                            struct.pack(
                                "<BBBBBhHI",
                                2 | (128 if case["crc"] else 0),
                                0,
                                7,
                                raw[2],
                                0,
                                0,
                                0,
                                1000000,
                            )
                            + raw[9:13]
                        )
                        if case["bad_length"] and not bad_sent:
                            reply = reply[:-1]
                            bad_sent = True
                        else:
                            connected = True
                        if case["crc"]:
                            reply += struct.pack("<I", crc32c(reply))
                        assert peer.sendto(reply, address) == len(reply)
                        sent.append(dict(data=reply.hex(), peer=list(address)))
                    elif (
                        raw[0] & 127 == 5 and case["duplicate"] and not duplicates_sent
                    ):
                        reply = bytes.fromhex(sent[-1]["data"])
                        for _ in range(3):
                            assert peer.sendto(reply, address) == len(reply)
                            sent.append(dict(data=reply.hex(), peer=list(address)))
                        duplicates_sent = True
            except Exception as error:
                errors.append(repr(error))

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(
                prefix="original-udp-client-"
            ) as temporary:
                directory = Path(temporary)
                config_path, result = (
                    directory / "config.json",
                    directory / "result.json",
                )
                config_path.write_text(
                    json.dumps(
                        dict(
                            binary=str(binary),
                            endpoint="127.0.0.1:" + str(peer.getsockname()[1]),
                            result=str(result),
                            bootstrap_helper=str(bootstrap),
                            fixture=str(
                                ROOT / "app/tests/fixtures/video/sequential.h264"
                            ),
                            expected_handlers=4
                            if case["duplicate"]
                            else 2
                            if case["bad_length"]
                            else 1,
                        )
                    )
                )
                commands = directory / "probe.gdb"
                commands.write_text(
                    "\n".join(
                        [
                            "set pagination off",
                            "set confirm off",
                            "set auto-load off",
                            "set debuginfod enabled off",
                            "set startup-with-shell off",
                            "set disable-randomization off",
                            "set breakpoint pending on",
                            "set python print-stack full",
                            "break __libc_start_main",
                            "run",
                            "set $source_main = $rdi",
                            "tbreak *$source_main",
                            "continue",
                            "python import json,os;from pathlib import Path;"
                            "config=json.loads(Path(os.environ['NSL_OFFICIAL_SDK_PROBE_CONFIG']).read_text());"
                            f"exec(compile(Path({str(helper)!r}).read_text(),{str(helper)!r},'exec'))",
                            "continue",
                            "",
                        ]
                    )
                )
                env = dict(os.environ)
                assert "STEAMVIDEOTOKEN" not in env
                env.update(
                    QT_QPA_PLATFORM="offscreen",
                    NSL_OFFICIAL_SDK_PROBE_CONFIG=str(config_path),
                    LD_LIBRARY_PATH=":".join(str(p) for p in [qt[0], sdk, *qt[1:]]),
                )
                completed = subprocess.run(
                    [
                        "gdb",
                        "--nx",
                        "--batch",
                        "--quiet",
                        "-x",
                        str(commands),
                        "--args",
                        str(binary),
                        "--version",
                    ],
                    env=env,
                    capture_output=True,
                    timeout=45,
                    check=False,
                )
                output.with_suffix(".gdb.log").write_bytes(
                    completed.stdout + completed.stderr
                )
                assert completed.returncode == 0 and result.exists(), str(output)
                assert (
                    b"1.3.32.316" in completed.stdout
                    and b"exited normally" in completed.stdout
                )
                report = json.loads(result.read_text())
        finally:
            stop.set()
            thread.join()
    assert not errors, errors
    result = dict(case, received=received, sent=sent, process=report)
    verify(result)
    output.write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--sdk-directory", type=Path, required=True)
    parser.add_argument(
        "--qt-library-directory", type=Path, action="append", required=True
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path)
    args = parser.parse_args()
    binary, sdk, qt = (
        args.binary.resolve(),
        args.sdk_directory.resolve(),
        [p.resolve() for p in args.qt_library_directory],
    )
    assert process.digest(binary) == process.boundary.codec.SHA
    assert binary.name == "steamlink" and binary.parent.name == "bin"
    assert process.digest(sdk / "libavcodec.so.61") == process.boundary.CODEC_SHA
    assert process.digest(sdk / "libavutil.so.59") == process.boundary.codec.SDK_SHA
    dependencies = {}
    for name in ("Core", "Gui", "Widgets", "Svg"):
        library = next(
            (
                p / f"libQt6{name}.so.6"
                for p in qt
                if (p / f"libQt6{name}.so.6").is_file()
            ),
            None,
        )
        assert library, name
        dependencies[name] = process.digest(library)
    cases = []
    for name, crc, duplicate, bad_length in [
        ("crc_off", False, False, False),
        ("crc_on", True, False, False),
        ("duplicate_crc_on", True, True, False),
        ("bad_length_crc_off", False, False, True),
    ]:
        path = args.output.with_name(args.output.stem + "-" + name + ".json")
        case = audit(
            binary,
            sdk,
            qt,
            path,
            dict(name=name, crc=crc, duplicate=duplicate, bad_length=bad_length),
        )
        cases.append(case)
        print(
            name,
            "actual UDP -> original client phase2, handshake 060a00, FEC gate0",
            flush=True,
        )
    report = dict(
        scope=__doc__,
        archive_url="https://repo.steampowered.com/steamlink/1.3.32.316/steamlink-1.3.32.316.tgz",
        client_sha256=process.digest(binary),
        helper_sha256=process.digest(ROOT / "scripts/steam-client-udp-gdb.py"),
        bootstrap_helper_sha256=process.digest(
            ROOT / "scripts/steam-client-sdk-gdb.py"
        ),
        qt_dependency_sha256=dependencies,
        qt_required_controller_patch=process.QT_PATCH,
        source_functions=process.boundary.inventory(binary.read_bytes(), FUNCTIONS),
        cases=cases,
    )
    data = (json.dumps(report, indent=2) + "\n").encode()
    args.output.write_bytes(data)
    if args.snapshot:
        args.snapshot.write_bytes(gzip.compress(data, mtime=0))
    print("Original UDP client: four handshake/CRC/duplicate/length cases passed")


if __name__ == "__main__":
    main()
