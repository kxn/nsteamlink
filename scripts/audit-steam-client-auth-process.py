#!/usr/bin/env python3
"""Actual original UDP handshake, HMAC request and authentication reply branches.

Pinned official Linux client, real socket/CRC/reliable RX/FIFO/OnThink/protobuf/
crypto execute; peer token and raw datagrams are explicit fixture inputs. No
phase, parsed packet/frame, crypto result, callback or original body is replaced.
This is not Steam server identity/authentication, full negotiation or device proof.
"""

import argparse
import gzip
import hmac
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "udp", ROOT / "scripts/audit-steam-client-udp-process.py"
)
udp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(udp)
FUNCTIONS = {
    **udp.FUNCTIONS,
    0x320720: "on_server_handshake",
    0x31B060: "start_authentication",
    0x3207D0: "on_authentication_response",
    0x31AA00: "stop_connection",
    0x31A3A0: "finish_stop",
    0x194A80: "frame_read_protobuf",
}
PHASES = {
    "request_crc_off": 3,
    "request_crc_on": 3,
    "default_mtu": 3,
    "success": 4,
    "default_result": 4,
    "failed": 0,
    "version_missing": 0,
    "version_zero": 0,
    "version_unknown": 0,
    "result_unknown": 4,
    "failed_then_unknown": 0,
    "unknown_then_failed": 0,
    "failed_then_success": 4,
    "version_then_unknown": 4,
    "version_then_zero": 0,
    "result_wrong_wire": 4,
    "result_fixed64": 4,
    "unknown_group": 4,
    "result_wrap32": 4,
    "varint_overflow": 4,
    "zero_tag": 3,
    "trailing_zero": 3,
    "group_99": 4,
    "group_100": 4,
    "group_101": 3,
    "malformed_response": 3,
    "server_missing_info": 2,
}


class Peer:
    def __init__(self, peer, case, sent):
        self.peer, self.case, self.sent = peer, case, sent
        self.connected = self.handshake = self.response = False

    def send(self, raw, address):
        if self.case["crc"] and raw[0] != 2:
            raw[0] |= 128
            raw += struct.pack("<I", udp.crc32c(raw))
        assert self.peer.sendto(raw, address) == len(raw)
        self.sent.append(dict(data=bytes(raw).hex(), peer=list(address)))

    def __call__(self, raw, address):
        if raw[0] == 1 and len(raw) == 17 and not self.connected:
            data = bytearray(
                struct.pack("<BBBBBhHI", 2, 0, 7, raw[2], 0, 0, 0, 1000000) + raw[9:13]
            )
            # Connected negotiates CRC; its own datagram carries that CRC too.
            if self.case["crc"]:
                data[0] |= 128
                data += struct.pack("<I", udp.crc32c(data))
            assert self.peer.sendto(data, address) == len(data)
            self.sent.append(dict(data=bytes(data).hex(), peer=list(address)))
            self.connected = True
        elif raw[0] & 127 == 5:
            data = udp.without_crc(raw)
            if data[13] == 6 and not self.handshake:
                reply = bytearray(
                    struct.pack("<BBBBBhHI", 5, 0, 7, raw[2], 1, 0, 0, 1000000)
                    + bytes.fromhex(self.case["server"])
                )
                self.send(reply, address)
                self.handshake = True
            elif (
                data[13] == 1
                and self.case["response"] is not None
                and not self.response
            ):
                reply = bytearray(
                    struct.pack("<BBBBBhHI", 5, 0, 7, raw[2], 1, 0, 1, 1000000)
                    + bytes.fromhex(self.case["response"])
                )
                self.send(reply, address)
                self.response = True


def verify(case):
    r = case["process"]
    assert r["exit_code"] == 0 and r["cleanup_complete"] and not r["source_assertions"]
    assert r["module_refs"] == [0, 0]
    assert any(e[0] == "join_completed" and e[2] == 0 for e in r["trace"])
    assert not {
        pid
        for pid, state in r["tasks_after_shutdown"].items()
        if state not in ("X", "Z")
    } - set(r["tasks_before"])
    assert r["control_inputs"] == [case["server"]] + (
        [case["response"]] if case["response"] is not None else []
    )
    if case["finish_event"] == "server_handshake_return":
        assert not r["authentication_frames"]
    else:
        token = hmac.new(
            bytes(range(32)), b"Steam In-Home Streaming", hashlib.sha256
        ).digest()
        request = bytes.fromhex("010a20") + token + bytes.fromhex("10011800")
        assert r["authentication_frames"] == [dict(type=1, payload=request[1:].hex())]
        actual = [
            udp.without_crc(bytes.fromhex(p["data"]))
            for p in case["received"]
            if bytes.fromhex(p["data"])[0] & 127 == 5
        ]
        assert any(p[13:] == request for p in actual)
        assert all(p[13:] in (bytes.fromhex("060a00"), request) for p in actual)
    assert r["connected_state"]["outgoing_fec"] in (None, 0)
    assert r["connected_state"]["client_phase"] == PHASES[case["name"]]
    assert r["connected_state"]["mtu"] == (
        512
        if case["name"] == "default_mtu"
        else 1024
        if case["name"] == "server_missing_info"
        else 1472
    )
    assert sum(bytes.fromhex(p["data"])[0] & 127 == 9 for p in case["received"]) == 1


def scenarios():
    base = dict(
        server="070a0308c00b",
        response=None,
        finish_event="authentication_frame",
        duplicate=False,
        bad_length=False,
    )
    for name, crc, extra in [
        ("request_crc_off", False, {}),
        ("request_crc_on", True, {}),
        ("default_mtu", False, dict(server="070a00")),
        ("success", False, dict(response="0208001001")),
        ("default_result", True, dict(response="021001")),
        ("failed", False, dict(response="0208011001")),
        ("version_missing", False, dict(response="020800")),
        ("version_zero", False, dict(response="0208001000")),
        ("version_unknown", True, dict(response="0208001002")),
        ("result_unknown", False, dict(response="0208021001")),
        ("failed_then_unknown", False, dict(response="02080108021001")),
        ("unknown_then_failed", False, dict(response="02080208011001")),
        ("failed_then_success", False, dict(response="02080108001001")),
        ("version_then_unknown", False, dict(response="02080010011002")),
        ("version_then_zero", False, dict(response="0210011000")),
        ("result_wrong_wire", False, dict(response="020a001001")),
        ("result_fixed64", False, dict(response="020900000000000000001001")),
        ("unknown_group", False, dict(response="024b08014c1001")),
        ("result_wrap32", False, dict(response="020880808080101001")),
        ("varint_overflow", False, dict(response="0208808080808080808080021001")),
        ("zero_tag", False, dict(response="0200")),
        ("trailing_zero", False, dict(response="02100100")),
        ("group_99", False, dict(response="02" + "4b" * 99 + "4c" * 99 + "1001")),
        ("group_100", False, dict(response="02" + "4b" * 100 + "4c" * 100 + "1001")),
        ("group_101", False, dict(response="02" + "4b" * 101 + "4c" * 101 + "1001")),
        ("malformed_response", False, dict(response="02ff")),
        (
            "server_missing_info",
            False,
            dict(server="07", finish_event="server_handshake_return"),
        ),
    ]:
        case = dict(base, name=name, crc=crc)
        case.update(extra)
        if case["response"] is not None:
            case["finish_event"] = "authentication_response_return"
        yield case


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
    assert udp.process.digest(binary) == udp.process.boundary.codec.SHA
    assert (
        udp.process.digest(sdk / "libavcodec.so.61") == udp.process.boundary.CODEC_SHA
    )
    assert (
        udp.process.digest(sdk / "libavutil.so.59")
        == udp.process.boundary.codec.SDK_SHA
    )
    functions = udp.process.boundary.inventory(binary.read_bytes(), FUNCTIONS)
    cases = []
    for case in scenarios():
        path = args.output.with_name(args.output.stem + "-" + case["name"] + ".json")
        result = udp.audit(
            binary,
            sdk,
            qt,
            path,
            case,
            helper=ROOT / "scripts/steam-client-auth-gdb.py",
            reactor=Peer,
            probe_config=dict(
                udp_helper=str(ROOT / "scripts/steam-client-udp-gdb.py"),
                finish_event=case["finish_event"],
            ),
            validate=verify,
        )
        cases.append(result)
        print(case["name"], result["process"]["connected_state"], flush=True)
    report = dict(
        scope=__doc__,
        client_sha256=udp.process.digest(binary),
        source_functions=functions,
        helper_sha256=udp.process.digest(ROOT / "scripts/steam-client-auth-gdb.py"),
        udp_helper_sha256=udp.process.digest(ROOT / "scripts/steam-client-udp-gdb.py"),
        bootstrap_helper_sha256=udp.process.digest(
            ROOT / "scripts/steam-client-sdk-gdb.py"
        ),
        archive_url="https://repo.steampowered.com/steamlink/1.3.32.316/steamlink-1.3.32.316.tgz",
        qt_dependency_sha256={
            name: udp.process.digest(
                next(
                    p / f"libQt6{name}.so.6"
                    for p in qt
                    if (p / f"libQt6{name}.so.6").is_file()
                )
            )
            for name in ("Core", "Gui", "Widgets", "Svg")
        },
        qt_required_controller_patch=udp.process.QT_PATCH,
        cases=cases,
    )
    data = (json.dumps(report, indent=2) + "\n").encode()
    args.output.write_bytes(data)
    if args.snapshot:
        args.snapshot.write_bytes(gzip.compress(data, mtime=0))
    print(f"Original UDP authentication: {len(cases)} request/response cases passed")


if __name__ == "__main__":
    main()
