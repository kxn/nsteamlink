#!/usr/bin/env python3
"""Independently execute official discovery C++ protobuf and Frame instructions.

OnPingRequest, generated constructors/parser/ByteSize/serializer, Frame Get/Put,
padding and destructors execute original ARM64. Input Frame/packet storage is
seeded. Allocation/libc storage and final SendUnconnected are adapters. Captured
bytes exclude the message byte/header/CRC normally written by that final call.
No actual socket, network, host or decoder is exercised.
"""

import argparse
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "client_config", ROOT / "scripts/audit-steam-client-config.py"
)
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == config.SHA
    cases = []
    for data, requested, presence in (
        ("08071000", 0, 3),
        ("08071040", 64, 3),
        ("", 0, 0),
        ("0807", 0, 1),
        ("1040", 64, 2),
    ):
        payload = bytes.fromhex(data)
        r = config.Core(binary)
        client, frame, packet, raw, address = (r.alloc(4096) for _ in range(5))
        request = bytes(13) + b"\x01" + struct.pack("<I", len(payload)) + payload
        r.u.mem_write(raw, request)
        r.wq(frame + 8, packet)
        r.b(frame + 16, 1)
        r.wq(packet + 40, raw)
        r.wq(packet + 56, raw)
        r.wi(packet + 48, 4096)
        r.wi(packet + 52, len(request))
        observed = {}

        def put():
            observed["object_sp_offset"] = r.r(1) - r.u.reg_read(config.SP)
            r.jump(0x7F321C)

        def send():
            p = r.q(r.r(0) + 8)
            ptr, size = r.q(p + 56), r.i(p + 52)
            observed["frame_body"] = bytes(r.u.mem_read(ptr + 14, size - 14)).hex()
            r.ret(0)

        r.callbacks[0xC0E2E0] = put
        r.callbacks[0xC0E760] = send
        assert r.call(0x7ACC20, client, frame, address) == 1
        assert observed["object_sp_offset"] == 88
        body = bytes.fromhex(observed["frame_body"])
        size = struct.unpack_from("<I", body)[0]
        assert body[4 : 4 + size] == payload
        cases.append(
            dict(
                input=dict(protobuf=data, requested=requested, presence=presence),
                observed=observed,
            )
        )
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--refresh-reference", action="store_true")
    args = parser.parse_args()
    report = dict(
        binary_sha256=config.SHA, scope=__doc__, cases=audit(args.binary.read_bytes())
    )
    reference = ROOT / "scripts/fixtures/steam-discovery-protobuf-reference.json"
    if args.refresh_reference:
        if reference.exists():
            assert report == json.loads(reference.read_text())
        reference.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert report == json.loads(reference.read_text())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Official discovery C++ protobuf: {len(report['cases'])} cases passed")


if __name__ == "__main__":
    main()
