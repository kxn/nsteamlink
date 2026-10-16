#!/usr/bin/env python3
"""Feed original Windows sender output into the original Android receiver.

This joins SHA-pinned sender control/configuration/channel/RS instructions to
Android socket/connection/channel/window/RS instructions. Existing audit doubles
still replace OS, storage, clocks, refcounts, encryption and actual transport.
Payloads are opaque deterministic bytes, not decoded video or live sessions.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import runpy
import struct
import sys


def load_script(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host32-binary", type=Path, required=True)
    parser.add_argument("--host64-binary", type=Path, required=True)
    parser.add_argument("--android-binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    directory = Path(__file__).parent
    modules = {
        32: load_script(directory / "audit-steam-host-fec.py", "host32_audit"),
        64: load_script(directory / "audit-steam-host64-fec.py", "host64_audit"),
    }
    images = {}
    for arch, path in ((32, args.host32_binary), (64, args.host64_binary)):
        binary = path.read_bytes()
        assert hashlib.sha256(binary).hexdigest() == modules[arch].SHA256
        pe = modules[arch].pefile.PE(data=binary)
        images[arch] = pe, pe.get_memory_mapped_image()
    saved = sys.argv
    sys.argv = [
        str(directory / "audit-steam-fec.py"),
        "--binary",
        str(args.android_binary),
        "--output",
        str(args.output.with_name("interop-android-baseline.json")),
    ]
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            android = runpy.run_path(sys.argv[0])
    finally:
        sys.argv = saved

    def host(arch):
        module = modules[arch]
        instance = (module.Host if arch == 32 else module.Host64)(*images[arch])
        if arch == 64:
            instance.u.mem_write(instance.conn + 11, bytes([12, 34]))
        return instance

    def configure(arch, instance, enabled):
        protobuf = b"\x0a\x03\xc8\x01" + bytes([enabled])
        if arch == 32:
            instance.control(99, protobuf)
        else:
            instance.control(protobuf)

    def output(arch, instance):
        return instance.sent if arch == 32 else instance.wires

    def receiver():
        f = android["FEC"]()
        r, ch = f.r, f.channel
        window = ch + 280
        r.b(ch + 16, 3)
        r.w32(ch + 28, 6553)
        r.w32(ch + 240, r.now)
        r.w32(window + 4, 2047)
        r.wq(window + 16, 0x200A0000)
        r.wq(window + 24, 0x200B0000)
        sock, array = 0x20080000, 0x20090000
        r.wq(sock + 8, array)
        r.w32(sock + 24, 1)
        r.wq(array, f.conn)
        r.w32(f.conn + 16, 1)
        r.b(f.conn + 12, 34)
        r.b(f.conn + 13, 12)
        r.w32(f.conn + 1212, 0xFFFFFFFF)
        r.b(f.conn + 11, 0)

        def jump(address):
            r.u.reg_write(android["base"]["UC_ARM64_REG_PC"], address)

        r.callbacks.update(
            {
                0xC11100: lambda: jump(0x7F7230),
                0xC11130: lambda: jump(0x7F76F4),
                0xC11110: lambda: jump(0x7FD204),
                0xC11120: lambda: jump(0x7F743C),
                0xC115A0: lambda: jump(0x7FF640),
                0xC11350: lambda: jump(0x7FACFC),
                0xC0DC80: lambda: r.ret(1),
                0xC11360: lambda: r.ret(),
                0xC11370: lambda: r.ret(),
                0xC0E390: lambda: r.ret(f.channel),
                0xC11250: lambda: jump(0x7F9250),
                0xC11260: lambda: jump(0x7F9940),
            }
        )
        return f, sock

    def receive(f, sock, datagrams):
        before = len(f.delivered)
        for datagram in datagrams:
            f.run(0x7FF3E0, sock, f.packet(datagram), f.r.now)
        f.run(0x7FA3B0, f.channel, f.r.now)
        return [data[13:] for data in f.delivered[before:]]

    def describe(datagrams):
        return [
            {
                "type": data[0] & 127,
                "sequence": struct.unpack_from("<H", data, 7)[0],
                "shard": struct.unpack_from("<H", data, 5)[0],
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            for data in datagrams
        ]

    cases = []
    for arch in (32, 64):
        for dropped, order in (
            ([], [0, 1, 2, 3]),
            ([1], [0, 2, 3]),
            ([0, 1], [2, 3]),
            ([1], [3, 2, 0]),
        ):
            h = host(arch)
            configure(arch, h, True)
            ch = h.video(4)
            payload = bytes((i * 19) & 255 for i in range(3000))
            h.send(ch, payload)
            datagrams = output(arch, h)
            assert len(datagrams) == 4
            f, sock = receiver()
            actual = receive(f, sock, [datagrams[i] for i in order])
            assert actual == ([payload] if len(dropped) <= 1 else [])
            cases.append(
                {
                    "name": f"win{arch}_erase_{dropped}_order_{order}",
                    "input": {
                        "host_arch": arch,
                        "fec": True,
                        "video_codec": 4,
                        "payload_bytes": 3000,
                        "payload_recipe": "byte[i] = (i * 19) & 255",
                        "dropped_shards": dropped,
                        "receive_order": order,
                    },
                    "observed": {
                        "sender_packets": describe(datagrams),
                        "delivered_count": len(actual),
                        "delivered_payload_sha256": [
                            hashlib.sha256(v).hexdigest() for v in actual
                        ],
                    },
                }
            )

        for prior_count in (1, 3):
            h = host(arch)
            configure(arch, h, False)
            ch = h.video(4)
            f, sock = receiver()
            stages = []

            def send(label, value):
                before = len(output(arch, h))
                payload = bytes([value]) * 100
                h.send(ch, payload)
                datagrams = output(arch, h)[before:]
                actual = receive(f, sock, datagrams)
                if actual:
                    assert actual == [payload]
                stages.append(
                    {
                        "stage": label,
                        "value": value,
                        "sender_packets": describe(datagrams),
                        "delivered_count": len(actual),
                        "ordinary_head": f.r.h(f.channel + 288),
                    }
                )
                return bool(actual)

            for i in range(prior_count):
                assert send("ordinary_before", 65 + i)
            configure(arch, h, True)
            assert send("fec", 80)
            configure(arch, h, False)
            for i in range(prior_count + 1):
                actual = send("ordinary_after", 90 + i)
                assert actual == (arch == 32 or i == prior_count)
            cases.append(
                {
                    "name": f"win{arch}_toggle_after_{prior_count}_ordinary_frames",
                    "input": {
                        "host_arch": arch,
                        "updates": [False, True, False],
                        "ordinary_before_count": prior_count,
                        "post_toggle_count": prior_count + 1,
                        "video_codec": 4,
                        "payload_bytes_each": 100,
                    },
                    "observed": {"stages": stages, "delivered_total": len(f.delivered)},
                }
            )

    # Identical emitted bytes, not just identical tables or equal shard counts.
    for old, new in zip(cases[:4], cases[6:10]):
        assert old["observed"]["sender_packets"] == new["observed"]["sender_packets"]

    result = {
        "host32_sha256": modules[32].SHA256,
        "host64_sha256": modules[64].SHA256,
        "android_sha256": hashlib.sha256(args.android_binary.read_bytes()).hexdigest(),
        "scope": __doc__,
        "case_count": len(cases),
        "cases": cases,
    }
    fixture = directory / "fixtures/steam-fec-interoperability-reference.json"
    assert fixture.is_file(), "Missing fixed original-code reference"
    assert result == json.loads(
        fixture.read_text()
    ), "Cross-binary replay differs from fixed reference"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(
        f"PASS: {len(cases)} original sender/receiver interoperability cases; {args.output}"
    )


if __name__ == "__main__":
    main()
