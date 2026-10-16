#!/usr/bin/env python3
"""Execute current Windows x64 host FEC/raw activation and mode transitions.

Pinned official SteamUI instructions perform protobuf parsing, control dispatch,
configuration application, channel construction/reset, coding and queue draining.
Doubles replace allocation/free, OS locks, logs/name lookup, ticks, platform-ID
lookup (unrelated bitrate cap), outbound control encryption/reliable delivery,
and final socket sends. No authenticated host, live network or device is tested.
"""
import argparse
import hashlib
import json
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

import pefile
import struct
import unicorn
from collections import deque
from pathlib import Path
from unicorn.x86_const import (
    UC_X86_REG_RAX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDX,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_RIP,
    UC_X86_REG_RSP,
)

SHA256 = "1b9457943205dc3af0bd53463ba331cbd2a381388699705c02271aac7a2b1252"
NODES = {
    0x13A1ECA00: "server_dispatch",
    0x13A1EF170: "initial_config_handler",
    0x13A6FD1D0: "protobuf_parse",
    0x13A4627A0: "client_config_wire_parser",
    0x13A47CD90: "config_copy",
    0x13A1F5C10: "apply_config",
    0x13A1E82B0: "set_channel_mode",
    0x13A1E5AB0: "reset_previous_mode",
    0x13A1E7220: "purge_fec_queue",
    0x13A1E72D0: "purge_raw_queue",
    0x13A1E52B0: "clear_ordinary_window",
    0x13A1E8240: "set_fec_percentage",
    0x13A1F5580: "start_video",
    0x13A1F4F00: "start_audio",
    0x13A1E7CF0: "send_unreliable",
    0x13A1E7AD0: "channel_send",
    0x13A1E3D60: "fec_encode",
    0x13A1E9D70: "rs_create",
    0x13A1E76F0: "fec_drain",
    0x13A1E7800: "raw_drain",
}


class Host64:
    def __init__(self, p, image):
        self.pe = p
        self.u = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        self.base = p.OPTIONAL_HEADER.ImageBase
        self.u.mem_map(self.base, (p.OPTIONAL_HEADER.SizeOfImage + 4095) & ~4095)
        self.u.mem_write(self.base, image)
        self.u.mem_map(0x20000000, 0x2000000)
        self.u.mem_map(0x40000000, 0x10000)
        self.heap = 0x20100000
        self.sizes = {}
        self.hooks = {}
        self.events = deque(maxlen=50)
        self.visited = set()
        self.controls = []
        self.wires = []
        self.attempts = []
        self.socket_result = 0
        self.u.hook_add(unicorn.UC_HOOK_CODE, self.hook)
        for lib in p.DIRECTORY_ENTRY_IMPORT:
            for x in lib.imports:
                n = x.name.decode() if x.name else ""
                if "AssertFailed" in n:
                    a = 0x40000100 + len(self.hooks) * 16
                    self.qw(x.address, a)
                    self.hooks[a] = self.assertion
                elif n in (
                    "EnterCriticalSection",
                    "LeaveCriticalSection",
                    "InitializeCriticalSection",
                    "DeleteCriticalSection",
                    "Log",
                    "Error",
                ) or n.startswith("??0CThreadMutex"):
                    a = 0x40000100 + len(self.hooks) * 16
                    self.qw(x.address, a)
                    self.hooks[a] = lambda: self.ret(0)
        self.hooks.update(
            {
                0x13A59A3C0: lambda: self.ret(self.alloc(self.arg(0))),
                0x13A59A410: lambda: self.ret(),
                0x13AC31740: self.memset,
                0x13A1E9F50: lambda: self.ret(900000),
                0x13A1E9EC0: lambda: self.ret(0x13AC5D040),
                0x13A1E1090: lambda: self.ret(),
                0x13A1E22D0: self.control_send,
                0x13A8B5670: lambda: self.ret(0),
                0x13A1F6C10: self.socket_send,
            }
        )
        global_slot, allocator, vt = self.alloc(8), self.alloc(8), self.alloc(256)
        self.qw(0x13AC4B3A8, global_slot)
        self.qw(global_slot, allocator)
        self.qw(allocator, vt)
        for off, cb in [
            (0x10, lambda: self.ret(self.alloc(self.arg(1)))),
            (0x18, lambda: self.ret(self.alloc(self.arg(1)))),
            (0x20, self.realloc),
            (0x38, lambda: self.ret()),
            (0x40, lambda: self.ret()),
        ]:
            a = 0x40001000 + len(self.hooks) * 16
            self.qw(vt + off, a)
            self.hooks[a] = cb
        self.server = self.alloc(0x6000)
        self.conn = self.alloc(0x1000)
        self.qw(self.server + 0x30, self.conn)
        self.w(self.server + 0x94, 7)
        self.w(self.conn + 0x10, 1)
        self.qw(self.conn, self.alloc(0x1000))
        self.w(self.server + 0x340, 1)
        self.slots = self.alloc(16)
        self.qw(self.server + 0x350, self.slots)
        self.w(self.server + 0x344, 0xFFFFFFFF)
        self.w(self.server + 0x348, 0xFFFFFFFF)
        self.call(0x13A47A2A0, self.server + 0x190, 0)
        self.w(0x13B0BBDA8, 1500)

    def r(self, x):
        return self.u.reg_read(x)

    def rd(self, a):
        return struct.unpack("<I", self.u.mem_read(a, 4))[0]

    def q(self, a):
        return struct.unpack("<Q", self.u.mem_read(a, 8))[0]

    def w(self, a, n):
        self.u.mem_write(a, struct.pack("<I", n & 0xFFFFFFFF))

    def qw(self, a, n):
        self.u.mem_write(a, struct.pack("<Q", n))

    def alloc(self, n):
        a = self.heap
        assert 0 <= n <= 0x400000
        self.heap += (max(1, n) + 15) & ~15
        assert self.heap < 0x21F00000
        self.sizes[a] = n
        return a

    def arg(self, n):
        return (
            self.r([UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9][n])
            if n < 4
            else self.q(self.r(UC_X86_REG_RSP) + 40 + (n - 4) * 8)
        )

    def ret(self, n=0):
        sp = self.r(UC_X86_REG_RSP)
        self.u.reg_write(UC_X86_REG_RAX, n)
        self.u.reg_write(UC_X86_REG_RIP, self.q(sp))
        self.u.reg_write(UC_X86_REG_RSP, sp + 8)

    def memset(self):
        a, v, n = [self.arg(i) for i in range(3)]
        self.u.mem_write(a, bytes([v & 255]) * n)
        self.ret(a)

    def realloc(self):
        old, n = self.arg(1), self.arg(2)
        new = self.alloc(n)
        if old:
            self.u.mem_write(new, bytes(self.u.mem_read(old, min(self.sizes[old], n))))
        self.ret(new)

    def control_send(self):
        if not self.arg(2):
            return
        self.controls.append(self.u.mem_read(self.arg(0) + 0x19, 1)[0])
        self.ret()

    def socket_send(self):
        p = self.arg(2)
        data = bytes(self.u.mem_read(self.q(p + 0x28), self.rd(p + 0x34)))
        self.attempts.append(data)
        if self.socket_result == 0:
            self.wires.append(data)
        self.ret(self.socket_result)

    def hook(self, u, a, n, _):
        self.events.append(a)
        if a in NODES:
            self.visited.add(NODES[a])
        if a == 0x40000000:
            self.u.emu_stop()
        elif a in self.hooks:
            self.hooks[a]()

    def call(self, a, *args):
        sp = 0x200EFFF8
        self.qw(sp, 0x40000000)
        for i, v in enumerate(args):
            if i < 4:
                self.u.reg_write(
                    [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9][i], v
                )
            else:
                self.qw(sp + 40 + (i - 4) * 8, v)
        self.u.reg_write(UC_X86_REG_RSP, sp)
        try:
            self.u.emu_start(a, 0, count=5000000)
        except Exception as e:
            raise RuntimeError(
                f"{e},pc={self.r(UC_X86_REG_RIP):x},trace={[hex(x) for x in self.events]}"
            ) from e
        assert self.r(UC_X86_REG_RIP) == 0x40000000, (
            hex(self.r(UC_X86_REG_RIP)),
            [hex(x) for x in self.events],
        )
        return self.r(UC_X86_REG_RAX)

    def packet(self, data):
        p, b = self.alloc(0x928), self.alloc(max(4096, len(data)))
        self.u.mem_write(b, data)
        self.w(p, 2)
        self.qw(p + 0x28, b)
        self.w(p + 0x30, max(4096, len(data)))
        self.w(p + 0x34, len(data))
        self.qw(p + 0x38, b)
        return p

    def control(self, data, kind=99, state=None):
        if state is not None:
            self.w(self.server + 0x94, state)
        p = self.packet(
            struct.pack("<BBBBBHHI", 5, 0, 34, 12, 1, 0, 0, 900000)
            + bytes([kind])
            + data
        )
        self.qw(self.slots, p)
        self.w(self.server + 0x344, 0)
        self.w(self.server + 0x348, 0)
        self.call(0x13A1ECA00, self.server)

    def assertion(self):
        raise AssertionError(
            f"Original assertion at {self.q(self.r(UC_X86_REG_RSP)):x}"
        )

    def channel(self, ch):
        return self.q(self.conn + 0x68 + ch * 8)

    def video(self, codec=4):
        self.call(0x13A1F5580, self.server, codec, 0, 1920, 1080, 0)
        return self.u.mem_read(self.server + 0x2FE, 1)[0]

    def audio(self, codec=3):
        self.call(0x13A1F4F00, self.server, codec, 48000, 2, 0)
        return self.u.mem_read(self.server + 0x2FD, 1)[0]

    def send(self, ch, payload):
        p = self.packet(bytes(13) + payload)
        result = self.call(0x13A1E7CF0, self.conn, p, ch)
        return result, self.u.mem_read(self.q(p + 0x28), 1)[0]

    def observe(self):
        ch = self.u.mem_read(self.server + 0x2FE, 1)[0]
        c = self.channel(ch)
        return {
            "config_fec": self.u.mem_read(self.server + 0x201, 1)[0],
            "server_state": self.rd(self.server + 0x94),
            "video_channel": ch,
            "video_mode": self.rd(c + 0x20) if c else None,
            "controls": self.controls,
            "visited": sorted(self.visited),
        }


def wire_summary(data):
    result = {
        "type": data[0] & 127,
        "channel": data[4],
        "bytes": len(data),
        "header": data[:13].hex(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    if result["type"] == 11:
        length, shard, redundancy = struct.unpack_from("<IHH", data, 13)
        result.update(
            length=length,
            shard_size=shard,
            redundancy=redundancy,
            shard_index=struct.unpack_from("<H", data, 5)[0],
            group=struct.unpack_from("<H", data, 7)[0],
        )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == SHA256, "Unsupported x64 SteamUI.dll"
    pe = pefile.PE(data=binary)
    assert pe.OPTIONAL_HEADER.ImageBase == 0x13A000000
    image = pe.get_memory_mapped_image()
    schema_bytes = binary[0xD55800 : 0xD55800 + 21827]
    schema = descriptor_pb2.FileDescriptorProto.FromString(schema_bytes)
    assert schema.name == "steammessages_remoteplay.proto"
    pool = descriptor_pool.DescriptorPool()
    pool.Add(schema)

    def message(name, **fields):
        return message_factory.GetMessageClass(pool.FindMessageTypeByName(name))(
            **fields
        )

    def config(value):
        return message(
            "CStreamingClientConfig",
            **({} if value is None else {"enable_unreliable_fec": value}),
        )

    def update(value):
        return message(
            "CSetStreamingClientConfig", config=config(value)
        ).SerializeToString()

    cases = []

    def record(name, inputs, host, **extra):
        cases.append(
            {"name": name, "input": inputs, "observed": dict(host.observe(), **extra)}
        )

    for value in (None, False, True):
        h = Host64(pe, image)
        payload = message(
            "CNegotiationSetConfigMsg",
            config=message("CNegotiatedConfig"),
            streaming_client_config=config(value),
        ).SerializeToString()
        h.control(payload, kind=4, state=6)
        channel = h.video()
        assert h.rd(h.channel(channel) + 0x20) == bool(value)
        assert {
            "initial_config_handler",
            "config_copy",
            "apply_config",
            "client_config_wire_parser",
        } <= h.visited
        record(
            f"initial_{value}",
            {
                "message": 4,
                "state": 6,
                "protobuf": payload.hex(),
                "start_video_codec": 4,
            },
            h,
        )

    for state in (6, 7, 8, 9):
        for value in (None, False, True):
            h = Host64(pe, image)
            channel = h.video()
            h.controls.clear()
            h.visited.clear()
            payload = update(value)
            h.control(payload, state=state)
            assert h.rd(h.channel(channel) + 0x20) == (bool(value) and state in (7, 8))
            assert ("config_copy" in h.visited) == (state in (7, 8))
            assert not h.controls
            record(
                f"runtime_{state}_{value}",
                {
                    "message": 99,
                    "state": state,
                    "protobuf": payload.hex(),
                    "active_video_codec": 4,
                },
                h,
            )

    for codec in (4, 5, 8, 9):
        for value in (False, True):
            h = Host64(pe, image)
            h.control(update(value))
            channel = h.video(codec)
            result, packet_type = h.send(
                channel, bytes((i * 19) & 255 for i in range(3000))
            )
            expected_mode = 2 if codec == 9 else int(value)
            assert h.rd(h.channel(channel) + 0x20) == expected_mode
            assert packet_type == (3, 11, 12)[expected_mode]
            assert h.rd(h.channel(channel) + 0x24) == 5
            if expected_mode == 1:
                assert len(h.wires) == 4 and "rs_create" in h.visited
                assert all(wire_summary(w)["redundancy"] == 1 for w in h.wires)
            elif expected_mode == 2:
                assert len(h.wires) == 1 and "raw_drain" in h.visited
                assert h.wires[0][13:] == bytes((i * 19) & 255 for i in range(3000))
                assert "fec_encode" not in h.visited
            record(
                f"video_codec_{codec}_fec_{value}",
                {
                    "codec": codec,
                    "fec": value,
                    "payload_bytes": 3000,
                    "payload_recipe": "byte[i] = (i * 19) & 255",
                    "mtu": 1500,
                },
                h,
                result=result,
                wires=[wire_summary(w) for w in h.wires],
            )

    for value in (False, True):
        for codec in (1, 3):
            h = Host64(pe, image)
            h.control(update(value))
            channel = h.audio(codec)
            h.send(channel, bytes(range(100)))
            assert h.rd(h.channel(channel) + 0x20) == 0
            assert h.rd(h.channel(channel) + 0x24) == (0 if codec == 3 else 5)
            assert len(h.wires) == 1 and h.wires[0][0] == 3
            record(
                f"fresh_audio_{codec}_fec_{value}",
                {"audio_codec": codec, "fec": value, "new_connection": True},
                h,
                audio_mode=0,
                audio_fec_percentage=h.rd(h.channel(channel) + 0x24),
                wires=[wire_summary(w) for w in h.wires],
            )

    for old, new in ((False, True), (True, False), (True, True), (False, False)):
        h = Host64(pe, image)
        h.control(update(old))
        channel = h.video()
        h.socket_result = 1
        h.send(channel, bytes((i * 19) & 255 for i in range(3000)))
        assert len(h.attempts) == 1 and not h.wires
        h.visited.clear()
        h.control(update(new))
        assert ("reset_previous_mode" in h.visited) == (old != new)
        h.socket_result = 0
        if old:
            h.call(0x13A1E76F0, h.channel(channel) + 0x128, h.conn, h.q(h.conn))
        else:
            h.call(0x13A1E7D60, h.channel(channel), 0)
        assert bool(h.wires) == (old == new)
        drained = [wire_summary(w) for w in h.wires]
        result, packet_type = h.send(channel, bytes(range(100)))
        assert packet_type == (11 if new else 3)
        record(
            f"transition_{old}_{new}",
            {
                "updates": [old, new],
                "blocked_payload_bytes": 3000,
                "first_socket_result": 1,
                "drain_socket_result": 0,
            },
            h,
            old_queue_drained=drained,
            subsequent_packet_type=packet_type,
            result=result,
        )

    for value in (False, None):
        h = Host64(pe, image)
        h.control(update(True))
        channel = h.video()
        h.control(update(value))
        assert h.rd(h.channel(channel) + 0x20) == 0
        record(f"disable_{value}", {"updates": [True, value]}, h)

    # A valid FEC toggle alone cannot leave Pyrowave's raw mode.
    for value in (False, True):
        h = Host64(pe, image)
        h.control(update(not value))
        channel = h.video(9)
        h.visited.clear()
        h.control(update(value))
        assert h.rd(h.channel(channel) + 0x20) == 2
        assert "reset_previous_mode" not in h.visited
        record(
            f"pyrowave_toggle_{value}", {"codec": 9, "updates": [not value, value]}, h
        )

    h = Host64(pe, image)
    h.control(update(True))
    channel = h.video(9)
    h.socket_result = 1
    h.send(channel, bytes(range(100)))
    h.control(update(False))
    h.socket_result = 0
    h.call(0x13A1E7800, h.channel(channel) + 0x1A8, h.conn, h.q(h.conn))
    assert len(h.wires) == 1 and h.wires[0][0] == 12
    record(
        "pyrowave_fec_toggle_preserves_raw_queue",
        {
            "codec": 9,
            "updates": [True, False],
            "first_socket_result": 1,
            "drain_socket_result": 0,
        },
        h,
        wires=[wire_summary(w) for w in h.wires],
    )

    # StartVideo allocates the next channel ID before applying config. Cleanup
    # concerns the reused ID, not every channel that belonged to an older codec.
    h = Host64(pe, image)
    h.control(update(True))
    old_channel = h.video(9)
    h.socket_result = 1
    h.send(old_channel, bytes(range(100)))
    h.visited.clear()
    allocated = [h.video(4) for _ in range(29)]
    assert allocated == list(range(4, 32)) + [3]
    assert "purge_raw_queue" in h.visited
    h.socket_result = 0
    h.call(0x13A1E7800, h.channel(old_channel) + 0x1A8, h.conn, h.q(h.conn))
    assert not h.wires
    record(
        "reused_video_channel_purges_previous_raw_mode",
        {
            "initial_codec": 9,
            "restart_codecs": [4] * 29,
            "fec": True,
            "blocked_old_payload_bytes": 100,
        },
        h,
        allocated_channels=allocated,
        drained_old_raw_packets=0,
    )

    result = {
        "binary_sha256": SHA256,
        "schema_sha256": hashlib.sha256(schema_bytes).hexdigest(),
        "original_nodes": {name: hex(address) for address, name in NODES.items()},
        "case_count": len(cases),
        "cases": cases,
    }
    fixture = Path(__file__).with_name("fixtures") / "steam-host64-fec-reference.json"
    assert fixture.is_file(), "Missing fixed original-code reference"
    assert result == json.loads(
        fixture.read_text()
    ), "Original x64 replay differs from fixed reference"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(f"PASS: {len(cases)} original Windows x64 host cases; {args.output}")


if __name__ == "__main__":
    main()
