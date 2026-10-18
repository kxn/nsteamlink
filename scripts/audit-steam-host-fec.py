#!/usr/bin/env python3
"""Replay SHA-pinned Windows SteamUI FEC activation from plaintext control packets.

Original x86 instructions perform frame extraction, protobuf parsing/CopyFrom,
server dispatch, configuration application, stream/channel setup, FEC encoding
and queue draining. Explicit doubles replace allocation, OS locks, time, logging,
outbound control encryption/reliable delivery, and the final socket send. No
Steam process, device, authentication, ciphertext or real network is exercised.
"""
import argparse
from collections import deque
import hashlib
import json
from pathlib import Path
import struct

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
import pefile
import unicorn
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_ESP


SHA256 = "0cad7c69ace13e802be17beb06df299f7f733f01b4450a74bc68709494b21ddb"
BASE, STOP = 0x3A000000, 0x40000000
NODES = {
    0x3A16A4A0: "server_dispatch",
    0x3A16C870: "initial_config_handler",
    0x3A16A882: "runtime_config_handler",
    0x3A5718E0: "protobuf_parse",
    0x3A371990: "client_config_wire_parser",
    0x3A388A60: "client_config_copy_from",
    0x3A171E40: "apply_config",
    0x3A172298: "assign_outgoing_fec",
    0x3A171470: "server_config_api",
    0x3A1715D0: "start_audio",
    0x3A171880: "start_video",
    0x3A167200: "set_channel_fec_percentage",
    0x3A166B70: "send_unreliable",
    0x3A163A30: "fec_add_packet",
    0x3A1686B0: "rs_create",
    0x3A1668F0: "fec_drain",
}


class Host:
    def __init__(self, pe, image):
        self.u = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        self.u.mem_map(BASE, (pe.OPTIONAL_HEADER.SizeOfImage + 4095) & ~4095)
        self.u.mem_write(BASE, image)
        # fs:0 is only the single-threaded Windows SEH registration slot.
        self.u.mem_map(0, 4096)
        self.u.mem_map(0x20000000, 0x2000000)
        self.u.mem_map(STOP, 0x10000)
        self.heap, self.sizes = 0x20100000, {}
        self.hooks, self.visited = {}, set()
        self.trace = deque(maxlen=32)
        self.controls, self.attempts, self.sent = [], [], []
        self.socket_result = 0
        self.u.hook_add(unicorn.UC_HOOK_CODE, self.instruction)

        def imported(iat, address, callback):
            self.w(iat, address)
            self.hooks[address] = callback

        imported(0x3A9F143C, STOP + 0x100, lambda: self.ret(0, 4))
        imported(0x3A9F1438, STOP + 0x110, lambda: self.ret(0, 4))
        imported(0x3A9F1930, STOP + 0x120, lambda: self.ret(self.reg(UC_X86_REG_ECX)))
        imported(0x3A9F19A0, STOP + 0x130, lambda: self.ret())
        imported(0x3A9F1898, STOP + 0x140, self.assertion)
        # Error() is an imported diagnostic, not a protocol branch.
        for lib in pe.DIRECTORY_ENTRY_IMPORT:
            for symbol in lib.imports:
                if symbol.name == b"Error":
                    imported(symbol.address, STOP + 0x150, lambda: self.ret())

        self.hooks.update(
            {
                0x3A8941E0: self.memset,
                0x3A893C60: self.memcpy,
                0x3A469C10: lambda: self.ret(self.alloc(self.arg(0))),
                0x3A469C40: lambda: self.ret(),
                0x3A168820: lambda: self.ret(900000),
                # Message-name diagnostic takes a Steam lock; it does not dispatch.
                0x3A168790: lambda: self.ret(0x3A9F5340),
                0x3A160F60: lambda: self.ret(0, 16),
                0x3A161D70: self.control_send,
                0x3A172AF0: self.socket_send,
            }
        )
        global_slot, allocator, vtable = self.alloc(4), self.alloc(4), self.alloc(128)
        self.w(0x3A9F189C, global_slot)
        self.w(global_slot, allocator)
        self.w(allocator, vtable)
        for offset, address, callback in (
            (8, STOP + 0x200, lambda: self.ret(self.alloc(self.arg(0)), 20)),
            (12, STOP + 0x210, lambda: self.ret(self.alloc(self.arg(0)), 4)),
            (16, STOP + 0x220, self.realloc),
            (28, STOP + 0x230, lambda: self.ret(0, 8)),
            (32, STOP + 0x240, lambda: self.ret(0, 4)),
        ):
            self.w(vtable + offset, address)
            self.hooks[address] = callback

        self.server, self.conn = self.alloc(0x5000), self.alloc(0x1000)
        self.w(self.server + 0x18, self.conn)
        self.w(self.server + 0x6C, 7)
        self.w(self.conn + 0xC, 1)
        self.put(self.conn + 8, bytes([12, 34]))
        self.w(self.conn, self.alloc(0x1000))
        self.call(0x3A386B80, self.server + 0x11C, [0])
        self.w(self.server + 0x23C, 1)
        self.slots = self.alloc(8)
        self.w(self.server + 0x24C, self.slots)
        self.w(self.server + 0x240, 0xFFFFFFFF)
        self.w(self.server + 0x244, 0xFFFFFFFF)
        self.w(0x3ACB1220, 1500)
        self.visited.clear()

    def reg(self, register):
        return self.u.reg_read(register)

    def read(self, address):
        return struct.unpack("<I", self.u.mem_read(address, 4))[0]

    def byte(self, address):
        return self.u.mem_read(address, 1)[0]

    def w(self, address, value):
        self.put(address, struct.pack("<I", value & 0xFFFFFFFF))

    def put(self, address, value):
        self.u.mem_write(address, value)

    def arg(self, index):
        return self.read(self.reg(UC_X86_REG_ESP) + 4 + index * 4)

    def alloc(self, size):
        assert 0 <= size <= 0x400000
        address = self.heap
        self.heap += (max(1, size) + 15) & ~15
        assert self.heap < 0x21F00000
        self.sizes[address] = size
        return address

    def ret(self, value=0, pop=0):
        stack = self.reg(UC_X86_REG_ESP)
        self.u.reg_write(UC_X86_REG_EAX, value)
        self.u.reg_write(UC_X86_REG_EIP, self.read(stack))
        self.u.reg_write(UC_X86_REG_ESP, stack + 4 + pop)

    def memset(self):
        address, value, size = [self.arg(i) for i in range(3)]
        if size:
            self.put(address, bytes([value & 255]) * size)
        self.ret(address)

    def memcpy(self):
        dest, source, size = [self.arg(i) for i in range(3)]
        if size:
            self.put(dest, bytes(self.u.mem_read(source, size)))
        self.ret(dest)

    def realloc(self):
        old, size = self.arg(0), self.arg(1)
        new = self.alloc(size)
        if old:
            self.put(new, bytes(self.u.mem_read(old, min(size, self.sizes[old]))))
        self.ret(new, 20)

    def assertion(self):
        raise AssertionError(
            f"Original AssertFailed at caller {self.read(self.reg(UC_X86_REG_ESP)):x}"
        )

    def control_send(self):
        if self.arg(1) == 0:
            return  # Execute the original media SendFrame instructions.
        frame = self.reg(UC_X86_REG_ECX)
        self.controls.append(self.byte(frame + 0x11))
        self.ret(0, 8)

    def socket_send(self):
        packet = self.arg(1)
        data = bytes(
            self.u.mem_read(self.read(packet + 0x20), self.read(packet + 0x28))
        )
        self.attempts.append(data)
        if self.socket_result == 0:
            self.sent.append(data)
        self.ret(self.socket_result, 8)

    def instruction(self, _uc, address, _size, _user):
        self.trace.append(address)
        if address in NODES:
            self.visited.add(NODES[address])
        if address == STOP:
            self.u.emu_stop()
        elif address in self.hooks:
            self.hooks[address]()

    def call(self, address, this=0, args=(), edx=0):
        stack = 0x200F0000
        self.w(stack, STOP)
        for index, value in enumerate(args):
            self.w(stack + 4 + index * 4, value)
        self.u.reg_write(UC_X86_REG_ESP, stack)
        self.u.reg_write(UC_X86_REG_ECX, this)
        self.u.reg_write(UC_X86_REG_EDX, edx)
        try:
            self.u.emu_start(address, 0, count=5000000)
        except unicorn.UcError as error:
            raise RuntimeError(
                f"{error}; pc={self.reg(UC_X86_REG_EIP):x}; trace={list(self.trace)}"
            ) from error
        assert self.reg(UC_X86_REG_EIP) == STOP, list(self.trace)
        return self.reg(UC_X86_REG_EAX)

    def packet(self, data):
        packet, buffer = self.alloc(0x914), self.alloc(max(0x1000, len(data)))
        self.put(buffer, data)
        self.w(packet, 2)  # Test owns one reference while dispatcher owns another.
        self.w(packet + 0x20, buffer)
        self.w(packet + 0x2C, buffer)
        self.w(packet + 0x24, max(0x1000, len(data)))
        self.w(packet + 0x28, len(data))
        return packet

    def control(self, kind, protobuf, *, state=None, channel=1):
        if state is not None:
            self.w(self.server + 0x6C, state)
        data = struct.pack("<BBBBBHHI", 5, 0, 34, 12, channel, 0, 0, 900000)
        data += bytes([kind]) + protobuf
        self.w(self.slots, self.packet(data))
        self.w(self.server + 0x240, 0)
        self.w(self.server + 0x244, 0)
        self.call(0x3A16A4A0, self.server)

    def channel(self, number):
        return self.read(self.conn + 0x50 + number * 4)

    def audio(self, codec):
        self.call(0x3A1715D0, self.server, [codec, 48000, 2, 0])
        return self.byte(self.server + 0x20D)

    def video(self, codec=4):
        self.call(0x3A171880, self.server, [codec, 1920, 1080, 0])
        return self.byte(self.server + 0x20E)

    def send(self, channel, payload):
        packet = self.packet(bytes(13) + payload)
        result = self.call(0x3A166B70, self.conn, [packet, channel])
        return result, self.byte(self.read(packet + 0x20))

    def observation(self):
        return {
            "outgoing_fec": self.byte(self.conn + 7),
            "config_fec": self.byte(self.server + 0x165),
            "config_fec_present": bool(self.read(self.server + 0x124) & 0x4000),
            "server_state": self.read(self.server + 0x6C),
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
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    options = parser.parse_args()
    binary = options.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == SHA256, "Unsupported SteamUI.dll"
    pe = pefile.PE(data=binary)
    assert pe.OPTIONAL_HEADER.ImageBase == BASE
    image = pe.get_memory_mapped_image()
    schema_bytes = binary[0xAAAAD0 : 0xAAAAD0 + 20634]
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

    def initial(value):
        return message(
            "CNegotiationSetConfigMsg",
            config=message("CNegotiatedConfig"),
            streaming_client_config=config(value),
        ).SerializeToString()

    records = []

    def record(name, inputs, host, **extra):
        records.append(
            {
                "name": name,
                "input": inputs,
                "observed": dict(host.observation(), **extra),
            }
        )

    for value in (None, False, True):
        h = Host(pe, image)
        payload = initial(value)
        h.control(4, payload, state=6)
        assert h.byte(h.conn + 7) == bool(value)
        assert {
            "initial_config_handler",
            "protobuf_parse",
            "client_config_copy_from",
            "apply_config",
            "assign_outgoing_fec",
        } <= h.visited
        record(
            f"initial_{value}", {"state": 6, "message": 4, "protobuf": payload.hex()}, h
        )

    for state in (1, 3, 5, 6, 7, 8, 9):
        for value in (False, True):
            h = Host(pe, image)
            payload = update(value)
            h.control(99, payload, state=state)
            expected = value and state in (7, 8)
            assert h.byte(h.conn + 7) == expected
            assert ("runtime_config_handler" in h.visited) == (state in (7, 8))
            assert not h.controls  # This receive handler sends no config ACK/echo.
            record(
                f"runtime_{state}_{value}",
                {"state": state, "message": 99, "protobuf": payload.hex()},
                h,
            )

    for final in (False, None):
        h = Host(pe, image)
        h.control(99, update(True))
        h.control(99, update(final))
        assert h.byte(h.conn + 7) == 0
        record(
            f"runtime_disable_{final}",
            {"updates": [update(True).hex(), update(final).hex()]},
            h,
        )

    for payload in (b"\x0a\x03\xc8\x01", b"\x0a\x01\x80"):
        h = Host(pe, image)
        h.control(99, update(True))
        h.visited.clear()
        h.control(99, payload)
        assert h.byte(h.conn + 7) == 1 and "apply_config" not in h.visited
        record(
            "malformed_keeps_previous_" + payload.hex(),
            {"initial_fec": True, "protobuf": payload.hex()},
            h,
        )

    for codec in range(1, 6):
        h = Host(pe, image)
        h.control(99, update(True))
        channel = h.audio(codec)
        rate = h.read(h.channel(channel) + 0x18)
        assert rate == (0 if codec == 3 else 5)
        record(
            f"audio_codec_{codec}",
            {"codec": codec, "frequency": 48000, "channels": 2},
            h,
            channel=channel,
            fec_percentage=rate,
        )
        h.send(channel, bytes(range(100)))
        assert len(h.sent) == (1 if codec == 3 else 2)
        assert all(w[0] == 11 for w in h.sent)
        assert all(
            wire_summary(w)["redundancy"] == (0 if codec == 3 else 1) for w in h.sent
        )
        record(
            f"audio_wire_codec_{codec}",
            {"codec": codec, "fec": True, "payload_recipe": "bytes(range(100))"},
            h,
            wires=[wire_summary(w) for w in h.sent],
        )

    for state in (6, 7, 8):
        for suppress in (False, True):
            h = Host(pe, image)
            source, data = h.alloc(0x5C), h.alloc(16)
            h.call(0x3A386B80, source, [0])
            payload = config(True).SerializeToString()
            h.put(data, payload)
            assert h.call(0x3A5718E0, source, [data, len(payload)]) & 255
            h.w(h.server + 0x6C, state)
            h.call(0x3A171470, h.server, [source, suppress])
            assert h.byte(h.conn + 7) == 1
            assert h.controls == ([99] if state in (7, 8) and not suppress else [])
            record(
                f"host_config_api_{state}_{suppress}",
                {
                    "state": state,
                    "suppress_notification": suppress,
                    "config_protobuf": payload.hex(),
                },
                h,
            )

    for value in (False, True):
        for length in (1, 1472, 1473, 3000, 29440, 29441):
            h = Host(pe, image)
            h.control(99, update(value))
            channel = h.video()
            result, packet_type = h.send(
                channel, bytes((i * 19) & 255 for i in range(length))
            )
            assert h.read(h.channel(channel) + 0x18) == 5
            assert packet_type == (11 if value else 3)
            if value:
                assert {
                    "start_video",
                    "set_channel_fec_percentage",
                    "send_unreliable",
                    "fec_add_packet",
                    "rs_create",
                    "fec_drain",
                } <= h.visited
                first = wire_summary(h.sent[0])
                k = (length + first["shard_size"] - 1) // first["shard_size"]
                assert first["redundancy"] == (k * 5 + 99) // 100
                assert len(h.sent) == k + first["redundancy"]
            record(
                f"video_{value}_{length}",
                {
                    "fec": value,
                    "video_codec": 4,
                    "payload_bytes": length,
                    "payload_recipe": "byte[i] = (i * 19) & 255",
                    "mtu": 1500,
                },
                h,
                result=result,
                packet_type=packet_type,
                wires=[wire_summary(w) for w in h.sent],
            )

    # Retain a blocked FEC group, then disable through the real message handler.
    h = Host(pe, image)
    h.control(99, update(True))
    channel = h.video()
    h.socket_result = 1
    h.send(channel, bytes((i * 19) & 255 for i in range(3000)))
    assert len(h.attempts) == 1 and not h.sent
    before = bytes(h.u.mem_read(h.channel(channel) + 0xCC, 0x18))
    h.control(99, update(False))
    after = bytes(h.u.mem_read(h.channel(channel) + 0xCC, 0x18))
    assert before == after and h.byte(h.conn + 7) == 0
    h.socket_result = 0
    h.call(0x3A1668F0, h.channel(channel) + 0xCC, [h.conn, h.read(h.conn)])
    assert len(h.sent) == 4 and all(w[0] == 11 for w in h.sent)
    _, next_type = h.send(channel, bytes(range(100)))
    assert next_type == 3
    record(
        "disable_preserves_pending_fec",
        {
            "message_updates": [True, False],
            "payload_bytes": 3000,
            "first_socket_result": 1,
            "drain_socket_result": 0,
        },
        h,
        fec_queue_unchanged=before == after,
        subsequent_packet_type=next_type,
        wires=[wire_summary(w) for w in h.sent],
    )

    h = Host(pe, image)
    h.control(99, update(False))
    channel = h.video()
    h.socket_result = 1
    h.send(channel, bytes(range(100)))
    assert len(h.attempts) == 1 and not h.sent
    before = bytes(h.u.mem_read(h.channel(channel) + 0xA4, 0x28))
    h.control(99, update(True))
    after = bytes(h.u.mem_read(h.channel(channel) + 0xA4, 0x28))
    assert before == after
    h.socket_result = 0
    h.call(0x3A166D30, h.channel(channel), [0])
    assert len(h.sent) == 1 and h.sent[0][0] == 3
    _, packet_type = h.send(channel, bytes(range(100)))
    assert packet_type == 11
    record(
        "enable_preserves_pending_ordinary",
        {
            "message_updates": [False, True],
            "first_socket_result": 1,
            "drain_socket_result": 0,
        },
        h,
        ordinary_window_unchanged=before == after,
        wires=[wire_summary(w) for w in h.sent],
    )

    h = Host(pe, image)
    h.control(99, update(True))
    channel = h.video()
    for value in (True, False, True):
        h.control(99, update(value))
        h.send(channel, bytes(range(100)))
    fec_groups = [wire_summary(w)["group"] for w in h.sent if w[0] == 11]
    assert fec_groups == [1, 1, 2, 2]
    assert [w[0] for w in h.sent] == [11, 11, 3, 11, 11]
    record(
        "toggle_does_not_reset_fec_group",
        {"updates": [True, False, True], "payload_recipe": "bytes(range(100))"},
        h,
        wires=[wire_summary(w) for w in h.sent],
    )

    result = {
        "binary_sha256": SHA256,
        "schema_sha256": hashlib.sha256(schema_bytes).hexdigest(),
        "original_nodes": {name: hex(address) for address, name in NODES.items()},
        "case_count": len(records),
        "cases": records,
    }
    fixture = Path(__file__).with_name("fixtures") / "steam-host-fec-reference.json"
    assert fixture.is_file(), "Missing fixed original-code reference"
    assert result == json.loads(
        fixture.read_text()
    ), "Original host replay differs from fixed reference"
    options.output.parent.mkdir(parents=True, exist_ok=True)
    options.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(
        f"PASS: {len(records)} original Windows host FEC activation cases; {options.output}"
    )


if __name__ == "__main__":
    main()
