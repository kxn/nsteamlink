#!/usr/bin/env python3
"""Bound Linux CLIENT FEC entry evidence to original connection/config/mic code.

The pinned Valve client executes its connection/socket factory and constructors,
Connect/SendConnectPacket/HandleConnected, real channel factory, config parser,
copy/serializer/API/control-FIFO dispatcher/peer99 and nonempty microphone
producer/Frame send routing. The control FIFO is an explicitly admitted input
boundary, not Socket/CRC/crypto admission.
Connection completion's delegate is a terminal; client state 6 and negotiated
codec/reliability are a declared post-auth boundary, not a replay of handshake,
negotiation, full Qt startup or capture/encoding. Control encryption, final
Channel sends, connect socket send, registration, save/notify, diagnostic labels,
OS/entropy/clock
and allocation/C++ strings are terminals. Packet bodies retained at those
terminals are plaintext, not encrypted UDP or physical resources.

Memory hooks record original wide/alias writes covering gate and percentages.
Manual percentage/forced-gate cases are labelled capability inputs; they do not
prove a product activation trigger. Static references cover decoded .text FDEs,
RIP-relative addresses and dynamic relocations, not arbitrary indirect calls,
inline/alias writes, uncovered code, other libraries or versions. Bounded lack
of activation does not prove the whole client can never enable outgoing FEC.
"""

import argparse
from collections import Counter
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from elftools.dwarf.callframe import FDE
from elftools.elf.elffile import ELFFile
from unicorn import UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_RIP

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "recovery", ROOT / "scripts/audit-steam-client-avcodec-recovery.py"
)
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)
codec = recovery.codec
FUNCTIONS = {
    0x19BD00: "connection_factory",
    0x19FED0: "socket_adapter_constructor",
    0x19BB80: "connection_constructor",
    0x19A590: "connection_next_id",
    0x19ABF0: "connection_member_constructor_280",
    0x19AEF0: "connection_member_constructor_2f0",
    0x19B870: "connection_member_constructor_358_3f0",
    0x19BB20: "connection_member_constructor_488",
    0x19AA40: "connect",
    0x19A8D0: "send_connect_packet",
    0x198AA0: "packet_constructor",
    0x198AE0: "packet_destructor",
    0x19B720: "handle_connected",
    0x19B0A0: "process_timestamp",
    0x19EAB0: "get_channel",
    0x19E910: "channel_constructor",
    0x19ED10: "set_channel_priority",
    0x19ED60: "set_channel_fec_percentage",
    0x31B480: "start_microphone_stream",
    0x318960: "allocate_channel",
    0x31AE90: "send_microphone_data",
    0x31AF60: "send_control",
    0x1947A0: "frame_send",
    0x1945E0: "frame_constructor",
    0x194540: "frame_destructor",
    0x194730: "frame_put_bytes",
    0x194990: "frame_put_protobuf",
    0x194A80: "frame_read_protobuf",
    0x45A330: "config_constructor",
    0x7C9920: "protobuf_parse_array",
    0x44BD20: "config_byte_size",
    0x7C9A90: "protobuf_serialize_array",
    0x48FCA0: "config_copy",
    0x321F80: "set_client_config",
    0x322060: "on_peer_config",
    0x322B90: "control_fifo_dispatcher",
    0x194520: "frame_packet_constructor",
    0x194400: "frame_assign_packet",
    0x4583F0: "set_config_msg_constructor",
    0x4576F0: "microphone_msg_constructor",
    0x438EA0: "microphone_msg_destructor",
}
TARGETS = {
    0x19ED60,
    0x19EC60,
    0x19DA80,
    0x19D540,
    0x199220,
    0x321F80,
    0x322060,
    0x19BB80,
    0x31AE90,
    0x31B480,
}


class Client(recovery.Recovery):
    def __init__(self, binary, wire, *, crc=False, reliable=False, patch=None):
        self.entered, self.visits = Counter(), Counter()
        self.assertions, self.writes, self.events = [], [], []
        self.conn, self.stage, self.patch_hits = None, "factory", 0
        self.patch = patch
        # Reuse ELF/protobuf process setup without opening an AVCodec decoder.
        codec._ElfReplay.__init__(self, binary)
        # No video-policy/enum-validation shortcuts in this protocol audit.
        for pc in (0x318B50, 0x31F7F0, 0x319360, 0x326EE0, 0x44B100, 0x44B110):
            self.hooks.pop(pc, None)
        if patch:
            pc, before, after = patch
            assert bytes(self.u.mem_read(pc, len(before))) == before
            assert len(before) == len(after)
            self.u.mem_write(pc, after)
        self.u.hook_add(UC_HOOK_MEM_WRITE, self.write)
        self.hooks.update(
            {
                0x1A4530: lambda: self.ret(1000000),
                0x1A9C80: lambda: self.ret(),
                0x1A0AA0: self.registration,
                0x1A0190: self.connect_send,
                0x199DE0: lambda: self.send("reliable"),
                0x19A4B0: lambda: self.send("unreliable"),
                0x19DA80: lambda: self.send("fec_capability"),
                0x194B60: lambda: self.ret(1),
                0x31A010: self.save,
                codec.STOP + 0xF100: self.connected,
                codec.STOP + 0xF110: self.notify,
                codec.STOP + 0xF120: self.retain_transport,
                0x1A5B70: lambda: self.ret(),
                0x1A4610: self.diagnostic_label,
            }
        )
        self.config = self.client + 456
        self.parse_config(self.config, wire)
        self.network = self.alloc(4096)
        transport_vtable = self.alloc(64)
        self.wq(self.network, transport_vtable)
        self.wq(transport_vtable, codec.STOP + 0xF120)
        conn = self.call(0x19BD00, self.network)
        assert conn == self.conn
        self.wq(self.client + 280, conn)
        delegate, vtable = self.alloc(256), self.alloc(256)
        self.wq(delegate, vtable)
        self.wq(vtable + 40, codec.STOP + 0xF100)
        self.wq(conn + 368, delegate)
        player, vtable = self.alloc(256), self.alloc(256)
        self.wq(player, vtable)
        self.wq(vtable + 128, codec.STOP + 0xF110)
        self.wq(self.client + 48, player)
        self.crc, self.reliable = crc, reliable

    def hook(self, u, pc, size, data):
        if pc == 0x1A5610:
            self.assertion()
            return
        if pc in FUNCTIONS:
            self.visits[pc] += 1
        if self.patch and pc == self.patch[0]:
            self.patch_hits += 1
        name = self.names.get(pc, "")
        if name == "rand":
            self.ret(12)  # Declared entropy input for the original ID helper.
        elif name == "_Znwm" and self.arg(0) == 0x4E8:
            assert self.conn is None
            self.conn = self.alloc(self.arg(0))
            self.u.mem_write(self.conn + 8, b"\xa5" * 8)
            self.ret(self.conn)
        else:
            super().hook(u, pc, size, data)

    def write(self, u, access, address, size, value, data):
        target = None
        if self.conn and address <= self.conn + 11 < address + size:
            target = "outgoing_gate"
        elif self.conn:
            for channel in range(32):
                pointer = self.q(self.conn + 112 + 8 * channel)
                if pointer and address < pointer + 36 and pointer + 32 < address + size:
                    target = f"percentage_{channel}"
                    break
        if target:
            self.writes.append(
                [self.stage, u.reg_read(UC_X86_REG_RIP), target, size, value]
            )

    def registration(self):
        assert self.arg(1) == self.conn
        self.events.append(["register_connection"])
        self.ret()

    def retain_transport(self):
        assert self.arg(0) == self.network
        self.events.append(["socket_transport_retain_terminal"])
        self.ret()

    def diagnostic_label(self):
        self.events.append(["diagnostic_label_terminal", self.arg(0), self.arg(1)])
        label = self.alloc(16)
        self.u.mem_write(label, b"diagnostic\0")
        self.ret(label)

    def connect_send(self):
        assert self.arg(1) == self.conn
        p = self.arg(2)  # Original call: socket, connection, packet.
        assert self.i(p + 52) == 17
        self.events.append(
            [
                "connect_send_terminal",
                bytes(self.u.mem_read(self.q(p + 40), self.i(p + 52))).hex(),
            ]
        )
        self.ret(0)

    def connected(self):
        assert self.arg(1) == self.conn
        self.events.append(["connected_delegate_terminal"])
        self.ret()

    def notify(self):
        assert self.arg(1) == self.config
        self.events.append(["config_notify_terminal", self.arg(2)])
        self.ret()

    def save(self):
        self.events.append(["config_save_terminal"])
        self.ret()

    def send(self, kind):
        channel, packet = self.arg(0), self.arg(1)
        self.events.append(
            [
                "channel_send_terminal",
                kind,
                self.u.mem_read(channel + 16, 1)[0],
                bytes(
                    self.u.mem_read(self.q(packet + 56) + 13, self.i(packet + 52) - 13)
                ).hex(),
            ]
        )
        self.ret(0)

    def parse_config(self, obj, wire):
        self.call(0x45A330, obj)
        raw = self.alloc(len(wire) + 32)
        if wire:
            self.u.mem_write(raw, wire)
        assert self.call(0x7C9920, obj, raw, len(wire)) == 1

    def state(self):
        assert not self.assertions, self.assertions
        channels = []
        for channel in range(32):
            pointer = self.q(self.conn + 112 + 8 * channel)
            if pointer:
                channels.append([channel, self.i(pointer + 20), self.i(pointer + 32)])
        return dict(
            stage=self.stage,
            events=list(self.events),
            writes=list(self.writes),
            gate=self.u.mem_read(self.conn + 11, 1)[0],
            crc=self.u.mem_read(self.conn + 10, 1)[0],
            connection_state=self.i(self.conn + 16),
            config=self.serialize_config(),
            channels=channels,
            mic_channel=self.u.mem_read(self.client + 0x273, 1)[0],
        )

    def action(self, op, value=None):
        self.stage, self.events, self.writes = op, [], []
        if op == "connect":
            self.call(0x19AA40, self.conn, self.alloc(24))
        elif op == "connected":
            packet, raw = self.alloc(128), self.alloc(64)
            self.wq(packet + 40, raw)
            self.wq(packet + 56, raw)
            self.wi(packet + 52, 17)
            self.u.mem_write(
                raw, bytes([2 | (128 if self.crc else 0), 0, 7]) + bytes(14)
            )
            self.call(0x19B720, self.conn, packet, 1000000)
        elif op == "post_auth_boundary":
            self.wi(self.client + 256, 6)
            self.wi(self.client + 336, 3)
            self.u.mem_write(self.client + 344, bytes([self.reliable]))
        elif op == "start_mic":
            self.call(0x31B480, self.client, 3, 48000, 2, 0)
        elif op == "send_mic":
            raw = self.alloc(16)
            self.u.mem_write(raw, b"\x11\x22\x33\x44")
            self.call(0x31AE90, self.client, raw, 4)
        elif op == "api":
            wire, local = value
            config = self.alloc(512)
            self.parse_config(config, bytes.fromhex(wire))
            self.call(0x321F80, self.client, config, local)
        elif op == "peer99":
            frame = self.alloc(128)
            self.call(0x1945E0, frame, 1, 99)
            wire = bytes.fromhex(value)
            dest = self.call(0x194730, frame, len(wire))
            if wire:
                self.u.mem_write(dest, wire)
            # Already admitted incoming control FIFO boundary. Original Frame
            # parses this header; dispatcher pops/refcounts/dispatches/frees.
            packet = self.q(frame + 8)
            header = self.q(packet + 40)
            self.u.mem_write(header, b"\x03\x30\0\0\x01")
            self.u.mem_write(self.q(packet + 56) + 13, b"\x63")
            slot = self.alloc(8)
            self.wq(slot, packet)
            self.wi(self.client + 0x2D0, 0)
            self.wi(self.client + 0x2D4, 0)
            self.wi(self.client + 0x2D8, 0)
            self.wq(self.client + 0x2E0, slot)
            self.call(0x1A9B20, packet)
            self.call(0x322B90, self.client)
            assert self.i(self.client + 0x2D4) == 0xFFFFFFFF
            self.call(0x194540, frame)
        elif op == "manual_percentage_capability":
            self.call(0x19ED60, self.conn, 3, value & 0xFFFFFFFF)
        elif op == "forced_gate_capability":
            self.u.mem_write(self.conn + 11, b"\1")
        else:
            raise AssertionError(op)
        return self.state()


def run(binary, case, patch=None):
    r = Client(
        binary,
        bytes.fromhex(case["initial_config"]),
        crc=case["crc"],
        reliable=case["reliable"],
        patch=patch,
    )
    result = dict(case, initial=r.state())
    result["states"] = [r.action(op, value) for op, value in case["actions"]]
    result["entries"] = {FUNCTIONS[pc]: n for pc, n in sorted(r.visits.items())}
    result["patch_hits"] = r.patch_hits
    return result


def scenarios():
    prefix = [
        ["connect", None],
        ["connected", None],
        ["post_auth_boundary", None],
        ["start_mic", None],
        ["send_mic", None],
    ]
    cases = []
    for crc in (False, True):
        for reliable in (False, True):
            for config in ("", "c80100", "c80101"):
                actions = list(prefix)
                for wire in ("c80101", "c80100", "", "0801c80101d00f09"):
                    for local in (0, 1):
                        actions += [["api", [wire, local]], ["send_mic", None]]
                for wire in ("c80100", "c80101", ""):
                    actions += [
                        [
                            "peer99",
                            (
                                bytes([10, len(bytes.fromhex(wire))])
                                + bytes.fromhex(wire)
                            ).hex(),
                        ],
                        ["send_mic", None],
                    ]
                actions += [["peer99", "0a80"], ["send_mic", None]]
                cases.append(
                    dict(
                        name=f"crc{int(crc)}_reliable{int(reliable)}_fec_{config or 'absent'}",
                        crc=crc,
                        reliable=reliable,
                        initial_config=config,
                        actions=actions,
                    )
                )
    for percentage in (0, 5, 20, 100, -1, 2147483647, -2147483648):
        cases.append(
            dict(
                name=f"percentage_{percentage}_capability",
                crc=False,
                reliable=False,
                initial_config="c80101",
                actions=prefix
                + [
                    ["manual_percentage_capability", percentage],
                    ["send_mic", None],
                    ["forced_gate_capability", None],
                    ["send_mic", None],
                ],
            )
        )
    return cases


def static(binary):
    elf = ELFFile(io.BytesIO(binary))
    text = elf.get_section_by_name(".text")
    raw, base = text.data(), text["sh_addr"]
    functions = sorted(
        {
            (f["initial_location"], f["address_range"])
            for f in elf.get_dwarf_info().EH_CFI_entries()
            if isinstance(f, FDE)
        }
    )
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    calls, addresses, incomplete = [], [], []
    instruction_count = decoded_bytes = scanned = 0
    for start, length in functions:
        if not base <= start < base + len(raw):
            continue
        scanned += 1
        end = start
        for pc, size, op, args in cs.disasm_lite(
            raw[start - base : start - base + length], start
        ):
            end = pc + size
            instruction_count += 1
            decoded_bytes += size
            if (
                op in ("call", "jmp")
                and args.startswith("0x")
                and int(args, 16) in TARGETS
            ):
                calls.append(
                    [pc, start, op, int(args, 16), binary[pc : pc + size].hex()]
                )
            match = re.search(r"\[rip ([+-]) (0x[0-9a-f]+)\]", args)
            if match:
                dest = end + (1 if match[1] == "+" else -1) * int(match[2], 16)
                if dest in TARGETS:
                    addresses.append(
                        [pc, start, op, dest, binary[pc : pc + size].hex()]
                    )
        if end != start + length:
            incomplete.append([start, length, end - start])
    relocations = []
    for name in (".rela.dyn", ".rela.plt"):
        for rel in elf.get_section_by_name(name).iter_relocations():
            if rel["r_addend"] in TARGETS:
                relocations.append(
                    [name, rel["r_offset"], rel["r_info_type"], rel["r_addend"]]
                )
    return dict(
        text_start=base,
        text_size=len(raw),
        scanned_fdes=scanned,
        decoded_bytes=decoded_bytes,
        decoded_instructions=instruction_count,
        incomplete_fdes=incomplete,
        calls=calls,
        rip_addresses=addresses,
        relocations=relocations,
    )


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == codec.SHA
    cases = [run(binary, case) for case in scenarios()]
    for case in cases[:12]:
        assert case["initial"]["gate"] == 0
        assert case["initial"]["writes"] == [
            ["factory", 0x19BB9B, "outgoing_gate", 4, 0]
        ]
        expected_config = case["initial_config"]
        for (op, value), state in zip(case["actions"], case["states"], strict=True):
            assert state["gate"] == 0
            assert all(channel[2] == 0 for channel in state["channels"])
            if op == "connected":
                assert state["connection_state"] == 1 and state["crc"] == case["crc"]
            if op == "start_mic":
                assert state["mic_channel"] == 3
                assert [3, 1, 0] in state["channels"]
                assert state["events"] == [
                    ["channel_send_terminal", "reliable", 1, "6b100318032880f7023002"]
                ]
            if op == "api":
                expected_config, local = value
                expected_events = [
                    ["config_notify_terminal", local],
                    ["config_save_terminal"],
                ]
                if not local:
                    expected_events.append(
                        [
                            "channel_send_terminal",
                            "reliable",
                            1,
                            "630a"
                            + format(len(bytes.fromhex(expected_config)), "02x")
                            + expected_config,
                        ]
                    )
                assert state["events"] == expected_events
            if op == "peer99" and value != "0a80":
                expected_config = value[4:]
                assert state["events"] == [
                    ["config_notify_terminal", 1],
                    ["config_save_terminal"],
                    ["diagnostic_label_terminal", 1, 99],
                ]
            assert state["config"] == expected_config
            for event in state["events"]:
                if event[0] == "channel_send_terminal" and event[2] == 3:
                    assert event[1] == (
                        "reliable" if case["reliable"] else "unreliable"
                    )
                    assert event[3].endswith("11223344") and len(event[3]) == 34
    assert all(
        any(name in case["entries"] for case in cases) for name in FUNCTIONS.values()
    )
    previous = codec.FUNCTIONS
    try:
        codec.FUNCTIONS = FUNCTIONS
        inventory = codec.inventory(binary)
    finally:
        codec.FUNCTIONS = previous
    checks = []
    for label, pc, before, after in (
        ("constructor_enables_fec", 0x19BB9B, "c7470800000000", "c7470800000001"),
        ("crc_written_to_fec_gate", 0x19B754, "88470a", "88470b"),
        ("route_from_crc_instead_of_fec", 0x19EC93, "807b0b00", "807b0a00"),
        ("omit_api_local_only_gate", 0x321FD4, "750b", "9090"),
        ("mic_always_unreliable", 0x31AF22, "0fb69358010000", "31d29090909090"),
        ("omit_percentage_store", 0x19ED6C, "895820", "909090"),
    ):
        reference = (
            cases[13]
            if label == "omit_percentage_store"
            else cases[9 if label == "mic_always_unreliable" else 6]
        )
        mutant = run(
            binary,
            {
                k: v
                for k, v in reference.items()
                if k not in ("initial", "states", "entries", "patch_hits")
            },
            (pc, bytes.fromhex(before), bytes.fromhex(after)),
        )
        assert mutant["patch_hits"] > 0
        assert mutant["states"] != reference["states"], label
        checks.append(label)
    return dict(
        binary_sha256=codec.SHA,
        archive_sha256=codec.ARCHIVE_SHA,
        scope=__doc__,
        functions=inventory,
        static=static(binary),
        cases=cases,
        mutation_checks=checks,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--refresh-reference", action="store_true")
    args = parser.parse_args()
    report = audit(args.binary.read_bytes())
    path = ROOT / "scripts/fixtures/steam-client-linux-fec-reference.json.gz"
    encoded = (json.dumps(report, indent=2) + "\n").encode()
    if args.refresh_reference:
        if path.exists():
            assert json.loads(gzip.decompress(path.read_bytes())) == report
        path.write_bytes(gzip.compress(encoded, mtime=0))
    else:
        assert json.loads(gzip.decompress(path.read_bytes())) == report
    args.output.write_bytes(encoded)
    print(
        f"Official Linux FEC: {len(report['cases'])} cases, {sum(len(c['states']) for c in report['cases'])} states, {len(FUNCTIONS)} functions, {len(report['mutation_checks'])} mutations"
    )


if __name__ == "__main__":
    main()
