#!/usr/bin/env python3
"""Observe official client FEC fields across bounded connection/control/mic paths.

SHA-pinned Android core instructions execute Connection construction/Connect,
HandleConnected -> real client callback/ClientHandshake, actual channel factory,
post-auth control dispatch/negotiation/start, QoS, config API/peer99 and nonempty
StartMicrophoneStream/SendMicrophoneData -> Frame/Connection send routing.

OS locks, socket registration/final connect send, final Channel sends, crypto,
refcounts, stats/player start and config persistence/delegate are adapters.
HandleConnected input is already admitted (17 bytes, after Socket CRC removal).
Auth completion and time are controlled; this is not a full authenticated session,
codec capture/encoding, outgoing windows/RS, UDP wire or device test. No forced
FEC gate/percentage is used. Bounded non-activation does not prove global absence
of another product entry, another upstream producer or a loss-adaptive strategy.
"""

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile
from unicorn import UC_HOOK_MEM_WRITE
from unicorn.arm64_const import UC_ARM64_REG_PC

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "config", ROOT / "scripts/audit-steam-client-config.py"
)
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
CONN, SOCK = 0x20080000, 0x20090000
FUNCTIONS = (
    "_ZN17CStreamConnectionC1EP13CStreamSocket",
    "_ZN17CStreamConnection7ConnectERK10CIPAndPort",
    "_ZN17CStreamConnection17SendConnectPacketEv",
    "_ZN17CStreamConnection15HandleConnectedEP13CStreamPacketj",
    "_ZN13CStreamClient17OnStreamConnectedEP17CStreamConnection",
    "_ZN13CStreamClient21HandleIncomingPacketsEv",
    "_ZN13CStreamClient17OnNegotiationInitER12CStreamFrame",
    "_ZN13CStreamClient22OnNegotiationSetConfigER12CStreamFrame",
    "_ZN13CStreamClient20HandleStreamStartingEv",
    "_ZN13CStreamClient8OnSetQoSER12CStreamFrame",
    "_ZN13CStreamClient24SetStreamingClientConfigERK22CStreamingClientConfigb",
    "_ZN13CStreamClient26OnSetStreamingClientConfigER12CStreamFrame",
    "_ZN13CStreamClient21StartMicrophoneStreamE17EStreamAudioCodeciiPK10CUtlBuffer",
    "_ZN13CStreamClient18SendMicrophoneDataEPKvm",
    "_ZN12CStreamFrame4SendEP17CStreamConnectionb",
    "_ZN17CStreamConnection14SendUnreliableEP13CStreamPacketh",
    "_ZN17CStreamConnection10GetChannelEh",
    "_ZN14CStreamChannelC1EP13CStreamSocketP17CStreamConnectionh",
)


class Client(c.Core):
    def __init__(self, binary, patch=None, patch_hits=None):
        self.patch, self.patch_hits = patch, patch_hits
        self.stage, self.observed, self.channels = "constructor", [], {}
        super().__init__(binary)
        self.callbacks.update(
            {
                0xC0A950: lambda: self.ret(1000000),
                0xC11320: lambda: self.ret(12),
                0xC0E390: lambda: self.jump(0x7FBA34),
                0xC11470: self.channel_ctor,
                0xC11170: self.connect_send,
                0xC111F0: lambda: self.send("reliable"),
                0xC11210: lambda: self.send("unreliable"),
                0xC11230: lambda: self.send("fec"),
                0xC0E110: lambda: self.jump(0x7A7D90),
                0xC10FF0: lambda: self.jump(0x7FB9B4),
                0xC11000: lambda: self.jump(0x7FBB58),
                0xC0E3A0: lambda: self.ret(1),  # plaintext capture, not wire encryption
                0xC0E2F0: lambda: self.jump(0x7F3078),
                0xC0E2A0: lambda: self.jump(0x7FBC68),
                0xC0E250: self.qos,
                0xC0C220: lambda: self.ret(),
                0xC0E290: lambda: self.ret(),
                0xC0E2B0: lambda: self.ret(),
                c.STOP + 0x304: self.connected,
                c.STOP + 0x308: lambda: self.ret(),
                0xC017F0: lambda: self.ret(1),
                0xC01810: self.guard,
                0xC09AB0: lambda: self.ret(self.alloc(self.r(0))),
                0xC09AC0: lambda: self.ret(),
                0xC0E3E0: lambda: self.ret(int(self.r(0) == 4)),
                0xC0E120: lambda: self.ret(),
                0xC0A380: lambda: self.ret(2),
                0xC0A390: lambda: self.ret(1),
            }
        )
        if patch:
            pc, before, after = patch
            assert bytes(self.u.mem_read(pc, 4)) == struct.pack("<I", before)
            self.u.mem_write(pc, struct.pack("<I", after))
        self.u.hook_add(UC_HOOK_MEM_WRITE, self.write)
        # Makes omitted initialization observable. No writes ever force gate=1.
        self.u.mem_write(CONN + 8, b"\xa5" * 8)
        self.call(0x7FB23C, CONN, SOCK)
        self.wq(c.CLIENT + 280, CONN)
        delegate, vt = self.alloc(4096), self.alloc(4096)
        self.wq(delegate, vt)
        self.wq(vt + 40, c.STOP + 0x304)
        self.wq(CONN + 368, delegate)
        self.wq(c.VTABLE + 96, c.STOP + 0x308)
        self.call(self.symbols["_ZN17CNegotiatedConfigC1Ev"], c.CLIENT + 288)
        self.call(self.symbols["_ZN20CStreamingClientCapsC1Ev"], c.CLIENT + 352)

    def hook(self, uc, address, size, data):
        name = self.plts.get(address, "")
        if self.patch and address == self.patch[0]:
            self.patch_hits.append(address)
        if name == "_ZN13CStreamSocket13AddConnectionEP17CStreamConnection":
            assert self.r(0) == SOCK and self.r(1) == CONN
            self.ret()
        elif name.startswith("_ZN16SteamThreadTools12CThreadMutexC"):
            self.ret()
        elif name == "Log":
            self.ret()
        else:
            if address == 0x7FBBD0:
                self.observed.append(dict(event="gate_branch", value=self.r(8)))
            super().hook(uc, address, size, data)

    def channel_ctor(self):
        self.channels[self.r(3)] = self.r(0)
        self.jump(0x7F8630)

    def connected(self):
        assert self.r(1) == CONN
        self.u.reg_write(c.X0, c.CLIENT)
        self.jump(0x7ACE2C)

    def guard(self):
        self.b(self.r(0), 1)
        self.ret()

    def write(self, uc, access, address, size, value, data):
        # Includes wide/alias stores that a STRB-offset static search would miss.
        target = None
        if address <= CONN + 11 < address + size:
            target = "outgoing_gate"
        else:
            for channel, pointer in self.channels.items():
                if address < pointer + 36 and pointer + 32 < address + size:
                    target = f"percentage_{channel}"
                    break
        if target:
            self.observed.append(
                dict(
                    event="memory_write",
                    target=target,
                    pc=uc.reg_read(UC_ARM64_REG_PC),
                    size=size,
                    value=value,
                    relative_address=address
                    - (CONN if target == "outgoing_gate" else pointer),
                )
            )

    def send(self, kind):
        p = self.r(1)
        self.observed.append(
            dict(
                event="channel_send",
                kind=kind,
                channel=self.u.mem_read(self.r(0) + 16, 1)[0],
                body=bytes(
                    self.u.mem_read(self.q(p + 56) + 13, self.i(p + 52) - 13)
                ).hex(),
            )
        )
        self.ret(0)

    def connect_send(self):
        p = self.r(2)
        self.observed.append(
            dict(
                event="connect_send",
                packet=bytes(self.u.mem_read(self.q(p + 40), self.i(p + 52))).hex(),
            )
        )
        self.ret(0)

    def qos(self):
        assert self.r(2) == CONN + 20
        self.observed.append(dict(event="set_qos", value=self.r(1)))
        self.ret()

    def receive(self, tag, body):
        """Actual drain/dispatcher on a controlled post-decryption FIFO packet."""
        p, q = self.alloc(4096), self.alloc(4096)
        data = (
            struct.pack("<BBBBBHHI", 5, 0, 34, 12, 1, 0, 0, 900000)
            + bytes([tag])
            + body
        )
        self.wq(p + 40, p + 64)
        self.wq(p + 56, p + 64)
        self.wi(p + 52, len(data))
        self.u.mem_write(p + 64, data)
        self.wq(c.CLIENT + 736, q)
        self.wq(q, p)
        self.wi(c.CLIENT + 720, 3)
        self.wi(c.CLIENT + 724, 0)
        self.wi(c.CLIENT + 728, 0)
        self.call(0x7A6368, c.CLIENT)

    def snapshot(self):
        raw = self.serialize(c.CLIENT + 456)
        result = dict(
            stage=self.stage,
            connection_state=self.i(CONN + 16),
            client_state=self.i(c.CLIENT + 256),
            crc=self.u.mem_read(CONN + 10, 1)[0],
            outgoing_gate=self.u.mem_read(CONN + 11, 1)[0],
            percentages={
                str(ch): self.i(ptr + 32) for ch, ptr in sorted(self.channels.items())
            },
            config=raw.hex(),
            events=list(self.observed),
        )
        self.observed.clear()
        return result


def audit(binary, patch=None, patch_hits=None):
    schema = c.descriptor_pb2.FileDescriptorProto.FromString(
        binary[0x3E5474 : 0x3E5474 + 21560]
    )
    pool = c.descriptor_pool.DescriptorPool()
    pool.Add(schema)

    def cls(name):
        return c.message_factory.GetMessageClass(pool.FindMessageTypeByName(name))

    def message(name, **fields):
        return cls(name)(**fields).SerializeToString()

    cases = []
    for crc in (False, True):
        for reliable in (False, True):
            for initial in (None, False, True):
                r = Client(binary, patch, patch_hits)
                stages = []

                def snap():
                    s = r.snapshot()
                    assert s["outgoing_gate"] == 0, s
                    assert all(value == 0 for value in s["percentages"].values()), s
                    assert not any(e.get("kind") == "fec" for e in s["events"]), s
                    stages.append(s)
                    return s

                initial_config = message(
                    "CStreamingClientConfig",
                    **({} if initial is None else dict(enable_unreliable_fec=initial)),
                )
                assert r.parse(c.CLIENT + 456, initial_config)
                s = snap()
                assert s["connection_state"] == 3
                assert [
                    e for e in s["events"] if e.get("target") == "outgoing_gate"
                ] == [
                    dict(
                        event="memory_write",
                        target="outgoing_gate",
                        pc=0x7FB250,
                        relative_address=8,
                        size=4,
                        value=0,
                    )
                ]
                r.stage = "connect"
                r.wi(c.CLIENT + 256, 2)
                r.call(0x7FB62C, CONN, r.alloc(64))
                assert snap()["connection_state"] == 0
                r.stage = "connected"
                p = r.alloc(4096)
                data = struct.pack(
                    "<BBBBBHHII",
                    2 | (128 if crc else 0),
                    0,
                    34,
                    12,
                    0,
                    0,
                    0,
                    900000,
                    800000,
                )
                r.u.mem_write(p + 64, data)
                r.wq(p + 40, p + 64)
                r.wq(p + 56, p + 64)
                r.wi(p + 52, len(data))
                r.call(0x7FBEF4, CONN, p, 1000000)
                s = snap()
                assert s["connection_state"] == 1 and s["crc"] == int(crc)
                assert [
                    e["body"] for e in s["events"] if e["event"] == "channel_send"
                ] == ["060a00"]
                # Explicit authentication boundary: this audit does not run auth.
                r.wi(c.CLIENT + 256, 4)
                r.stage = "negotiation_init"
                r.receive(
                    3,
                    message(
                        "CNegotiationInitMsg",
                        reliable_data=reliable,
                        supported_audio_codecs=[3],
                        supported_video_codecs=[4],
                    ),
                )
                s = snap()
                sends = [e for e in s["events"] if e["event"] == "channel_send"]
                assert len(sends) == 1 and sends[0]["body"].startswith("04")
                config4 = cls("CNegotiationSetConfigMsg").FromString(
                    bytes.fromhex(sends[0]["body"])[1:]
                )
                assert config4.streaming_client_config.HasField(
                    "enable_unreliable_fec"
                ) == (initial is not None)
                assert config4.streaming_client_config.enable_unreliable_fec == bool(
                    initial
                )
                r.stage = "peer_set_config"
                r.receive(
                    4,
                    message(
                        "CNegotiationSetConfigMsg",
                        config=dict(
                            reliable_data=reliable,
                            selected_audio_codec=3,
                            selected_video_codec=4,
                        ),
                        streaming_client_config=dict(
                            enable_unreliable_fec=not bool(initial)
                        ),
                    ),
                )
                s = snap()
                assert s["client_state"] == 5 and s["config"] == initial_config.hex()
                r.stage = "stream_starting"
                r.call(0x7A6F9C, c.CLIENT)
                assert snap()["client_state"] == 6
                r.stage = "microphone_start"
                r.call(0x7A87F0, c.CLIENT, 3, 48000, 2, 0)
                s = snap()
                assert [
                    e["body"] for e in s["events"] if e["event"] == "channel_send"
                ] == ["6b100318032880f7023002"]
                # This nonempty upstream producer is original, not a forged gate.
                payload = r.alloc(64)
                r.u.mem_write(payload, b"\x11\x22\x33\x44")

                def mic(label):
                    r.stage = "microphone_" + label
                    r.call(0x7A8A38, c.CLIENT, payload, 4)
                    s = snap()
                    sends = [e for e in s["events"] if e["event"] == "channel_send"]
                    assert len(sends) == 1 and sends[0]["channel"] == 3
                    assert sends[0]["kind"] == (
                        "reliable" if reliable else "unreliable"
                    ), s
                    assert sends[0]["body"].endswith("11223344")
                    branch = [e for e in s["events"] if e["event"] == "gate_branch"]
                    assert branch == (
                        [] if reliable else [dict(event="gate_branch", value=0)]
                    )

                mic("initial")
                r.wq(c.CLIENT + 272, r.alloc(4096))
                for qos, body in (
                    (False, message("CSetQoSMsg", use_qos=False)),
                    (True, message("CSetQoSMsg", use_qos=True)),
                    (None, b"\xff"),
                ):
                    r.stage = f"qos_{qos}"
                    r.receive(87, body)
                    s = snap()
                    assert [e for e in s["events"] if e["event"] == "set_qos"] == (
                        []
                        if qos is None
                        else [dict(event="set_qos", value=2 * int(qos))]
                    )
                for value in (False, True):
                    for local in (0, 1):
                        r.stage = f"config_api_{value}_{local}"
                        raw = message(
                            "CStreamingClientConfig", enable_unreliable_fec=value
                        )
                        assert r.parse(c.INPUT, raw)
                        r.call(0x7B01C4, c.CLIENT, c.INPUT, local)
                        s = snap()
                        assert s["config"] == raw.hex()
                        sends = [
                            e["body"]
                            for e in s["events"]
                            if e["event"] == "channel_send"
                        ]
                        expected = (
                            b"\x63"
                            + message(
                                "CSetStreamingClientConfig",
                                config=cls("CStreamingClientConfig").FromString(raw),
                            )
                        ).hex()
                        assert sends == ([] if local else [expected])
                        mic(f"api_{value}_{local}")
                for value in (None, False, True, "bad"):
                    r.stage = f"peer99_{value}"
                    raw = (
                        message(
                            "CStreamingClientConfig",
                            **(
                                {}
                                if value is None
                                else dict(enable_unreliable_fec=value)
                            ),
                        )
                        if value != "bad"
                        else None
                    )
                    body = (
                        message(
                            "CSetStreamingClientConfig",
                            config=cls("CStreamingClientConfig").FromString(raw),
                        )
                        if raw is not None
                        else b"\xff"
                    )
                    previous = r.serialize(c.CLIENT + 456)
                    r.receive(99, body)
                    s = snap()
                    assert s["config"] == (raw if raw is not None else previous).hex()
                    assert not any(e["event"] == "channel_send" for e in s["events"])
                    mic(f"peer99_{value}")
                cases.append(
                    dict(
                        input=dict(
                            crc=crc, reliable_data=reliable, initial_fec=initial
                        ),
                        stages=stages,
                    )
                )
    return cases


def inventory(binary):
    elf = ELFFile(io.BytesIO(binary))
    symbols = {s.name: s for s in elf.get_section_by_name(".dynsym").iter_symbols()}
    text = elf.get_section_by_name(".text")
    result = {}
    for name in FUNCTIONS:
        s = symbols[name]
        offset = s["st_value"] - text["sh_addr"]
        data = text.data()[offset : offset + s["st_size"]]
        assert data and len(data) == s["st_size"]
        result[name] = dict(
            address=s["st_value"],
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
        )
    return result


def mutations(binary, reference):
    words = {
        pc: struct.unpack_from("<I", binary, pc)[0]
        for pc in (0x7FB250, 0x7FBF44, 0x7ADA8C, 0x7FBBD0, 0x7A8AB8)
    }
    patches = (
        ("omit_gate_initialization", 0x7FB250, 0xD503201F),
        ("crc_written_to_fec_gate", 0x7FBF44, words[0x7FBF44] + (1 << 10)),
        ("omit_config_copy_to_message4", 0x7ADA8C, 0xD503201F),
        ("invert_connection_gate", 0x7FBBD0, words[0x7FBBD0] ^ (1 << 24)),
        (
            "mic_reliability_from_fec",
            0x7A8AB8,
            (words[0x7A8AB8] & ~(4095 << 10)) | (0x239 << 10),
        ),
    )
    for name, pc, after in patches:
        hits = []
        try:
            changed = audit(binary, (pc, words[pc], after), hits)
        except AssertionError as error:
            tb = error.__traceback__
            while tb.tb_next:
                tb = tb.tb_next
            location = f"{Path(tb.tb_frame.f_code.co_filename).name}:{tb.tb_lineno}"
        else:
            assert changed != reference, name
            location = "reference output mismatch"
        assert hits, f"mutation instruction was never executed: {name}"
        print(f"Detected original-instruction mutation: {name} @{pc:#x}, {location}")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    p.add_argument("--verify-mutations", action="store_true")
    args = p.parse_args()
    binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == c.SHA
    report = dict(
        binary_sha256=c.SHA,
        scope=__doc__,
        functions=inventory(binary),
        cases=audit(binary),
    )
    ref = ROOT / "scripts/fixtures/steam-client-fec-lifecycle-reference.json.gz"
    encoded = (json.dumps(report, indent=2) + "\n").encode()
    if args.refresh_reference:
        if ref.exists():
            assert json.loads(gzip.decompress(ref.read_bytes())) == report
        ref.write_bytes(gzip.compress(encoded, mtime=0))
    else:
        assert json.loads(gzip.decompress(ref.read_bytes())) == report
    args.output.write_bytes(encoded)
    if args.verify_mutations:
        mutations(binary, report["cases"])
    print(
        f"Official client FEC lifecycle: {len(report['cases'])} cases, "
        f"{sum(len(x['stages']) for x in report['cases'])} states, {len(report['functions'])} functions"
    )


if __name__ == "__main__":
    main()
