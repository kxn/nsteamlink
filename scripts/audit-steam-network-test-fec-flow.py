#!/usr/bin/env python3
"""Official CLIENT network-test controls -> result recommendation -> saved FEC.

Pinned Android shell instructions run the UI mode selection, NetworkTest and
Connection constructors, Start API, connected callback, admitted control-packet
Frame/parser/dispatcher, authentication response, request8, target94, timeout,
Complete/CheckState, recommendation and confirm/cancel/preset serializer chain.

Authorization metadata, an established connection and the authentication-request
state are explicit boundaries. OS/thread/clock, identity encrypt/decrypt, final
Channel sends, close, Qt presentation and file load/save are adapters. No real
network/crypto, background thread, media samples, hardware or filesystem is run.
The optional downstream Native checker separately uses real files/UDP/crypto;
this does not add a Switch network-test UI or copy Android capabilities.
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
_spec = importlib.util.spec_from_file_location(
    "config", ROOT / "scripts/audit-steam-client-config.py"
)
config = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(config)
PANEL, APP, CONFIG = (config.BASE[n] for n in ("PANEL", "APP", "CONFIG"))
TEST = PANEL + 280
SHA = config.BASE["SHA"]
REFERENCE = ROOT / "scripts/fixtures/steam-network-test-fec-flow-reference.json.gz"


def varint(value):
    value &= (1 << 64) - 1
    out = bytearray()
    while value > 127:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


class Flow(config.Core):
    def __init__(self, binary, patch=None):
        self.now, self.frames, self.assertions = 1000000, [], []
        self.allocations, self.saves, self.gate_writes = {}, [], []
        self.connection, self.patch, self.patch_hits = None, patch, []
        super().__init__(binary)
        if patch:
            pc, before, after = patch
            assert bytes(self.u.mem_read(pc, 4)) == struct.pack("<I", before)
            self.u.mem_write(pc, struct.pack("<I", after))
        self.u.hook_add(UC_HOOK_MEM_WRITE, self.memory_write)
        self.call(self.symbols["_ZN12CNetworkTestC1Ev"], TEST)

    def alloc(self, size):
        address = super().alloc(max(size, 16))
        self.allocations[address] = max(size, 16)
        return address

    def memory_write(self, u, access, address, size, value, unused):
        if self.connection and address <= self.connection + 11 < address + size:
            self.gate_writes.append(
                dict(
                    pc=u.reg_read(UC_ARM64_REG_PC),
                    offset=address - self.connection,
                    size=size,
                    value=value,
                )
            )

    def hook(self, u, pc, size, data):
        if self.patch and pc == self.patch[0]:
            self.patch_hits.append(pc)
        name = self.plts.get(pc, "")
        if name == "_Z18GetStreamTimestampv":
            self.ret(self.now)
        elif name == "_Znam":
            self.ret(self.alloc(self.r(0)))
        elif name == "realloc":
            old, size = self.r(0), self.r(1)
            new = self.alloc(size)
            if old:
                self.u.mem_write(
                    new, bytes(self.u.mem_read(old, min(size, self.allocations[old])))
                )
            self.ret(new)
        elif name == "_ZdaPv":
            self.ret()
        elif name in (
            "_Z34StreamSetThreadedNetworkProcessingb",
            "_ZN16SteamThreadTools7CThreadC2Ev",
            "_ZN16SteamThreadTools7CThreadD2Ev",
        ) or name.startswith("_ZN16SteamThreadTools12CThreadMutexC"):
            self.ret()
        elif name.startswith("_ZN12CNetworkTest5Start"):
            self.jump(self.symbols[name])
        elif name in (
            "_ZN17CStreamConnection10DisconnectEv",
            "_ZN17CStreamConnection5CloseEv",
        ):
            self.ret()
        elif name == "_ZN12CStreamFrame8BDecryptEyPKhj":
            self.b(self.r(0) + 16, 1)
            self.ret(1)
        elif name == "_ZNK16SteamThreadTools7CThread7IsAliveEv":
            self.ret(0)
        elif name in (
            "_ZN16SteamThreadTools7CThread5StartEm",
            "_ZN16SteamThreadTools7CThread4JoinEj",
        ):
            self.ret(1)
        elif name == "_ZN13CStreamSocket13AddConnectionEP17CStreamConnection":
            self.ret()
        elif name == "_ZN17CStreamConnection19GetNextConnectionIDEv":
            self.ret(12)
        elif name == "_ZN10CUtlString8SetValueEPKc":
            self.ret()
        elif name in (
            "_ZN6google8protobuf8internal10NameOfEnumEPKNS0_14EnumDescriptorEi",
            "_Z14GetMessageNamehh",
        ):
            self.ret(self.alloc(32))
        elif name == "_ZN14CStreamChannel4SendEP13CStreamPacket":
            packet = self.r(1)
            self.frames.append(
                dict(
                    channel=self.u.mem_read(self.r(0) + 16, 1)[0],
                    body=bytes(
                        self.u.mem_read(
                            self.q(packet + 56) + 13, self.i(packet + 52) - 13
                        )
                    ).hex(),
                )
            )
            self.ret(0)
        elif name == "_ZN12CStreamFrame8BEncryptEyPKhj":
            self.ret(1)
        elif "SaveStreamingSettings" in name:
            self.saves.append(self.freeze(self.r(1)))
            super().hook(u, pc, size, data)
        elif "AssertFailed" in name:
            self.assertions.append(self.r(1))
            self.ret(1)
        else:
            super().hook(u, pc, size, data)

    def receive(self, tag, payload):
        packet = self.alloc(4096)
        raw = packet + 64
        wire = (
            struct.pack("<BBBBBHHI", 5, 0, 34, 12, 1, 0, 0, 900000)
            + bytes([tag])
            + payload
        )
        self.u.mem_write(raw, wire)
        self.wq(packet + 40, raw)
        self.wq(packet + 56, raw)
        self.wi(packet + 52, len(wire))
        self.wi(packet + 48, 4000)
        self.call(
            self.symbols[
                "_ZN12CNetworkTest14OnStreamPacketEP17CStreamConnectionP13CStreamPacket"
            ],
            TEST,
            self.connection,
            packet,
        )

    def observe(self, label):
        channels = []
        if self.connection:
            for ch in range(32):
                p = self.q(self.connection + 112 + 8 * ch)
                if p:
                    channels.append([ch, self.i(p + 20), self.i(p + 32)])
        return dict(
            label=label,
            mode=self.i(TEST + 8),
            status=self.i(TEST + 12),
            state=self.i(TEST + 0x114),
            previous_kbps=self.i(TEST + 0x13C),
            current_kbps=self.i(TEST + 0x140),
            last_data=self.i(TEST + 0x150),
            recommendation=self.i(PANEL + 704),
            tx_sequence=self.q(TEST + 0xD0),
            rx_sequence=self.q(TEST + 0xD8),
            gate=self.u.mem_read(self.connection + 11, 1)[0]
            if self.connection
            else None,
            channels=channels,
            saves=len(self.saves),
        )


def inputs():
    for quality in (1, 2, 3):
        for before in (False, True):
            for accepted in (0, 1):
                for targets in ([99999], [100000], [99999, 100000], [100000, 99999]):
                    yield dict(
                        quality=quality,
                        before=before,
                        accepted=accepted,
                        bitrate=-1,
                        targets=targets,
                    )
    for bitrate in (0, 20000):
        for before in (False, True):
            for accepted in (0, 1):
                for targets in ([99999, 100000], [100000, 99999]):
                    yield dict(
                        quality=2,
                        before=before,
                        accepted=accepted,
                        bitrate=bitrate,
                        targets=targets,
                    )


def run(binary, values, patch=None):
    r = Flow(binary, patch)
    r.config(CONFIG, values["before"], values["quality"])
    # A declared preference input keeps subsequent desktop lookup on software;
    # it is not an Android or Switch hardware capability claim.
    r.wi(CONFIG + 16, r.i(CONFIG + 16) | 0x18000000)
    r.wi(CONFIG + 152, values["bitrate"])
    r.b(CONFIG + 156, 0)
    r.loaded = CONFIG
    initial = r.serialize(CONFIG).hex()
    r.wq(PANEL + 728, r.empty)
    r.wq(PANEL + 200, APP + 0x2000)
    r.wi(APP + 0x2000 + 8, 6)
    r.call(0xC7029C, PANEL)
    states = [r.observe("ui_start")]
    r.connection, sock = r.alloc(4096), r.alloc(4096)
    r.u.mem_write(r.connection + 8, b"\xa5" * 8)
    r.call(r.symbols["_ZN17CStreamConnectionC1EP13CStreamSocket"], r.connection, sock)
    r.wi(r.connection + 16, 1)
    r.wq(TEST + 0x128, r.connection)
    r.call(
        r.symbols["_ZN12CNetworkTest17OnStreamConnectedEP17CStreamConnection"],
        TEST,
        r.connection,
    )
    states.append(r.observe("connected"))
    # The real network-test auth request's OS/HMAC path is outside this audit.
    r.wi(TEST + 0x114, 3)
    r.receive(2, bytes.fromhex("1001"))
    states.append(r.observe("authenticated_response"))
    for target in values["targets"]:
        r.receive(94, b"\x08" + varint(target))
        states.append(r.observe("target_" + str(target)))
    # Empty-media timeout boundary: this is not an observed network stall.
    r.now += 196608
    r.call(r.symbols["_ZN12CNetworkTest17HandleNetworkTestEv"], TEST)
    states.append(r.observe("timeout_equal"))
    r.now += 1
    r.call(r.symbols["_ZN12CNetworkTest17HandleNetworkTestEv"], TEST)
    states.append(r.observe("timeout_after"))
    r.call(r.symbols["_ZN12CNetworkTest19CompleteNetworkTestEv"], TEST)
    states.append(r.observe("complete"))
    r.call(0xC707C4, PANEL)
    states.append(r.observe("result_page"))
    r.wi(PANEL + 208, 3)
    r.b(PANEL + 212, 1)
    r.call(0xC72164, PANEL, values["accepted"])
    states.append(r.observe("user_result"))
    assert not r.assertions
    saved = [r.serialize(p).hex() for p in r.saves]
    observed = dict(
        states=states,
        frames=r.frames,
        saved=saved,
        final=saved[-1] if saved else initial,
        gate_writes=r.gate_writes,
        source_assertions=r.assertions,
    )
    return dict(input=values, initial=initial, observed=observed), r.patch_hits


def inventory(binary):
    elf = ELFFile(io.BytesIO(binary))
    names = {
        "_ZN13CPanelConnect24SetPanelStateNetworkTestEv",
        "_ZN13CPanelConnect21CheckNetworkTestStateEv",
        "_ZN13CPanelConnect25HandleNetworkTestCompleteEv",
        "_ZN13CPanelConnect21OnNetworkTestCompleteEi",
        "_ZN17CStreamConnectionC1EP13CStreamSocket",
        "_ZN17CStreamConnection4SendEP13CStreamPacketh",
        "_ZN17CStreamConnection10GetChannelEh",
        "_ZN14CStreamChannelC1EP13CStreamSocketP17CStreamConnectionh",
        "_ZN12CStreamFrame4SendEP17CStreamConnectionb",
        "_ZN12CStreamFrameC1EP13CStreamPacket",
        "_ZN12CStreamFrame3GetEPN6google8protobuf11MessageLiteEb",
        "_ZNK22CStreamingClientConfig12ByteSizeLongEv",
        "_ZN22CStreamingClientConfigC1ERKS_",
    }
    text = elf.get_section_by_name(".text")
    result = {}
    for s in elf.get_section_by_name(".dynsym").iter_symbols():
        if s["st_value"] and (
            s.name in names
            or s.name.startswith("_ZN12CNetworkTest")
            or s.name.startswith("_ZN13CNetworkStats")
            or "CreateStreamingConfig" in s.name
        ):
            begin = s["st_value"] - text["sh_addr"]
            code = text.data()[begin : begin + s["st_size"]]
            assert code and len(code) == s["st_size"]
            result[s.name] = dict(
                address=s["st_value"],
                size=len(code),
                sha256=hashlib.sha256(code).hexdigest(),
            )
    assert names <= set(result)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    p.add_argument("--verify-mutations", action="store_true")
    args = p.parse_args()
    binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == SHA
    cases = [run(binary, i)[0] for i in inputs()]
    report = dict(
        client_sha256=SHA, scope=__doc__, functions=inventory(binary), cases=cases
    )
    if args.refresh_reference:
        if REFERENCE.exists():
            assert json.loads(gzip.decompress(REFERENCE.read_bytes())) == report
        REFERENCE.write_bytes(
            gzip.compress((json.dumps(report, indent=2) + "\n").encode(), mtime=0)
        )
    else:
        assert json.loads(gzip.decompress(REFERENCE.read_bytes())) == report
    if args.verify_mutations:
        selected = next(
            c
            for c in cases
            if c["input"]
            == dict(
                quality=1, before=False, accepted=1, bitrate=-1, targets=[99999, 100000]
            )
        )
        # The dispatcher inlines target94; the exported same-name handler is
        # not substituted for its actual producer.
        pc = 0xCAB3E8
        image = config.BASE["load_image"](binary)[0]
        original = struct.unpack_from("<I", image, pc)[0]
        changed, hits = run(binary, selected["input"], (pc, original, 0x2A0A03E8))
        assert (
            hits
            and changed != selected
            and not changed["observed"]["source_assertions"]
        )
        assert changed["observed"]["saved"] != selected["observed"]["saved"]
        args.output.with_name(args.output.stem + "-mutation.json").write_text(
            json.dumps(
                dict(
                    pc=pc,
                    before=original,
                    after=0x2A0A03E8,
                    executed_hits=hits,
                    original=selected,
                    mutant=changed,
                ),
                indent=2,
            )
            + "\n"
        )
        print(
            "Detected executed original inline target94 mutation: latest rate replaces prior recorded target"
        )
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"Official test/FEC flow: {len(cases)} cases, {sum(len(c['observed']['states']) for c in cases)} states"
    )


if __name__ == "__main__":
    main()
