#!/usr/bin/env python3
"""Official Android microphone APIs with controlled clock and shared quota.

Original Start/Send/Stop, protobuf, Frame, Connection factory, Channel windows,
selection, Socket shaping and CRC execute. Initial connection/negotiated config,
clock, locks, refcounts, final UDP, encryption identity and network-stat endpoints
are explicit adapters. Each Native API is followed by its real dispatch step;
periodic steps scan the named channel's reliable then unreliable sender. No
background scheduling, actual encryption, capture, encoder or Host is proved.
"""

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "lifecycle", ROOT / "scripts/audit-steam-client-fec-lifecycle.py"
)
source = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(source)
c = source.c
REFERENCE = ROOT / "scripts/fixtures/steam-microphone-schedule-reference.json.gz"


class Sender(source.Client):
    def __init__(self, binary, crc, reliable, rate):
        self.now, self.wires = 1000000, []
        super().__init__(binary)
        self.shaper, transport, vt = (self.alloc(4096) for _ in range(3))
        self.wq(source.SOCK, transport)
        self.wq(transport, vt)
        self.wq(vt + 72, c.STOP + 0x500)
        self.wq(source.SOCK + 64, self.shaper)
        for offset, value in ((0, 12500000), (4, rate), (8, self.now), (12, self.now)):
            self.wi(self.shaper + offset, value)
        self.wi(source.CONN + 16, 1)
        self.b(source.CONN + 10, int(crc))
        self.b(source.CONN + 12, 12)
        self.b(source.CONN + 13, 34)
        self.wi(c.CLIENT + 256, 6)
        assert self.parse(
            c.CLIENT + 288,
            bytes.fromhex("0801" if reliable else "0800"),
            "CNegotiatedConfig",
        )
        self.callbacks.update(
            {
                0xC0A950: lambda: self.ret(self.now),
                0xC111F0: lambda: self.jump(0x7F89DC),
                0xC11210: lambda: self.jump(0x7F8BD8),
                0xC11170: lambda: self.jump(0x7FF1DC),
                0xC10FE0: lambda: self.ret(),  # sent-byte statistics, not quota
                0xC11370: lambda: self.ret(),  # outgoing timestamp statistic
                0xC09F10: lambda: self.ret(),
                0xC09F30: lambda: self.ret(),
                0xBFF1A0: lambda: self.ret(),
                c.STOP + 0x500: self.send_wire,
            }
        )
        for address, value in ((0xF479A0, 13107), (0xF47988, 3276), (0xF4798C, 65)):
            self.wi(address, value)
        self.b(0xF479A8, 1)
        self.wi(self.symbols["_ZN13CStreamPacket6s_nMTUE"], 1472)
        self.payload = self.alloc(4)
        self.u.mem_write(self.payload, bytes.fromhex("11223344"))

    def send_wire(self):
        packet = self.r(1)
        raw = self.q(packet + 56)
        size = self.i(packet + 52) + (4 if self.u.mem_read(raw, 1)[0] & 128 else 0)
        self.wires.append(bytes(self.u.mem_read(raw, size)).hex())
        self.ret(0)

    def step(self, operation, tick, channel=0):
        self.now = tick
        if operation == "start":
            self.call(0x7A87F0, c.CLIENT, 3, 48000, 2, 0)
        elif operation == "stop":
            self.call(0x7A8B18, c.CLIENT)
        elif operation == "data":
            self.call(0x7A8A38, c.CLIENT, self.payload, 4)
        else:
            assert operation == "scan"
            self.call(0x7F8AC4, self.channels[channel], tick)
            self.call(0x7F8CBC, self.channels[channel], 0)
        result = dict(
            now=tick,
            wires=self.wires,
            deadlines=[self.i(self.shaper + n) for n in (8, 12)],
            blocked=bool(self.u.mem_read(source.SOCK + 57, 1)[0]),
            channel=self.u.mem_read(c.CLIENT + 627, 1)[0],
            frame=int.from_bytes(self.u.mem_read(c.CLIENT + 0x1F6F4, 2), "little"),
            channels=[
                [
                    ch,
                    self.i(p + 20),
                    int.from_bytes(self.u.mem_read(p + 122, 2), "little"),
                    int.from_bytes(self.u.mem_read(p + 258, 2), "little"),
                ]
                for ch, p in sorted(self.channels.items())
            ],
        )
        self.wires = []
        return result


def schedules():
    for crc in (False, True):
        for reliable in (False, True):
            for rate in (0, 625000, 65536):
                boundary = (24 << 16) // rate if rate else 0
                for delta in (-1, 0, 1):
                    tick = 1000000
                    actions = [
                        [op, tick, 0]
                        for op in ("start", "data", "stop", "start", "data")
                    ]
                    actions += [
                        ["start", tick + max(boundary - 1, 0), 0],
                        ["data", tick + max(boundary + delta, 0), 0],
                    ]
                    for offset in (100, 200, 300):
                        actions.extend(
                            ["scan", tick + boundary + offset, ch]
                            for ch in (1, 3, 4, 5)
                        )
                    yield dict(
                        crc=crc,
                        reliable=reliable,
                        rate=rate,
                        delta=delta,
                        actions=actions,
                    )


def inventory(binary):
    elf = ELFFile(io.BytesIO(binary))
    names = set(source.FUNCTIONS) | {
        "_ZN13CStreamClient20StopMicrophoneStreamEv",
        "_ZN14CStreamChannel19SendReliablePacketsEj",
        "_ZN14CStreamChannel21SendUnreliablePacketsEb",
        "_ZN14CStreamChannel4SendEP13CStreamPacket",
        "_ZN13CStreamSocket4SendEP17CStreamConnectionP13CStreamPacket",
    }
    text = elf.get_section_by_name(".text")
    result = {}
    for s in elf.get_section_by_name(".dynsym").iter_symbols():
        if s.name in names:
            offset = s["st_value"] - text["sh_addr"]
            code = text.data()[offset : offset + s["st_size"]]
            assert code and len(code) == s["st_size"]
            result[s.name] = dict(
                address=s["st_value"],
                size=len(code),
                sha256=hashlib.sha256(code).hexdigest(),
            )
    assert set(result) == names
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    args = p.parse_args()
    binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == c.SHA
    cases = []
    for inputs in schedules():
        r = Sender(binary, inputs["crc"], inputs["reliable"], inputs["rate"])
        states = [r.step(*row) for row in inputs["actions"]]
        # A controlled, non-vacuous counterexample to a global control barrier.
        if inputs["reliable"] and inputs["rate"] == 625000 and inputs["delta"] == 0:
            assert states[6]["wires"] and bytes.fromhex(states[6]["wires"][0])[4] == 5
            assert states[3]["wires"] == states[5]["wires"] == []
            assert any(bytes.fromhex(w)[13] == 108 for w in states[7]["wires"])
        cases.append(dict(input=inputs, observed=states))
    report = dict(
        binary_sha256=c.SHA, scope=__doc__, functions=inventory(binary), cases=cases
    )
    if args.refresh_reference:
        if REFERENCE.exists():
            assert json.loads(gzip.decompress(REFERENCE.read_bytes())) == report
        REFERENCE.write_bytes(
            gzip.compress((json.dumps(report, indent=2) + "\n").encode(), mtime=0)
        )
    else:
        assert json.loads(gzip.decompress(REFERENCE.read_bytes())) == report
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"Official microphone schedule: {len(cases)} cases, {sum(len(x['observed']) for x in cases)} states"
    )


if __name__ == "__main__":
    main()
