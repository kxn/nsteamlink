#!/usr/bin/env python3
"""Run original Socket RX/TX and real connection network collectors.

Pinned instructions perform CRC verification/append, packet sizing, connection
admission, receive/byte samples and sample-window math. Appended cases enter
real Streaming/SendFrameEvents/C++ protobuf/Frame Send and compare full bodies.
Socket connection table, full-stats flag,
address comparison, connection state and platform I/O results are controlled;
channel consumers, connect/disconnect bodies, unclaimed replies and refcounts
are adapters, as are report encryption and final Connection frame admission.
This is not a real Steam session, decoder or errno-equivalence test.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "collectors", ROOT / "scripts/audit-steam-network-collectors.py"
)
collectors = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collectors)
config = collectors.config


class Wire(collectors.Collectors):
    def __init__(self, binary, crc=False, address=True):
        super().__init__(binary)
        self.sock, table, self.transport, vtable, shaper, channel = (
            self.alloc(4096) for _ in range(6)
        )
        self.wq(self.sock, self.transport)
        self.wq(self.transport, vtable)
        self.wq(vtable + 72, config.STOP + 0x500)
        self.wq(self.sock + 8, table)
        self.wi(self.sock + 24, 1)
        self.wq(table, self.connection)
        self.wq(self.sock + 64, shaper)
        self.wq(self.connection, self.sock)
        self.wi(self.connection + 16, 1)
        self.b(self.connection + 12, 12)
        self.b(self.connection + 13, 34)
        self.b(self.connection + 10, int(crc))
        self.entries, self.writes = [], []
        self.transport_result = 0
        self.callbacks.update(
            {
                0xC11350: self.handle,
                0xC11170: lambda: self.ret(
                    0
                ),  # unclaimed RX reply only; direct TX executes 7ff1dc
                0xC0A390: lambda: self.ret(1),
                0xC0DC80: lambda: self.ret(int(address)),
                0xC0E390: lambda: self.ret(channel),
                0xC11250: lambda: self.ret(0),
                0xC0E030: lambda: self.ret(0),
                0xC0DA00: lambda: self.ret(),
                0xC11380: lambda: self.ret(0),
                0xC11390: lambda: self.ret(0),
                0xC0E110: lambda: self.jump(0x7A7D90),
                0xC0E3A0: lambda: self.ret(1),
                0xC10FF0: self.send_frame,
                config.STOP + 0x500: self.write,
            }
        )

    def send_frame(self):
        p = self.r(1)
        raw = self.q(p + 56)
        self.frames.append(
            dict(
                channel=self.r(2),
                body=bytes(self.u.mem_read(raw + 13, self.i(p + 52) - 13)).hex(),
            )
        )
        self.ret(0)

    def handle(self):
        self.entries.append(self.i(self.r(1) + 52))
        self.jump(0x7FACFC)

    def write(self):
        p = self.r(1)
        size = self.i(p + 52)
        raw = self.q(p + 40)
        has_crc = bool(self.u.mem_read(raw, 1)[0] & 128)
        self.writes.append(
            dict(size=size, wire_size=size + (4 if has_crc else 0), crc=has_crc)
        )
        self.ret(self.transport_result)

    def packet(self, kind, channel, crc, source, dest, size, bad_crc=False):
        packet = self.alloc(max(4096, size + 128))
        raw = packet + 64
        wire = struct.pack(
            "<BBBBBHHI",
            kind | (128 if crc else 0),
            0,
            source,
            dest,
            channel,
            0,
            0,
            self.now,
        ) + bytes(size)
        self.u.mem_write(raw, wire)
        if crc:
            check = self.call(0x8E1610, raw, len(wire)) & 0xFFFFFFFF
            self.u.mem_write(raw + len(wire), struct.pack("<I", check ^ int(bad_crc)))
        self.wq(packet + 40, raw)
        self.wq(packet + 56, raw)
        self.wi(packet + 48, max(4096, size + 128) - 64)
        self.wi(packet + 52, len(wire) + (4 if crc else 0))
        return packet

    def observe(self):
        state = self.observe_collectors()
        return dict(
            rates=state["rates"],
            packets=state["packets"],
            entries=list(self.entries),
            writes=list(self.writes),
        )

    def observe_collectors(self):
        return super().observe()


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == config.SHA
    scenarios = []
    for kind in range(1, 14):
        scenarios.append(
            dict(
                name=f"rx_type_{kind}",
                crc=False,
                address=True,
                actions=[["RX", 1000000, kind, 3, 0, 34, 12, 20, 0]],
            )
        )
    for name, crc, address, channel, present, source, dest, bad in [
        ("required_missing", True, True, 3, 0, 34, 12, 0),
        ("required_present", True, True, 3, 1, 34, 12, 0),
        ("bad_crc", True, True, 3, 1, 34, 12, 1),
        ("wrong_source", False, True, 3, 0, 35, 12, 0),
        ("wrong_destination", False, True, 3, 0, 34, 13, 0),
        ("wrong_address", False, False, 3, 0, 34, 12, 0),
        ("channel31", False, True, 31, 0, 34, 12, 0),
        ("channel32", False, True, 32, 0, 34, 12, 0),
    ]:
        scenarios.append(
            dict(
                name=name,
                crc=crc,
                address=address,
                actions=[["RX", 1000000, 5, channel, present, source, dest, 20, bad]],
            )
        )
    for crc in (False, True):
        for kind in (0, 1, 3, 5, 9):
            for result in range(5):
                scenarios.append(
                    dict(
                        name=f"tx_{kind}_{result}_{int(crc)}",
                        crc=crc,
                        address=True,
                        actions=[["TX", 1000000, kind, 3, 20, result]],
                    )
                )
        for base in (1000000, 0xFFFF0000):
            actions = []
            for n, delta in enumerate((0, 0, 196608, 196609, 393218)):
                tick = (base + delta) & 0xFFFFFFFF
                actions += [
                    ["RX", tick, 13, 3, int(crc), 34, 12, 20 + n, 0],
                    ["TX", tick, 5, 1, 40 + n, 0],
                ]
            scenarios.append(
                dict(
                    name=f"windows_{base}_{int(crc)}",
                    crc=crc,
                    address=True,
                    actions=actions,
                )
            )
    for crc in (False, True):
        for full in (False, True):
            scenarios.append(
                dict(
                    name=f"report_{int(crc)}_{int(full)}",
                    crc=crc,
                    address=True,
                    full=full,
                    actions=[
                        ["RX", 1000000, 13, 3, int(crc), 34, 12, 100, 0],
                        ["TX", 1000001, 5, 1, 70, 0],
                        ["T", 999345, 1000000, 1000000],
                        ["R", 1],
                        ["C", 1, 906000],
                        ["S", 1100000],
                        ["RX", 1200000, 13, 3, int(crc), 34, 12, 200, 0],
                        ["TX", 1200001, 5, 1, 40, 1],
                        ["R", 2],
                        ["C", 2, 1199000],
                        ["S", 1200002],
                    ],
                )
            )
    for kind in (1, 2, 9):
        for label, required, channel, source, dest in (
            ("wrong_src", False, 3, 35, 12),
            ("dst_zero", False, 3, 34, 0),
            ("wrong_dst", False, 3, 34, 13),
            ("crc_missing", True, 3, 34, 12),
            ("channel32", False, 32, 34, 12),
        ):
            scenarios.append(
                dict(
                    name=f"special_{kind}_{label}",
                    crc=required,
                    address=True,
                    actions=[["RX", 1000000, kind, channel, 0, source, dest, 20, 0]],
                )
            )
    for source in (0, 35):
        scenarios.append(
            dict(
                name=f"connect_unknown_peer_{source}",
                crc=False,
                address=True,
                remote=0,
                actions=[["RX", 1000000, 1, 3, 0, source, 13, 20, 0]],
            )
        )
    cases = []
    for i in scenarios:
        r = Wire(binary, i["crc"], i["address"])
        r.b(r.connection + 13, i.get("remote", 34))
        r.b(config.CLIENT + 636, int(i.get("full", False)))
        observed = []
        for action in i["actions"]:
            op, *v = action
            r.entries.clear()
            r.writes.clear()
            r.frames.clear()
            if op == "RX":
                r.now, kind, channel, crc, source, dest, size, bad = v
                p = r.packet(kind, channel, crc, source, dest, size, bad)
                r.call(0x7FF3E0, r.sock, p, r.now)
            elif op == "TX":
                r.now, kind, channel, size, r.transport_result = v
                p = r.packet(kind, channel, False, 12, 34, size)
                r.call(0x7FF1DC, r.sock, r.connection, p)
            elif op == "T":
                r.call(0x7F9A2C, r.connection, *v)
            elif op == "R":
                r.receive(v[0])
            elif op == "C":
                fid, r.now = v
                r.call(0x7AC3F8, config.CLIENT, 1, fid, 1)
            else:
                assert op == "S"
                r.now = v[0]
                r.call(0x7A7140, config.CLIENT)
            observation = r.observe()
            if "full" in i:
                observation.update(
                    frames=list(r.frames),
                    frame_events_time=r.i(config.CLIENT + 0x1C678),
                    keepalive_time=r.i(config.CLIENT + 0x1F6F0),
                    sequence=r.q(config.CLIENT + 128),
                    reported=r.i(r.ring(1) + 8) >> 16,
                )
            observed.append(observation)
        assert not r.asserts, (i, r.asserts)
        cases.append(dict(input=i, observed=observed))
    return cases


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    report = dict(
        binary_sha256=config.SHA, scope=__doc__, cases=audit(a.binary.read_bytes())
    )
    ref = ROOT / "scripts/fixtures/steam-network-wire-reference.json"
    if a.refresh_reference:
        if ref.exists():
            old = json.loads(ref.read_text())
            assert old["cases"] == report["cases"][: len(old["cases"])]
        ref.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert json.loads(ref.read_text()) == report
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Official Socket network sampling: {len(report['cases'])} cases passed")


if __name__ == "__main__":
    main()
