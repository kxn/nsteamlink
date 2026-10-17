#!/usr/bin/env python3
"""Execute official frame-stat receive/event/complete/report and C++ serialization.

Real CFastFrameStats constructors, client ring branches, completion, accumulator,
Save, protobuf constructors/serialization and Frame Put/Send run pinned ARM64.
Selected appended cases also execute Frame::SetPacket/OnDataPacket and
CreateInputMark. Direct receive cases supply already normalized local stamps.
Client/channel/time/connection metrics are controlled seed state. NetworkStats
and bitrate sample collectors, allocation/libm,
diagnostic enum-name formatting, final Connection send and destructors are adapters. No transport, hardware,
actual OnThink cadence or complete CStreamClient initialization is claimed.
"""

import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import struct
from unicorn.arm64_const import UC_ARM64_REG_S0

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "config", ROOT / "scripts/audit-steam-client-config.py"
)
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)


class Stats(config.Core):
    def __init__(self, binary, full=False, offset=0):
        self.allocations = {}
        super().__init__(binary)
        self.now = 1000000
        self.frames = []
        self.asserts = []
        self.offset = offset
        connection = self.alloc(4096)
        self.connection = connection
        self.wq(config.CLIENT + 280, connection)
        self.wi(connection + 848, offset)
        self.b(config.CLIENT + 625, 3)
        self.b(config.CLIENT + 626, 4)
        self.b(config.CLIENT + 636, int(full))
        for typ in (0, 1):
            for index in range(240):
                self.call(0x7F3894, self.ring(typ) + 12 + index * 120)
        enum_name = self.alloc(32)
        self.callbacks.update(
            {
                0xC0A950: lambda: self.ret(self.now),
                0xC097E0: self.assertion,
                0xC097F0: lambda: self.ret(0),
                0xC04290: lambda: self.ret(0),
                0xC0DD40: lambda: self.ret(enum_name),
                0xC0C250: lambda: self.ret(),
                0xC0E6C0: lambda: self.ret(),
                0xC0E2F0: lambda: self.jump(0x7F3078),
                0xC10FF0: self.send,
                0xC0A380: lambda: self.ret(2),
                0xC0E6B0: lambda: self.jump(0x7ABEB0),
            }
        )

    def alloc(self, size):
        address = super().alloc(max(size, 16))
        self.allocations[address] = max(size, 16)
        return address

    def call(self, entry, *params):
        self.u.reg_write(config.SP, 0x300FF000)
        self.u.reg_write(config.LR, config.STOP)
        for i, value in enumerate(params):
            self.u.reg_write(config.X0 + i, value)
        self.u.emu_start(entry, config.STOP + 4, count=3000000)
        assert self.u.reg_read(config.BASE["UC_ARM64_REG_PC"]) == config.STOP, (
            "instruction budget exceeded"
        )
        return self.r(0)

    @staticmethod
    def ring(typ):
        return config.CLIENT + typ * 28812 + 1096

    def assertion(self):
        self.asserts.append(self.r(1))
        self.ret(0)

    def send(self):
        p = self.r(1)
        self.frames.append(
            bytes(self.u.mem_read(self.q(p + 56) + 13, self.i(p + 52) - 13)).hex()
        )
        self.ret(0)

    def hook(self, uc, address, size, data):
        name = self.plts.get(address, "")
        if name == "realloc":
            old, size = self.r(0), self.r(1)
            new = self.alloc(size)
            if old:
                self.u.mem_write(
                    new, bytes(self.u.mem_read(old, min(size, self.allocations[old])))
                )
            self.ret(new)
        elif name in ("sqrtf", "sqrt"):
            value = struct.unpack(
                "<f", struct.pack("<I", self.u.reg_read(UC_ARM64_REG_S0))
            )[0]
            bits = struct.unpack("<I", struct.pack("<f", math.sqrt(value)))[0]
            self.u.reg_write(UC_ARM64_REG_S0, bits)
            self.ret()
        else:
            super().hook(uc, address, size, data)

    def receive(
        self,
        fid,
        frame_start=900000,
        sent=901000,
        received=902000,
        size=100,
        typ=1,
        input_mark=0,
        input_received=0,
        packet=False,
    ):
        f, p, raw = (self.alloc(max(4096, size + 64)) for _ in range(3))
        self.wq(p + 40, raw)
        self.wq(p + 56, raw)
        if packet:
            # Real Frame::SetPacket + OnDataPacket. Inputs to these cases are
            # host timestamps, not the normalized local values of direct R.
            wire = struct.pack("<BBBBBHHI", 5, 0, 34, 12, 4 if typ else 3, 0, 0, sent)
            wire += b"\x01" + struct.pack(
                "<HIHI", fid, frame_start, input_mark, input_received
            )
            wire += bytes(size)
            self.u.mem_write(raw, wire)
            self.wi(p + 52, len(wire))
            self.wi(p + 28, received)
            self.wi(p + 32, received)
            self.call(0x7F2BAC, f, p)
            assert self.i(f + 28) == frame_start and self.i(f + 32) == sent
            assert self.i(f + 48) == input_received
            self.call(0x7AD148, config.CLIENT, f)
            return
        self.wq(f + 8, p)
        self.wi(p + 52, size + 13)
        self.b(f + 24, 4 if typ else 3)
        self.u.mem_write(f + 26, struct.pack("<H", fid))
        for position, value in (
            (28, frame_start),
            (32, sent),
            (36, sent),
            (40, received),
        ):
            self.wi(f + position, value)
        self.u.mem_write(f + 44, struct.pack("<H", input_mark))
        self.wi(f + 48, input_received)
        self.call(0x7ABEB0, config.CLIENT, f)

    def observe(self, ids, typ=1):
        b = self.ring(typ)
        slots = []
        for fid in ids:
            pointer = self.call(0x7AC5A4, config.CLIENT, typ, fid)
            if not pointer:
                slots.append(None)
                continue
            raw = bytes(self.u.mem_read(pointer, 120))
            slots.append(
                dict(
                    id=struct.unpack_from("<H", raw)[0],
                    size=self.i(pointer + 4),
                    input=struct.unpack_from("<H", raw, 8)[0],
                    events=list(struct.unpack_from("<19I", raw, 12)),
                    result=self.i(pointer + 88),
                    extra=raw[92:].hex(),
                )
            )
        observed = dict(
            last_frame=self.i(b),
            last_display=self.i(b + 4),
            displayed=struct.unpack("<H", self.u.mem_read(b + 8, 2))[0],
            reported=struct.unpack("<H", self.u.mem_read(b + 10, 2))[0],
            slots=slots,
            frames=list(self.frames),
            asserts=list(self.asserts),
        )
        self.frames.clear()
        self.asserts.clear()
        return observed


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == config.SHA
    cases = []
    scenarios = [
        dict(
            case="simple",
            full=full,
            offset=offset,
            actions=[
                ["R", 1],
                ["E", 1, 14, 903000],
                ["E", 1, 15, 904000],
                ["C", 1, 1, 905000],
                ["S"],
                ["S"],
            ],
            ids=[0, 1],
        )
        for full in (False, True)
        for offset in (0, 123, -123)
    ]

    def case(name, actions, ids, full=True, **extra):
        scenarios.append(
            dict(case=name, actions=actions, ids=ids, full=full, offset=0, **extra)
        )

    for full in (False, True):
        for count in (2, 3, 8, 9):
            actions = []
            for fid in range(1, count + 1):
                base = 900000 + fid * 1001
                actions += [
                    ["R", fid, base, base + 17, base + 211],
                    ["E", fid, 14, base + 307],
                    ["E", fid, 15, base + 401],
                    ["E", fid, 16, base + 503],
                    ["E", fid, 17, base + 601],
                    ["C", fid, 1, base + 809],
                ]
            actions += [["S"], ["S"]]
            case(f"samples_{count}", actions, list(range(1, count + 1)), full)
        case(
            "stale_events",
            [
                ["E", 1, 14, 1],
                ["C", 1, 1, 2],
                ["R", 1],
                ["E", 241, 15, 3],
                ["E", 1, 14, 903000],
                ["E", 1, 14, 904000],
                ["C", 1, 1, 905000],
                ["C", 1, 6, 906000],
                ["E", 1, 15, 907000],
                ["S"],
            ],
            [1, 241],
            full,
        )
        case(
            "gap_cancel",
            [["R", 1], ["R", 2], ["C", 2, 1, 905000], ["S"], ["S"]],
            [1, 2],
            full,
        )
        case(
            "drop_then_display",
            [
                ["R", 1],
                ["C", 1, 4, 905000],
                ["S"],
                ["R", 2],
                ["C", 2, 1, 906000],
                ["S"],
            ],
            [1, 2],
            full,
        )
        case(
            "duplicate_received",
            [
                ["R", 1],
                ["C", 1, 1, 905000],
                ["R", 1, 800000, 801000, 907000, 999],
                ["S"],
            ],
            [1],
            full,
        )
        case(
            "zero_initial",
            [
                ["R", 0],
                ["C", 0, 1, 905000],
                ["S"],
                ["R", 1],
                ["C", 1, 1, 906000],
                ["S"],
            ],
            [0, 1],
            full,
        )
        case(
            "receive_clock_clamp",
            [["R", 1, 900000, 905000, 902000], ["C", 1, 1, 906000], ["S"]],
            [1],
            full,
        )
        case(
            "zero_events",
            [
                ["R", 1, 0, 0, 0],
                ["E", 1, 14, 0],
                ["E", 1, 15, 4],
                ["C", 1, 1, 8],
                ["S"],
            ],
            [1],
            full,
        )
        case(
            "out_of_order_display",
            [
                ["R", 1],
                ["R", 2],
                ["C", 2, 1, 905000],
                ["C", 1, 1, 906000],
                ["S"],
                ["C", 2, 1, 907000],
                ["S"],
            ],
            [1, 2],
            full,
        )
        for older, newer in ((1, 129), (1, 240), (1, 241), (239, 479)):
            case(
                f"alias_{older}_{newer}",
                [
                    ["R", older],
                    ["R", newer],
                    ["E", older, 14, 903000],
                    ["C", newer, 1, 905000],
                    ["S"],
                ],
                [older, newer],
                full,
            )
        case(
            "wrap",
            [
                ["R", 65535],
                ["C", 65535, 1, 905000],
                ["R", 0],
                ["C", 0, 1, 906000],
                ["S"],
            ],
            [0, 65535],
            full,
            watermark=65534,
        )
        case(
            "input_mark",
            [
                ["I", 17, 890000, 891000],
                ["R", dict(fid=1, input_mark=17, input_received=892000)],
                ["C", 1, 1, 905000],
                ["S"],
            ],
            [1],
            full,
        )
        case(
            "network_samples",
            [["R", 1], ["C", 1, 1, 905000], ["S"]],
            [1],
            full,
            network=dict(
                ping=12.5,
                server=8000000,
                client=4000000,
                link=16000000,
                total=100,
                lost=3,
            ),
        )
    case("audio_report", [["R", 1], ["C", 1, 1, 905000], ["S"]], [1], type=0)
    for offset in (0, 123, -123):
        for full in (False, True):
            case(
                "packet_normalization",
                [
                    [
                        "P",
                        dict(
                            fid=1,
                            frame_start=900000,
                            sent=901000,
                            input_mark=17,
                            input_received=892000,
                        ),
                    ],
                    ["C", 1, 1, 905000],
                    ["S"],
                ],
                [0, 1],
                full,
            )
            scenarios[-1]["offset"] = offset
    for last_mark, mark, repeat in (
        (16, 17, False),
        (65535, 1, False),
        (16, 17, True),
        (16, 16, False),
        (16, 18, False),
    ):
        case(
            "create_input_mark",
            [
                ["M", last_mark, 890000, 891000],
                ["R", dict(fid=1, input_mark=mark, input_received=892000)],
                *(
                    [["R", dict(fid=2, input_mark=mark, input_received=893000)]]
                    if repeat
                    else []
                ),
                ["C", 1, 1, 905000],
                ["S"],
            ],
            [1, 2],
        )
    for full in (False, True):
        case(
            "event_replacement_and_zero_clock",
            [
                ["R", 1, 0, 0, 0],
                ["E", 1, 12, 100],
                ["E", 1, 14, 0],
                ["E", 1, 14, 20],
                ["E", 1, 15, 1],
                ["E", 1, 15, 30],
                ["C", 1, 0, 0],
                ["C", 1, 1, 1],
                ["S"],
                ["E", 1, 15, 40],
                ["C", 1, 1, 50],
            ],
            [0, 1],
            full,
        )
        case(
            "older_input_mark",
            [
                ["M", 16, 890000, 891000],
                ["M", 17, 892000, 893000],
                ["R", dict(fid=1, input_mark=17, input_received=894000)],
                ["R", dict(fid=2, input_mark=18, input_received=895000)],
                ["C", 2, 1, 905000],
                ["S"],
            ],
            [1, 2],
            full,
        )
    for i in scenarios:
        r = Stats(binary, i["full"], i["offset"])
        typ = i.get("type", 1)
        if "watermark" in i:
            r.u.mem_write(
                r.ring(typ) + 8, struct.pack("<HH", i["watermark"], i["watermark"])
            )
        if "network" in i:
            n = i["network"]
            for address, value in (
                (r.connection + 732, n["ping"]),
                (r.connection + 1152, n["server"]),
                (r.connection + 1000, n["client"]),
                (config.CLIENT + 964, n["link"]),
            ):
                r.u.mem_write(address, struct.pack("<f", value))
            r.wi(r.connection + 1248, n["total"])
            r.wi(r.connection + 1252, n["lost"])
        stages = []
        for action in i["actions"]:
            if action[0] in ("R", "P"):
                if isinstance(action[1], dict):
                    r.receive(**action[1], typ=typ, packet=action[0] == "P")
                else:
                    r.receive(*action[1:], typ=typ)
            elif action[0] == "E":
                r.call(0x7AC35C, config.CLIENT, typ, *action[1:])
            elif action[0] == "C":
                _, fid, result, r.now = action
                r.call(0x7AC3F8, config.CLIENT, typ, fid, result)
            elif action[0] == "I":
                _, mark, begin, sent = action
                r.u.mem_write(config.CLIENT + 0x1F67C, struct.pack("<H", mark))
                r.u.mem_write(
                    config.CLIENT + 0x1C67C + (mark & 1023) * 12,
                    struct.pack("<H2xII", mark, begin, sent),
                )
            elif action[0] == "M":
                _, last_mark, begin, r.now = action
                r.u.mem_write(config.CLIENT + 0x1F67C, struct.pack("<H", last_mark))
                assert r.call(0x7A9240, config.CLIENT, begin) == (
                    last_mark + 1 if last_mark != 65535 else 1
                )
            else:
                r.call(0x7A82E8, config.CLIENT, typ)
            stages.append(r.observe(i["ids"], typ))
        cases.append(dict(input=i, observed=stages))
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
    ref = ROOT / "scripts/fixtures/steam-frame-stats-reference.json"
    if a.refresh_reference:
        if ref.exists():
            old = json.loads(ref.read_text())
            assert old["cases"] == report["cases"][: len(old["cases"])]
        ref.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert json.loads(ref.read_text()) == report
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Official frame stats: {len(report['cases'])} cases passed")


if __name__ == "__main__":
    main()
