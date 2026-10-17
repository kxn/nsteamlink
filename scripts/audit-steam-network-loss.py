#!/usr/bin/env python3
"""Execute official client Socket -> Channel -> windows -> live loss collectors.

Pinned Android instructions execute channel construction, real window growth,
insert, reliable/unreliable update, Pop and PacketStats. Channel max receive delay
is set through the real setter to the active-media value documented in §25.2.
Final feedback I/O, packet refcounts, platform locks and the player delegate are
adapters. Optional report steps execute original Streaming/FrameEvents/protobuf;
report encryption/final frame admission remain adapters. No decoder, full global
loop, early-media cache, FEC or Steam session equivalence is implied.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "wire", ROOT / "scripts/audit-steam-network-wire.py"
)
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)
config = wire.config


class Loss(wire.Wire):
    def __init__(self, binary, crc=False):
        super().__init__(binary, crc)
        self.channels, self.delivered = {}, []
        player, vt = self.alloc(4096), self.alloc(4096)
        self.wq(self.connection + 368, player)
        self.wq(player, vt)
        self.wq(vt + 48, config.STOP + 0x380)
        self.callbacks.update(
            {
                0xC017F0: lambda: self.ret(1),
                0xC01810: self.release_guard,
                0xC09AB0: lambda: self.ret(self.alloc(self.r(0))),
                0xC09AC0: lambda: self.ret(),
                0xC0E390: lambda: self.jump(0x7FBA34),
                0xC11470: self.construct,
                0xC11250: lambda: self.jump(0x7F9250),
                config.STOP + 0x380: self.deliver,
            }
        )
        # This is the real setter called by StartVideo/AudioData, not a claim
        # that generic channels have this constructor default.
        self.call(0x7FBC98, self.connection, 3, 6553)

    def release_guard(self):
        self.b(self.r(0), 1)
        self.ret()

    def construct(self):
        self.channels[self.r(3)] = self.r(0)
        self.jump(0x7F8630)

    def deliver(self):
        p = self.r(2)
        raw = self.q(p + 40)
        self.delivered.append(
            bytes(self.u.mem_read(raw + 13, self.i(p + 52) - 13)).hex()
        )
        self.ret()

    def receive_packet(self, kind, channel, packet_id, retry, fragment, sent, payload):
        payload = bytes.fromhex(payload)
        p = self.packet(kind, channel, False, 34, 12, len(payload))
        raw = self.q(p + 40)
        crc = bool(self.u.mem_read(self.connection + 10, 1)[0])
        self.u.mem_write(
            raw,
            struct.pack(
                "<BBBBBHHI",
                kind | (128 if crc else 0),
                retry,
                34,
                12,
                channel,
                fragment,
                packet_id,
                sent,
            )
            + payload,
        )
        if crc:
            check = self.call(0x8E1610, raw, 13 + len(payload))
            self.u.mem_write(raw + 13 + len(payload), struct.pack("<I", check))
            self.wi(p + 52, 17 + len(payload))
        self.call(0x7FF3E0, self.sock, p, self.now)


def scenarios():
    cases = []
    for crc in (False, True):
        for kind, ch in ((5, 4), (3, 3)):
            for retry in (0, 1, 2, 3, 255):
                actions = [
                    ["W", 1000000, kind, ch, 0, retry, 0, 900000, "06aabb"],
                    ["W", 1000001, kind, ch, 0, 255, 0, 900001, "06ccdd"],
                    ["U", 1000002, ch],
                    ["W", 1000003, kind, ch, 0, 255, 0, 900002, "06eeff"],
                    ["U", 1000004, ch],
                ]
                cases.append(
                    dict(
                        name=f"retry_{kind}_{retry}_{int(crc)}",
                        crc=crc,
                        actions=actions,
                    )
                )
            cases.append(
                dict(
                    name=f"fragments_{kind}_{int(crc)}",
                    crc=crc,
                    actions=[
                        ["W", 1000000, kind, ch, 0, 2, 2, 900000, "06aa"],
                        ["W", 1000001, kind + 1, ch, 2, 1, 1, 900000, "dd"],
                        ["U", 1000002, ch],
                        ["W", 1000003, kind + 1, ch, 1, 3, 0, 900000, "bbcc"],
                        ["U", 1000004, ch],
                    ],
                )
            )
            cases.append(
                dict(
                    name=f"hole_fill_{kind}_{int(crc)}",
                    crc=crc,
                    actions=[
                        ["W", 1000000, kind, ch, 1, 2, 0, 900000, "06aa"],
                        ["U", 1000001, ch],
                        ["W", 1000002, kind, ch, 0, 3, 0, 899999, "06bb"],
                        ["U", 1000003, ch],
                    ],
                )
            )
        for base in (900000, 0xFFFFF000):
            for delta in (6946, 6947):
                cases.append(
                    dict(
                        name=f"age_{base}_{delta}_{int(crc)}",
                        crc=crc,
                        actions=[
                            ["T", 999344, 1000000, 1000000],
                            ["W", 1000000, 3, 3, 1, 2, 0, base, "06aa"],
                            [
                                "W",
                                1000001,
                                3,
                                3,
                                3,
                                3,
                                0,
                                (base + delta) & 0xFFFFFFFF,
                                "06bb",
                            ],
                            ["U", 1000002, 3],
                        ],
                    )
                )
        cases.append(
            dict(
                name=f"orphan_{int(crc)}",
                crc=crc,
                actions=[
                    ["W", 1000000, 4, 3, 0, 2, 0, 900000, "aa"],
                    ["W", 1000001, 3, 3, 1, 3, 0, 900000, "06bb"],
                    ["U", 1000002, 3],
                ],
            )
        )
        cases.append(
            dict(
                name=f"growth_{int(crc)}",
                crc=crc,
                actions=[
                    ["W", 1000000, 5, 4, 600, 2, 0, 900000, "06aa"],
                    ["W", 1000001, 5, 4, 600, 3, 0, 900001, "06bb"],
                    ["W", 1000002, 5, 4, 16384, 2, 0, 900002, "06cc"],
                    ["U", 1000003, 4],
                ],
            )
        )
        cases.append(
            dict(
                name=f"loss_without_frame_{int(crc)}",
                crc=crc,
                actions=[
                    ["W", 1000000, 3, 3, 1, 0, 0, 900000, "06aa"],
                    ["W", 1000001, 3, 3, 3, 0, 1, 910000, "06bb"],
                    ["U", 1000002, 3],
                    ["U", 1000003, 3],
                ],
            )
        )
        cases.append(
            dict(
                name=f"sample_expiry_{int(crc)}",
                crc=crc,
                actions=[
                    ["W", 1000000, 5, 4, 0, 2, 0, 900000, "06aa"],
                    ["U", 1000001, 4],
                    ["W", 1196608, 5, 4, 1, 3, 0, 900001, "06bb"],
                    ["U", 1196609, 4],
                    ["W", 1393218, 5, 4, 1, 255, 0, 900001, "06cc"],
                    ["U", 1393219, 4],
                ],
            )
        )
        for full in (False, True):
            cases.append(
                dict(
                    name=f"report_{int(crc)}_{int(full)}",
                    crc=crc,
                    full=full,
                    actions=[
                        ["W", 1000000, 5, 4, 0, 2, 0, 900000, "06aa"],
                        ["U", 1000001, 4],
                        ["R", 1],
                        ["C", 1, 906000],
                        ["S", 1100000],
                        ["W", 1200000, 3, 3, 1, 3, 0, 1000000, "06bb"],
                        ["W", 1200001, 3, 3, 3, 1, 0, 1010000, "06cc"],
                        ["U", 1200002, 3],
                        ["R", 2],
                        ["C", 2, 1199000],
                        ["S", 1200003],
                    ],
                )
            )
    return cases


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == config.SHA
    cases = []
    for i in scenarios():
        r = Loss(binary, i["crc"])
        r.b(config.CLIENT + 636, int(i.get("full", False)))
        observed = []
        for op, *v in i["actions"]:
            r.entries.clear()
            r.frames.clear()
            r.delivered.clear()
            if op == "W":
                r.now, *args = v
                r.receive_packet(*args)
            elif op == "U":
                r.now, ch = v
                r.call(0x7F9C9C, r.channels[ch], r.now)
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
            state = r.observe()
            state["delivered"] = list(r.delivered)
            if "full" in i:
                state.update(
                    frames=list(r.frames),
                    frame_events_time=r.i(config.CLIENT + 0x1C678),
                    keepalive_time=r.i(config.CLIENT + 0x1F6F0),
                    sequence=r.q(config.CLIENT + 128),
                    reported=r.i(r.ring(1) + 8) >> 16,
                )
            observed.append(state)
        # Original "increasing" diagnostic on a gap feedback path; assertions
        # are captured, return false and do not terminate the original function.
        assert all(line == 1139 for line in r.asserts), (i, r.asserts)
        cases.append(
            dict(input=i, observed=observed, source_assertions=list(r.asserts))
        )
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
    ref = ROOT / "scripts/fixtures/steam-network-loss-reference.json"
    if a.refresh_reference:
        if ref.exists():
            assert (
                json.loads(ref.read_text())["cases"]
                == report["cases"][: len(json.loads(ref.read_text())["cases"])]
            )
        ref.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert json.loads(ref.read_text()) == report
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Official client network loss: {len(report['cases'])} cases passed")


if __name__ == "__main__":
    main()
