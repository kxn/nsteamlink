#!/usr/bin/env python3
"""Run original Socket Wait/Update -> CRC RX -> Connection/channel updates.

The pinned client executes readiness flag/GetWaitMS, drain loop, timestamp
capture, Connection::Update, real channel factory/windows, reliable/media feedback,
Socket TX/CRC and network/clock collectors. Transport wait/read/final write,
packet refcounts and delivered-frame/client-update delegates are adapters;
connection state/clock initialization are controlled. Incoming rows can spend
controlled ticks in read and processing, including the final empty read.
Outgoing queues are empty. This does not prove full client OnThink, producer/TX
worker interleaving, decoder, fatal OS-read policy, authentication or device IO.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "loss", ROOT / "scripts/audit-steam-network-loss.py"
)
loss = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loss)
config = loss.config


class Cycle(loss.Loss):
    def __init__(self, binary, crc):
        super().__init__(binary, crc)
        self.rows, self.index, self.eof_cost = [], 0, 0
        self.metadata, self.wires, self.waits = [], [], []
        self.ready, self.work = True, 0
        vt = self.q(self.transport)
        self.wq(vt + 64, config.STOP + 0x390)
        self.wq(vt + 80, config.STOP + 0x394)
        pvt = self.q(self.q(self.connection + 368))
        self.wq(pvt + 56, config.STOP + 0x398)
        self.callbacks.update(
            {
                config.STOP + 0x390: self.wait,
                config.STOP + 0x394: self.read,
                config.STOP + 0x398: lambda: self.ret(),
                0xC11550: self.handle_timed,
                0xC11490: lambda: self.jump(0x7FC108),
                0xC11170: lambda: self.jump(0x7FF1DC),
            }
        )

    def wait(self):
        self.waits.append(self.r(1))
        self.ret(int(self.ready))

    def read(self):
        if self.index == len(self.rows):
            self.now = (self.now + self.eof_cost) & 0xFFFFFFFF
            self.ret(1)
            return
        packet, cost, self.work = self.rows[self.index]
        self.index += 1
        self.now = (self.now + cost) & 0xFFFFFFFF
        self.wq(self.r(1), packet)
        self.ret(0)

    def handle_timed(self):
        self.now = (self.now + self.work) & 0xFFFFFFFF
        self.jump(0x7FF3E0)

    def deliver(self):
        p = self.r(2)
        raw = self.q(p + 40)
        self.delivered.append(
            bytes(self.u.mem_read(raw + 13, self.i(p + 52) - 13)).hex()
        )
        self.metadata.append(
            dict(
                first=self.i(p + 28),
                last=self.i(p + 32),
                sent=struct.unpack("<I", self.u.mem_read(raw + 9, 4))[0],
                fragment=struct.unpack("<H", self.u.mem_read(raw + 5, 2))[0],
            )
        )
        self.ret()

    def write(self):
        p = self.r(1)
        raw = self.q(p + 40)
        crc = bool(self.u.mem_read(raw, 1)[0] & 128)
        self.wires.append(
            bytes(self.u.mem_read(raw, self.i(p + 52) + (4 if crc else 0))).hex()
        )
        super().write()

    def prepare(self, rows, crc):
        out = []
        for kind, channel, pid, retry, fragment, sent, payload, cost, work in rows:
            data = bytes.fromhex(payload)
            p = self.packet(kind, channel, False, 34, 12, len(data))
            raw = self.q(p + 40)
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
                    pid,
                    sent,
                )
                + data,
            )
            if crc:
                check = self.call(0x8E1610, raw, 13 + len(data))
                self.u.mem_write(raw + 13 + len(data), struct.pack("<I", check))
                self.wi(p + 52, 17 + len(data))
            out.append((p, cost, work))
        self.rows, self.index = out, 0


def packet(
    pid, kind=5, retry=0, cost=0, work=0, channel=4, fragment=0, payload="06aabb"
):
    return [kind, channel, pid, retry, fragment, 900000 + pid, payload, cost, work]


def schedules():
    cases = []
    for crc in (False, True):
        for blocked in (False, True):
            for ready in (False, True):
                cases.append(
                    dict(
                        name=f"empty_{int(crc)}_{int(blocked)}_{int(ready)}",
                        crc=crc,
                        cycles=[
                            dict(
                                tick=1000000,
                                blocked=blocked,
                                ready=ready,
                                eof=100,
                                rows=[],
                            )
                        ],
                    )
                )
        for count in (1, 2, 17, 130):
            cases.append(
                dict(
                    name=f"batch_{count}_{int(crc)}",
                    crc=crc,
                    cycles=[
                        dict(
                            tick=1000000,
                            blocked=False,
                            ready=True,
                            eof=100,
                            rows=[
                                packet(i, retry=i % 4, cost=7, work=11)
                                for i in range(count)
                            ],
                        )
                    ],
                )
            )
        cases.append(
            dict(
                name=f"fragments_{int(crc)}",
                crc=crc,
                cycles=[
                    dict(
                        tick=1000000,
                        blocked=False,
                        ready=True,
                        eof=500,
                        rows=[
                            packet(
                                0, fragment=2, retry=2, cost=10, work=20, payload="06aa"
                            ),
                            packet(
                                2,
                                kind=6,
                                fragment=1,
                                retry=3,
                                cost=30,
                                work=40,
                                payload="dd",
                            ),
                            packet(
                                1,
                                kind=6,
                                fragment=0,
                                retry=1,
                                cost=50,
                                work=60,
                                payload="bbcc",
                            ),
                        ],
                    )
                ],
            )
        )
        for age in (64, 65, 66):
            cases.append(
                dict(
                    name=f"gap_age_{age}_{int(crc)}",
                    crc=crc,
                    cycles=[
                        dict(
                            tick=1000000,
                            blocked=False,
                            ready=True,
                            eof=1000,
                            rows=[packet(1, retry=1, cost=age)],
                        )
                    ],
                )
            )
        cases.append(
            dict(
                name=f"ack_capture_{int(crc)}",
                crc=crc,
                cycles=[
                    dict(
                        tick=1000000,
                        blocked=False,
                        ready=True,
                        eof=100,
                        rows=[packet(0, cost=100, work=100)],
                    ),
                    dict(
                        tick=1001000,
                        blocked=False,
                        ready=True,
                        eof=200,
                        rows=[
                            packet(
                                0,
                                kind=7,
                                cost=300,
                                work=400,
                                payload=struct.pack("<I", 1000000).hex(),
                            )
                        ],
                    ),
                ],
            )
        )
        cases.append(
            dict(
                name=f"split_updates_{int(crc)}",
                crc=crc,
                cycles=[
                    dict(
                        tick=1000000,
                        blocked=False,
                        ready=True,
                        eof=100,
                        rows=[packet(0)],
                    ),
                    dict(
                        tick=1000100,
                        blocked=False,
                        ready=True,
                        eof=100,
                        rows=[packet(1)],
                    ),
                    dict(tick=1000200, blocked=False, ready=False, eof=1000, rows=[]),
                ],
            )
        )
    for crc in (False, True):
        for name, rows in (
            (
                "media_batch",
                [packet(n, kind=3, channel=3, cost=7, work=11) for n in range(2)],
            ),
            (
                "media_fill",
                [
                    packet(n, kind=3, channel=3, retry=1, cost=7, work=11)
                    for n in (1, 0)
                ],
            ),
            (
                "media_fragments",
                [
                    packet(
                        0,
                        kind=3,
                        channel=3,
                        fragment=1,
                        payload="06aa",
                        cost=7,
                        work=11,
                    ),
                    packet(1, kind=4, channel=3, payload="bbcc", cost=7, work=11),
                ],
            ),
        ):
            cases.append(
                dict(
                    name=f"{name}_{int(crc)}",
                    crc=crc,
                    cycles=[
                        dict(
                            tick=1000000, blocked=False, ready=True, eof=100, rows=rows
                        )
                    ],
                )
            )
        cases.append(
            dict(
                name=f"media_gap_{int(crc)}",
                crc=crc,
                cycles=[
                    dict(
                        tick=1000000,
                        blocked=False,
                        ready=True,
                        eof=0,
                        rows=[packet(1, kind=3, channel=3, retry=1)],
                    ),
                    *[
                        dict(
                            tick=1000000 + d, blocked=False, ready=False, eof=0, rows=[]
                        )
                        for d in (64, 65, 66)
                    ],
                    dict(
                        tick=1000300,
                        blocked=False,
                        ready=True,
                        eof=100,
                        rows=[packet(0, kind=3, channel=3, retry=2, cost=7, work=11)],
                    ),
                ],
            )
        )
        cases.append(
            dict(
                name=f"media_expire_{int(crc)}",
                crc=crc,
                cycles=[
                    dict(
                        tick=1000000,
                        blocked=False,
                        ready=True,
                        eof=100,
                        rows=[
                            packet(1, kind=3, channel=3),
                            packet(
                                3,
                                kind=3,
                                channel=3,
                                fragment=1,
                                cost=7,
                                work=11,
                                payload="06bb",
                            ),
                        ],
                    ),
                ],
            )
        )
        cases[-1]["cycles"][0]["rows"][1][5] = 910000
    for crc in (False, True):
        for priority in (10, -10):
            cases.append(
                dict(
                    name=f"media_priority_{priority}_{int(crc)}",
                    crc=crc,
                    priorities=[[3, priority], [4, -priority]],
                    cycles=[
                        dict(
                            tick=1000000,
                            blocked=False,
                            ready=True,
                            eof=100,
                            rows=[
                                packet(1, kind=3, channel=3, retry=0, cost=7, work=11),
                                packet(0, kind=5, channel=4, retry=0, cost=7, work=11),
                                packet(1, kind=5, channel=4, retry=0, cost=7, work=11),
                            ],
                        )
                    ],
                )
            )
    return cases


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == config.SHA
    cases = []
    for i in schedules():
        r = Cycle(binary, i["crc"])
        for channel, priority in i.get("priorities", []):
            r.call(0x7FBC68, r.connection, channel, priority & 0xFFFFFFFF)
        r.wi(r.connection + 52, i["cycles"][0]["tick"])
        r.wi(r.connection + 56, i["cycles"][0]["tick"])
        observed = []
        for cycle in i["cycles"]:
            r.prepare(cycle["rows"], i["crc"])
            r.now = cycle["tick"]
            r.ready = cycle["ready"]
            r.eof_cost = cycle["eof"]
            r.b(r.sock + 57, int(cycle["blocked"]))
            r.entries.clear()
            r.writes.clear()
            r.wires.clear()
            r.waits.clear()
            r.delivered.clear()
            r.metadata.clear()
            wait = r.call(0x7FEB7C, r.sock)
            r.call(0x7FEB90, r.sock, wait)
            r.call(0x7FECD4, r.sock)
            state = r.observe()
            state.update(
                waits=list(r.waits),
                wires=list(r.wires),
                delivered=list(r.delivered),
                metadata=list(r.metadata),
                now=r.now,
                update_tick=r.i(r.connection + 48),
                last_receive=r.i(r.connection + 52),
                ping=r.observe_collectors()["ping"],
                clock={
                    k: r.i(r.connection + v)
                    for k, v in (
                        ("echo", 56),
                        ("minimum", 740),
                        ("smooth", 744),
                        ("next_min_update", 736),
                        ("offset", 848),
                    )
                },
            )
            observed.append(state)
        assert all(a == 1139 for a in r.asserts), (i["name"], r.asserts)
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
    ref = ROOT / "scripts/fixtures/steam-receive-cycle-reference.json"
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
    print(f"Official receive cycle: {len(report['cases'])} cases passed")


if __name__ == "__main__":
    main()
