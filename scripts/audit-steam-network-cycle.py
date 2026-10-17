#!/usr/bin/env python3
"""Execute official Android initial sends and combined RX/feedback/periodic TX.

Pinned client instructions create channels and outgoing windows, admit initial
reliable/unreliable packets, drain Socket input, update RX windows and send each
channel's reliable/unreliable traffic followed by rotating retries. Full wires,
collectors, clock, outgoing retention, shaper and rotation are observed. OS I/O,
locks, refcounts and delivered-frame delegates are adapters; time, priorities
and transport return values are controlled. FEC queues are empty. This does not
prove global producer interleaving, FEC activation, full OnThink, decoder or a
real Steam/Switch session. Initial APIs execute before the controlled RX batch.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "cycle", ROOT / "scripts/audit-steam-receive-cycle.py"
)
cycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cycle)


class Network(cycle.Cycle):
    def __init__(self, binary, crc):
        super().__init__(binary, crc)
        self.seeds = []
        self.write_cost = 0
        self.callbacks.update(
            {
                0xC11200: lambda: self.jump(0x7F8AC4),
                0xC11220: lambda: self.jump(0x7F8CBC),
            }
        )

    def seed(self, tick, kind, channel, payload, result):
        self.now, self.transport_result = tick, result
        ch = self.call(0x7FBA34, self.connection, channel)
        data = bytes.fromhex(payload)
        p = self.packet(kind, channel, False, 12, 34, len(data))
        self.u.mem_write(self.q(p + 40) + 13, data)
        self.call(0x7F89DC if kind == 5 else 0x7F8BD8, ch, p)
        ident = struct.unpack("<H", self.u.mem_read(self.q(p + 40) + 7, 2))[0]
        self.seeds.append((kind, channel, ident))

    def write(self):
        super().write()
        self.now = (self.now + self.write_cost) & 0xFFFFFFFF

    def tx_state(self):
        windows = []
        for kind, channel, ident in self.seeds:
            ch = self.channels[channel]
            w = ch + (112 if kind == 5 else 248)
            head, tail = struct.unpack("<HH", self.u.mem_read(w + 8, 4))
            p = 0
            if ((ident - head) & 65535) < ((tail - head) & 65535):
                p = self.q(self.q(w + 16) + (ident & self.i(w + 4)) * 8)
            state = dict(kind=kind, channel=channel, id=ident, retained=bool(p))
            if kind == 3:
                raw = self.q(p + 40) if p else 0
                state.update(
                    head=head,
                    tail=tail,
                    cursor=struct.unpack("<H", self.u.mem_read(ch + 244, 2))[0],
                    count=self.u.mem_read(raw + 1, 1)[0] if p else 0,
                    stamp=struct.unpack("<I", self.u.mem_read(raw + 9, 4))[0]
                    if p
                    else 0,
                )
            windows.append(state)
        shaper = self.q(self.sock + 64)
        return dict(
            windows=windows,
            order=[
                self.u.mem_read(self.q(self.connection + 384 + n * 8) + 16, 1)[0]
                for n in range(len(self.channels))
            ],
            rotation=self.u.mem_read(self.connection + 377, 1)[0],
            blocked=bool(self.u.mem_read(self.sock + 57, 1)[0]),
            deadlines=[self.i(shaper + 8), self.i(shaper + 12)],
        )


def batch(
    tick=1000000, rows=(), *, eof=100, ready=True, result=0, blocked=False, write_cost=0
):
    return dict(
        tick=tick,
        rows=list(rows),
        eof=eof,
        ready=ready,
        result=result,
        blocked=blocked,
        write_cost=write_cost,
    )


def seed(kind=5, channel=4, tick=999900, result=0, payload="aabb"):
    return [tick, kind, channel, payload, result]


def schedules():
    cases = []
    for crc in (False, True):

        def add(name, seeds, cycles, **extra):
            cases.append(
                dict(
                    name=f"{name}_{int(crc)}",
                    crc=crc,
                    seeds=seeds,
                    cycles=cycles,
                    **extra,
                )
            )

        for age in (80, 81, 82):
            add(f"rto_batch_{age}", [seed(tick=1000000 - age)], [batch()])
        add(
            "failed_initial",
            [seed(result=1), seed(kind=3, channel=5, result=1)],
            [batch(), batch(1000200, ready=False)],
        )
        add(
            "unreliable_fresh_expire",
            [seed(kind=3, tick=986670), seed(tick=999919)],
            [batch()],
        )
        add("no_readiness", [seed(), seed(kind=3, channel=5)], [batch(ready=False)])
        for priority in (10, -10):
            rows = [
                cycle.packet(1, kind=3, channel=3, cost=7, work=11),
                cycle.packet(0, cost=7, work=11),
                cycle.packet(1, cost=7, work=11),
            ]
            add(
                f"feedback_tx_priority_{priority}",
                [seed(channel=3), seed(channel=4), seed(kind=3, channel=5, result=1)],
                [batch(rows=rows)],
                priorities=[[3, priority], [4, -priority]],
            )
        echo = struct.pack("<I", 999900).hex()
        # Reliable ACK is type7, NACK type8. An ACK of id0 confirms the first
        # retained outgoing packet. Nonempty bodies keep the general RX fixture
        # carrier path independent of its empty-frame consumer special case.
        nack = cycle.packet(
            1, kind=8, payload=struct.pack("<I", 999980).hex() + "ffff", cost=7, work=11
        )
        ack = cycle.packet(0, kind=7, payload=echo, cost=7, work=11)
        add("nack_then_ack", [seed(tick=999980)], [batch(rows=[nack, ack])])
        add("nack_only", [seed(tick=999980)], [batch(rows=[nack])])
        add("ack_then_nack", [seed(tick=999980)], [batch(rows=[ack, nack])])
        for result in (1, 2, 3, 4):
            add(
                f"tx_failure_{result}",
                [
                    seed(),
                    seed(channel=4),
                    seed(channel=5),
                    seed(kind=3, channel=6, result=1),
                ],
                [batch(result=result), batch(1000200, ready=False)],
            )
        for cls in (0, 1):
            add(
                f"budget_class_{cls}",
                [seed(), seed(channel=5), seed(kind=3, channel=5, result=1)],
                [
                    batch(eof=0),
                    batch(1000020, ready=False),
                    batch(1001100, ready=False),
                ],
                budget=[cls, 1000, 1000010],
            )
        # Mark initial packets with a real type10 NACK and exercise retry rotation
        # through a complete factory order wrap, with a limited class0 budget.
        unacks = [
            cycle.packet(1, kind=10, channel=ch, payload=echo + "ffff", cost=7, work=11)
            for ch in (4, 5, 6)
        ]
        add(
            "rotation",
            [seed(kind=3), seed(kind=3, channel=5), seed(kind=3, channel=6)],
            [
                batch(rows=unacks),
                *[batch(1002000 + n * 2000, rows=unacks) for n in range(9)],
            ],
            budget=[0, 1000, 1000000],
        )
        add(
            "write_cost_batch_tick",
            [
                seed(channel=3, tick=999918),
                seed(channel=4, tick=999919),
                seed(kind=3, channel=5, result=1),
            ],
            [batch(eof=0, write_cost=100)],
        )
        add(
            "feedback_write_cost",
            [seed(channel=4, tick=999955), seed(kind=3, channel=5, result=1)],
            [
                batch(
                    rows=[cycle.packet(1, kind=3, channel=3, cost=7, work=11)],
                    write_cost=100,
                )
            ],
        )
    return cases


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == cycle.config.SHA
    cases = []
    for inp in schedules():
        r = Network(binary, inp["crc"])
        for row in inp["seeds"]:
            r.seed(*row)
        initial = list(r.wires)
        for channel, priority in inp.get("priorities", []):
            r.call(0x7FBC68, r.connection, channel, priority & 0xFFFFFFFF)
        if "budget" in inp:
            cls, rate, deadline = inp["budget"]
            shaper = r.q(r.sock + 64)
            r.wi(shaper + cls * 4, rate)
            r.wi(shaper + 8 + cls * 4, deadline)
        r.wi(r.connection + 52, inp["cycles"][0]["tick"])
        r.wi(r.connection + 56, inp["cycles"][0]["tick"])
        observed = []
        for b in inp["cycles"]:
            r.prepare(b["rows"], inp["crc"])
            r.now, r.ready, r.eof_cost = b["tick"], b["ready"], b["eof"]
            r.transport_result, r.write_cost = b["result"], b["write_cost"]
            r.b(r.sock + 57, int(b["blocked"]))
            for values in (
                r.entries,
                r.writes,
                r.wires,
                r.waits,
                r.delivered,
                r.metadata,
            ):
                values.clear()
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
                tx=r.tx_state(),
                initial_wires=initial,
            )
            initial = []
            observed.append(state)
        assert all(a == 1139 for a in r.asserts), (inp["name"], r.asserts)
        # Assert non-vacuous discriminators independently of the native mirror.
        if inp["name"].startswith("nack_only"):
            assert len(observed[0]["wires"]) == 1
        if inp["name"].startswith("nack_then_ack"):
            assert (
                not observed[0]["wires"]
                and not observed[0]["tx"]["windows"][0]["retained"]
            )
        if inp["name"].startswith("rotation"):
            assert {bytes.fromhex(w)[4] for v in observed for w in v["wires"]} == {
                4,
                5,
                6,
            }
        if inp["name"].startswith("write_cost_batch_tick"):
            assert [bytes.fromhex(w)[4] for w in observed[0]["wires"]] == [3, 5]
        cases.append(
            dict(input=inp, observed=observed, source_assertions=list(r.asserts))
        )
    return cases


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    report = dict(
        binary_sha256=cycle.config.SHA,
        scope=__doc__,
        cases=audit(a.binary.read_bytes()),
    )
    ref = ROOT / "scripts/fixtures/steam-network-cycle-reference.json"
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
    print(
        f"Official network cycle: {len(report['cases'])} cases, {sum(len(c['observed']) for c in report['cases'])} states"
    )


if __name__ == "__main__":
    main()
