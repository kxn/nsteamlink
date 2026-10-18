#!/usr/bin/env python3
"""Execute official client channel TX -> deadline -> next-update disconnect.

The pinned Android Socket/Connection and real retained windows execute, including
Disconnect, CRC wire creation, next-update ID clearing and original client
OnStreamDisconnected. Client phase effects of that handler are recorded source
only: native application notices are compared at the transport delegate boundary,
not claimed to be the same app/player callback. Initial connection state, clock,
paused byte, transport results and next ID are controlled. Locks, OS I/O,
refcounts and frame delivery remain adapters. Full OnThink/Stopping, all producer
interleaving, FEC activation, decoder and device lifecycle are excluded.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "network", ROOT / "scripts/audit-steam-network-cycle.py"
)
network = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network)
config = network.cycle.config


class Deadline(network.Network):
    def __init__(self, binary, crc, phase):
        super().__init__(binary, crc)
        self.notices = []
        self.wi(config.CLIENT + 256, phase)
        vt = self.q(self.q(self.connection + 368))
        self.wq(vt + 56, 0x7B0790)  # real default OnStreamUpdate: ret
        self.wq(vt + 64, config.STOP + 0x3A0)
        self.callbacks.update(
            {
                0xC0E030: lambda: self.jump(0x7FB724),
                0xC11320: lambda: self.ret(12),
                config.STOP + 0x3A0: self.closed,
            }
        )

    def closed(self):
        self.notices.append(
            dict(
                state=self.i(self.connection + 16),
                local=self.u.mem_read(self.connection + 12, 1)[0],
                peer=self.u.mem_read(self.connection + 13, 1)[0],
                tick=self.now,
            )
        )
        self.u.reg_write(config.X0, config.CLIENT)
        self.jump(0x7B00D0)

    def snapshot(self, initial):
        state = self.observe()
        state.update(
            waits=list(self.waits),
            wires=list(self.wires),
            delivered=list(self.delivered),
            metadata=list(self.metadata),
            now=self.now,
            update_tick=self.i(self.connection + 48),
            last_receive=self.i(self.connection + 52),
            ping=self.observe_collectors()["ping"],
            clock={
                k: self.i(self.connection + v)
                for k, v in (
                    ("echo", 56),
                    ("minimum", 740),
                    ("smooth", 744),
                    ("next_min_update", 736),
                    ("offset", 848),
                )
            },
            tx=self.tx_state(False),
            initial_wires=initial,
            lifecycle=dict(
                state=self.i(self.connection + 16),
                local=self.u.mem_read(self.connection + 12, 1)[0],
                peer=self.u.mem_read(self.connection + 13, 1)[0],
                notices=list(self.notices),
            ),
        )
        return state


def schedules():
    cases = []
    for crc in (False, True):
        for paused in (False, True):
            last = 1000000
            boundary = last + (180 if paused else 15) * 65536

            def add(name, cycles, *, phase=6, disconnect=False, budget=None):
                cases.append(
                    dict(
                        name=f"{name}_{int(paused)}_{int(crc)}",
                        crc=crc,
                        paused=paused,
                        phase=phase,
                        last_receive=last,
                        seeds=[network.seed(tick=boundary - 1000)],
                        cycles=cycles,
                        disconnect=disconnect,
                        budget=budget,
                    )
                )

            for delta in (-1, 0, 1):
                ticks = [boundary + delta, boundary + 200]
                if delta < 0:
                    ticks.append(boundary + 400)
                add(
                    f"edge_{delta}", [network.batch(tick=t, ready=False) for t in ticks]
                )
            add(
                "empty_read_cross",
                [
                    network.batch(boundary - 50, eof=1000),
                    network.batch(boundary + 1200, ready=False),
                    network.batch(boundary + 1400, ready=False),
                ],
            )
            add(
                "write_cross",
                [
                    network.batch(boundary - 1, eof=0, write_cost=1000),
                    network.batch(boundary + 2000, ready=False),
                    network.batch(boundary + 2200, ready=False),
                ],
            )
            add(
                "blocked_reliable",
                [
                    network.batch(boundary, ready=False),
                    network.batch(boundary + 200, ready=False),
                ],
                budget=[1, 1000, boundary + 1000],
            )
            for result in (1, 2, 3, 4):
                add(
                    f"io_failure_{result}",
                    [
                        network.batch(boundary, ready=False, result=result),
                        network.batch(boundary + 200, ready=False),
                    ],
                )
            add(
                "valid_rx_renews",
                [
                    network.batch(
                        boundary,
                        rows=[
                            network.cycle.packet(0, cost=7, work=11),
                            network.cycle.packet(1, cost=7, work=11),
                        ],
                    ),
                    network.batch(boundary + 200, ready=False),
                ],
            )
            add(
                "peer_disconnect",
                [
                    network.batch(
                        boundary,
                        rows=[
                            network.cycle.packet(
                                0, kind=9, payload="00", cost=7, work=11
                            )
                        ],
                    )
                ],
            )
            for phase in (0, 2, 6, 7):
                add(
                    f"closing_client_{phase}",
                    [network.batch(boundary, ready=False)],
                    phase=phase,
                    disconnect=True,
                )
    for crc in (False, True):
        for paused in (False, True):
            last = 0xFFFF0000
            boundary = (last + (180 if paused else 15) * 65536) & 0xFFFFFFFF
            cases.append(
                dict(
                    name=f"wrap_{int(paused)}_{int(crc)}",
                    crc=crc,
                    paused=paused,
                    phase=6,
                    last_receive=last,
                    seeds=[network.seed(tick=boundary - 1000)],
                    cycles=[
                        network.batch(boundary, ready=False),
                        network.batch(boundary + 200, ready=False),
                    ],
                    disconnect=False,
                    budget=None,
                )
            )
    return cases


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == config.SHA
    cases = []
    for inp in schedules():
        r = Deadline(binary, inp["crc"], inp["phase"])
        for row in inp["seeds"]:
            r.seed(*row)
        r.b(r.connection + 8, int(inp["paused"]))
        r.wi(r.connection + 52, inp["last_receive"])
        r.wi(r.connection + 56, inp["cycles"][0]["tick"])
        if inp["disconnect"]:
            r.call(0x7FB724, r.connection)
        initial = list(r.wires)
        if inp["budget"]:
            cls, rate, deadline = inp["budget"]
            p = r.q(r.sock + 64)
            r.wi(p + cls * 4, rate)
            r.wi(p + 8 + cls * 4, deadline)
        observed = []
        phases = []
        for b in inp["cycles"]:
            r.prepare(b["rows"], inp["crc"])
            r.now, r.ready, r.eof_cost = b["tick"], b["ready"], b["eof"]
            r.transport_result, r.write_cost = b["result"], b["write_cost"]
            r.b(r.sock + 57, int(b["blocked"]))
            for a in (
                r.entries,
                r.writes,
                r.wires,
                r.waits,
                r.delivered,
                r.metadata,
                r.notices,
            ):
                a.clear()
            wait = r.call(0x7FEB7C, r.sock)
            r.call(0x7FEB90, r.sock, wait)
            r.call(0x7FECD4, r.sock)
            observed.append(r.snapshot(initial))
            initial = []
            phases.append(r.i(config.CLIENT + 256))
        assert all(a == 1139 for a in r.asserts), (inp["name"], r.asserts)
        if inp["name"].startswith("edge_0"):
            assert [bytes.fromhex(w)[0] & 127 for w in observed[0]["wires"]] == [5, 9]
            assert (
                observed[0]["lifecycle"]["state"] == 2
                and not observed[0]["lifecycle"]["notices"]
            )
            assert (
                observed[1]["lifecycle"]["notices"][0]["state"] == 2
                and observed[1]["lifecycle"]["state"] == 3
            )
        if inp["name"].startswith(("empty_read_cross", "write_cross")):
            assert [bytes.fromhex(w)[0] & 127 for w in observed[0]["wires"]] == [5]
        if inp["disconnect"]:
            assert phases == [7 if inp["phase"] == 6 else 0]
        cases.append(
            dict(
                input=inp,
                observed=observed,
                source_client_phases=phases,
                source_assertions=list(r.asserts),
            )
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
    ref = ROOT / "scripts/fixtures/steam-network-deadline-reference.json"
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
        f"Official network deadline: {len(report['cases'])} cases, {sum(len(c['observed']) for c in report['cases'])} states"
    )


if __name__ == "__main__":
    main()
