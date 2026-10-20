#!/usr/bin/env python3
"""Execute official network manager, Socket drain and optional main OnThink.

The pinned Android client executes threaded-mode setter, AddSocket, pending-vector
append, readiness selection, reverse Socket updates/removal, real Socket/Connection/
channel RX and feedback, StreamProcessNetwork, Run stop checks and BInit/OnThink
network dispatch.
Only one Socket has a live connection; other Sockets intentionally have none.
Manager/container initial storage and clocks are seeded. OS waits/read/write,
mutex operations, thread Join/Start/priority requests, destruction/refcounts, frame/client
delegates and OnThink transport/log stages are adapters. No OS scheduling,
thread creation, decoder, global producer serialization or Steam session claim.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "cycle", ROOT / "scripts/audit-steam-receive-cycle.py"
)
cycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cycle)
config = cycle.config
MANAGER = 0xF479F0


class Manager(cycle.Cycle):
    def __init__(self, binary, inp):
        super().__init__(binary, inp["crc"])
        self.trace, self.depth = [], 0
        self.inp = inp
        self.sockets, self.by_transport = {}, {}
        self.live_updates = 0
        self.now = 1000000
        self.wi(self.connection + 52, self.now)
        self.wi(self.connection + 56, self.now)
        # The real manager's vector storage is preallocated, not its algorithms.
        active, pending = self.alloc(512), self.alloc(512)
        self.u.mem_write(MANAGER, bytes(176))
        self.wq(MANAGER + 120, pending)
        self.wi(MANAGER + 128, 64)
        self.wq(MANAGER + 144, active)
        self.wi(MANAGER + 152, 64)
        self.call(0x7FEEC0, int(inp["threaded"]))
        if inp["entry"] == "think":
            assert inp["threaded"] == inp["own_network"]
            assert self.call(0x7A5DF8, config.CLIENT, int(inp["own_network"])) == 1
            assert [
                self.u.mem_read(config.CLIENT + offset, 1)[0] for offset in (16, 17, 18)
            ] == [int(inp["own_network"])] * 3
            assert self.u.mem_read(MANAGER + 168, 1)[0] == int(inp["own_network"])
        self.b(MANAGER + 170, int(inp.get("running", inp["threaded"])))
        for index, flags in enumerate(inp["sockets"]):
            if index == inp["live"]:
                sock, transport = self.sock, self.transport
            else:
                sock, transport, vt = (self.alloc(4096) for _ in range(3))
                self.wq(sock, transport)
                self.wq(transport, vt)
                self.wq(vt + 64, config.STOP + 0x390)
                self.wq(vt + 80, config.STOP + 0x394)
            self.sockets[sock] = index
            self.by_transport[transport] = index
            self.b(sock + 57, int(flags["blocked"]))
            if index < inp["active"]:
                self.wq(active + index * 8, sock)
        self.wi(MANAGER + 160, inp["active"])
        self.prepare(
            [cycle.packet(i, retry=i + 1, cost=7, work=11) for i in range(2)],
            inp["crc"],
        )
        self.eof_cost = 100
        self.callbacks.update(
            {
                0xC09F10: lambda: self.mutex(True),
                0xC09F30: lambda: self.mutex(False),
                0xC11520: self.check,
                0xC11540: self.update_socket,
                0xC11490: self.update_connection,
                0xC114E0: self.destroy_socket,
                0xC11560: self.priority,
                0xC0B900: lambda: self.thread_request("thread_join", 1),
                0xC0B8D0: lambda: self.thread_request("thread_start", 1),
                0xC0E0B0: lambda: self.jump(0x7FEF1C),
                0xC0E0C0: lambda: self.event("transport_update"),
                0xC0E100: lambda: self.event("pending_logs"),
                0xC0E2B0: lambda: self.jump(0x7FEF34),
                0xC0E290: lambda: self.jump(0x7FEF28),
                config.STOP + 0x398: self.client_update,
            }
        )
        self.add_trace = []
        for sock, index in self.sockets.items():
            if index >= inp["active"]:
                self.call(0x7FE7E8, MANAGER, sock)
        self.add_trace, self.trace = self.trace, []
        # A non-null transport and empty client queue permit real OnThink and
        # HandleIncomingPackets without inventing decrypted control messages.
        self.wq(config.CLIENT + 264, self.transport)
        if inp["entry"] != "think":
            self.b(config.CLIENT + 16, int(inp["own_network"]))
        self.wi(config.CLIENT + 256, 0)
        self.wi(config.CLIENT + 724, -1)

    def event(self, name):
        self.trace.append(dict(event=name, tick=self.now, locked=bool(self.depth)))
        self.ret()

    def hook(self, uc, address, size, data):
        # Core's generic platform adapter consumes mutex PLTs before consulting
        # callbacks. Observe them here so lock assertions use executed calls.
        if address in (0xC09F10, 0xC09F30) and hasattr(self, "trace"):
            self.mutex(address == 0xC09F10)
        else:
            super().hook(uc, address, size, data)

    def mutex(self, lock):
        if self.r(0) == MANAGER + 72:
            if lock:
                assert self.depth == 0
                self.depth += 1
            else:
                assert self.depth == 1
                self.depth -= 1
            self.trace.append(dict(event="lock" if lock else "unlock", tick=self.now))
        self.ret(0)

    def wait(self):
        index = self.by_transport[self.r(0)]
        assert not self.depth
        self.trace.append(dict(event="wait", socket=index, ms=self.r(1), tick=self.now))
        self.ret(int(self.inp["sockets"][index]["ready"]))

    def read(self):
        index = self.by_transport[self.r(0)]
        assert self.depth == 1
        self.trace.append(dict(event="read", socket=index, tick=self.now))
        if index == self.inp["live"]:
            super().read()
        else:
            self.ret(1)

    def check(self):
        self.trace.append(dict(event="check", tick=self.now))
        self.jump(0x7FE904)

    def update_socket(self):
        assert self.depth == 1
        self.trace.append(
            dict(event="socket_update", socket=self.sockets[self.r(0)], tick=self.now)
        )
        self.jump(0x7FECD4)

    def update_connection(self):
        assert self.depth == 1
        self.trace.append(dict(event="connection_update", tick=self.r(1)))
        self.jump(0x7FC108)

    def destroy_socket(self):
        assert self.depth == 1
        self.trace.append(dict(event="destroy_socket", socket=self.sockets[self.r(0)]))
        self.ret()

    def priority(self):
        self.trace.append(dict(event="thread_priority", value=self.r(1)))
        self.ret()

    def thread_request(self, name, result):
        assert self.depth == 1
        self.trace.append(dict(event=name, argument=self.r(1)))
        self.ret(result)

    def client_update(self):
        assert self.depth == 1
        self.live_updates += 1
        self.trace.append(dict(event="client_update", tick=self.now))
        if self.inp["entry"] == "run" and self.live_updates == self.inp["rounds"]:
            # Explicit stop injection after N complete connection updates. The
            # real Run checks this manager flag after CheckSockets returns.
            self.b(MANAGER + 169, 1)
        self.ret()

    def deliver(self):
        assert self.depth == 1
        self.trace.append(dict(event="frame_delegate", tick=self.now))
        super().deliver()

    def write(self):
        assert self.depth == 1
        self.trace.append(dict(event="write", tick=self.now))
        super().write()

    def result(self):
        assert self.depth == 0
        count = self.i(MANAGER + 160)
        return dict(
            trace=self.trace,
            add_trace=self.add_trace,
            sockets=[
                self.sockets[self.q(self.q(MANAGER + 144) + i * 8)]
                for i in range(count)
            ],
            pending=self.i(MANAGER + 136),
            running=bool(self.u.mem_read(MANAGER + 170, 1)[0]),
            live_updates=self.live_updates,
            delivered=self.delivered,
            metadata=self.metadata,
            wires=self.wires,
            update_tick=self.i(self.connection + 48),
            now=self.now,
            packet_samples=self.observe()["packets"],
        )


def scenarios():
    cases = []
    for count in range(6):
        for mask in range(1 << count):
            cases.append(
                dict(
                    entry="process",
                    threaded=False,
                    own_network=False,
                    crc=False,
                    active=count,
                    live=0 if count else -1,
                    sockets=[
                        dict(blocked=bool(mask & (1 << j)), ready=True)
                        for j in range(count)
                    ],
                    rounds=1,
                )
            )
    for crc in (False, True):
        for entry in ("process", "think", "run"):
            for own in (False, True):
                for active, live in ((0, 0), (1, 0), (1, 1), (3, 2)):
                    cases.append(
                        dict(
                            entry=entry,
                            threaded=entry == "run" or own,
                            own_network=own,
                            crc=crc,
                            active=active,
                            live=live,
                            sockets=[
                                dict(blocked=j == 1, ready=j == live)
                                for j in range(max(active, live + 1))
                            ],
                            rounds=3 if entry == "run" else 1,
                        )
                    )
    cases.append(
        dict(
            entry="run_stopped",
            threaded=True,
            own_network=True,
            crc=False,
            active=1,
            live=0,
            sockets=[dict(blocked=False, ready=True)],
            rounds=0,
        )
    )
    for entry in ("process", "think", "run"):
        for active in (0, 1, 3):
            cases.append(
                dict(
                    entry=entry,
                    threaded=entry == "run",
                    running=False,
                    own_network=False,
                    crc=False,
                    active=active,
                    live=-1,
                    sockets=[dict(blocked=False, ready=True)] * max(1, active),
                    rounds=0,
                )
            )
    for running in (False, True):
        cases.append(
            dict(
                entry="run",
                threaded=True,
                running=running,
                own_network=True,
                crc=False,
                active=0,
                live=0,
                sockets=[dict(blocked=False, ready=True)],
                rounds=2,
            )
        )
    return cases


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == config.SHA
    out = []
    for inp in scenarios():
        r = Manager(binary, inp)
        if inp["entry"] == "think":
            result = r.call(0x7A5FF8, config.CLIENT)
        elif inp["entry"].startswith("run"):
            r.b(MANAGER + 169, int(inp["entry"] == "run_stopped"))
            result = r.call(0x7FEE74, MANAGER)
        else:
            result = r.call(0x7FEF1C)
        assert all(a == 1139 for a in r.asserts), (inp, r.asserts)
        observed = r.result()
        if inp["entry"] != "think":
            observed["return"] = result
        out.append(dict(input=inp, observed=observed, source_assertions=r.asserts))
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    report = dict(
        binary_sha256=config.SHA, scope=__doc__, cases=audit(a.binary.read_bytes())
    )
    ref = ROOT / "scripts/fixtures/steam-network-manager-reference.json"
    if a.refresh_reference:
        if ref.exists():
            assert json.loads(ref.read_text()) == report
        ref.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert json.loads(ref.read_text()) == report
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Official network manager: {len(report['cases'])} cases passed")


if __name__ == "__main__":
    main()
