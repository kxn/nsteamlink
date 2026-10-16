#!/usr/bin/env python3
"""Execute official Android client Connect, retries, Connected and Disconnect.

Original BConnect/Create/constructor/Connect/Update/SendConnectPacket/SocketSend
instructions decide policy and wire bytes. Allocation, packet constructor/refcount,
socket construction,
transport activation/I/O, stats and client delegates are
explicit adapters. No Steam host or Switch is involved.
"""

import argparse
import importlib.util
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "outgoing", ROOT / "scripts/audit-steam-outgoing.py"
)
outgoing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(outgoing)


def audit(base):
    Run, STOP = base["Run"], base["STOP"]

    class Client(Run):
        def __init__(self, now=1000000, result=0):
            super().__init__(now=now)
            self.sock, self.transport, self.tvt, self.client, self.cvt, self.address = (
                0x20000000 + i * 4096 for i in range(6)
            )
            self.conn = 0
            self.result = result
            self.actions = []
            self.wq(self.transport, self.tvt)
            self.wq(self.tvt + 8, STOP + 0x100)
            self.wq(self.tvt + 16, STOP + 0x110)
            self.wq(self.tvt + 72, STOP + 0x120)
            self.wq(self.client, self.cvt)
            self.w32(self.client + 256, 1)
            self.wq(self.cvt + 40, STOP + 0x130)
            self.wq(self.cvt + 56, STOP + 0x140)
            self.wq(self.cvt + 64, STOP + 0x150)
            self.callbacks.update(
                {
                    0xC097E0: self.assertion,
                    0xC09E30: lambda: self.ret(),
                    0xBFF1A0: lambda: self.ret(),
                    0xC0DA00: lambda: self.ret(),
                    0xC09C30: lambda: self.ret(),
                    0xC0E330: lambda: self.ret(),
                    0xC0E340: lambda: self.ret(),
                    0xC0E350: lambda: self.jump(0x7FAAF8),
                    0xC11300: self.socket,
                    0xC11310: self.constructor,
                    0xC11320: lambda: self.ret(12),
                    0xC113A0: lambda: self.ret(),
                    0xC113B0: lambda: self.ret(),
                    0xC113C0: lambda: self.ret(),
                    0xC113D0: lambda: self.ret(),
                    0xC113E0: lambda: self.ret(),
                    0xC0E360: lambda: self.jump(0x7FB62C),
                    0xC11440: lambda: self.jump(0x7FB84C),
                    0xC11170: lambda: self.jump(0x7FF1DC),
                    0xC11450: lambda: self.jump(0x8E1610),
                    0xC10FE0: lambda: self.ret(),
                    0xC11370: lambda: self.ret(),
                    0xC0E030: self.disconnect,
                    0xC0E290: lambda: self.ret(),
                    0xC0E2B0: lambda: self.ret(),
                    0xC112A0: lambda: self.ret(),
                    STOP + 0x100: lambda: self.ret(),
                    STOP + 0x110: lambda: self.ret(1),
                    STOP + 0x120: self.send,
                    STOP + 0x130: lambda: self.action("connected"),
                    STOP + 0x140: lambda: self.ret(),
                    STOP + 0x150: lambda: self.action("closed"),
                }
            )
            self.call(0x7FE284)
            assert self.i(0xF47980) == 6553

        def assertion(self):
            raise AssertionError((self.r(1), bytes(self.u.mem_read(self.r(2), 256))))

        def jump(self, address):
            self.u.reg_write(base["UC_ARM64_REG_PC"], address)

        def call(self, address, *params):
            self.u.reg_write(base["UC_ARM64_REG_SP"], 0x300FF000)
            self.u.reg_write(base["UC_ARM64_REG_X30"], STOP)
            self.run(address, *params)
            return self.r(0) & 0xFFFFFFFF

        def socket(self):
            self.sock = self.r(0)
            self.wq(self.sock, self.transport)
            self.ret()

        def constructor(self):
            self.conn = self.r(0)
            self.jump(0x7FB23C)

        def action(self, kind):
            self.actions.append(dict(action=kind))
            self.ret()

        def send(self):
            p = self.r(1)
            ptr = self.q(p + 56)
            n = self.i(p + 52) + (4 if self.u.mem_read(ptr, 1)[0] & 128 else 0)
            self.actions.append(
                dict(action="send", wire=bytes(self.u.mem_read(ptr, n)).hex())
            )
            self.ret(self.result)

        def disconnect(self):
            self.actions.append(dict(action="disconnect"))
            self.jump(0x7FB724)

        def connect(self):
            # First allocation is the UDP transport: preserve its fixture vtable.
            self.callbacks[0xC0E330] = lambda: (
                self.wq(self.r(0), self.tvt),
                self.ret(),
            )
            result = self.call(0x7A7808, self.client, 1, 1, 1, 1, self.address, 0, 0)
            self.w32(self.conn + 1212, 0xFFFFFFFF)
            return result

        def update(self, now):
            self.now = now & 0xFFFFFFFF
            self.call(0x7FC108, self.conn, self.now)

        def connected(self, size, crc):
            p = self.alloc(4096)
            self.packet(p, typ=2 | (128 if crc else 0), stamp=self.now, retry=0, id=0)
            self.b(p + 66, 34)
            self.b(p + 67, 12)
            self.w32(p + 52, 13 + size)
            self.call(0x7FBEF4, self.conn, p, self.now)

        def snapshot(self):
            value = dict(
                state=self.i(self.conn + 16),
                last_connect=self.i(self.conn + 44),
                actions=self.actions,
                crc_required=bool(self.u.mem_read(self.conn + 10, 1)[0]),
            )
            self.actions = []
            return value

    cases = []

    def record(name, group, inputs, observed):
        cases.append(dict(case=name, group=group, input=inputs, observed=observed))

    for result in (0, 1, 2):
        for start in (0, 1000000, 0xFFFFFFF0):
            r = Client(start, result)
            assert r.connect() == 1  # Client BConnect ignores initial send's result.
            values = [r.snapshot()]
            times = [
                start,
                (start + 1) & 0xFFFFFFFF,
                (start + 6552) & 0xFFFFFFFF,
                (start + 6553) & 0xFFFFFFFF,
                (start + 6554) & 0xFFFFFFFF,
                (start + 13106) & 0xFFFFFFFF,
            ]
            for now in times:
                r.update(now)
                values.append(r.snapshot())
            assert values[0]["last_connect"] == 0
            assert len(values[0]["actions"]) == 1
            assert (
                values[0]["actions"][0]["wire"]
                == (
                    struct.pack("<BBBBBHHI", 1, 0, 12, 0, 0, 0, 0, start)
                    + bytes.fromhex("c73d8f3c")
                ).hex()
            )
            record(
                f"retry_start{start}_result{result}",
                "retry",
                dict(start=start, result=result, updates=times),
                values,
            )

    for size in (3, 4, 5):
        for crc in (False, True):
            r = Client()
            r.connect()
            r.snapshot()
            r.update(1000000)
            r.snapshot()
            r.connected(size, crc)
            accepted = r.snapshot()
            r.update(1006553)
            after = r.snapshot()
            assert (accepted["state"] == 1) == (size == 4)
            assert bool(after["actions"]) == (size != 4)
            record(
                f"connected_size{size}_crc{int(crc)}",
                "connected",
                dict(size=size, crc=crc),
                [accepted, after],
            )

    for paused in (False, True):
        for delta in (-1, 0, 1):
            r = Client()
            r.connect()
            r.snapshot()
            r.b(r.conn + 8, int(paused))
            now = 1000000 + (180 if paused else 15) * 65536 + delta
            r.update(now)
            observed = [r.snapshot()]
            r.update(now + 1)
            observed.append(r.snapshot())
            assert observed[0]["actions"][0]["action"] == "send"
            assert (observed[0]["state"] == 2) == (delta >= 0)
            record(
                f"timeout_paused{int(paused)}_delta{delta}",
                "timeout",
                dict(paused=paused, now=now),
                observed,
            )

    for crc in (False, True):
        r = Client()
        r.connect()
        r.snapshot()
        r.update(1000000 + 15 * 65536)
        before = r.snapshot()
        r.now += 1
        r.connected(4, crc)
        after = r.snapshot()
        assert after["state"] == 2 and not after["actions"]
        record(
            f"late_connected_crc{int(crc)}",
            "late_connected",
            dict(crc=crc),
            [before, after],
        )

    for state in (0, 1, 2, 3):
        for result in (0, 1, 2):
            r = Client(result=result)
            r.connect()
            r.snapshot()
            r.w32(r.conn + 16, state)
            r.call(0x7FB724, r.conn)
            observed = [r.snapshot()]
            r.update(r.now)
            observed.append(r.snapshot())
            assert len(observed[0]["actions"]) == (1 if state == 1 else 0)
            record(
                f"disconnect_state{state}_result{result}",
                "disconnect",
                dict(state=state, result=result),
                observed,
            )
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--refresh-reference", action="store_true")
    args = parser.parse_args()
    base = outgoing.load(args.binary, args.output.with_name("official-branches.json"))
    report = dict(binary_sha256=outgoing.SHA, scope=__doc__, cases=audit(base))
    reference = ROOT / "scripts/fixtures/steam-connect-reference.json"
    if args.refresh_reference:
        if reference.exists():
            previous = {
                c["case"]: c for c in json.loads(reference.read_text())["cases"]
            }
            for case in report["cases"]:
                if case["case"] in previous:
                    assert case == previous[case["case"]], "existing case changed"
        reference.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert report == json.loads(reference.read_text()), (
            "official Connect reference changed"
        )
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"Official Android Connect: {len(report['cases'])} original-instruction cases passed"
    )


if __name__ == "__main__":
    main()
