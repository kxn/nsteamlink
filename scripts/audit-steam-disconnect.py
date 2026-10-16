#!/usr/bin/env python3
"""Official client shutdown paths, peer packets, Close and connection IDs.

Executes pinned ARM64 client/connection/socket/CRC instructions. Packet allocation,
base construction/refcounts, empty queues, absent decoder/device objects, stats,
address comparison and final transport I/O/destruction are explicit adapters.
The callback recorder observes state/IDs before Update clears them.
"""

import argparse
import importlib.util
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "connect", ROOT / "scripts/audit-steam-connect.py"
)
connect = importlib.util.module_from_spec(spec)
spec.loader.exec_module(connect)


def crc32c(data):
    crc = 0xFFFFFFFF
    for value in data:
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def audit(base):
    connect.audit(base)
    STOP = base["STOP"]

    class Client(connect.audit.Client):
        def __init__(self, state=1, crc=True, result=0):
            super().__init__(result=result)
            self.callbacks.update(
                {
                    0xC0E010: lambda: self.jump(0x7FBCE0),
                    0xC0DFA0: lambda: self.jump(0x7A527C),
                    0xC0E040: lambda: self.jump(0x7A7238),
                    0xC0AA50: self.exchange,
                    0xC04BE0: lambda: self.ret(),
                    0xC0C270: lambda: self.action("stats_stop"),
                    0xC0C280: lambda: self.ret(3),
                    0xC0E070: lambda: self.action("stats_save"),
                    0xC0E340: self.transport_client,
                    0xC115A0: lambda: self.jump(0x7FF640),
                    0xC11350: lambda: self.jump(0x7FACFC),
                    0xC11390: lambda: self.jump(0x7FBEF4),
                    0xC110D0: lambda: self.jump(0x7F6DD0),
                    0xC0DC80: lambda: self.ret(int(self.address_matches)),
                    0xC11360: lambda: self.ret(),
                    STOP + 0x150: self.closed,
                    STOP + 0x160: lambda: self.action("transport_release"),
                }
            )
            self.address_matches = True
            self.connect()
            self.w32(self.conn + 16, state)
            self.b(self.conn + 10, int(crc))
            self.b(self.conn + 13, 34)
            self.w32(self.client + 724, 0xFFFFFFFF)
            self.w32(self.client + 728, 0xFFFFFFFF)
            self.w32(self.client + 820, 0xFFFFFFFF)
            self.w32(self.client + 824, 0xFFFFFFFF)
            array = self.alloc(4096)
            self.wq(array, self.conn)
            self.wq(self.sock + 8, array)
            self.w32(self.sock + 24, 1)
            self.actions = []

        def transport_client(self):
            vt = 0x20008000
            self.wq(vt + 56, STOP + 0x160)
            self.wq(self.r(0), vt)
            self.ret()

        def exchange(self):
            p = self.r(0)
            old = self.i(p)
            self.w32(p, self.r(1))
            self.ret(old)

        def closed(self):
            self.actions.append(
                dict(
                    action="closed",
                    state=self.i(self.conn + 16),
                    local=self.u.mem_read(self.conn + 12, 1)[0],
                    peer=self.u.mem_read(self.conn + 13, 1)[0],
                )
            )
            self.ret()

        def snapshot(self):
            result = super().snapshot()
            result.update(
                attached=bool(self.q(self.conn)),
                delegate=bool(self.q(self.conn + 368)),
                client_state=self.i(self.client + 256),
                local=self.u.mem_read(self.conn + 12, 1)[0],
                peer=self.u.mem_read(self.conn + 13, 1)[0],
                last_receive=self.i(self.conn + 52),
            )
            return result

        def peer(self, *, crc=True, bad_crc=False, source=34, dest=12):
            data = struct.pack(
                "<BBBBBHHI", 9 | (128 if crc else 0), 0, source, dest, 0, 0, 0, self.now
            )
            if crc:
                data += struct.pack("<I", crc32c(data) ^ int(bad_crc))
            p = self.alloc(4096)
            self.packet(p)
            self.u.mem_write(p + 64, data)
            self.w32(p + 52, len(data))
            self.call(0x7FF3E0, self.sock, p, self.now)
            return data.hex()

    cases = []

    def record(name, group, inputs, observed):
        cases.append(dict(case=name, group=group, input=inputs, observed=observed))

    for state in range(4):
        for crc in (False, True):
            for result in (0, 1, 2):
                r = Client(state, crc, result)
                r.call(0x7FB724, r.conn)
                values = [r.snapshot()]
                r.call(0x7FB724, r.conn)
                values.append(r.snapshot())
                r.update(r.now + 1)
                values.append(r.snapshot())
                r.update(r.now + 65536)
                values.append(r.snapshot())
                assert sum(
                    a["action"] == "send" for v in values for a in v["actions"]
                ) == int(state == 1)
                record(
                    f"disconnect_state{state}_crc{int(crc)}_result{result}",
                    "disconnect",
                    dict(state=state, crc=crc, result=result),
                    values,
                )

    for state in range(4):
        for crc in (False, True):
            r = Client(state, crc)
            r.call(0x7FBCE0, r.conn)
            values = [r.snapshot()]
            r.call(0x7FBCE0, r.conn)
            values.append(r.snapshot())
            r.update(r.now + 1)
            values.append(r.snapshot())
            assert not any(
                a["action"] == "closed" for v in values for a in v["actions"]
            )
            record(
                f"close_state{state}_crc{int(crc)}",
                "close",
                dict(state=state, crc=crc),
                values,
            )

    for client_state in range(8):
        for state in (0, 1, 2, 3):
            r = Client(state)
            r.w32(r.client + 256, client_state)
            r.call(0x7A7ACC, r.client)
            values = [r.snapshot()]
            r.update(r.now + 1)
            values.append(r.snapshot())
            assert not values[0]["attached"] and not values[0]["delegate"]
            assert values[0]["client_state"] == 0
            assert not any(
                a["action"] == "closed" for v in values for a in v["actions"]
            )
            record(
                f"client_disconnect_phase{client_state}_state{state}",
                "client_disconnect",
                dict(client_state=client_state, state=state),
                values,
            )

    for state in range(4):
        for mode in (
            "valid",
            "no_crc",
            "bad_crc",
            "bad_source",
            "bad_dest",
            "bad_address",
        ):
            for delay in (0, 100):
                r = Client(state)
                r.address_matches = mode != "bad_address"
                r.now += delay
                wire = r.peer(
                    crc=mode != "no_crc",
                    bad_crc=mode == "bad_crc",
                    source=35 if mode == "bad_source" else 34,
                    dest=13 if mode == "bad_dest" else 12,
                )
                values = [r.snapshot()]
                r.update(r.now + 1)
                values.append(r.snapshot())
                record(
                    f"peer_disconnect_state{state}_{mode}"
                    + (f"_delay{delay}" if delay else ""),
                    "peer_disconnect",
                    dict(
                        state=state,
                        mode=mode,
                        datagram=wire,
                        **({"delay": delay} if delay else {}),
                    ),
                    values,
                )
    for state in range(4):
        for close in (False, True):
            r = Client(state)
            r.call(0x7FBCE0 if close else 0x7FB724, r.conn)
            r.snapshot()
            r.update(1000001)
            values = [r.snapshot()]
            r.update(2000000)
            values.append(r.snapshot())
            assert not values[-1]["actions"] and values[-1]["state"] == 3
            record(
                f"terminal_timeout_state{state}_close{int(close)}",
                "terminal_timeout",
                dict(state=state, close=close),
                values,
            )
    for prior, random_values, warmup in (
        (0, [0, 255, 510, 254], 0),
        (1, [1], 0),
        (254, [254], 0),
        (255, [254], 1),
    ):
        r = Client()
        r.b(0xF479E0, prior)
        random_calls = []

        def random():
            value = random_values[len(random_calls)]
            random_calls.append(value)
            r.ret(value)

        r.callbacks[0xC0CA00] = random
        ids = [r.call(0x7FAB70) for _ in range(260)]
        assert all(1 <= value <= 255 for value in ids)
        record(
            f"connection_ids_prior{prior}",
            "connection_ids",
            dict(prior=prior, random=random_values, warmup=warmup, count=260),
            dict(ids=ids, random_calls=random_calls),
        )
    for fallback in (False, True):
        r = Client()
        obj = 0x20009000
        calls = []

        def socket():
            calls.append(dict(call="socket", family=r.r(0)))
            r.ret(-1 if fallback and len(calls) == 1 else 77)

        def fcntl():
            command = r.r(1)
            calls.append(dict(call="fcntl", command=command, argument=r.r(2)))
            r.ret(0x100 if command == 3 else 0)

        r.callbacks.update(
            {
                0xC11710: lambda: r.ret(),
                0xC0D730: socket,
                0xC0D740: lambda: r.ret(),
                0xC0D760: fcntl,
            }
        )
        value = r.call(0x8024B4, obj)
        assert value == 1 and calls[-1] == dict(call="fcntl", command=4, argument=0x900)
        record(
            f"udp_init_fallback{int(fallback)}",
            "udp_init",
            dict(fallback=fallback),
            dict(result=value, calls=calls),
        )
    for errno_name, error in (
        ("OK", 0),
        ("EAGAIN", 11),
        ("EMSGSIZE", 90),
        ("EBADF", 9),
        ("EIO", 5),
        ("EINTR", 4),
    ):
        for crc in (False, True):
            r = Client(crc=crc)
            error_pointer = 0x20007000
            r.w32(error_pointer, error)
            r.w32(r.transport + 20, 77)

            def sendto():
                data = bytes(r.u.mem_read(r.r(1), r.r(2)))
                r.actions.append(dict(action="send", wire=data.hex()))
                r.ret(-1 if error else r.r(2))

            r.callbacks.update(
                {
                    STOP + 0x120: lambda: r.jump(0x802754),
                    0xC0D7B0: lambda: r.ret(),
                    0xC0D7C0: sendto,
                    0xC0A4C0: lambda: r.ret(error_pointer),
                }
            )
            p = r.alloc(4096)
            r.packet(p, typ=9, retry=0, id=0)
            r.b(p + 66, 12)
            r.b(p + 67, 34)
            value = r.call(0x7FF1DC, r.sock, r.conn, p)
            record(
                f"udp_send_{errno_name}_crc{int(crc)}",
                "udp_send",
                dict(errno_name=errno_name, crc=crc),
                dict(result=value, actions=r.actions),
            )
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--refresh-reference", action="store_true")
    args = parser.parse_args()
    base = connect.outgoing.load(
        args.binary, args.output.with_name("official-branches.json")
    )
    report = dict(binary_sha256=connect.outgoing.SHA, scope=__doc__, cases=audit(base))
    reference = ROOT / "scripts/fixtures/steam-disconnect-reference.json"
    if args.refresh_reference:
        if reference.exists():
            previous = {
                c["case"]: c for c in json.loads(reference.read_text())["cases"]
            }
            for case in report["cases"]:
                if case["case"] in previous:
                    assert case == previous[case["case"]], case["case"]
        reference.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert report == json.loads(reference.read_text()), (
            "official shutdown reference changed"
        )
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"Official Android shutdown: {len(report['cases'])} original-instruction cases passed"
    )


if __name__ == "__main__":
    main()
