#!/usr/bin/env python3
"""Execute official channel construction, reliable receive/window and feedback wire.

Channel ctor/Clear, HandlePacket/BInsert, PopHead/Advance, channel Update,
packet headers, Socket/CRC execute original ARM64. Receive storage is preallocated;
mutex/queue ctor, refcounts, frame delegate, allocation/destruction, diagnostics,
stats and final UDP are adapters. No crypto, host or full connection loop runs.
"""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "wire", ROOT / "scripts/audit-steam-control-wire.py"
)
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)


def audit(base):
    wire.audit(base)
    STOP = base["STOP"]

    class Receiver(wire.audit.Sender):
        def __init__(self, crc, rtt=100, start=1000000):
            super().__init__(crc, 1024, b"")
            self.now = start
            self.delivered, self.asserts = [], []
            player, vt = self.alloc(4096), self.alloc(4096)
            self.wq(self.conn + 368, player)
            self.wq(player, vt)
            self.wq(vt + 48, STOP + 0x380)
            self.w32(self.conn + 744, rtt)
            self.callbacks.update(
                {
                    0xC11470: self.construct,
                    0x7F8738: self.constructed,
                    0xC09E40: lambda: self.ret(),
                    0xC111B0: lambda: self.jump(0x7F88E4),
                    0xC11100: lambda: self.jump(0x7F7230),
                    0xC11120: lambda: self.jump(0x7F743C),
                    0xC11130: lambda: self.jump(0x7F76F4),
                    0xC112E0: lambda: self.jump(0x7F9D0C),
                    0xC112F0: lambda: self.jump(0x7FA3B0),
                    0xC11270: lambda: self.ret(),
                    0xC0A380: lambda: self.ret(2),
                    0xC09AB0: lambda: self.ret(self.alloc(self.r(0))),
                    0xC097E0: self.assertion,
                    0xC097F0: lambda: self.ret(),
                    STOP + 0x380: self.deliver,
                }
            )
            self.call(0x7FBA34, self.conn, 1)
            self.ch = self.channels[1]

        def construct(self):
            self.channels[self.r(3)] = self.r(0)
            self.created.append(self.r(3))
            self.jump(0x7F8630)

        def constructed(self):
            # Original constructor completed. Only reserve empty RX storage;
            # the real BInsert/PopHead/Advance manipulate its ring from here.
            ch = self.r(20)
            self.w32(ch + 148, 511)
            self.wq(ch + 160, self.alloc(4096))
            self.wq(ch + 168, self.alloc(4096))

        def assertion(self):
            message = bytes(self.u.mem_read(self.r(2), 256)).split(b"\0")[0].decode()
            self.asserts.append(message)
            self.ret(
                0
            )  # real non-debug release path continues after IsInDebugSession=false

        def deliver(self):
            p = self.r(2)
            self.delivered.append(
                bytes(self.u.mem_read(self.q(p + 56) + 13, self.i(p + 52) - 13)).hex()
            )
            self.ret()

        def handle_packet(self, p):
            self.call(0x7F9250, self.ch, p, self.now)

        def receive(self, op):
            self.now = op[1] & 0xFFFFFFFF
            p = self.alloc(4096)
            self.packet(
                p,
                typ=op[3] | (128 if self.u.mem_read(self.conn + 10, 1)[0] else 0),
                id=op[2],
                stamp=op[5],
                received=op[6] if len(op) > 6 else self.now,
                retry=0,
            )
            self.b(p + 66, 34)
            self.b(p + 67, 12)
            self.b(p + 68, 1)
            self.wh(p + 69, op[4])
            self.w32(p + 52, 16)
            self.u.mem_write(p + 77, bytes([6, 0xAA, 0xBB]))
            self.handle_packet(p)

        def observe(self):
            ch = self.ch
            value = dict(
                wire=list(self.sent),
                delivered=list(self.delivered),
                dirty=bool(self.u.mem_read(ch + 40, 1)[0]),
                pending_ack=bool(self.u.mem_read(ch + 41, 1)[0]),
                confirmed=self.h(ch + 42),
                peer_time=self.i(ch + 44),
                peer_received=self.i(ch + 48),
                deadline=self.i(ch + 104),
                head=self.h(ch + 152),
                tail=self.h(ch + 154),
                asserts=list(self.asserts),
            )
            self.sent.clear()
            self.delivered.clear()
            self.asserts.clear()
            return value

    cases = []
    sequences = {
        "first_zero": [["R", 1000100, 0, 5, 0, 900000], ["U", 1000100], ["U", 1000200]],
        "duplicate_zero": [
            ["R", 1000100, 0, 5, 0, 900000],
            ["U", 1000100],
            ["R", 1000101, 0, 5, 0, 900001],
            ["U", 1000101],
            ["U", 1000165],
        ],
        "two_batched": [
            ["R", 1000100, 0, 5, 0, 900000],
            ["R", 1000101, 1, 5, 0, 900001],
            ["U", 1000101],
        ],
        "first_hole": [
            ["R", 1000100, 1, 5, 0, 900000],
            ["U", 1000100],
            ["U", 1000165],
            ["U", 1000166],
            ["U", 1000231],
        ],
        "fragment_head": [["R", 1000100, 0, 5, 2, 900000], ["U", 1000100]],
        "fragment_gap": [
            ["R", 1000100, 0, 5, 2, 900000],
            ["R", 1000101, 2, 6, 1, 900001],
            ["U", 1000101],
            ["U", 1000167],
            ["R", 1000170, 1, 6, 0, 900002],
            ["U", 1000170],
            ["U", 1000232],
        ],
    }
    scenarios = [
        (name, crc, 100, 1000000, ops)
        for crc in (0, 1)
        for name, ops in sequences.items()
    ]
    extra = {
        "empty_updates": [["U", 1000100], ["U", 1100000]],
        "ack_debounce": [
            ["R", 1000100, 0, 5, 0, 900000],
            ["U", 1000100],
            ["R", 1000101, 1, 5, 0, 900001],
            ["U", 1000101],
            ["R", 1000102, 2, 5, 0, 900002],
            ["U", 1000102],
            ["U", 1000165],
            ["U", 1000166],
            ["U", 1000231],
        ],
        "stale_equal_timestamp": [
            ["R", 1000100, 0, 5, 0, 900000],
            ["U", 1000100],
            ["R", 1000110, 1, 5, 0, 899999],
            ["U", 1000110],
            ["R", 1000120, 2, 5, 0, 900000],
            ["U", 1000120],
            ["U", 1000175],
        ],
        "old_duplicate_cumulative_ack": [
            ["R", 1000100, 0, 5, 0, 900000],
            ["R", 1000101, 1, 5, 0, 900001],
            ["U", 1000101],
            ["R", 1000200, 0, 5, 0, 900002],
            ["U", 1000200],
            ["U", 1000300],
        ],
        "buffered_duplicate": [
            ["R", 1000100, 0, 5, 2, 900000],
            ["U", 1000100],
            ["R", 1000101, 0, 5, 2, 900001],
            ["U", 1000101],
        ],
        "young_base_old_successor": [
            ["R", 1000100, 4, 5, 0, 900000],
            ["R", 1000180, 2, 5, 0, 900001],
            ["U", 1000180],
            ["U", 1000244],
            ["U", 1000245],
        ],
        "new_receive_rearms_gap": [
            ["R", 1000100, 2, 5, 0, 900000],
            ["U", 1000166],
            ["U", 1000231],
            ["U", 1000300],
            ["R", 1000400, 3, 5, 0, 900001],
            ["U", 1000400],
        ],
        "peer_timestamp_wrap": [
            ["R", 1000100, 0, 5, 0, 0xFFFFFFF0],
            ["U", 1000100],
            ["R", 1000101, 1, 5, 0, 0x10],
            ["U", 1000101],
            ["R", 1000200, 0, 5, 0, 0xFFFFFFF5],
            ["U", 1000200],
        ],
        "peer_zero_replacement": [
            ["R", 1000100, 0, 5, 0, 0],
            ["U", 1000100],
            ["R", 1000110, 1, 5, 0, 0x80000001],
            ["U", 1000110],
        ],
    }
    for code in range(1, 5):
        extra[f"ack_socket_error_{code}"] = [
            ["S", code],
            ["R", 1000100, 0, 5, 0, 900000],
            ["R", 1000101, 1, 5, 0, 900001],
            ["U", 1000101],
            ["S", 0],
            ["U", 1000166],
            ["R", 1000200, 0, 5, 0, 900002],
            ["U", 1000200],
        ]
        extra[f"nack_socket_error_{code}"] = [
            ["S", code],
            ["R", 1000100, 2, 5, 0, 900000],
            ["U", 1000166],
            ["S", 0],
            ["U", 1000231],
            ["R", 1000300, 3, 5, 0, 900001],
            ["U", 1000300],
        ]
    for bits in (1, 7, 8, 9, 319, 320, 321):
        extra[f"bitmap_span_{bits}"] = [
            ["R", 1000100, 2, 5, 0, 900000],
            ["R", 1000101, 2 + bits - 1, 5, 0, 900001],
            ["U", 1000167],
        ]
    for crc in (0, 1):
        scenarios.extend((name, crc, 100, 1000000, ops) for name, ops in extra.items())
        for rtt in (0, 64, 65, 66, 260, 264, 400, 3276, 3277):
            interval = max(min(max(rtt, 65), 3276) // 4, 65)
            for start in (1000000, 0xFFFFFF00):
                t = (start + 100) & 0xFFFFFFFF
                ops = [
                    ["R", t, 0, 5, 0, 900000],
                    ["R", t, 1, 5, 0, 900001],
                    ["U", t],
                    ["R", (t + 1) & 0xFFFFFFFF, 2, 5, 0, 900002],
                    ["U", (t + interval - 1) & 0xFFFFFFFF],
                    ["U", (t + interval) & 0xFFFFFFFF],
                    ["U", (t + interval * 2) & 0xFFFFFFFF],
                ]
                scenarios.append(("rtt_ack_deadline", crc, rtt, start, ops))
    for crc in (0, 1):
        for name, ops in {
            "old_successor_outside_bitmap": [
                ["R", 1000100, 322, 5, 0, 900000],
                ["R", 1000180, 2, 5, 0, 900001],
                ["U", 1000180],
            ],
            "packet_receive_time_not_handler_time": [
                ["R", 1000100, 0, 5, 0, 900000, 1000000],
                ["U", 1000100],
                ["R", 1000110, 1, 5, 0, 900001, 1000020],
                ["U", 1000110],
            ],
            "packet_age_not_handler_age": [
                ["R", 1000100, 2, 5, 0, 900000, 1000000],
                ["U", 1000100],
            ],
            "ignored_far_future": [["R", 1000100, 16384, 5, 0, 900000], ["U", 1000100]],
            "old_packet_before_zero": [
                ["R", 1000100, 65535, 5, 0, 900000],
                ["U", 1000100],
            ],
        }.items():
            scenarios.append((name, crc, 100, 1000000, ops))
        for rtt in (0, 64, 65, 66, 260, 264, 400, 3276, 3277):
            interval = max(min(max(rtt, 65), 3276) // 4, 65)
            for start in (1000000, 0xFFFFFF00):
                t = (start + 100) & 0xFFFFFFFF
                ops = [
                    ["R", t, 2, 5, 0, 900000],
                    ["U", t],
                    ["U", (t + max(interval, 66) - 1) & 0xFFFFFFFF],
                    ["U", (t + max(interval, 66)) & 0xFFFFFFFF],
                    ["U", (t + max(interval, 66) * 2) & 0xFFFFFFFF],
                ]
                scenarios.append(("rtt_nack_deadline", crc, rtt, start, ops))
    for name, crc, rtt, start, ops in scenarios:
        r = Receiver(crc, rtt, start)
        initial = r.observe()
        outputs = []
        for op in ops:
            if op[0] == "R":
                r.receive(op)
            elif op[0] == "S":
                r.transport_result = op[1]
            else:
                r.now = op[1] & 0xFFFFFFFF
                r.call(0x7F9C9C, r.ch, r.now)
            outputs.append(r.observe())
        cases.append(
            dict(
                case=name,
                input=dict(crc=crc, rtt=rtt, start=start, ops=ops),
                initial=initial,
                observed=outputs,
            )
        )
    audit.Receiver = Receiver
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--refresh-reference", action="store_true")
    args = parser.parse_args()
    base = wire.outgoing.load(
        args.binary, args.output.with_name("reliable-feedback-base.json")
    )
    report = dict(binary_sha256=wire.outgoing.SHA, scope=__doc__, cases=audit(base))
    ref = ROOT / "scripts/fixtures/steam-reliable-feedback-reference.json"
    if args.refresh_reference:
        if ref.exists():
            previous = json.loads(ref.read_text())
            assert previous["cases"] == report["cases"][: len(previous["cases"])]
        ref.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert report == json.loads(ref.read_text())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Official reliable feedback: {len(report['cases'])} cases passed")


if __name__ == "__main__":
    main()
