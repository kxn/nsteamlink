#!/usr/bin/env python3
"""Execute connection -> generic reliable channel -> real client frame routing.

Same pinned Android ELF as the reliable feedback audit. Connection admission,
GetChannel/ctor, HandlePacket, window, Update, frame extraction, client routing
HandleIncomingPackets, OnDataPacket normalization and Socket/CRC run original instructions. Empty RX storage, address comparison,
allocation/refcounts/destruction, mutexes, stats, final UDP and terminal frame
queue append/data consumer are explicit adapters; real queue drain and unknown-type drops run original code. No host, decoder or full main loop.
"""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "feedback", ROOT / "scripts/audit-steam-reliable-feedback.py"
)
feedback = importlib.util.module_from_spec(spec)
spec.loader.exec_module(feedback)


def audit(base):
    feedback.audit(base)

    class Client(feedback.audit.Receiver):
        def __init__(self, crc, state=6, channel=2, payload="06aabb", configured=False):
            super().__init__(crc)
            self.target = channel
            self.player = self.q(self.conn + 368)
            self.w32(self.player + 256, state)
            self.wq(self.q(self.player) + 48, 0x7ACFA8)
            self.actions = []
            self.pending = self.alloc(4096)
            self.incoming = self.alloc(4096)
            self.wq(self.player + 744, self.pending)
            self.w32(self.player + 752, 64)
            self.w32(self.player + 720, 63)
            self.w32(self.player + 724, 0xFFFFFFFF)
            self.w32(self.player + 728, 0xFFFFFFFF)
            self.wq(self.player + 736, self.incoming)
            self.payload = bytes.fromhex(payload)
            self.wq(self.player + 280, self.conn)
            if configured:
                self.b(self.player + 625, channel)
                self.wq(self.player + 32, self.alloc(4096))
            self.callbacks.update(
                {
                    0xC11250: lambda: self.jump(0x7F9250),
                    0xC0E390: lambda: self.jump(0x7FBA34),
                    0xC0DC80: lambda: self.ret(1),
                    0xC11360: lambda: self.ret(),
                    0xC11370: lambda: self.ret(),
                    0xC112A0: lambda: self.ret(),
                    0xC0E130: lambda: self.jump(0x7F2B98),
                    0xC10FC0: lambda: self.jump(0x7F2BAC),
                    0xC0E770: lambda: self.jump(0x7AD148),
                    0xC0E6B0: lambda: self.ret(),
                    0xC0B930: self.data,
                    0xC0E790: self.queued,
                    0xC09F10: lambda: self.ret(),
                    0xC09F30: lambda: self.ret(),
                    0xC0E1A0: lambda: self.ret(0),
                    0xC09F90: lambda: self.ret(),
                    0x7A65C0: self.ignored,
                    0x7ACFA8: self.dispatched,
                    0xC11290: lambda: self.jump(0x7F95DC),
                    0xC0E7E0: self.copy_pending,
                    0xC09990: lambda: self.ret(),
                }
            )

        def receive(self, op):
            original = self.payload
            if len(op) > 7:
                self.payload = bytes.fromhex(op[7])
            super().receive(op)
            self.payload = original

        def copy_pending(self):
            dest, src, count = (self.r(i) for i in range(3))
            memory = self.alloc(max(4096, count * 8))
            if count:
                self.u.mem_write(memory, bytes(self.u.mem_read(src, count * 8)))
            self.wq(dest, memory)
            self.w32(dest + 8, count)
            self.w32(dest + 12, 0)
            self.w32(dest + 16, count)
            self.ret()

        def configure(self, channel=None):
            self.b(self.player + 625, self.target if channel is None else channel)
            self.wq(self.player + 32, self.alloc(4096))
            self.call(0x7AFF74, self.player)

        def constructed(self):
            super().constructed()
            ch = self.r(20)
            for offset in (112, 248):
                self.w32(ch + offset + 4, 15)
                self.wq(ch + offset + 16, self.alloc(4096))
                self.wq(ch + offset + 24, self.alloc(4096))

        def dispatched(self):
            self.delivered.append(self.raw(self.r(2)))

        def nack(self, op):
            self.now = op[1]
            p = self.alloc(4096)
            self.packet(
                p,
                typ=8 | (128 if self.u.mem_read(self.conn + 10, 1)[0] else 0),
                id=op[2],
                stamp=op[3],
                received=self.now,
                retry=0,
            )
            self.b(p + 66, 34)
            self.b(p + 67, 12)
            self.b(p + 68, self.target)
            body = b"" if op[4] == "-" else bytes.fromhex(op[4])
            self.w32(p + 52, 13 + len(body))
            self.u.mem_write(p + 77, body)
            self.call(0x7FACFC, self.conn, p, self.now)

        def send_frame(self, op):
            self.now = op[1]
            original = self.payload
            self.payload = bytes.fromhex(op[2])
            self.call(0x7F2AF4, self.frame, self.target, 6)
            self.call(0x7F321C, self.frame, self.message, 0)
            self.call(0x7F3078, self.frame, self.conn, 1)
            self.payload = original

        def queued(self):
            p = self.q(self.r(1))
            head, tail = self.i(self.player + 724), self.i(self.player + 728)
            tail = 0 if head == 0xFFFFFFFF else tail + 1
            if head == 0xFFFFFFFF:
                self.w32(self.player + 724, 0)
            self.w32(self.player + 728, tail)
            self.wq(self.incoming + (tail & 63) * 8, p)
            self.ret()

        def ignored(self):
            self.actions.append(dict(ignored=self.raw(self.r(26))))

        def raw(self, p):
            return bytes(
                self.u.mem_read(self.q(p + 56) + 13, self.i(p + 52) - 13)
            ).hex()

        def data(self):
            f = self.r(1)
            # Frame::ctor has already extracted its envelope. Keep both the
            # type and post-type body, without pretending a decoder ran.
            self.actions.append(
                dict(
                    data_type=self.u.mem_read(f + 25, 1)[0],
                    frame=self.frame_body(f),
                    id=self.h(f + 26),
                    timestamp=self.i(f + 28),
                    send_timestamp=self.i(f + 32),
                    receive_timestamp=self.i(f + 40),
                    input_mark=self.h(f + 44),
                    input_received=self.i(f + 48),
                )
            )
            self.ret()

        def frame_body(self, f):
            return self.raw(self.q(f + 8))

        def handle_packet(self, p):
            self.b(p + 68, self.target)
            self.w32(p + 52, 13 + len(self.payload))
            self.u.mem_write(p + 77, self.payload)
            self.call(0x7FACFC, self.conn, p, self.now)
            self.ch = self.channels.get(self.target)

        def observe_channel(self):
            if self.target not in self.channels:
                return None
            self.ch = self.channels[self.target]
            value = super().observe()
            value["last_nack"] = self.i(self.ch + 52)
            return value

    cases = []
    scenarios = [
        (crc, channel, state, "06aabb", False)
        for crc in (0, 1)
        for channel in (0, 2, 3, 31)
        for state in (0, 2, 6, 7)
    ]
    scenarios += [
        (crc, channel, state, "012200f0ff0d003300f8ff0d00aabb", configured)
        for crc in (0, 1)
        for channel in (3, 31)
        for state in (0, 2, 6, 7)
        for configured in (False, True)
    ]
    ops = [
        ["R", 1000100, 1, 5, 0, 900001],
        ["U", 1000100],
        ["U", 1000166],
        ["R", 1000200, 0, 5, 0, 900002],
        ["U", 1000200],
    ]
    scenarios = [
        (crc, channel, state, payload, configured, ops)
        for crc, channel, state, payload, configured in scenarios
    ]
    for crc in (0, 1):
        for channel in (0, 2, 3, 31):
            seen = (1000101).to_bytes(4, "little").hex() + "ffff"
            scenarios.append(
                (
                    crc,
                    channel,
                    6,
                    "06aabb",
                    False,
                    [
                        ["F", 1000100, "aabb"],
                        ["N", 1000101, 1, 900010, seen],
                        ["U", 1000102],
                    ],
                )
            )
    media = "012200f0ff0d003300f8ff0d00aabb"
    for crc in (0, 1):
        for channel in (3, 31):
            for configured in (False, True):
                fragments = [
                    ["R", 1000100, 0, 5, 2, 900000, 1000100, media[:10]],
                    ["U", 1000100],
                    ["R", 1000101, 2, 6, 1, 900002, 1000101, media[20:]],
                    ["U", 1000167],
                    ["R", 1000200, 1, 6, 0, 900001, 1000200, media[10:20]],
                    ["U", 1000200],
                    ["U", 1000232],
                ]
                scenarios.append((crc, channel, 6, media, configured, fragments))
            scenarios.append(
                (crc, channel, 6, media, False, scenarios[0][5] + [["C", 1000300]])
            )
    for crc in (0, 1):
        for channel in (0, 2, 3, 31):
            seen = (1000101).to_bytes(4, "little").hex() + "ffff"
            for first_stamp, first_body, second_stamp in (
                (1000010, "00", 1000000),
                (0, "", 0xFFFFFFFF),
            ):
                scenarios.append(
                    (
                        crc,
                        channel,
                        6,
                        "06aabb",
                        False,
                        [
                            ["F", 1000100, "aabb"],
                            ["N", 1000101, 0, first_stamp, first_body or "-"],
                            ["N", 1000101, 1, second_stamp, seen],
                            ["U", 1000102],
                        ],
                    )
                )
    # Original HandlePendingDataPackets snapshots ALL complete packets and
    # re-enters OnStreamPacket for each one, including unmatched channels.
    for crc in (0, 1):
        for channel in (3, 31):
            other = 4 if channel == 3 else 3
            for mode in (
                "keep",
                "pause",
                "pause_matched",
                "phase0",
                "phase5",
                "phase7",
            ):
                second = "012300f0ff0d003300f8ff0d00ccdd"
                pending_ops = [
                    ["R", 1000100, 0, 5, 0, 900000, 1000100, media],
                    ["R", 1000101, 1, 5, 0, 900001, 1000101, second],
                    ["U", 1000200],
                ]
                if mode.startswith("pause"):
                    pending_ops.append(["P", 1000210, 1])
                elif mode.startswith("phase"):
                    pending_ops.append(["T", 1000210, int(mode[-1])])
                pending_ops.append(
                    ["C", 1000220, channel if mode == "pause_matched" else other]
                )
                if mode.startswith("pause"):
                    pending_ops.append(["P", 1000230, 0])
                elif mode.startswith("phase"):
                    pending_ops.append(["T", 1000230, 6])
                pending_ops.append(["C", 1000240, channel])
                scenarios.append((crc, channel, 6, media, False, pending_ops))
    for crc, channel, state, payload, configured, ops in scenarios:
        r = Client(crc, state, channel, payload, configured)
        initial = r.observe_channel()
        stages = []
        for op in ops:
            if op[0] == "R":
                r.receive(op)
            elif op[0] == "F":
                r.send_frame(op)
            elif op[0] == "N":
                r.nack(op)
            elif op[0] == "C":
                r.now = op[1]
                r.configure(op[2] if len(op) > 2 else None)
            elif op[0] in ("P", "T"):
                r.now = op[1]
                if op[0] == "P":
                    r.b(r.player + 19, op[2])
                else:
                    r.w32(r.player + 256, op[2])
            else:
                r.now = op[1]
                if r.target in r.channels:
                    r.call(0x7F9C9C, r.channels[r.target], r.now)
                    r.call(0x7A6368, r.player)
            stages.append(
                dict(
                    state=r.observe_channel(),
                    actions=list(r.actions),
                    channels=list(r.created),
                    pending=[
                        r.raw(r.q(r.pending + i * 8))
                        for i in range(r.i(r.player + 760))
                    ],
                )
            )
            r.actions.clear()
        cases.append(
            dict(
                input=dict(
                    crc=crc,
                    channel=channel,
                    state=state,
                    payload=payload,
                    configured=configured,
                    ops=ops,
                ),
                initial=initial,
                observed=stages,
            )
        )
    return cases


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    args = p.parse_args()
    base = feedback.wire.outgoing.load(
        args.binary, args.output.with_name("reliable-channels-base.json")
    )
    report = dict(
        binary_sha256=feedback.wire.outgoing.SHA, scope=__doc__, cases=audit(base)
    )
    ref = ROOT / "scripts/fixtures/steam-reliable-channels-reference.json"
    if args.refresh_reference:
        if ref.exists():
            previous = json.loads(ref.read_text())
            assert previous["cases"] == report["cases"][: len(previous["cases"])]
        ref.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert report == json.loads(ref.read_text())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"Official generic reliable channel routing: {len(report['cases'])} cases passed"
    )


if __name__ == "__main__":
    main()
