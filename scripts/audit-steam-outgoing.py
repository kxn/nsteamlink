#!/usr/bin/env python3
"""Execute official Android channel sends, socket budget and connection scheduling.

Pinned libmain.so instructions perform packet selection, retry counters, retention,
CRC, two-class shaping, priority sort and both send phases. Receive consumers,
empty FEC queues, window releases, final transport I/O and stats are explicit
adapters. This is not a real Steam session or a wall-clock fairness measurement.
"""

import argparse
import contextlib
import io
import json
import runpy
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHA = "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"


def load(binary, output):
    previous = sys.argv
    sys.argv = [
        str(ROOT / "scripts/audit-steam-video-recovery.py"),
        "--binary",
        str(binary),
        "--output",
        str(output),
    ]
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            return runpy.run_path(sys.argv[0])
    finally:
        sys.argv = previous


def audit(base):
    Run, STOP = base["Run"], base["STOP"]

    class Sender(Run):
        def __init__(self, *, rate=65536, deadline=1000000, transport=0):
            super().__init__()
            self.conn, self.sock, self.shaper, self.transport, self.vt = (
                0x20000000 + i * 4096 for i in range(5)
            )
            self.channels, self.windows, self.sent, self.actions = {}, {}, [], []
            self.transport_result = transport
            self.wq(self.sock, self.transport)
            self.wq(self.transport, self.vt)
            self.wq(self.vt + 72, STOP + 0x200)
            self.wq(self.sock + 64, self.shaper)
            self.w32(self.shaper, rate)
            self.w32(self.shaper + 4, rate)
            self.w32(self.shaper + 8, deadline)
            self.w32(self.shaper + 12, deadline)
            self.wq(self.conn, self.sock)
            self.w32(self.conn + 16, 1)
            self.w32(self.conn + 52, self.now)
            self.b(self.conn + 10, 1)
            self.u.mem_write(self.conn + 732, struct.pack("<f", 10))
            self.w32(self.conn + 744, 100)
            self.b(0xF479A8, 1)
            self.w32(0xF479A0, 13107)
            self.callbacks.update(
                {
                    0xC097E0: self.assertion,
                    0xC09E30: lambda: self.ret(),
                    0xBFF1A0: lambda: self.ret(),
                    0xC11170: lambda: self.jump(0x7FF1DC),
                    0xC11200: lambda: self.jump(0x7F8AC4),
                    0xC11220: lambda: self.jump(0x7F8CBC),
                    0xC11450: lambda: self.jump(0x8E1610),
                    0xC10FE0: lambda: self.ret(),
                    0xC11370: lambda: self.ret(),
                    0xC112E0: lambda: self.receive("reliable"),
                    0xC112F0: lambda: self.receive("unreliable"),
                    0xC11160: lambda: self.ret(),
                    0xC11130: self.advance,
                    0xC112B0: self.release,
                    STOP + 0x200: self.send,
                }
            )
            self.call(0x7FE284)

        def assertion(self):
            text = bytes(self.u.mem_read(self.r(2), 512)).split(b"\0")[0].decode()
            raise AssertionError((self.r(1), text, self.windows))

        def jump(self, address):
            self.u.reg_write(base["UC_ARM64_REG_PC"], address)

        def call(self, address, *params):
            self.u.reg_write(base["UC_ARM64_REG_SP"], 0x300FF000)
            self.u.reg_write(base["UC_ARM64_REG_X30"], STOP)
            self.run(address, *params)
            return self.r(0) & 0xFFFFFFFF

        def send(self):
            packet = self.r(1)
            raw = bytes(self.u.mem_read(self.q(packet + 56), self.i(packet + 52) + 4))
            self.sent.append(raw.hex())
            self.ret(self.transport_result)

        def receive(self, kind):
            self.actions.append([kind, self.u.mem_read(self.r(0) + 16, 1)[0]])
            self.ret()

        def advance(self):
            window, count = self.r(0), self.r(1)
            for _ in range(count):
                head = self.h(window + 8)
                self.wq(self.q(window + 16) + (head & 7) * 8, 0)
                self.w32(self.q(window + 24) + (head & 7) * 4, 0)
                self.wh(window + 8, head + 1)
            self.ret()

        def release(self):
            window, ident = self.r(0), self.r(1)
            self.wq(self.q(window + 16) + (ident & 7) * 8, 0)
            self.ret()

        def channel(
            self, ident, priority, reliable=(), unreliable=(), *, head=100, cursor=None
        ):
            channel = self.alloc(4096)
            self.wq(channel, self.sock)
            self.wq(channel + 8, self.conn)
            self.b(channel + 16, ident)
            self.w32(channel + 20, priority)
            self.wq(self.conn + 112 + len(self.channels) * 8, channel)
            self.b(self.conn + 376, 1)
            self.channels[ident] = channel
            for offset, packets in ((112, reliable), (248, unreliable)):
                window = channel + offset
                pointers, times = self.alloc(4096), self.alloc(4096)
                self.w32(window + 4, 7)
                self.wh(window + 8, head)
                self.wh(window + 10, head + len(packets))
                self.wq(window + 16, pointers)
                self.wq(window + 24, times)
                entries = []
                for index, spec in enumerate(packets):
                    packet = self.alloc(4096)
                    count, stamp, created = spec
                    ident_packet = (head + index) & 65535
                    self.packet(
                        packet,
                        typ=5 if offset == 112 else 3,
                        stamp=stamp,
                        retry=count,
                        id=ident_packet,
                    )
                    self.b(packet + 68, ident)
                    self.w32(packet + 52, 14)
                    self.b(packet + 77, ident)
                    self.wq(pointers + (ident_packet & 7) * 8, packet)
                    self.w32(times + (ident_packet & 7) * 4, created)
                    entries.append((ident_packet, packet))
                self.windows[(ident, offset)] = (window, entries)
            self.wh(channel + 244, head if cursor is None else cursor)
            return channel

        def observe(self, result=None):
            windows = []
            for (ident, offset), (window, entries) in self.windows.items():
                windows.append(
                    dict(
                        channel=ident,
                        reliable=offset == 112,
                        head=self.h(window + 8),
                        tail=self.h(window + 10),
                        cursor=self.h(self.channels[ident] + 244)
                        if offset == 248
                        else None,
                        packets=[
                            dict(
                                id=i,
                                count=self.u.mem_read(self.q(p + 40) + 1, 1)[0],
                                stamp=self.i(self.q(p + 40) + 9),
                                retained=bool(
                                    self.q(self.q(window + 16) + (i & 7) * 8)
                                ),
                            )
                            for i, p in entries
                        ],
                    )
                )
            value = dict(
                sent=list(self.sent),
                receive=list(self.actions),
                windows=windows,
                unreliable_deadline=self.i(self.shaper + 8),
                reliable_deadline=self.i(self.shaper + 12),
                blocked=bool(self.u.mem_read(self.sock + 57, 1)[0]),
                rotation=self.u.mem_read(self.conn + 377, 1)[0],
            )
            if result is not None:
                value["result"] = result
            self.sent.clear()
            self.actions.clear()
            return value

    cases = []

    def record(name, group, inp, observed):
        cases.append(dict(case=name, group=group, input=inp, observed=observed))

    # Real channel sender -> real Socket::Send, including failed sends and
    # subsequent attempts. Packet timestamps are mutated before admission.
    for reliable in (False, True):
        for transport in (0, 1, 2):
            for offset in (-1, 0, 1):
                r = Sender(deadline=1000000 + offset, transport=transport)
                packets = [(0, 999999, 999999)] * 3
                ch = r.channel(
                    1, 0, **{("reliable" if reliable else "unreliable"): packets}
                )
                entry = 0x7F8AC4 if reliable else 0x7F8CBC
                arg = r.now if reliable else 0
                result = r.call(entry, ch, arg)
                first = r.observe(result)
                assert first["windows"][0 if reliable else 1]["packets"][0][
                    "count"
                ] == (1 if transport == 0 and offset <= 0 else 0)
                r.transport_result = 0
                r.now += 1
                result = r.call(entry, ch, r.now if reliable else 0)
                record(
                    f"{'reliable' if reliable else 'unreliable'}_deadline{offset:+}_transport{transport}",
                    "sender",
                    dict(
                        reliable=reliable,
                        transport=transport,
                        deadline_offset=offset,
                        packets=packets,
                    ),
                    [first, r.observe(result)],
                )

    # Strict reliable RTO, count/timestamp zero, saturation, wrap, stop after
    # first transport failure. The shaper is unlimited to isolate RTO decisions.
    for count, age, stamp_zero in (
        (0, 0, False),
        (1, 0, True),
        (1, 125, False),
        (1, 126, False),
        (254, 126, False),
        (255, 126, False),
    ):
        r = Sender(rate=0)
        stamp = 0 if stamp_zero else r.now - age
        ch = r.channel(1, 0, reliable=[(count, stamp, stamp)])
        result = r.call(0x7F8AC4, ch, r.now)
        record(
            f"reliable_count{count}_age{age}_zero{int(stamp_zero)}",
            "rto",
            dict(count=count, age=age, zero=stamp_zero),
            r.observe(result),
        )

    # Both clamp bounds and the strict tick boundary, including uint32 wrap.
    for srtt in (0, 64, 65, 66, 3276, 3277):
        delay = max(65, min(3276, srtt))
        delay += delay // 4
        for now in (1000000, 48):
            for age in (delay - 1, delay, delay + 1):
                r = Sender(rate=0, deadline=now)
                r.now = now
                r.w32(r.conn + 744, srtt)
                stamp = (now - age) & 0xFFFFFFFF
                ch = r.channel(1, 0, reliable=[(1, stamp, stamp)])
                value = r.observe(r.call(0x7F8AC4, ch, now))
                assert bool(value["sent"]) == (age > delay)
                record(
                    f"rto_srtt{srtt}_now{now}_age{age}",
                    "rto",
                    dict(count=1, age=age, zero=False, now=now, srtt=srtt),
                    value,
                )

    # Previously sent unreliable packets are only considered in retry phase,
    # only if NACK marked the timestamp zero, and only inside retention age.
    for head in (100, 65535):
        for retry_phase in (False, True):
            for age in (14679, 14680):
                for marked in (False, True):
                    r = Sender(rate=0)
                    created = r.now - age
                    stamp = 0 if marked else created
                    ch = r.channel(
                        1,
                        0,
                        unreliable=[(1, stamp, created)],
                        head=head,
                        cursor=(head + 1) & 65535,
                    )
                    result = r.call(0x7F8CBC, ch, int(retry_phase))
                    value = r.observe(result)
                    assert bool(value["sent"]) == (
                        retry_phase and marked and age == 14679
                    )
                    record(
                        f"retry_head{head}_phase{int(retry_phase)}_age{age}_marked{int(marked)}",
                        "retention",
                        dict(
                            head=head, retry_phase=retry_phase, age=age, marked=marked
                        ),
                        value,
                    )

    # NACK marks/releases -> ordinary pass -> retry pass with actual sender and
    # socket. The window storage/refcount adapter only performs the requested
    # release; NACK ordering, cutoff and bitmap branches execute unchanged.
    for head in (100, 65534):
        for bitmap in (None, b"", b"\x00", b"\x05", b"\x07"):
            for echo_age in (100, 1500):
                r = Sender(rate=0)
                ch = r.channel(
                    1,
                    0,
                    unreliable=[(1, r.now - 1000, r.now - 1000)] * 4,
                    head=head,
                    cursor=(head + 4) & 65535,
                )
                packet = r.alloc(4096)
                r.packet(packet, typ=10, stamp=r.now, retry=0, id=(head + 1) & 65535)
                body = (
                    b""
                    if bitmap is None
                    else struct.pack("<IH", r.now - echo_age, (head - 1) & 65535)
                    + bitmap
                )
                r.w32(packet + 52, 13 + len(body))
                if body:
                    r.u.mem_write(packet + 77, body)
                r.call(0x7F95DC, ch, ch + 176, packet)
                marked = r.observe()
                result = r.call(0x7F8CBC, ch, 0)
                ordinary = r.observe(result)
                result = r.call(0x7F8CBC, ch, 1)
                retry = r.observe(result)
                assert not marked["sent"] and not ordinary["sent"]
                record(
                    f"nack_head{head}_bitmap{None if bitmap is None else bitmap.hex()}_echo{echo_age}",
                    "nack",
                    dict(
                        head=head,
                        bitmap=None if bitmap is None else bitmap.hex(),
                        echo_age=echo_age,
                    ),
                    [marked, ordinary, retry],
                )

    # Raw header fallback uses a signed 32-bit subtraction of the zero-extended
    # IDs, rather than a signed 16-bit wrapped difference. Exercise both sides
    # of wrap/half-range without an out-of-cursor selective ACK assertion.
    for head in (100, 65534):
        for offset in (-1, 0, 4, 32768):
            for bitmap in (None, b""):
                r = Sender(rate=0)
                ch = r.channel(
                    1,
                    0,
                    unreliable=[(1, 999000, 999000)] * 4,
                    head=head,
                    cursor=(head + 4) & 65535,
                )
                packet = r.alloc(4096)
                r.packet(
                    packet, typ=10, stamp=r.now, retry=0, id=(head + offset) & 65535
                )
                body = (
                    b""
                    if bitmap is None
                    else struct.pack("<IH", r.now - 100, (head - 1) & 65535)
                )
                r.w32(packet + 52, 13 + len(body))
                if body:
                    r.u.mem_write(packet + 77, body)
                r.call(0x7F95DC, ch, ch + 176, packet)
                values = [r.observe()]
                values.append(r.observe(r.call(0x7F8CBC, ch, 0)))
                values.append(r.observe(r.call(0x7F8CBC, ch, 1)))
                record(
                    f"nack_fallback_head{head}_offset{offset}_extended{int(bitmap is not None)}",
                    "nack",
                    dict(
                        head=head,
                        base_offset=offset,
                        bitmap=None if bitmap is None else "",
                        echo_age=100,
                    ),
                    values,
                )

    # Malformed bodies still consume the feedback timestamp; zero is the
    # original sentinel, so a first timestamp zero does not reject the next -1.
    for first_stamp, first_body, second_stamp in (
        (1000010, b"\x00", 1000000),
        (1000000, b"", 999999),
        (0, b"", 0xFFFFFFFF),
    ):
        r = Sender(rate=0)
        ch = r.channel(1, 0, unreliable=[(1, 999000, 999000)] * 4, cursor=104)
        values = []
        for stamp, body, ident in (
            (first_stamp, first_body, 100),
            (second_stamp, b"", 101),
        ):
            packet = r.alloc(4096)
            r.packet(packet, typ=10, stamp=stamp, retry=0, id=ident)
            r.w32(packet + 52, 13 + len(body))
            if body:
                r.u.mem_write(packet + 77, body)
            r.call(0x7F95DC, ch, ch + 176, packet)
            values.append(r.observe())
        values.append(r.observe(r.call(0x7F8CBC, ch, 1)))
        record(
            f"nack_timestamp_first{first_stamp}_body{first_body.hex()}_second{second_stamp}",
            "nack_sequence",
            dict(
                first_stamp=first_stamp,
                first_body=first_body.hex(),
                second_stamp=second_stamp,
            ),
            values,
        )

    # A failed attempt writes the socket timestamp but does not increment the
    # count. With an existing count it must wait the strict RTO; an unsent count
    # zero is attempted again immediately. Later packets do not pass the failure.
    for count in (0, 1, 254, 255):
        for transport in (1, 2):
            r = Sender(rate=0, transport=transport)
            ch = r.channel(1, 0, reliable=[(count, r.now - 1000, r.now - 1000)] * 2)
            values = []
            start = r.now
            for delta in (0, 1, 125, 126):
                r.now = start + delta
                values.append(r.observe(r.call(0x7F8AC4, ch, r.now)))
                r.transport_result = 0
            assert len(values[0]["sent"]) == 1
            if count:
                assert len(values[1]["sent"]) == 1 and not values[2]["sent"]
                assert bytes.fromhex(values[3]["sent"][0])[1] == count
            else:
                assert len(values[1]["sent"]) == 2
                assert bytes.fromhex(values[1]["sent"][0])[1] == 0
            record(
                f"failure_count{count}_transport{transport}",
                "failure",
                dict(count=count, transport=transport),
                values,
            )

    # Execute consecutive complete Update calls, not just one ideal rotation.
    # Both sender bodies execute; receives, FEC and transport are the adapters.
    for priorities in ((-1, 0, 2), (0, 0, 0)):
        for blocked in (False, True):
            r = Sender(rate=0, deadline=1000001 if blocked else 1000000)
            for ident, priority in zip((2, 3, 1), priorities):
                r.channel(
                    ident,
                    priority,
                    reliable=[(0, r.now, r.now)],
                    unreliable=[(1, 0, r.now)],
                    cursor=101,
                )
            values = []
            for _ in range(5):
                r.call(0x7FC108, r.conn, r.now)
                values.append(r.observe())
                r.now += 1
            assert [v["rotation"] for v in values] == [1, 2, 3, 0, 1]
            record(
                f"connection_priorities{list(priorities)}_blocked{int(blocked)}",
                "connection",
                dict(priorities=priorities, blocked=blocked),
                values,
            )
    # Rebuilding priorities starts from the connection's creation-order table,
    # not the previously sorted view. Run the actual setter as the trigger.
    for total in (3, 16, 32):
        r = Sender(rate=0)
        entries = [(ident, ident % 3 - 1) for ident in reversed(range(total))]
        for ident, priority in entries:
            r.channel(ident, priority, reliable=[(0, r.now, r.now)])
        r.call(0x7FC108, r.conn, r.now)
        values = [r.observe()]
        r.callbacks[0xC0E390] = lambda: r.ret(r.channels.get(r.r(1), 0))
        for ident, _ in entries:
            r.call(0x7FBC68, r.conn, ident, 0)
        r.now += 126
        r.call(0x7FC108, r.conn, r.now)
        values.append(r.observe())
        record(
            f"connection_priority_reset_count{total}",
            "priority_reset",
            dict(entries=entries),
            values,
        )
    # Actual comparator/sort instructions for the bounded 32-channel domain.
    # These synthetic keys cover small-sort and the 24-element partition switch.
    for total in (0, 1, 2, 3, 4, 5, 23, 24, 25, 31, 32):
        patterns = [
            list(range(total)),
            list(reversed(range(total))),
            [0] * total,
            [i % 3 - 1 for i in range(total)],
            [(i * 5) % 7 - 3 for i in range(total)],
            [(-2147483648 if i & 1 else 2147483647) for i in range(total)],
        ]
        for pattern, priorities in enumerate(patterns):
            r = Sender(rate=0)
            array = r.alloc(4096)
            for i, priority in enumerate(priorities):
                ch = r.alloc(4096)
                r.b(ch + 16, i)
                r.w32(ch + 20, priority)
                r.wq(array + 8 * i, ch)
            r.call(
                0x7FD464,
                array,
                array + 8 * total,
                2 * (total.bit_length() - 1) if total else 0,
                1,
            )
            order = [r.u.mem_read(r.q(array + 8 * i) + 16, 1)[0] for i in range(total)]
            record(
                f"sort_count{total}_pattern{pattern}",
                "sort",
                dict(priorities=priorities),
                dict(order=order),
            )
    # Real factory fills a dense prefix; only allocation/constructor are adapters.
    for requests in ((3, 1, 7, 0), (0, 31, 31), (32, 255, 3)):
        r = Sender(rate=0)
        created = []
        values = []

        def construct():
            p = r.r(0)
            ident = r.r(3)
            r.wq(p, r.r(1))
            r.wq(p + 8, r.r(2))
            r.b(p + 16, ident)
            r.w32(p + 20, 0)
            created.append(ident)
            r.ret()

        r.callbacks[0xC11470] = construct
        r.callbacks[0xC097E0] = lambda: r.ret(1)
        for ident in requests:
            result = r.call(0x7FBA34, r.conn, ident)
            values.append(
                dict(
                    order=list(created),
                    returned=None if not result else r.u.mem_read(result + 16, 1)[0],
                )
            )
        record(
            f"channel_factory_{list(requests)}",
            "factory",
            dict(requests=requests),
            values,
        )
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--refresh-reference", action="store_true")
    args = parser.parse_args()
    base = load(args.binary, args.output.with_name("official-branches.json"))
    cases = json.loads(json.dumps(audit(base)))
    report = dict(binary_sha256=SHA, scope=__doc__, cases=cases)
    reference = ROOT / "scripts/fixtures/steam-outgoing-reference.json"
    if args.refresh_reference:
        if reference.exists():
            previous = {
                c["case"]: c for c in json.loads(reference.read_text())["cases"]
            }
            for case in cases:
                if case["case"] in previous:
                    assert case == previous[case["case"]], case["case"]
        reference.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert report == json.loads(reference.read_text()), (
            "official outgoing reference changed"
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Official Android outgoing: {len(cases)} original-instruction cases passed")


if __name__ == "__main__":
    main()
