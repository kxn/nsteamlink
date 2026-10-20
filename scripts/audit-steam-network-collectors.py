#!/usr/bin/env python3
"""Execute pinned official client network collector constructors and sample queues.

Original bitrate, packet/loss, ping and video-bandwidth records, expiration,
same-timestamp merge and derived calculations run, including real CUtlQueue
construction/growth. Appended cases run FrameReceived, wire Frame parsing and
ProcessTimestamp through real Ping/TimeOffset queues. libc memory, mutexes and
exit destructor registration are adapters. Direct inputs do not
prove transport/decoder caller reachability or live network behavior.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "stats", ROOT / "scripts/audit-steam-frame-stats.py"
)
stats = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stats)
config = stats.config


class Collectors(stats.Stats):
    def __init__(self, binary):
        super().__init__(binary)
        self.callbacks.update(
            {
                0xC09E30: lambda: self.ret(self.r(0)),
                0xC09F10: lambda: self.ret(0),
                0xC09F30: lambda: self.ret(0),
                0xBFF1A0: lambda: self.ret(0),
                0xC0E6C0: lambda: self.jump(0x7B04DC),
            }
        )
        self.rates = [self.connection + 856, self.connection + 1008]
        self.packets = self.connection + 1160
        self.ping = self.connection + 640
        self.video = config.CLIENT + 840
        for pointer, ctor in [(b, 0x7FCB14) for b in self.rates] + [
            (self.packets, 0x7FCEC8),
            (self.ping, 0x7FC5F0),
            (self.video, 0x7B046C),
            (self.connection + 752, 0x7FC938),
        ]:
            self.call(ctor, pointer)
        self.call(0x7FE284)
        self.b(0xF479E8, 1)
        self.wi(0xF479E4, 65)

    def queue(self, pointer, size):
        first, last = self.i(pointer + 52), self.i(pointer + 56)
        count = 0 if first & 0x80000000 else ((last - first) & 0x7FFFFFFF) + 1
        assert count < 10000, count
        data = self.q(pointer + 64)
        mask = self.i(pointer + 48)
        return [
            bytes(self.u.mem_read(data + ((first + i) & mask) * size, size)).hex()
            for i in range(count)
        ]

    def observe(self):
        return dict(
            rates=[
                dict(
                    sum=self.q(b + 136),
                    bits=self.i(b + 144),
                    samples=self.queue(b + 48, 8),
                )
                for b in self.rates
            ],
            packets=dict(
                total=self.i(self.packets + 88),
                lost=self.i(self.packets + 92),
                samples=self.queue(self.packets, 12),
            ),
            ping=dict(
                sum=self.i(self.ping + 88),
                bits=self.i(self.ping + 92),
                samples=self.queue(self.ping, 8),
            ),
            video=dict(
                frame=struct.unpack("<H", self.u.mem_read(self.video + 88, 2))[0],
                pending=[self.i(self.video + p) for p in (92, 96, 100)],
                totals=[self.i(self.video + p) for p in (104, 108, 112, 116)],
                bits=[self.i(self.video + p) for p in (120, 124)],
                samples=self.queue(self.video, 20),
            ),
        )


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == config.SHA
    cases = []
    schedules = []
    for base in (0, 1000000, 0xFFFF0000):
        ticks = [(base + d) & 0xFFFFFFFF for d in (0, 0, 1, 196608, 196609, 393218)]
        schedules.append(
            (
                f"boundaries_{base}",
                [
                    action
                    for n, tick in enumerate(ticks)
                    for action in (
                        ["B", 0, tick, 100 + n],
                        ["B", 1, tick, 211 + n],
                        ["P", tick, 1 + n, n % 2],
                        ["G", 100 + n, tick],
                    )
                ],
            )
        )
    schedules += [
        (
            "bitrate_signed",
            [["B", 0, 100, n] for n in (0, 1, -1, 2147483647, -2147483648)],
        ),
        (
            "packet_merge_flags",
            [
                ["P", 100, n, lost]
                for n, lost in ((1, 0), (2, 0), (3, 1), (4, 1), (-5, 1), (6, 0))
            ],
        ),
        (
            "ping_unsigned_sum",
            [
                ["G", n, 100 + i]
                for i, n in enumerate((1, 2, 0xFFFFFFFF, 65535, 65536, 0x80000000, 0))
            ],
        ),
    ]
    for delta in (0x7FFFFFFF, 0x80000000, 0xFFFFFFFF):
        tick = (1000000 + delta) & 0xFFFFFFFF
        schedules.append(
            (
                f"unsigned_age_{delta:x}",
                [
                    ["B", 0, 1000000, 13],
                    ["P", 1000000, 7, 1],
                    ["G", 5, 1000000],
                    ["B", 0, tick, 17],
                    ["P", tick, 11, 0],
                    ["G", 9, tick],
                ],
            )
        )
    for count in (9, 10, 11, 17, 65):
        schedules.append(
            (
                f"video_{count}",
                [
                    [
                        "V",
                        900000 + i * 1000 + part * 3,
                        899995 + i * 1000 + part * 3,
                        900010 + i * 1000 + part * 7,
                        i,
                        100 + part,
                    ]
                    for i in range(1, count + 2)
                    for part in (0, 1, 2)
                ],
            )
        )
    schedules += [
        (
            "video_reject_and_idle",
            [
                ["V", 0, 0, 0, 0, 100],
                ["V", 100, 0, 0, 1, 100],
                ["V", 100, 0, 1, 2, 100],
                ["V", 99, 0, 2, 3, 100],
                ["V", 100, 0, 3, 3, 100],
                ["V", 101, 0, 4, 4, 100],
                ["V", 300000, 0, 5, 5, 100],
                ["V", 300001, 0, 6, 6, 100],
            ],
        ),
        (
            "queue_growth",
            [["B", 0, 1000 + i, i * 17] for i in range(130)]
            + [["B", 0, 300000, 1], ["B", 0, 300000, 2]],
        ),
        (
            "video_stale_derived",
            [
                [
                    "V",
                    1000 + i * 100 + p * 3,
                    995 + i * 100 + p * 3,
                    1010 + i * 100 + p * 7,
                    i,
                    100,
                ]
                for i in range(1, 13)
                for p in (0, 1)
            ]
            + [
                ["V", 400000, 400000, 400003, 13, 1],
                ["V", 400010, 400005, 400014, 14, 1],
            ],
        ),
        ("ping_consumer_boundary", [["G", 655, 1000000], ["G", 656, 1000010]]),
        (
            "bitrate_merge_overflow_retire",
            [["B", 0, 100, 2147483647], ["B", 0, 100, 2147483647], ["B", 0, 300000, 1]],
        ),
    ]
    for op in ("F", "W"):
        schedules.append(
            (
                f"video_inline_{op}",
                [
                    [
                        op,
                        i,
                        900000 + i * 1000 + part * 3,
                        900010 + i * 1000 + part * 7,
                        100 + part,
                    ]
                    for i in range(1, 14)
                    for part in (0, 1, 2)
                ],
            )
        )
    schedules += [
        (
            "timestamp_real_queues",
            [
                ["T", 999345, 1000000, 1000000],
                ["T", 999354, 1000010, 1000010],
                ["T", 1195955, 1196608, 1196608],
                ["T", 1195957, 1196609, 1196609],
                ["T", 1654708, 1655360, 1655360],
                ["T", 1654710, 1655361, 1655361],
            ],
        ),
        (
            "timestamp_echo_guard",
            [
                ["T", 900000, 900100, 900655],
                ["T", 899870, 900101, 900656],
                ["T", 899739, 900102, 900657],
                ["T", 900900, 900901, 900800],
            ],
        ),
        (
            "timestamp_offset_ten_seconds",
            [
                ["T", 1000000, 1000100, 1000010],
                ["T", 1655360, 1655460, 1655370],
                ["T", 1655361, 1655461, 1655371],
            ],
        ),
    ]
    schedules.append(
        (
            "timestamp_offset_window_values",
            [
                ["TC", 1000000, 1000100, 1000010],
                ["TC", 1655360, 1655560, 1655370],
                ["TC", 1655361, 1655661, 1655371],
            ],
        )
    )
    for name, actions in schedules:
        r = Collectors(binary)
        observed = []
        for action in actions:
            op, *v = action
            if op == "B":
                direction, tick, size = v
                r.call(0x7FCB84, r.rates[direction], tick, size & 0xFFFFFFFF)
            elif op == "P":
                tick, count, lost = v
                r.call(0x7FCF24, r.packets, tick, count & 0xFFFFFFFF, lost)
            elif op == "G":
                r.call(0x7FC070, r.ping, *v)
            elif op in ("F", "W"):
                fid, sent, received, size = v
                r.receive(
                    fid,
                    frame_start=sent - 1,
                    sent=sent,
                    received=received,
                    size=size,
                    packet=op == "W",
                )
            elif op in ("T", "TC"):
                r.call(0x7F9A2C, r.connection, *v)
            else:
                r.call(0x7AC1D0, r.video, *v)
            observation = r.observe()
            if op in ("T", "TC"):
                observation["clock"] = {
                    key: r.i(r.connection + offset)
                    for key, offset in (
                        ("echo", 56),
                        ("minimum", 740),
                        ("smooth", 744),
                        ("next_min_update", 736),
                        ("offset", 848),
                    )
                }
                if op == "TC":
                    observation["clock"].update(
                        offset_count=len(r.queue(r.connection + 752, 8)),
                        offset_sum=r.q(r.connection + 840),
                    )
            observed.append(observation)
        assert not r.asserts
        cases.append(dict(input=dict(name=name, actions=actions), observed=observed))
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
    ref = ROOT / "scripts/fixtures/steam-network-collectors-reference.json"
    if a.refresh_reference:
        if ref.exists():
            old = json.loads(ref.read_text())
            assert old["binary_sha256"] == report["binary_sha256"]
            assert old["cases"] == report["cases"][: len(old["cases"])]
        ref.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert json.loads(ref.read_text()) == report
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Official network collectors: {len(report['cases'])} cases passed")


if __name__ == "__main__":
    main()
