#!/usr/bin/env python3
"""Compare original ARM64 receiver instructions with the compiled production code.

Runs real HandleDataPacket/BInsertPacket/PopHead/Advance/UpdateUnreliableState.
External allocation, reference-counting, locks, memcpy and socket I/O are stubbed.
F isolates feedback generation by freezing frame delivery in BOTH implementations;
U executes the original PopHead/Advance too and compares frame bytes/window head.
No host, MediaCodec, Switch output or allocator/lifecycle correctness is proved.
"""
import argparse
import contextlib
import io
import json
import runpy
import subprocess
import sys
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--binary", type=Path, required=True)
parser.add_argument("--driver", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--video-driver", type=Path)
parser.add_argument("--write-fixture", type=Path)
args = parser.parse_args()
argv = sys.argv
sys.argv = [
    str(Path(__file__).with_name("audit-steam-video-recovery.py")),
    "--binary",
    str(args.binary),
    "--output",
    str(args.output.with_name("official-branches.json")),
]
with contextlib.redirect_stdout(io.StringIO()):
    original = runpy.run_path(sys.argv[0])
sys.argv = argv
Run, STOP = original["Run"], original["STOP"]


class Receiver:
    def __init__(self, rtt, smooth, initial_now):
        import struct

        self.r = r = Run(now=initial_now)
        r.w32(0x20000000 + 240, initial_now)
        self.p, self.conn, self.ptr, self.times = (
            0x20000000,
            0x20001000,
            0x20010000,
            0x20020000,
        )
        self.window = self.p + 280
        self.deliver = False
        r.wq(self.p + 8, self.conn)
        r.b(self.p + 16, 3)
        r.w32(self.p + 28, 6553)
        r.w32(self.window + 4, 2047)
        r.wq(self.window + 16, self.ptr)
        r.wq(self.window + 24, self.times)
        r.wh(self.conn + 12, 12)
        r.u.mem_write(self.conn + 732, struct.pack("<f", rtt * (1000.0 / 65536)))
        r.w32(self.conn + 744, smooth)
        player, vt = 0x20030000, 0x20031000
        r.wq(self.conn + 368, player)
        r.wq(player, vt)
        r.wq(vt + 48, STOP + 0x280)

        def jump(address):
            r.u.reg_write(original["UC_ARM64_REG_PC"], address)

        r.callbacks[0xC11100] = lambda: jump(0x7F7230)
        r.callbacks[0xC11130] = lambda: jump(0x7F76F4)
        r.callbacks[0xC11110] = lambda: jump(0x7FD204)
        r.callbacks[0xC11120] = lambda: jump(0x7F743C) if self.deliver else r.ret(0)
        r.callbacks[0xC0A380] = lambda: r.ret(1)
        r.callbacks[0xC09AB0] = lambda: r.ret(r.alloc(r.r(0)))
        r.callbacks[0xC09AC0] = lambda: r.ret()

        def copy():
            r.u.mem_write(r.r(0), bytes(r.u.mem_read(r.r(1), r.r(2))))
            r.ret(r.r(0))

        r.callbacks[0xBFF3D0] = copy

        def fill():
            r.u.mem_write(r.r(0), bytes([r.r(1) & 255]) * r.r(2))
            r.ret(r.r(0))

        r.callbacks[0xC09980] = fill

        def socket():
            p = r.r(2)
            data = r.q(p + 40)
            r.w32(data + 9, r.now)  # actual CStreamSocket::Send @0x7ff240
            self.events.append({"wire": bytes(r.u.mem_read(data, r.i(p + 52))).hex()})
            r.ret(0)

        r.callbacks[0xC11170] = socket

        def frame():
            p = r.r(2)
            data = r.q(p + 40)
            self.events.append(
                {
                    "frame": r.h(data + 7),
                    "send": r.i(data + 9),
                    "payload": bytes(r.u.mem_read(data + 13, r.i(p + 52) - 13)).hex(),
                }
            )
            r.ret()

        r.callbacks[STOP + 0x280] = frame
        self.events = []

    def step(self, line):
        r, p = self.r, self.p
        fields = line.split()
        if fields[0] == "A":
            ident, stamp, received, count, typ, fragment = map(int, fields[1:])
            packet = r.alloc(4096)
            r.packet(
                packet, typ=typ, stamp=stamp, received=received, retry=count, id=ident
            )
            r.wh(packet + 64 + 5, fragment)
            r.w32(packet + 52, 14)
            r.b(packet + 64 + 13, ident & 255)
            r.run(0x7F9400, p, p + 176, packet)
            return []
        if fields[0] == "S":
            r.wh(self.window + 8, int(fields[1]))
            r.wh(self.window + 10, int(fields[1]))
            return []
        if fields[0] == "F":
            r.now = int(fields[1])
            self.deliver = False
        else:
            self.deliver = True
        self.events = []
        r.run(0x7FA3B0, p, r.now)
        if fields[0] == "F":
            sends = [event for event in self.events if "wire" in event]
            assert len(sends) <= 1
            return [{"ready": bool(sends), **(sends[0] if sends else {})}]
        return [event for event in self.events if "frame" in event] + [
            {"head": r.h(self.window + 8)}
        ]


def add(ident, stamp=100000, received=999900, count=0, typ=3, fragment=0):
    return f"A {ident} {stamp & 0xffffffff} {received & 0xffffffff} {count} {typ} {fragment}"


cases = []


def case(name, lines, rtt=656, smooth=656):
    cases.append((name, lines, rtt, smooth))


seed = [add(0), "U"]
for count in (0, 1, 2):
    for age in (0, 64, 65, 66):
        case(
            f"wire_counter_{count}_age_{age}",
            seed + [add(2, received=1000000 - age, count=count), "F 1000000"],
        )
case("separate_bitmap_base_and_watermark", seed + [add(2), add(4), "F 1000000"])
case(
    "echo_does_not_regress",
    seed + [add(2, 100100), add(4, 100200), add(1, 100000), "F 1000000"],
)
case(
    "duplicate_does_not_replace_echo",
    seed + [add(2, 100100), add(2, 99900), "F 1000000"],
)
case(
    "feedback_is_not_an_unconditional_periodic_nack",
    seed + [add(2), "F 1000000", "F 1001000"],
)
case("new_input_rearms_feedback", seed + [add(2), "F 1000000", add(4), "F 1001000"])
case(
    "deadline_before_and_equal",
    seed + [add(2), "F 1000000", add(4), "F 1000163", "F 1000164"],
)
case("bitmap_more_than_one_byte", seed + [add(2), add(12), "F 1000000"])
case("initial_missing_head", [add(1, typ=4), "F 1000000", add(0, fragment=1), "U"])
case(
    "fragment_hole_repaired",
    [add(0, fragment=2), add(2, typ=4, fragment=1), "F 1000000", add(1, typ=4), "U"],
)
case(
    "newer_reordered_packet_must_not_postpone_hole",
    seed + [add(3, 100300), add(2, 100700), add(4, 107300), "U"],
)
case(
    "earlier_timestamp_propagates_across_held_packets",
    seed + [add(2, 100700), add(3, 100300), add(4, 107300), "U"],
)
case("age_exact_boundary", seed + [add(2, 100000), add(3, 106946), "U"])
case("age_over_boundary", seed + [add(2, 100000), add(3, 106947), "U"])
case(
    "longer_rtt_keeps_same_gap", seed + [add(2, 100000), add(3, 108000), "U"], rtt=3932
)
case(
    "expired_head_then_orphan",
    [add(0, fragment=2), add(2, typ=4, fragment=1), add(3, 107000), "U"],
)
case(
    "sender_timestamp_wrap",
    [add(0, 0xFFFFF000), "U", add(2, 0xFFFFFFF0), add(3, 7000), "U"],
)
case(
    "echo_timestamp_wrap",
    [add(0, 0xFFFFFFF0), "U", add(2, 5), add(4, 0xFFFFFFE0), "F 1000000"],
)
case(
    "feedback_deadline_wrap",
    seed + [add(2, received=0xFFFFFFF0), "F 4294967280", add(4, received=40), "F 148"],
)

# Bitmap cap, RTT-derived deadlines and sequence-ID wrap are independent axes.
for distance in (1, 7, 8, 9, 319, 320, 321):
    case(f"bitmap_distance_{distance}", seed + [add(2), add(2 + distance), "F 1000000"])
for smooth in (0, 64, 65, 259, 260, 3275, 3276, 10000):
    interval = max(65, min(smooth, 3276) // 4)
    case(
        f"feedback_interval_{smooth}",
        seed
        + [
            add(2),
            "F 1000000",
            add(4),
            f"F {1000000+interval-1}",
            f"F {1000000+interval}",
        ],
        smooth=smooth,
    )
case(
    "packet_id_wrap_feedback", ["S 65534", add(65534), "U", add(0), add(2), "F 1000000"]
)
case("packet_id_wrap_repaired", ["S 65534", add(65534), "U", add(0), add(65535), "U"])

import random

rng = random.Random(0x7FA3B0)
for trial in range(120):
    origin = 0xFFFFE000 if trial % 3 == 0 else 100000
    ids = list(range(1, 19))
    rng.shuffle(ids)
    lines = [add(0, origin), "U"]
    for ident in ids:
        if rng.randrange(5) == 0:
            continue
        stamp = origin + rng.randrange(18000)
        lines.append(add(ident, stamp, count=rng.choice((0, 1, 2, 255))))
        if rng.randrange(3) == 0:
            lines.append("U")
    lines.append("U")
    case(f"random_window_{trial}", lines, rtt=rng.choice((0, 65, 656, 3932, 30000)))
for trial in range(60):
    lines = seed.copy()
    tick = 1000000
    for _ in range(12):
        ident = rng.choice((2, 3, 4, 8, 15, 20, 255, 323))
        received = tick - rng.randrange(100)
        lines += [
            add(
                ident, 100000 + rng.randrange(500), received, rng.choice((0, 1, 2, 255))
            ),
            f"F {tick}",
        ]
        tick += rng.randrange(1000)
    case(
        f"random_feedback_{trial}",
        lines,
        smooth=rng.choice((0, 65, 260, 656, 3276, 10000)),
    )

results = []
for name, lines, rtt, smooth in cases:
    initial_now = next(
        (int(line.split()[1]) for line in lines if line.startswith("F ")), 1000000
    )
    ref = Receiver(rtt, smooth, initial_now)
    expected = []
    for line in lines:
        expected.extend(ref.step(line))
    native = subprocess.run(
        [str(args.driver), str(rtt), str(smooth)],
        input="\n".join(lines) + "\n",
        text=True,
        capture_output=True,
        check=True,
    )
    actual = [
        json.loads(line) for line in native.stdout.splitlines() if line.startswith("{")
    ]
    results.append(
        {
            "case": name,
            "driver": "media",
            "input": lines,
            "rtt": rtt,
            "smooth": smooth,
            "match": actual == expected,
            "expected": expected,
            "actual": actual,
        }
    )

if args.video_driver:
    # Compare DecodeFrame admission/retry state with the REAL channel hook.
    # B/H initial states are primed through production frames; the ARM64 side
    # starts at the corresponding independently audited soft/hard state.
    class Video:
        def __init__(self, mode, base):
            self.r = r = Run(now=base)
            self.p, self.f, self.packet, self.data, self.vt = [
                0x20000000 + i * 4096 for i in range(5)
            ]
            p = self.p
            r.wq(p, self.vt)
            r.wq(self.vt + 120, STOP + 0x100)
            r.wq(p + 8, p + 0x8000)
            r.b(p + 404, int(mode == "H"))
            r.b(p + 405, int(mode == "B"))
            r.w32(p + 408, base if mode != "N" else 0)
            r.wh(p + 416, {"N": 1, "H": 3, "B": 4}[mode])
            r.wh(p + 418, 11 if mode == "B" else 10)
            r.wq(self.f + 8, self.packet)
            r.wq(self.packet + 56, self.data)
            r.b(0xF477F8, 1)
            r.w32(0xF477F0, 6553)

            def flush():
                r.w32(p + 412, 0)
                r.ret()

            r.callbacks[STOP + 0x100] = flush
            self.accepted = False
            self.result = 0
            r.stop_at[0x7B2170] = lambda: setattr(self, "accepted", True)

        def feed(self, tick, ident, seq, flags):
            r = self.r
            r.now = tick
            r.events = []
            self.accepted = False
            r.wh(self.f + 26, ident)
            r.wh(self.data + 13, seq)
            r.b(self.data + 15, flags)
            r.u.reg_write(original["UC_ARM64_REG_SP"], 0x300FF000)
            r.u.reg_write(original["UC_ARM64_REG_X30"], STOP)
            r.run(0x7B2000, self.p, self.f)
            lost = sum(event["event"] == "DataLost" for event in r.events)
            if self.accepted:
                r.wh(self.p + 418, ident)  # OnThink @0x7b2594, outside admission audit
                if self.result:
                    backend = original["final_decode"]("backend_loss", ok=False)
                    lost += sum(
                        event["event"] == "DataLost" for event in backend["events"]
                    )
                    self.result = 0
            return {"submitted": self.accepted, "lost": lost}

    for mode in ("N", "H", "B"):
        expected_seq = {"N": 1, "H": 3, "B": 4}[mode]
        for age in (0, 6552, 6553, 6554, 13108):
            for gap in (False, True):
                for key in (False, True):
                    base = 0xFFFFFFF0 if age == 6554 else 1000000
                    tick = (base + age) & 0xFFFFFFFF
                    seq = expected_seq + int(gap)
                    steps = [
                        f"F {tick} 20 {seq} {24 if key else 8}",
                        f"F {tick} 21 {seq+1} 8",
                        f"F {tick} 22 {seq+2} 24",
                    ]
                    name = f"video_{mode}_age{age}_gap{gap}_key{key}"
                    ref = Video(mode, base)
                    expected = [ref.feed(*map(int, line.split()[1:])) for line in steps]
                    native = subprocess.run(
                        [str(args.video_driver), "--oracle"],
                        input=f"M {mode} {base}\n" + "\n".join(steps) + "\n",
                        text=True,
                        capture_output=True,
                        check=True,
                    )
                    actual = [
                        json.loads(line)
                        for line in native.stdout.splitlines()
                        if line.startswith("{")
                    ]
                    results.append(
                        {
                            "case": name,
                            "driver": "video",
                            "input": [f"M {mode} {base}"] + steps,
                            "match": actual == expected,
                            "expected": expected,
                            "actual": actual,
                        }
                    )
    # An ordinary backend failure must request recovery without setting strict wait.
    steps = ["F 1000000 20 1 8", "F 1000001 21 2 8", "F 1000002 22 3 24"]
    ref = Video("N", 1000000)
    ref.result = 1
    expected = [ref.feed(*map(int, line.split()[1:])) for line in steps]
    native = subprocess.run(
        [str(args.video_driver), "--oracle"],
        input="M N 1000000\nR 1\n" + "\n".join(steps) + "\n",
        text=True,
        capture_output=True,
        check=True,
    )
    actual = [
        json.loads(line) for line in native.stdout.splitlines() if line.startswith("{")
    ]
    results.append(
        {
            "case": "video_backend_loss_continues",
            "driver": "video",
            "input": ["M N 1000000", "R 1"] + steps,
            "match": actual == expected,
            "expected": expected,
            "actual": actual,
        }
    )

if args.video_driver:
    steps = ["F 1000000 20 65535 24", "F 1000001 21 0 8", "F 1000002 22 1 8"]
    ref = Video("N", 1000000)
    expected = [ref.feed(*map(int, line.split()[1:])) for line in steps]
    native = subprocess.run(
        [str(args.video_driver), "--oracle"],
        input="M N 1000000\n" + "\n".join(steps) + "\n",
        text=True,
        capture_output=True,
        check=True,
    )
    actual = [
        json.loads(line) for line in native.stdout.splitlines() if line.startswith("{")
    ]
    results.append(
        {
            "case": "video_sequence_wrap",
            "driver": "video",
            "input": ["M N 1000000"] + steps,
            "match": actual == expected,
            "expected": expected,
            "actual": actual,
        }
    )

args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(
    json.dumps({"scope": __doc__, "cases": results}, indent=2) + "\n"
)
failed = [result["case"] for result in results if not result["match"]]
print(
    json.dumps(
        {
            "cases": len(results),
            "passed": len(results) - len(failed),
            "mismatches": failed,
            "report": str(args.output),
        }
    )
)
if args.write_fixture:
    assert not failed, "Never accept a native/original mismatch as a new fixture"
    fixture = {
        "binary_sha256": "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e",
        "scope": __doc__
        + " Video cases audit admission/retry/backend-loss, not original slice assembly or codecs.",
        "cases": [
            {k: v for k, v in result.items() if k not in ("match", "actual")}
            for result in results
        ],
    }
    args.write_fixture.parent.mkdir(parents=True, exist_ok=True)
    # One case per line: generated original outputs stay inspectable in review.
    args.write_fixture.write_text(
        "{\n"
        + ",\n".join(
            json.dumps(k) + ": " + json.dumps(v)
            for k, v in fixture.items()
            if k != "cases"
        )
        + ',\n"cases": [\n'
        + ",\n".join(json.dumps(c) for c in fixture["cases"])
        + "\n]}\n"
    )
raise SystemExit(bool(failed))
