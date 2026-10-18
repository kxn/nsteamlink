#!/usr/bin/env python3
"""Execute official video timestamp delivery, jitter and ready-frame selection.

Original constructors, Frame/DecodeFrame/OnThink/FinalDecode/NDK submission,
PutVideoFrame, CFrameJitterTracker/real float stats, GetVideoWait/GetNextVideoFrame,
completion/release and full Main OnThink reset execute. Texture mode has explicit
SDK capability/input-success terminals, not physical Android decoding. NAL metadata,
SDK/JNI/platform/locks/clock/libc/stat IO inherit declared mode-audit boundaries.
Clock and rendering opportunities are input actions; no physical OS/GPU cadence.
Complete raw Source completion calls are retained separately from the projected
known-picture result1/6 resource completions. Surface selector cases execute its
real cached device branches with SDL/Android properties/string storage as inputs.
No claim of all rendering/UI/AV sync, physical Switch/host or unbounded memory.
"""

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "mode", ROOT / "scripts/audit-steam-video-content-mode.py"
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
c = m.c
PAYLOAD = m.PAYLOAD


class Timing(m.Mode):
    def __init__(self, binary):
        self.pictures = []
        self.submissions = []
        self.selected = []
        self.waits = []
        self.decode_events = []
        self.queue_ticks = 0
        super().__init__(
            binary, dict(threads=True, backend=True, initial=None, ready=True, codec=4)
        )

    def hook(self, u, a, z, ctx):
        if self.tracing and a == 0xC0E6E0 and self.r(1) == 1 and self.r(3) in (14, 15):
            self.decode_events.append([self.action, self.r(2), self.r(3), self.now])
        if self.tracing and a == 0x7B1088:
            self.submissions.append([self.action, self.r(1), self.r(2)])
        if self.tracing and a == 0x767D9C:
            picture = self.r(1)
            self.pictures.append(
                [self.action, self.h(picture + 28), self.i(picture + 32)]
            )
        if self.plts.get(a) == "AMediaCodec_queueInputBuffer":
            body = bytes(u.mem_read(self.input + self.r(2), self.r(3)))
            assert body in (PAYLOAD, b""), ("SDK bytes", len(body))
            self.now = (self.now + self.queue_ticks) & 0xFFFFFFFF
        super().hook(u, a, z, ctx)

    def h(self, p):
        return struct.unpack("<H", self.u.mem_read(p, 2))[0]

    def picture(self, p):
        return [self.h(p + 28), self.i(p + 32)] if p else None

    def feed(self, fid, seq, flags, stamp, now, offset=0, size=2204):
        self.now = now
        body = (
            b"\1"
            + struct.pack("<HIHI", fid, stamp, 0, 0)
            + struct.pack("<HBHH", seq, flags, 0, 0)
            + PAYLOAD[offset : offset + size]
        )
        packet = self.packet(5, 3, False, 12, 34, len(body))
        self.labels[packet] = f"input_{fid}_{seq}"
        self.u.mem_write(self.q(packet + 40) + 13, body)
        frame = self.alloc(64)
        self.call(self.symbols["_ZN12CStreamFrameC1EP13CStreamPacket"], frame, packet)
        self.call(0x7B2000, self.video, frame)
        self.call(self.symbols["_ZN12CStreamFrameD1Ev"], frame)
        self.refs[f"input_{fid}_{seq}"] = packet
        self.call(0x7B24DC, self.video)

    def observe(self):
        j = self.player + 296
        count = self.i(j + 8)
        assert count < 60
        pending = []
        if self.q(self.player + 272):
            pending.append(self.picture(self.q(self.player + 272)))
        head, tail, mask, storage = (
            self.i(self.player + 244),
            self.i(self.player + 248),
            self.i(self.player + 240),
            self.q(self.player + 256),
        )
        if head != 0xFFFFFFFF:
            assert tail >= head and tail - head < 128
            pending += [
                self.picture(self.q(storage + ((n & mask) * 8)))
                for n in range(head, tail + 1)
            ]
        n = self.i(j + 56)
        assert n == count
        samples = bytes(self.u.mem_read(self.q(j + 40), n * 4)).hex() if n else ""
        complete = [
            e[2:] for e in self.effects if e[0] == "frame_complete" and e[1] == 1
        ]
        return dict(
            jitter=dict(
                count=count,
                sum_bits=self.i(j + 32),
                samples=samples,
                budget=self.i(j + 64),
            ),
            pending=pending,
            pictures=list(self.pictures),
            submissions=list(self.submissions),
            decode_events=list(self.decode_events),
            selected=list(self.selected),
            waits=list(self.waits),
            completed=[e for e in complete if e[1] in (1, 6)],
            source_completions=complete,
            request=self.i(self.video + 96),
            assertions=list(self.assertions),
        )


def run(binary, inp, ops):
    x = Timing(binary)
    states = []
    for n, a in enumerate(ops):
        x.action = n
        if a[0] == "P":
            x.feed(*a[1:])
        elif a[0] == "Q":
            x.queue_ticks = a[1]
        elif a[0] == "N":
            x.now = a[1]
            frame = x.call(0x767FE0, x.player)
            x.selected.append([n, x.picture(frame)])
            if frame:
                x.call(0x768048, x.player, frame, 1, 1)
        elif a[0] == "W":
            x.now = a[1]
            wait = x.call(0x767E64, x.player) & 0xFFFFFFFF
            x.waits.append([n, wait - 0x100000000 if wait & 0x80000000 else wait])
        elif a[0] == "R":
            x.call(0x7A5FF8, c.CLIENT)
        else:
            raise ValueError(a)
        states.append(x.observe())
        assert not x.assertions, (inp, n, x.assertions)
    return dict(input=inp, actions=ops, states=states)


def push(fid, stamp, now, flags=8, seq=None, offset=0, size=2204):
    return [
        "P",
        fid,
        fid if seq is None else seq,
        flags,
        stamp & 0xFFFFFFFF,
        now & 0xFFFFFFFF,
        offset,
        size,
    ]


def train(delays, base=1000000):
    ops = []
    for n, delay in enumerate(delays):
        now = (base + n * 1092) & 0xFFFFFFFF
        ops += [push(n, now - delay, now, 24 if n == 0 else 8), ["N", now]]
    return ops


def scenarios():
    now = 1000000 + 60 * 1092
    yield (
        dict(shape="metadata_finish"),
        [
            push(0, 900000, 1000000, 16, 0, 0, 551),
            push(1, 950000, 1000000, 0, 1, 551, 551),
            push(1, 1002000, 1002000, 8, 2, 1102, 1102),
            ["W", 1002000],
            ["N", 1002000],
        ],
    )
    yield dict(shape="zero_media_timestamp"), [push(0, 0, 0, 24), ["W", 0], ["N", 0]]
    yield (
        dict(shape="initial_future_ready"),
        [push(0, 1001000, 1000000, 24), ["W", 1000000], ["N", 1000000]],
    )
    staged = [["Q", 65, 650]]
    for n in range(60):
        t = 1000000 + n * 1092
        staged += [push(n, t - 655, t, 24 if n == 0 else 8), ["N", t + 715]]
    yield dict(shape="accepted_before_output"), staged
    extensions = {
        "threshold": [
            push(60, now, now),
            ["W", now],
            ["N", now],
            ["W", now + 589],
            ["N", now + 589],
            ["W", now + 590],
            ["N", now + 590],
        ],
        "head_blocks_ready_successor": [
            push(60, now - 327, now),
            push(61, now - 1311, now),
            ["N", now],
            ["W", now],
            ["N", now + 270],
        ],
        "newest_ready_keeps_future": [
            push(60, now - 1000, now),
            push(61, now - 900, now),
            push(62, now, now),
            ["N", now],
            ["W", now],
            ["N", now + 590],
        ],
        "negative_ignored": [
            push(60, now + 655, now),
            ["W", now],
            ["N", now],
            ["N", now + 1245],
        ],
        "outlier_keeps_budget": [
            push(60, now - 9831, now),
            ["N", now],
            push(61, now, now),
            ["W", now],
            ["N", now + 590],
        ],
        "outlier_boundary": [
            push(60, now - 9830, now),
            ["N", now],
            push(61, now - 9831, now),
            ["N", now],
            push(62, now, now),
            ["W", now],
            ["N", now + 590],
        ],
        "reset_preserves": [
            push(60, now, now),
            push(61, now, now, 72),
            ["R"],
            ["W", now],
            push(62, now, now, 88),
            ["W", now],
            ["N", now + 590],
        ],
    }
    for shape, extra in extensions.items():
        yield dict(shape=shape), train([655] * 60) + extra
    high = train([9830] * 43 + [0] * 17)
    for n in range(60, 80):
        t = 1000000 + n * 1092
        high += [push(n, t, t), ["N", t]]
    yield dict(shape="high_budget_continuity"), high
    yield (
        dict(shape="smooth_batches"),
        train([131] * 60 + [393] * 60) + [["W", 1000000 + 120 * 1092]],
    )
    base = 0xFFFF0000
    end = (base + 60 * 1092) & 0xFFFFFFFF
    yield (
        dict(shape="clock_wrap"),
        train([655] * 60, base)
        + [push(60, end, end), ["W", end], ["N", (end + 590) & 0xFFFFFFFF]],
    )
    yield (
        dict(shape="stddev"),
        train([64, 6553] * 30)
        + [["W", 1000000 + 59 * 1092], ["N", 1000000 + 59 * 1092 + 10000]],
    )


class Surface(m.k.r.Reset):
    def __init__(self, binary, inp):
        self.properties = inp
        self.calls = []
        super().__init__(
            binary, dict(threads=True, old_backend=False, init_success=True)
        )

    def hook(self, u, a, z, ctx):
        name = self.plts.get(a, "")
        if name == "_Z22BShouldUseVideoSurfacev":
            self.jump(0x909EA4)
            return
        if name == "SDL_IsTV":
            self.calls.append("tv")
            self.ret(int(self.properties["tv"]))
            return
        if name == "__system_property_get":
            prop = self.cstring(self.r(0))
            self.calls.append(prop)
            value = self.properties[
                "manufacturer" if prop.endswith("manufacturer") else "model"
            ].encode()
            self.u.mem_write(self.r(1), value + b"\0")
            self.ret(len(value))
            return
        if name == "_ZN10CUtlString6FormatEPKcz":
            assert self.cstring(self.r(1)) == "%s %s"
            value = (self.cstring(self.r(2)) + " " + self.cstring(self.r(3))).encode()
            p = self.alloc(len(value) + 1)
            self.u.mem_write(p, value + b"\0")
            self.wq(self.r(0), p)
            self.ret(len(value))
            return
        if name in ("strncmp", "strncasecmp"):
            left = self.cstring(self.r(0))[: self.r(2)]
            right = self.cstring(self.r(1))[: self.r(2)]
            if name == "strncasecmp":
                left = left.lower()
                right = right.lower()
            self.ret(((left > right) - (left < right)) & 0xFFFFFFFF)
            return
        super().hook(u, a, z, ctx)


def surface_cases(binary):
    cases = []
    for tv in (False, True):
        for manufacturer, model in [
            ("Generic", "Phone"),
            ("Amlogic", "X96-W"),
            ("Amlogic", "X96-W Plus"),
            ("Google", "Chromecast"),
            ("Google", "Chromecast HD"),
            ("Oculus", "Quest"),
            ("Oculus", "Quest 2"),
            ("Pico", "4"),
            ("PicoX", "4"),
        ]:
            inp = dict(tv=tv, manufacturer=manufacturer, model=model)
            x = Surface(binary, inp)
            result = x.call(0x909EA4) & 1
            calls = list(x.calls)
            x.properties = dict(tv=not tv, manufacturer="Changed", model="Device")
            cached = x.call(0x909EA4) & 1
            assert result == cached and x.calls == calls
            j = x.player + 296
            for n in range(60):
                x.call(0x76678C, j, 1000000, 1000655, 0)
            cases.append(
                dict(
                    input=inp,
                    result=result,
                    cached=cached,
                    calls=calls,
                    count=x.i(j + 8),
                    budget=x.i(j + 64),
                    assertions=list(x.assertions),
                )
            )
            assert not x.assertions
    return cases


def static(binary):
    elf = ELFFile(io.BytesIO(binary))
    text = elf.get_section_by_name(".text")
    base = text["sh_addr"]
    data = text.data()
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    return [
        dict(
            name=name,
            instructions=[
                [i.address, i.mnemonic, i.op_str, i.bytes.hex()]
                for i in md.disasm(data[at - base : at - base + size], at)
            ],
        )
        for name, at, size in [
            ("video_onthink", 0x7B24DC, 808),
            ("final_decode", 0x7B1088, 356),
            ("android_decode", 0x906570, 240),
            ("android_submit", 0x906660, 1760),
            ("player_ctor", 0x7676A8, 252),
            ("jitter_ctor", 0x7666E8, 92),
            ("jitter_update", 0x76678C, 332),
            ("jitter_ready", 0x7668D8, 156),
            ("jitter_wait", 0x766974, 152),
            ("put_video", 0x767D9C, 200),
            ("video_wait", 0x767E64, 184),
            ("available", 0x767F1C, 196),
            ("next_frame", 0x767FE0, 104),
            ("flush", 0x7681EC, 232),
            ("surface", 0x909EA4, 340),
        ]
    ]


def negative_checks(binary, cases):
    constructor = Timing.__init__
    found = []

    def selected(shape):
        return next(c for c in cases if c["input"]["shape"] == shape)

    checks = [
        (
            "omit_finished_timestamp",
            [(0x7B2748, 0x52800002)],
            selected("metadata_finish"),
        ),
        (
            "force_surface_bypass",
            [(0x7667B0, 0x14000000 | ((0x7668C8 - 0x7667B0) // 4))],
            selected("threshold"),
        ),
        (
            "always_ready",
            [(0x7668DC, 0x14000000 | ((0x766964 - 0x7668DC) // 4))],
            selected("threshold"),
        ),
        ("include_over_150ms", [(0x766824, 0x14000004)], selected("outlier_boundary")),
        ("mean_without_stddev", [(0x766868, 0x1E204002)], selected("stddev")),
        ("skip_budget_smoothing", [(0x766870, 0x14000004)], selected("smooth_batches")),
    ]
    keys = ("jitter", "pending", "selected", "waits", "submissions", "pictures")
    try:
        for name, patches, baseline in checks:

            def modified(self, *args, **kwargs):
                constructor(self, *args, **kwargs)
                for pc, word in patches:
                    self.u.mem_write(pc, struct.pack("<I", word))
                    self.u.ctl_remove_cache(pc, pc + 4)

            Timing.__init__ = modified
            got = run(binary, baseline["input"], baseline["actions"])

            def project(c):
                return [{k: s[k] for k in keys} for s in c["states"]]

            assert project(got) != project(baseline), (
                "undetected original mutation",
                name,
            )
            found.append(name)
    finally:
        Timing.__init__ = constructor
    inp = dict(tv=False, manufacturer="Generic", model="Phone")
    x = Surface(binary, inp)
    pc = 0x909ED0
    x.u.mem_write(pc, struct.pack("<I", 0xD503201F))
    x.u.ctl_remove_cache(pc, pc + 4)
    first = x.call(0x909EA4) & 1
    calls = list(x.calls)
    x.properties = dict(tv=True, manufacturer="Changed", model="Device")
    second = x.call(0x909EA4) & 1
    assert first != second and len(x.calls) > len(calls) and not x.assertions
    found.append("ignore_surface_cache")
    x = Surface(binary, dict(tv=True, manufacturer="Amlogic", model="X96-W"))
    pc = 0x909F88
    x.u.mem_write(pc, struct.pack("<I", 0x52800028))
    x.u.ctl_remove_cache(pc, pc + 4)
    assert x.call(0x909EA4) & 1 and not x.assertions
    found.append("ignore_surface_blacklist")
    return found


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == c.SHA
    cases = [run(binary, inp, ops) for inp, ops in scenarios()]
    return dict(
        binary_sha256=c.SHA,
        boundary=__doc__,
        cases=cases,
        surface=surface_cases(binary),
        empty_jobs=[
            run(
                binary,
                dict(shape="empty_accepted"),
                [push(0, 999345, 1000000, 24, size=0)],
            )
        ],
        static=static(binary),
        mutation_checks=negative_checks(binary, cases),
    )


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--write", type=Path)
    p.add_argument("--check", type=Path)
    a = p.parse_args()
    r = audit(a.binary.read_bytes())
    if a.write:
        a.write.write_bytes(
            gzip.compress((json.dumps(r, indent=2) + "\n").encode(), mtime=0)
        )
    if a.check:
        assert r == json.loads(gzip.decompress(a.check.read_bytes()))
    print(
        "Official video timing:",
        len(r["cases"]),
        "cases/",
        sum(len(c["states"]) for c in r["cases"]),
        "states;",
        len(r["surface"]),
        "device selector cases",
    )
