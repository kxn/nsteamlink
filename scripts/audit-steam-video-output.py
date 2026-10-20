#!/usr/bin/env python3
"""Execute pinned official Android frame-job to SDK-output rendering branches.

Original video input/assembly/Android submission/player selection and complete
Accel::RenderFrame/texture/VideoSurface/output status/map methods execute.
Separate cases execute the decoder BRenderFrame dispatcher. Accel return
registers are observations, not a bool contract for its void rendering method. SDK output
indices/timestamps/status/format and release return values are explicit inputs;
JNI/SDL rendering, libc++ uint64 sort, clock, locks and OS/storage inherit declared audit terminals.
No physical codec/pixels/GPU, Android callback scheduling, full player render/UI,
FFmpeg status equivalence, network FEC activation or Switch acceptance is claimed.
No-output SDK responses leave BufferInfo unchanged: stack-content-sensitive
observations are labelled and never promoted into a deterministic port policy.
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
    "timing", ROOT / "scripts/audit-steam-video-timing.py"
)
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
c = t.c
BINARY_FUNCS = [
    ("accel_render", 0x906D40, 244),
    ("android_render", 0x906E34, 236),
    ("texture_render", 0x908E04, 696),
    ("surface_render", 0x908494, 1184),
    ("output_status", 0x9080C4, 976),
    ("timestamp_lookup", 0x908934, 156),
    ("drop_before", 0x9089D0, 888),
    ("complete_timestamp", 0x908D48, 188),
    ("android_submit", 0x906660, 1760),
]


class Output(t.Timing):
    def __init__(self, binary, inp):
        self.inp = inp
        self.output = []
        self.controls = []
        self.io = []
        self.held = []
        self.rendering = False
        self.render_returns = []
        self.input_pts = []
        self.info_seeded = set()
        self.unsupplied_info_reads = []
        self.last_dequeue_index = None
        self.surface = inp.get("surface", False)
        super().__init__(binary)
        self.scenario["surface"] = self.surface
        if "budget" in inp:
            self.wi(self.player + 296 + 64, inp["budget"])
        self.b(c.CLIENT + 625, 4)
        self.b(c.CLIENT + 626, 3)
        self.adc = self.old + 24
        # Logical SDK/SDL/JNI handles and storage, not a physical GL context.
        self.texture = self.alloc(32)
        self.wi(self.texture + 4, 1280)
        self.wi(self.texture + 8, 720)
        self.wq(self.adc + 96, self.texture)
        self.wq(self.adc, 4001)
        self.wq(self.adc + 8, 41)
        self.wq(self.adc + 32, 102)
        self.wq(self.adc + 48, 103)
        self.format = self.alloc(32)
        self.format_text = self.alloc(96)
        self.u.mem_write(
            self.format_text,
            self.inp.get("format_text", "width=1280;height=720").encode() + b"\0",
        )
        self.renderer = self.alloc(8)
        self.wq(self.renderer, 7001)
        self.wq(0xC80750, self.renderer)

    def receive_stats(self, fid, result):
        # Explicit normalized Frame boundary, same fields as the established
        # Stats audit; channel matches this decoder's registered video channel.
        frame, packet = self.alloc(64), self.alloc(64)
        self.wq(frame + 8, packet)
        self.wi(packet + 52, 2217)
        self.b(frame + 24, 3)
        self.u.mem_write(frame + 26, struct.pack("<H", fid))
        for pos, value in [
            (28, self.now - 100),
            (32, self.now - 90),
            (36, self.now - 90),
            (40, self.now - 80),
        ]:
            self.wi(frame + pos, value)
        self.call(0x7ABEB0, c.CLIENT, frame)
        pointer = self.call(0x7AC5A4, c.CLIENT, 1, fid)
        assert pointer and self.h(pointer) == fid and self.i(pointer + 88) == 0
        if result:
            self.call(0x7AC3F8, c.CLIENT, 1, fid, result)
        assert self.i(pointer + 88) == result

    def config_send(self):
        assert self.r(1) == 148, ("unexpected control", self.r(1))
        self.controls.append([self.action, self.r(1), None, self.freeze(self.r(2), 64)])
        self.ret()

    def frame_complete(self):
        self.effects.append(["frame_complete", self.r(1), self.r(2), self.r(3)])
        self.jump(0x7AC3F8)

    def hook(self, u, a, z, ctx):
        n = self.plts.get(a, "")
        if (
            self.rendering
            and a in (0x908E80, 0x908568, 0x908540)
            and self.last_dequeue_index is not None
            and self.last_dequeue_index < 0
        ):
            self.unsupplied_info_reads.append([self.action, a, self.last_dequeue_index])
        if n == "AMediaCodec_queueInputBuffer":
            self.input_pts.append(
                [
                    self.action,
                    self.submissions[-1][1],
                    self.submissions[-1][2],
                    self.r(4),
                ]
            )
        if self.rendering:
            if n == "_ZNSt6__ndk16__sortIRNS_6__lessImmEEPmEEvT0_S5_T_":
                begin, end = self.r(0), self.r(1)
                assert end >= begin and (end - begin) % 8 == 0 and end - begin <= 2048
                values = struct.unpack(
                    "<" + "Q" * ((end - begin) // 8),
                    self.u.mem_read(begin, end - begin),
                )
                if values:
                    self.u.mem_write(
                        begin, struct.pack("<" + "Q" * len(values), *sorted(values))
                    )
                self.ret()
                return
            if n == "AMediaCodec_dequeueOutputBuffer":
                info = self.r(1)
                # Explicit stack precondition before first use; failures do not
                # write BufferInfo. Distinguishes inherited bytes from SDK data.
                if info not in self.info_seeded:
                    self.u.mem_write(
                        info,
                        struct.pack(
                            "<iiqI4x", 0, 0, self.inp.get("stack_stamp", -17), 0
                        ),
                    )
                    self.info_seeded.add(info)
                index, stamp = self.output.pop(0) if self.output else (-1, None)
                if stamp is not None:
                    self.u.mem_write(info, struct.pack("<iiqI4x", 0, 8, stamp, 0))
                self.last_dequeue_index = index
                self.io.append([self.action, "dequeue", self.r(2), index, stamp])
                self.ret(index & 0xFFFFFFFFFFFFFFFF)
                return
            if n in (
                "AMediaCodec_releaseOutputBuffer",
                "AMediaCodec_releaseOutputBufferAtTime",
            ):
                status = self.inp.get("release_status", 0)
                self.io.append([self.action, n, self.r(1), self.r(2), status])
                self.ret(status & 0xFFFFFFFF)
                return
            if n == "AMediaCodec_flush":
                status = self.inp.get("flush_status", 0)
                self.io.append([self.action, "flush", status])
                self.ret(status & 0xFFFFFFFF)
                return
            if n == "AMediaCodec_getOutputFormat":
                self.io.append([self.action, "get_format"])
                self.ret(self.format)
                return
            if n == "strstr":
                offset = self.cstring(self.r(0)).find(self.cstring(self.r(1)))
                self.ret(self.r(0) + offset if offset >= 0 else 0)
                return
            if n == "AMediaFormat_toString":
                self.ret(self.format_text)
                return
            if n == "AMediaFormat_getInt32":
                key = self.cstring(self.r(1))
                values = self.inp.get(
                    "format",
                    {"width": 1280, "height": 720, "stride": 1280, "slice-height": 720},
                )
                if key in values:
                    self.wi(self.r(2), values[key])
                self.io.append([self.action, "format_int", key, values.get(key)])
                self.ret(int(key in values))
                return
            if n == "AMediaFormat_delete":
                self.io.append([self.action, "delete_format"])
                self.ret()
                return
            if "CallVoidMethod" in n:
                assert self.r(1) == 41 and self.r(2) in (102, 103)
                self.io.append([self.action, "jni", self.r(2)])
                self.ret()
                return
            if n == "SDL_RenderTexture":
                assert self.r(0) == 7001 and self.r(1) == self.texture
                rects = [
                    list(struct.unpack("<4f", self.u.mem_read(self.r(k), 16)))
                    for k in (2, 3)
                ]
                self.io.append([self.action, "draw", *rects])
                self.ret(1)
                return
        super().hook(u, a, z, ctx)

    def render(self, frame, plan):
        self.output = plan.copy()
        self.info_seeded.clear()
        self.u.reg_write(c.SP, 0x300FF000)
        self.u.reg_write(c.LR, c.STOP)
        # Eight geometry integers: 6 in registers, 2 in stack argument slots.
        self.u.mem_write(0x300FF000, struct.pack("<QQ", 1280, 720))
        entry = 0x906E34 if self.inp.get("entry") == "decoder" else 0x906D40
        receiver = self.adc if self.inp.get("entry") == "decoder" else self.old
        for n, value in enumerate([receiver, frame, 0, 0, 1280, 720, 0, 0]):
            self.u.reg_write(c.X0 + n, value)
        self.rendering = True
        try:
            self.u.emu_start(entry, c.STOP + 4, count=2000000)
            assert self.u.reg_read(c.BASE["UC_ARM64_REG_PC"]) == c.STOP
            self.render_returns.append([self.action, self.r(0)])
        finally:
            self.rendering = False

    def observe_output(self):
        for entry in self.controls:
            if entry[2] is None:
                entry[2] = self.serialize(entry[3], "CStreamVideoOverflowMsg").hex()
        count, capacity, storage = (
            self.i(self.adc + 324),
            self.i(self.adc + 328),
            self.q(self.adc + 304),
        )
        assert capacity < 256 and count <= capacity
        mapping = []
        for n in range(capacity):
            node = storage + n * 16
            link = struct.unpack("<i", self.u.mem_read(node + 12, 4))[0]
            if link >= -1:
                mapping.append([self.q(node), self.h(node + 8)])
        assert len(mapping) == count
        return dict(
            mapping=sorted(mapping),
            unsupplied_info_reads=list(self.unsupplied_info_reads),
            pending_jobs=t.Timing.observe(self)["pending"],
            controls=[entry[:3] for entry in self.controls],
            remaining_output=[list(x) for x in self.output],
            recovery_latch=self.u.mem_read(self.adc + 201, 1)[0],
            texture_size=[self.i(self.texture + 4), self.i(self.texture + 8)],
            input_pts=list(self.input_pts),
            jobs=list(self.pictures),
            held=[self.picture(f) + [self.q(f + 40)] for f in self.held],
            io=list(self.io),
            returns=list(self.render_returns),
            last_request_pts=self.q(self.adc + 192),
            last_input_pts=self.q(self.adc + 184),
            request=self.i(self.video + 96),
            complete=[e[1:] for e in self.effects if e[0] == "frame_complete"],
            complete_abi=[
                [e[1], e[2] & 65535, e[3]]
                for e in self.effects
                if e[0] == "frame_complete"
            ],
            assertions=list(self.assertions),
        )


def run(binary, inp, actions, patches=()):
    x = Output(binary, inp)
    for pc, word in patches:
        x.u.mem_write(pc, struct.pack("<I", word))
        x.u.ctl_remove_cache(pc, pc + 4)
    states = []
    for n, action in enumerate(actions):
        x.action = n
        if action[0] == "S":
            x.receive_stats(action[1], action[2])
        elif action[0] == "P":
            x.feed(*action[1:])
        elif action[0] == "G":
            frame = x.call(0x767FE0, x.player)
            assert frame, (inp, n, x.observe_output())
            x.held.append(frame)
        elif action[0] == "R":
            frame = x.held[action[1]]
            pts = x.q(frame + 40)
            plan = [
                (
                    index,
                    None
                    if delta is None
                    else (
                        x.q(x.held[delta["job"]] + 40)
                        if "job" in delta
                        else next(
                            row[3]
                            for row in reversed(x.input_pts)
                            if row[1] == delta["fid"]
                        )
                    )
                    if isinstance(delta, dict)
                    else pts + delta,
                )
                for index, delta in action[2]
            ]
            x.render(frame, plan)
        else:
            raise ValueError(action)
        states.append(x.observe_output())
        assert not x.assertions, (inp, n, x.assertions)
    return dict(input=inp, actions=actions, states=states)


def scenarios():
    prefix = [t.push(1, 1000000, 1000000, 24), ["G"]]
    plans = {
        "exact": [[7, 0]],
        "earlier_exact": [[7, -1000], [8, 0]],
        "future_exact": [[7, 1000], [8, 0]],
        "only_earlier": [[7, -1000], [-1, None]],
        "only_future": [[7, 1000], [-1, None]],
        "mixed_without_exact": [[7, 1000], [8, -1000], [-1, None]],
        "buffers_changed_then_exact": [[-3, None], [7, 0]],
        "format_then_exact": [[-2, None], [7, 0]],
        "unknown_status": [[-9, None]],
    }
    for surface in (False, True):
        yield (
            dict(shape="decoder_dispatcher", surface=surface, entry="decoder"),
            prefix + [["R", 0, [[7, 0]]]],
        )
    for name, plan in plans.items():
        yield dict(shape=name), prefix + [["R", 0, plan]]
    for count in range(1, 6):
        yield (
            dict(shape="again_then_exact", attempts=count),
            prefix + [["R", 0, [[-1, None]] * count + [[7, 0]]]],
        )
    for status in (-1, -7):
        yield (
            dict(shape="release_failure", release_status=status),
            prefix + [["R", 0, [[7, 0]]]],
        )
        yield (
            dict(shape="flush_failure", flush_status=status),
            prefix + [["R", 0, [[-1, None], [7, 0]]]],
        )
    yield dict(shape="repeat_job"), prefix + [["R", 0, [[7, 0]]], ["R", 0, [[8, 0]]]]
    yield (
        dict(shape="repeat_after_failure", release_status=-1),
        prefix + [["R", 0, [[7, 0]]], ["R", 0, [[8, 0]]]],
    )
    for seed in (-17, 15258789):
        yield (
            dict(shape="no_output_stack_sensitive", stack_stamp=seed),
            prefix + [["R", 0, [[-1, None]] * 6]],
        )
    for surface in (False, True):
        yield (
            dict(shape="sequential_pts", surface=surface),
            [
                t.push(1, 1000000, 1000000, 24),
                ["G"],
                t.push(2, 1001000, 1001000),
                ["G"],
                ["R", 0, [[7, 0]]],
                ["R", 1, [[8, 0]]],
            ],
        )

    yield dict(shape="zero_timestamp"), [t.push(1, 0, 0, 24), ["G"], ["R", 0, [[7, 0]]]]
    for stamps in ([1000000, 1000000], [1001000, 1000000], [0xFFFFFFF0, 0x10]):
        yield (
            dict(shape="duplicate_regressive_wrap", stamps=stamps),
            [
                t.push(1, stamps[0], stamps[0], 24),
                ["G"],
                t.push(2, stamps[1], stamps[1]),
                ["G"],
                ["R", 0, [[7, 0]]],
                ["R", 1, [[8, 0]]],
            ],
        )
    surface_prefix = [
        t.push(1, 1000000, 1000000, 24),
        ["G"],
        t.push(2, 1001000, 1001000),
        ["G"],
    ]
    for name, plan in {
        "exact": [[7, 0]],
        "previous_then_exact": [[7, {"job": 0}], [8, 0]],
        "unknown_previous_then_exact": [[7, -1000], [8, 0]],
        "unknown_future": [[7, 1000], [-1, None]],
        "no_output": [[-1, None]],
        "unknown_error": [[-9, None]],
        "format_then_exact": [[-2, None], [7, 0]],
    }.items():
        yield (
            dict(shape="surface_" + name, surface=True),
            surface_prefix + [["R", 1, plan]],
        )
    for fid, step in [
        (3, 1092),
        (5, 1092),
        (6, 1092),
        (5, 2300),
        (6, 2300),
        (5, 2293),
        (5, 2294),
    ]:
        # Previous known output, with selected job ahead by ID/time. Original
        # lookup/default real Stats ring and recovery-latch branches execute.
        yield (
            dict(shape="surface_gap", surface=True, fid=fid, step=step),
            [
                t.push(1, 1000000, 1000000, 24),
                ["G"],
                t.push(fid, 1000000 + step, 1000000 + step, seq=2),
                ["G"],
                ["R", 1, [[7, {"job": 0}], [8, 0]]],
            ],
        )
    yield (
        dict(shape="future_output_for_ready_job", budget=10),
        [
            t.push(1, 998689, 1000000, 24),
            t.push(2, 1001311, 1000000),
            ["G"],
            ["R", 0, [[7, {"fid": 2}], [-1, None]]],
        ],
    )
    for result in range(0, 9):
        yield (
            dict(shape="surface_known_stats", surface=True, result=result),
            [
                t.push(1, 1000000, 1000000, 24),
                ["G"],
                t.push(6, 1001092, 1001092, seq=2),
                ["G"],
                ["S", 1, result],
                ["R", 1, [[7, {"job": 0}], [8, 0]]],
            ],
        )
    yield (
        dict(shape="surface_recovery_latch", surface=True),
        [
            t.push(1, 1000000, 1000000, 24),
            ["G"],
            t.push(6, 1001092, 1001092, seq=2),
            ["G"],
            ["R", 1, [[7, {"job": 0}], [8, 0]]],
            t.push(7, 1002184, 1002184, seq=3),
            ["G"],
            t.push(8, 1003276, 1003276, seq=4),
            ["G"],
            ["R", 3, [[9, {"job": 2}], [10, 0]]],
        ],
    )
    chain = [
        t.push(1, 1000000, 1000000, 24),
        ["G"],
        t.push(6, 1001092, 1001092, seq=2),
        ["G"],
        ["R", 1, [[7, {"job": 0}], [8, 0]]],
        t.push(7, 1002184, 1002184, seq=3),
        ["G"],
        t.push(12, 1003276, 1003276, seq=4),
        ["G"],
        ["R", 3, [[9, {"job": 2}], [10, 0]]],
        t.push(13, 1004368, 1004368, seq=5),
        ["G"],
        t.push(14, 1005460, 1005460, seq=6),
        ["G"],
        ["R", 5, [[11, {"job": 4}], [12, 0]]],
    ]
    yield dict(shape="surface_coalesce_then_recover", surface=True), chain
    yield (
        dict(shape="surface_recover_then_repeat_gap", surface=True),
        chain
        + [
            t.push(15, 1006552, 1006552, seq=7),
            ["G"],
            t.push(20, 1007644, 1007644, seq=8),
            ["G"],
            ["R", 7, [[13, {"job": 6}], [14, 0]]],
        ],
    )
    for values in [
        {"width": 1280, "height": 736},
        {
            "width": 1280,
            "height": 720,
            "display-width": 1278,
            "display-height": 718,
            "crop-left": 2,
            "crop-right": 1277,
            "crop-top": 2,
            "crop-bottom": 719,
        },
        {
            "width": 1280,
            "height": 720,
            "crop-left": 0,
            "crop-right": 1279,
            "crop-top": 0,
            "crop-bottom": 718,
        },
    ]:
        yield (
            dict(shape="format_dimensions", format=values),
            prefix + [["R", 0, [[-2, None], [7, 0]]]],
        )


def static(binary):
    elf = ELFFile(io.BytesIO(binary))
    text = elf.get_section_by_name(".text")
    base, data = text["sh_addr"], text.data()
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    return [
        dict(
            name=name,
            instructions=[
                [i.address, i.mnemonic, i.op_str, i.bytes.hex()]
                for i in md.disasm(data[at - base : at - base + size], at)
            ],
        )
        for name, at, size in BINARY_FUNCS
    ]


def negative_checks(binary, cases):
    checks = [
        ("force_first_match", "earlier_exact", [(0x908E8C, 0x14000010)]),
        ("omit_request_guard", "repeat_job", [(0x908E40, 0xD503201F)]),
        (
            "zero_initial_timeout",
            "exact",
            [(0x908E4C, 0x52800002), (0x908E58, 0xD503201F)],
        ),
        ("render_discarded_output", "earlier_exact", [(0x908EB8, 0x52800022)]),
        ("omit_again_flush", "again_then_exact", [(0x90830C, 0xD503201F)]),
        ("ignore_release_failure", "release_failure", [(0x90816C, 0x52800020)]),
    ]
    elf = ELFFile(io.BytesIO(binary))
    text = elf.get_section_by_name(".text")

    def cmp_immediate(pc, immediate):
        word = struct.unpack_from("<I", text.data(), pc - text["sh_addr"])[0]
        return (word & ~(0xFFF << 10)) | (immediate << 10)

    checks += [
        (
            "narrow_surface_id_gap",
            "surface_gap",
            [(0x9085E4, cmp_immediate(0x9085E4, 1))],
        ),
        ("zero_surface_time_gap", "surface_gap", [(0x9085F0, 0x52800008)]),
        (
            "classify_pending_stats_as_dropped",
            "surface_known_stats",
            [(0x908654, cmp_immediate(0x908654, 0))],
        ),
    ]
    checks += [
        ("force_accel_codec_exit", "exact", [(0x906D6C, 0x1400001A)]),
        (
            "omit_surface_recovery_latch",
            "surface_coalesce_then_recover",
            [(0x908750, 0xD503201F)],
        ),
        (
            "never_clear_surface_recovery",
            "surface_recover_then_repeat_gap",
            [(0x908614, 0xD503201F)],
        ),
    ]
    found = []
    for name, shape, patches in checks:
        original = next(x for x in cases if x["input"]["shape"] == shape)
        got = run(binary, original["input"], original["actions"], patches)
        keys = (
            "io",
            "returns",
            "mapping",
            "controls",
            "request",
            "complete_abi",
            "last_request_pts",
            "remaining_output",
        )
        assert [{k: s[k] for k in keys} for s in got["states"]] != [
            {k: s[k] for k in keys} for s in original["states"]
        ], ("undetected original mutation", name)
        found.append(name)
    return found


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == c.SHA
    cases = [run(binary, inp, actions) for inp, actions in scenarios()]
    return dict(
        binary_sha256=c.SHA,
        boundary=__doc__,
        cases=cases,
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
        "Official video output:",
        len(r["cases"]),
        "cases/",
        sum(len(x["states"]) for x in r["cases"]),
        "states;",
        len(r["mutation_checks"]),
        "mutations detected",
    )
