#!/usr/bin/env python3
"""Execute the official configured-streaming player render/completion caller.

Full CStreamPlayer::BUpdateVideo, BGetNextVideoFrame, Android Accel/texture or
Surface rendering, upload events, SDL present callsites and player/base/client
completion execute in the SHA-pinned client. SDK output/format/release results,
clock and streaming/window state are inputs. Initial format runs the original
NDK format handler. Logical SDL/JNI/overlay primitives, graph/history sample
sinks, storage and inherited OS/libc terminals replace physical platform IO.
This is not a whole CStreamPlayer constructor/startup/UI/device implementation.
Reports distinguish selected input task, actual SDK buffer, protocol result and
present occurrence; a displayed input result is not proof of new physical pixels.
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
    "output", ROOT / "scripts/audit-steam-video-output.py"
)
o = importlib.util.module_from_spec(spec)
spec.loader.exec_module(o)
c = o.c
UI_TERMINALS = {
    "_ZN13CStreamPlayer11DrawBordersEv",
    "_ZN13CStreamPlayer11DrawStartupEv",
    "_ZN13CStreamPlayer9DrawStatsEv",
    "_ZN13CStreamPlayer19DrawMagnifyingGlassEP11IVideoFrame",
    "_ZN13CStreamPlayer10DrawCursorEv",
    "_ZN13CStreamPlayer21AccumulateGraphSampleEPK15CFastFrameStats",
}
HISTORY = "_ZN18CStreamSampleQueueIN13CStreamPlayer18CDisplayFrameStatsENS1_13FrameSample_tELi10ELb0EE9AddSampleERKS2_j"


class Player(o.Output):
    def __init__(self, binary, inp):
        self.events = []
        self.present_count = 0
        self.results = []
        self.sampled = []
        self.ids = set()
        super().__init__(binary, inp)
        # A configured streaming/window boundary, not a constructor replacement
        # presented as full UI initialization. SDL object handles are logical.
        self.b(c.CLIENT + 613, 1)
        self.b(self.player + 0x18B, int(inp.get("redraw", False)))
        self.wq(self.player + 0x5D8, 8001)
        self.wq(self.player + 0x5B8, 7001)
        self.wq(self.player + 0x5C0, 7001)
        for pos, value in ((0x534, 2), (0x538, 1280), (0x53C, 720)):
            self.wi(self.player + pos, value)
        self.u.mem_write(
            self.player + 0x604, struct.pack("<8i", 0, 0, 1280, 720, 0, 0, 1280, 720)
        )
        overlay, vt = self.alloc(16), self.alloc(512)
        self.wq(overlay, vt)
        self.wq(self.player + 0x5E0, overlay)
        self.callbacks[c.STOP + 0xA00] = lambda: self.ret(0)
        for n in range(64):
            self.wq(vt + n * 8, c.STOP + 0xA00)
        self.rendering = True
        self.call(0x9080C4, self.adc, 0xFFFFFFFFFFFFFFFE, 0, 0xFFFFFFFFFFFFFFFF)
        self.rendering = False
        self.io.clear()

    def hook(self, u, a, z, ctx):
        name = self.plts.get(a, "")
        if a == 0xC0E6E0 and self.r(1) == 1:
            self.events.append([self.action, self.r(2) & 65535, self.r(3), self.r(4)])
        if self.rendering:
            if name in UI_TERMINALS:
                self.ret()
                return
            if name in (
                "SDL_SetRenderDrawColor",
                "SDL_RenderClear",
                "SDL_RenderPresent",
            ):
                self.io.append([self.action, name])
                self.present_count += name == "SDL_RenderPresent"
                self.ret(int(self.inp.get("present_status", True)))
                return
            if name == HISTORY:
                self.sampled.append(
                    [self.action, bytes(u.mem_read(self.r(1), 120)).hex(), self.r(2)]
                )
                self.ret()
                return
        super().hook(u, a, z, ctx)

    def pump(self, plan):
        self.output = []
        for index, fid in plan:
            pts = (
                None
                if fid is None
                else next(row[3] for row in reversed(self.input_pts) if row[1] == fid)
            )
            self.output.append((index, pts))
        self.info_seeded.clear()
        self.rendering = True
        try:
            result = self.call(0x7B782C, self.player)
            self.results.append([self.action, result])
        finally:
            self.rendering = False

    def observe(self):
        # Do not override the inherited decoder observer used while feeding.
        return super().observe()

    def snapshot_player(self):
        state = self.observe_output()
        state.update(
            current=self.picture(self.q(self.player + 280)),
            previous=self.picture(self.q(self.player + 288)),
            events=list(self.events),
            present_count=self.present_count,
            results=list(self.results),
            history_samples=list(self.sampled),
        )
        stats = []
        for fid in sorted(self.ids):
            ptr = self.call(0x7AC5A4, c.CLIENT, 1, fid)
            stats.append(
                [
                    fid,
                    None
                    if not ptr
                    else dict(
                        result=self.i(ptr + 88),
                        events=list(
                            struct.unpack("<19I", self.u.mem_read(ptr + 12, 76))
                        ),
                    ),
                ]
            )
        state["stats"] = stats
        return state


def run(binary, inp, actions, patches=()):
    x = Player(binary, inp)
    for pc, word in patches:
        x.u.mem_write(pc, struct.pack("<I", word))
        x.u.ctl_remove_cache(pc, pc + 4)
    states = []
    for n, action in enumerate(actions):
        x.action = n
        if action[0] == "S":
            x.receive_stats(action[1], action[2])
            x.ids.add(action[1])
        elif action[0] == "P":
            x.feed(*action[1:])
            x.ids.add(action[1])
        elif action[0] == "D":
            x.now = action[1]
            x.pump(action[2])
        else:
            raise ValueError(action)
        states.append(x.snapshot_player())
        assert not x.assertions, (inp, n, x.assertions)
    return dict(input=inp, actions=actions, states=states)


def scenarios():
    push = o.t.push
    for surface in (False, True):
        for stats in (False, True):
            prefix = [["S", 1, 0], ["S", 2, 0]] if stats else []
            prefix += [push(1, 998689, 1000000, 24), push(2, 1001311, 1000000)]
            plans = {
                "exact": [[7, 1]],
                "future_output": [[7, 2], [-1, None]],
                "no_output": [[-1, None]] * 6,
            }
            for shape, plan in plans.items():
                yield (
                    dict(shape=shape, surface=surface, budget=10, stats=stats),
                    prefix + [["D", 1000000, plan]],
                )
    for status in (-1, -7):
        yield (
            dict(shape="release_failure", budget=10, release_status=status),
            [["S", 1, 0], push(1, 998689, 1000000, 24), ["D", 1000000, [[7, 1]]]],
        )
    for present in (False, True):
        yield (
            dict(shape="present_status", budget=10, present_status=present),
            [["S", 1, 0], push(1, 998689, 1000000, 24), ["D", 1000000, [[7, 1]]]],
        )
    yield (
        dict(shape="repeat_previous", budget=10),
        [
            ["S", 1, 0],
            push(1, 998689, 1000000, 24),
            ["D", 1000000, [[7, 1]]],
            ["D", 1000000, [[8, 1]]],
        ],
    )
    yield (
        dict(shape="redraw_previous", budget=10, redraw=True),
        [
            ["S", 1, 0],
            push(1, 998689, 1000000, 24),
            ["D", 1000000, [[7, 1]]],
            ["D", 1000000, [[8, 1]]],
        ],
    )
    yield (
        dict(shape="empty_first", budget=0),
        [
            ["S", 1, 0],
            push(1, 999000, 1000000, 24, size=0),
            ["D", 1000000, [[-1, None]] * 6],
        ],
    )
    yield (
        dict(shape="future_chain", budget=10),
        [
            ["S", 1, 0],
            ["S", 2, 0],
            ["S", 3, 0],
            push(1, 998689, 1000000, 24),
            push(2, 1001000, 1000000),
            ["D", 1000000, [[7, 2], [-1, None]]],
            push(3, 1002000, 1001800),
            ["D", 1001800, [[8, 3], [-1, None]]],
        ],
    )
    yield (
        dict(shape="future_then_reuse", budget=10),
        [
            ["S", 1, 0],
            ["S", 2, 0],
            push(1, 998689, 1000000, 24),
            push(2, 1001311, 1000000),
            ["D", 1000000, [[7, 2], [-1, None]]],
            ["D", 1003000, [[-1, None]] * 6],
        ],
    )
    yield (
        dict(shape="multiple_ready", budget=0),
        [
            ["S", 1, 0],
            ["S", 2, 0],
            push(1, 999000, 1000000, 24),
            push(2, 999500, 1000000),
            ["D", 1000000, [[7, 1], [8, 2]]],
        ],
    )
    yield (
        dict(shape="zero_media", budget=0),
        [["S", 1, 0], push(1, 0, 1000000, 24), ["D", 1000000, [[7, 1]]]],
    )
    yield (
        dict(shape="empty_after_image", budget=0),
        [
            ["S", 1, 0],
            ["S", 2, 0],
            push(1, 999000, 1000000, 24),
            ["D", 1000000, [[7, 1]]],
            push(2, 999500, 1000000, size=0),
            ["D", 1000000, [[-1, None]] * 6],
        ],
    )


def static(binary):
    elf = ELFFile(io.BytesIO(binary))
    section = elf.get_section_by_name(".text")
    data, base = section.data(), section["sh_addr"]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    funcs = [
        ("player_update_video", 0x7B782C, 2276),
        ("player_complete", 0x7C2B28, 228),
        ("base_next", 0x76817C, 112),
        ("base_complete", 0x768048, 308),
    ]
    return [
        dict(
            name=name,
            instructions=[
                [i.address, i.mnemonic, i.op_str, i.bytes.hex()]
                for i in md.disasm(data[pc - base : pc - base + size], pc)
            ],
        )
        for name, pc, size in funcs
    ]


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == c.SHA
    cases = [run(binary, inp, actions) for inp, actions in scenarios()]
    checks = [
        ("omit_upload_begin", "future_output", [(0x7B7BE0, 0xD503201F)]),
        ("omit_upload_end", "future_output", [(0x7B7DB4, 0xD503201F)]),
        ("complete_as_late", "future_output", [(0x7B7FE0, 0x528000C1)]),
        ("omit_present", "future_output", [(0x7B7F78, 0xD503201F)]),
    ]
    found = []
    for name, shape, patches in checks:
        baseline = next(
            x
            for x in cases
            if x["input"]["shape"] == shape
            and x["input"]["stats"]
            and not x["input"]["surface"]
        )
        changed = run(binary, baseline["input"], baseline["actions"], patches)
        keys = ("events", "present_count", "stats", "complete_abi")
        assert [{k: s[k] for k in keys} for s in changed["states"]] != [
            {k: s[k] for k in keys} for s in baseline["states"]
        ], ("undetected", name)
        found.append(name)
    return dict(
        binary_sha256=c.SHA,
        boundary=__doc__,
        cases=cases,
        static=static(binary),
        mutation_checks=found,
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
        "Official video presentation:",
        len(r["cases"]),
        "cases/",
        sum(len(c["states"]) for c in r["cases"]),
        "states;",
        len(r["mutation_checks"]),
        "mutations",
    )
