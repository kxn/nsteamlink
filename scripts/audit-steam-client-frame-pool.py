#!/usr/bin/env python3
"""Replay official frame pool, player Flush and codec Stop ordering.

Pinned Linux Steam Link original FinalDecode/frame ctor/Release/dtors, player
queue/pop/current selection/Flush and public decoder Stop/Start execute. SDK
allocation/unref/free/status, allocator/libc, OS locks and platform absence are
terminals inherited from §95; no pixels, natural GPU or complete Qt are claimed.
External consumers use the original queue-pop primitive as an explicit boundary,
not a proven renderer path. NULL owner is an explicit constructor capability
case; its natural producer is not claimed. Existing single-thread scheduling and
bootstrap CPU assert are isolated; measured actions must return without asserts.
"""

import argparse
from collections import Counter
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "recovery", ROOT / "scripts/audit-steam-client-avcodec-recovery.py"
)
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)
codec = recovery.codec
FUNCTIONS = dict(recovery.FUNCTIONS)
FUNCTIONS.update(
    {
        0x323FF0: "frame_release",
        0x323CE0: "frame_destructor",
        0x323D70: "frame_deleting_destructor",
        0x2EF250: "queue_pop",
        0x2EEAA0: "select_current",
        0x2EEA50: "select_newest_ready",
        0x2EE9E0: "pop_ready",
        0x2B53C0: "ring_append",
        0x2B5310: "ring_temporary_release",
    }
)


class Pool(recovery.Recovery):
    def __init__(self, binary, patch=None):
        self.allocations = {}
        self.frame_names = {}
        self.sdk_names = {}
        self.dead_frames = set()
        self.dead_sdk = set()
        self.ops = []
        self.puts = []
        self.measuring = False
        self.visits = Counter()
        self.patch = None
        self.patch_hits = 0
        super().__init__(binary, bytes.fromhex("3800"))
        self.measuring = True
        self.sdk_name(self.q(self.dec + 0x268), "codec")
        self.sdk_name(self.q(self.dec + 0x270), "parser")
        self.slot = self.alloc(8)
        self.externals = []
        if patch:
            address, before, after = patch
            assert bytes(self.u.mem_read(address, len(before))) == before and len(
                before
            ) == len(after)
            self.u.mem_write(address, after)
            self.u.ctl_remove_cache(address, address + len(after))
            self.patch = patch

    def alloc(self, size):
        p = super().alloc(size)
        self.allocations[p] = size
        return p

    def sdk_name(self, p, kind):
        if not p:
            return None
        if p not in self.sdk_names:
            self.sdk_names[p] = (
                f"{kind}{1 + sum(v.startswith(kind) for v in self.sdk_names.values())}"
            )
        return self.sdk_names[p]

    def frame_name(self, p):
        assert p in self.frame_names, hex(p)
        return self.frame_names[p]

    def hook(self, u, pc, size, data):
        name = self.names.get(pc)
        if self.measuring and pc in FUNCTIONS:
            self.visits[pc] += 1
        if self.patch and pc == self.patch[0]:
            self.patch_hits += 1
        if self.measuring:
            if pc == 0x3240E0:
                p = self.arg(0)
                assert p not in self.frame_names
                self.frame_names[p] = f"frame{len(self.frame_names) + 1}"
                self.ops.append(
                    [
                        "construct",
                        self.frame_name(p),
                        "pool"
                        if self.arg(1) == self.dec + 0x278
                        else "null"
                        if self.arg(1) == 0
                        else "other",
                    ]
                )
            elif pc == 0x323FF0:
                p = self.arg(0)
                assert p not in self.dead_frames
                self.ops.append(
                    [
                        "release",
                        self.frame_name(p),
                        "pool" if self.q(p + 32) == self.dec + 0x278 else "null",
                    ]
                )
            elif pc == 0x323CE0:
                self.ops.append(["destroy", self.frame_name(self.arg(0))])
            elif pc == 0x2EDF70:
                p = self.arg(1)
                self.puts.append(p)
                self.ops.append(["put", self.frame_name(p), self.i(p + 40) & 65535])
            elif pc in (0x2EDBF0, 0x324840, 0x2EEAC0, 0x2ED980):
                self.ops.append([FUNCTIONS[pc]])
        if name in ("av_frame_free", "avcodec_free_context"):
            slot = self.arg(0)
            p = self.q(slot)
            if self.measuring:
                self.ops.append(
                    [
                        name,
                        self.sdk_name(
                            p, "sdk_frame" if name == "av_frame_free" else "codec"
                        ),
                    ]
                )
            if p:
                self.dead_sdk.add(p)
            self.wq(slot, 0)
            self.ret()
            return
        if name == "av_parser_close":
            p = self.arg(0)
            if self.measuring:
                self.ops.append([name, self.sdk_name(p, "parser")])
            self.dead_sdk.add(p)
            self.ret()
            return
        if name == "av_frame_unref" and self.measuring:
            self.ops.append(["av_frame_unref", self.sdk_name(self.arg(0), "sdk_frame")])
        if name in ("_ZdlPv", "_ZdlPvm", "_ZdaPv", "_ZdaPvm", "free"):
            p = self.arg(0)
            if p in self.frame_names:
                assert p not in self.dead_frames
                if self.measuring:
                    self.ops.append(["delete", self.frame_name(p)])
                self.dead_frames.add(p)
            self.ret()
            return
        if name in ("malloc", "_Znam"):
            self.ret(self.alloc(self.arg(0)))
            return
        if name == "realloc":
            old, length = self.arg(0), self.arg(1)
            p = self.alloc(length)
            if old:
                assert old in self.allocations
                self.u.mem_write(
                    p, bytes(self.u.mem_read(old, min(length, self.allocations[old])))
                )
            self.ret(p)
            return
        super().hook(u, pc, size, data)
        if name == "av_frame_alloc" and self.measuring:
            self.sdk_name(self.u.reg_read(codec.UC_X86_REG_RAX), "sdk_frame")
        elif name == "avcodec_alloc_context3" and self.measuring:
            self.sdk_name(self.u.reg_read(codec.UC_X86_REG_RAX), "codec")
        elif name == "av_parser_init" and self.measuring:
            self.sdk_name(self.u.reg_read(codec.UC_X86_REG_RAX), "parser")

    def ring(self, base):
        first, last = self.i(base + 4), self.i(base + 8)
        if first & 0x80000000:
            return []
        assert last >= first and last - first < 1024
        mask, buffer = self.i(base), self.q(base + 16)
        return [
            self.frame_name(self.q(buffer + 8 * (i & mask)))
            for i in range(first, last + 1)
        ]

    def snapshot(self):
        return dict(
            codec_alive=bool(self.q(self.dec + 0x268)),
            parser_alive=bool(self.q(self.dec + 0x270)),
            active=bool(self.u.mem_read(self.dec + 24, 1)[0]),
            pool=self.ring(self.dec + 0x2A8),
            queue=self.ring(self.player + 0xE8),
            current=[
                self.frame_names.get(self.q(self.player + off))
                for off in (0x108, 0x110, 0x118)
            ],
            externals=[self.frame_name(p) for p in self.externals],
            frames=[
                dict(name=name, deleted=True)
                if p in self.dead_frames
                else dict(
                    name=name,
                    deleted=False,
                    owner="pool" if self.q(p + 32) == self.dec + 0x278 else "null",
                    sdk_object_live=bool(self.q(p + 48)),
                    sdk_format=self.i(self.q(p + 48) + 116) if self.q(p + 48) else None,
                )
                for p, name in self.frame_names.items()
            ],
            ops=list(self.ops),
        )

    def perform(self, op, value=None):
        self.ops = []
        self.assertions = []
        if op == "feed":
            count, status = value
            for i in range(count):
                self.feed(dict(id=23 + i, receive=status))
        elif op == "take":
            for _ in range(value):
                assert self.call(0x2EF250, self.player + 0x40, self.slot) & 255 == 1
                p = self.q(self.slot)
                assert p in self.frame_names
                self.externals.append(p)
        elif op == "select":
            # Original returns bool in AL; upper RAX bits are unspecified.
            assert self.call(0x2EEAA0, self.player) & 255 == 1
        elif op == "release":
            while self.externals:
                p = self.externals.pop(0)
                self.call(0x323FF0, p)
        elif op == "stop":
            self.call(0x2EDBF0, self.dec)
        elif op == "start":
            self.call(0x2ED980, self.dec, self.dec + 32)
        elif op == "null_ctor":
            p = self.alloc(0x38)
            self.call(0x3240E0, p, 0)
            self.externals.append(p)
        else:
            raise AssertionError(op)
        assert not self.assertions, self.assertions
        return self.snapshot()


def scenarios():
    result = []
    for status in (0, -11, -1094995529):
        for count in (1, 3, 17):
            initial = [["feed", [count, status]]]
            for mode in (
                "queued",
                "current",
                "external_before",
                "external_after",
                "external_restart",
            ):
                actions = list(initial)
                if mode == "current":
                    actions += [["select", None]]
                elif mode.startswith("external"):
                    actions += [["take", count]]
                if mode == "external_before":
                    actions += [["release", None], ["feed", [1, status]]]
                actions += [["stop", None]]
                if mode == "external_after":
                    actions += [["release", None], ["stop", None]]
                elif mode == "external_restart":
                    actions += [
                        ["start", None],
                        ["release", None],
                        ["feed", [1, status]],
                        ["stop", None],
                    ]
                result.append(
                    dict(
                        name=f"{mode}_{count}_{status}",
                        mode=mode,
                        count=count,
                        status=status,
                        actions=actions,
                    )
                )
    result.append(
        dict(
            name="null_owner_capability",
            mode="capability_only",
            actions=[["null_ctor", None], ["release", None], ["stop", None]],
        )
    )
    return result


def run(binary, case, patch=None):
    p = Pool(binary, patch)
    initial = p.snapshot()
    states = [p.perform(*action) for action in case["actions"]]
    return dict(
        case,
        bootstrap_assertions=p.bootstrap_assertions,
        initial=initial,
        states=states,
        patch_hits=p.patch_hits,
        entries={FUNCTIONS[pc]: n for pc, n in sorted(p.visits.items())},
    )


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == codec.SHA
    cases = [run(binary, case) for case in scenarios()]
    for c in cases:
        assert (
            not c["states"][-1]["codec_alive"] and not c["states"][-1]["parser_alive"]
        )
        assert (
            not c["states"][-1]["pool"]
            and not c["states"][-1]["queue"]
            and not c["states"][-1]["externals"]
        )
        assert all(f["deleted"] for f in c["states"][-1]["frames"])
        for action, state in zip(c["actions"], c["states"], strict=True):
            if action[0] == "stop":
                assert not state["codec_alive"] and not state["parser_alive"]
                names = [event[0] for event in state["ops"]]
                if "avcodec_free_context" in names:
                    assert (
                        names.index("player_flush")
                        < names.index("av_parser_close")
                        < names.index("avcodec_free_context")
                    )
                    if "av_frame_free" in names:
                        assert max(
                            i for i, n in enumerate(names) if n == "av_frame_free"
                        ) < names.index("avcodec_free_context")
    mutations = []
    # Same-length mutations of measured original instructions, not replacement
    # implementations. Each trace must return normally and change an observation.
    for label, case_name, address, before, after in (
        (
            "release_without_sdk_unref",
            "external_after_1_0",
            0x324019,
            "ff90a0000000",
            "909090909090",
        ),
        (
            "stop_without_player_flush",
            "queued_3_0",
            0x324854,
            "e877130000",
            "9090909090",
        ),
        (
            "stop_without_parser_close",
            "external_after_1_0",
            0x3248EE,
            "ff5058",
            "909090",
        ),
        ("stop_without_codec_free", "external_after_1_0", 0x324922, "ffe0", "c390"),
    ):
        template = next(c for c in scenarios() if c["name"] == case_name)
        base = next(c for c in cases if c["name"] == case_name)
        changed = run(
            binary, template, (address, bytes.fromhex(before), bytes.fromhex(after))
        )
        assert changed["patch_hits"] > 0 and changed["states"] != base["states"]
        mutations.append(
            dict(
                name=label,
                address=hex(address),
                before=before,
                after=after,
                original=base,
                changed=changed,
            )
        )
    previous = codec.FUNCTIONS
    try:
        codec.FUNCTIONS = FUNCTIONS
        functions = codec.inventory(binary)
    finally:
        codec.FUNCTIONS = previous
    return dict(
        client_sha256=codec.SHA,
        scope=__doc__,
        functions=functions,
        cases=cases,
        mutations=mutations,
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    report = audit(a.binary.read_bytes())
    encoded = (json.dumps(report, indent=2) + "\n").encode()
    fixture = ROOT / "scripts/fixtures/steam-client-frame-pool-reference.json.gz"
    if a.refresh_reference:
        if fixture.exists():
            assert json.loads(gzip.decompress(fixture.read_bytes())) == report
        fixture.write_bytes(gzip.compress(encoded, mtime=0))
    else:
        assert json.loads(gzip.decompress(fixture.read_bytes())) == report
    a.output.write_bytes(encoded)
    print(
        "Official frame pool:",
        len(report["cases"]),
        "cases,",
        sum(len(c["states"]) for c in report["cases"]),
        "states,",
        len(report["functions"]),
        "FDEs",
    )


if __name__ == "__main__":
    main()
