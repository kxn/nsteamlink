#!/usr/bin/env python3
"""Replay official Linux AVCodec format callback and decoder-info timing.

The pinned official client runs StartDecoding, get_format dispatch/selection,
SendVideoDecoderInfo's complete protobuf/Frame/Send and pending-reset actor.
SDK open/send terminals may invoke the callback actually installed by original
StartDecoding. Their return status, offered formats and SDK thread metadata are
explicit inputs; no real SDK open, hardware success, Qt or physical IO is claimed.
Allocator, libc formatting, OS/platform absence, config persistence/encryption
and final connection send retain the declared terminals of the recovery audit.
Only final Connection handoff bodies are protocol observations; the encryption
terminal's earlier buffer does not yet contain the final control type byte.
"""

import argparse
from collections import Counter
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

from unicorn.x86_const import (
    UC_X86_REG_RAX,
    UC_X86_REG_RDI,
    UC_X86_REG_RSI,
    UC_X86_REG_RIP,
    UC_X86_REG_RSP,
)

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "recovery", ROOT / "scripts/audit-steam-client-avcodec-recovery.py"
)
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)
codec = recovery.codec
FUNCTIONS = dict(recovery.FUNCTIONS)
FUNCTIONS.update({0x319360: "request_decoder_reset", 0x1A9B40: "atomic_flag_set"})


class Info(recovery.Recovery):
    def __init__(self, binary, case, patch=None):
        self.info_visits = Counter()
        self.info_history = []
        self.cache_history = []
        self.phase = "initial_start"
        self.plan = None
        self.pending = None
        self.sdk_threads = case["threads"]
        self.send_ok = case.get("send_ok", True)
        self.patch = None
        self.patch_hits = 0
        super().__init__(binary, bytes.fromhex(case["config"]))
        self.hooks.pop(0x319360, None)
        self.hooks[codec.STOP + 0xFA00] = self.callback_return
        if patch:
            pc, before, after = patch
            assert bytes(self.u.mem_read(pc, len(before))) == before
            assert len(before) == len(after)
            self.u.mem_write(pc, after)
            self.u.ctl_remove_cache(pc, pc + len(before))
            self.patch = patch

    def connection_send(self):
        super().connection_send()
        self.u.reg_write(UC_X86_REG_RAX, int(self.send_ok))

    def callback_return(self):
        assert self.pending is not None
        api, status = self.pending
        self.events.append(
            ["sdk_callback_return", api, self.u.reg_read(UC_X86_REG_RAX) & 0xFFFFFFFF]
        )
        self.events.append(["sdk_return", api, status])
        self.pending = None
        self.ret(status)

    def hook(self, u, pc, size, data):
        if pc in FUNCTIONS:
            self.info_visits[pc] += 1
        if self.patch and pc == self.patch[0]:
            self.patch_hits += 1
        if pc == 0x31DD40:
            row = [
                self.phase,
                self.cstring(self.arg(1)).decode(),
                self.arg(2) & 0xFFFFFFFF,
            ]
            self.info_history.append(row)
            self.events.append(["info_entry", *row])
        name = self.names.get(pc, "")
        if name == "avcodec_open2":
            self.wi(self.arg(0) + 0x290, self.sdk_threads)
        if self.plan is not None and name == self.plan[0]:
            api, formats, status = self.plan
            self.plan = None
            ctx = self.arg(0)
            callback = self.q(ctx + 0xC0)
            assert callback == 0x324D00
            offered = self.alloc((len(formats) + 1) * 4)
            self.u.mem_write(
                offered, struct.pack("<" + "i" * (len(formats) + 1), *formats, -1)
            )
            self.events.append(
                ["sdk_callback_enter", api, callback, formats, self.sdk_threads]
            )
            # Original callback returns to this SDK continuation, then to the
            # original caller. No nested emu_start and no internal policy hook.
            sp = self.u.reg_read(UC_X86_REG_RSP) - 8
            self.wq(sp, codec.STOP + 0xFA00)
            self.u.reg_write(UC_X86_REG_RSP, sp)
            self.u.reg_write(UC_X86_REG_RDI, ctx)
            self.u.reg_write(UC_X86_REG_RSI, offered)
            self.u.reg_write(UC_X86_REG_RIP, callback)
            self.pending = (api, status)
            return
        ctx = self.arg(0) if name == "avcodec_open2" else None
        super().hook(u, pc, size, data)
        if ctx is not None:
            self.wi(ctx + 0x290, self.sdk_threads)

    def snapshot(self):
        state = self.state()
        cached = self.q(self.client + 0x288)
        self.cache_history.append(self.cstring(cached).decode() if cached else None)
        assert self.plan is None and self.pending is None
        state["info_history"] = list(self.info_history)
        state["info_bodies"] = [
            e[2] for e in self.events if e[:1] == ["feedback"] and e[2].startswith("50")
        ]
        return state

    def perform(self, op, value):
        self.phase, self.events = op, []
        if op == "format":
            self.action(op, value)
        elif op == "submit_format":
            self.plan = ("avcodec_send_packet", value, 0)
            self.feed(dict(send=0, receive=-11, id=23))
        elif op == "submit_plain":
            self.feed(dict(send=0, receive=-11, id=24))
        elif op == "restart":
            self.call(0x319360, self.client, 0)
            self.call(0x3230A0, self.client)
        elif op == "restart_open_format":
            self.plan = ("avcodec_open2", value, 0)
            self.call(0x319360, self.client, 0)
            self.call(0x3230A0, self.client)
        else:
            raise AssertionError(op)
        return self.snapshot()


def scenarios():
    result = []
    for config in ("", "3800", "3801"):
        for threads in (0, 1, 2, 4):
            for send_ok in (True, False):
                result.append(
                    dict(
                        name=f"config_{config or 'default'}_threads{threads}_send{int(send_ok)}",
                        config=config,
                        threads=threads,
                        send_ok=send_ok,
                        actions=[
                            ["format", [44, 0]],
                            ["format", [12]],
                            ["format", [44]],
                            ["format", []],
                            ["restart", None],
                            ["submit_format", [0]],
                            ["restart_open_format", [0]],
                        ],
                    )
                )
    for config in ("", "3800", "3801"):
        for send_ok in (True, False):
            result.append(
                dict(
                    name=f"native_config_{config or 'default'}_send{int(send_ok)}",
                    config=config,
                    threads=1,
                    send_ok=send_ok,
                    native_projection=True,
                    actions=[
                        ["submit_format", [0]],
                        ["submit_plain", None],
                        ["restart", None],
                        ["submit_format", [0]],
                        ["restart_open_format", [0]],
                        ["submit_format", [0]],
                    ],
                )
            )
    return result


def run(binary, case, patch=None, cached_info=None):
    r = Info(binary, case, patch)
    result = dict(case, initial=r.snapshot())
    assert result["initial"]["info_history"] == []
    result["states"] = [r.perform(*a) for a in case["actions"]]
    result["patch_hits"] = r.patch_hits
    result["entries"] = {FUNCTIONS[k]: v for k, v in sorted(r.info_visits.items())}
    if cached_info is not None:
        cached_info[case["name"]] = r.cache_history
    return result


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == codec.SHA
    cached_info = {}
    cases = [run(binary, c, cached_info=cached_info) for c in scenarios()]
    for index in range(0, len(cases), 2):
        assert cases[index]["states"] == cases[index + 1]["states"]
    for c in cases:
        assert cached_info[c["name"]][0] is None
        for index, state in enumerate(c["states"]):
            assert cached_info[c["name"]][index + 1] == (
                state["info_history"][-1][1] if state["info_history"] else None
            )
            for body in state["info_bodies"]:
                assert body.endswith("10" + format(c["threads"], "02x"))
    for c in cases[:24]:
        assert [len(s["info_history"]) for s in c["states"]] == [1, 2, 3, 4, 4, 5, 6]
        for index, s in enumerate(c["states"]):
            assert len(s["info_bodies"]) == int(index != 4)
            if index != 4:
                entry = s["info_history"][-1]
                assert entry[2] == c["threads"]
                assert entry[
                    1
                ] == f"libavcodec software decoding with {c['threads']} thread" + (
                    "s" if c["threads"] >= 2 else ""
                )
            events = s["events"]
            if index in (5, 6):
                names = [e[0] for e in events]
                assert (
                    names.index("sdk_callback_enter")
                    < names.index("info_entry")
                    < names.index("sdk_callback_return")
                    < names.index("sdk_return")
                )
    for c in cases[24:]:
        assert [len(s["info_history"]) for s in c["states"]] == [1, 1, 1, 2, 3, 4]
        assert [len(s["info_bodies"]) for s in c["states"]] == [1, 0, 0, 1, 1, 1]
    checks = []
    for label, pc, before, after in (
        ("omit_info_send", 0x324B7F, "e8bc91ffff", "9090909090"),
        ("omit_software_plural", 0x324A90, "480f4dc8", "90909090"),
    ):
        if label == "omit_software_plural":
            c = cases[4]
        else:
            c = cases[2]
        mutated = run(binary, c, (pc, bytes.fromhex(before), bytes.fromhex(after)))
        assert (
            mutated["patch_hits"]
            and mutated["states"]
            != next(x for x in cases if x["name"] == c["name"])["states"]
        )
        checks.append(label)
    previous = codec.FUNCTIONS
    try:
        codec.FUNCTIONS = FUNCTIONS
        inventory = codec.inventory(binary)
        codec.FUNCTIONS = {0x2B5C80: "cache_info_string"}
        cache_function = codec.inventory(binary)
    finally:
        codec.FUNCTIONS = previous
    return dict(
        binary_sha256=codec.SHA,
        scope=__doc__,
        functions=inventory,
        cache_function=cache_function,
        cached_info=cached_info,
        cases=cases,
        mutation_checks=checks,
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    report = audit(a.binary.read_bytes())
    encoded = (json.dumps(report, indent=2) + "\n").encode()
    path = ROOT / "scripts/fixtures/steam-client-decoder-info-reference.json.gz"
    if a.refresh_reference:
        if path.exists():
            old = json.loads(gzip.decompress(path.read_bytes()))
            assert old["cases"] == report["cases"][: len(old["cases"])]
            # Preserve every frozen observation; independent new columns may
            # extend the evidence without rewriting prior traces or hashes.
            assert all(v == report[k] for k, v in old.items() if k != "cases")
        path.write_bytes(gzip.compress(encoded, mtime=0))
    else:
        assert json.loads(gzip.decompress(path.read_bytes())) == report
    a.output.write_bytes(encoded)
    print(
        "Official decoder info:",
        len(report["cases"]),
        "cases,",
        sum(len(c["states"]) for c in report["cases"]),
        "states,",
        len(FUNCTIONS),
        "functions,",
        len(report["mutation_checks"]),
        "mutations",
    )


if __name__ == "__main__":
    main()
