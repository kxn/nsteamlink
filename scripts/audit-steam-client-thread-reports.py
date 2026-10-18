#!/usr/bin/env python3
"""Replay official CPU/thread gates through AVCodec restart and decoder-info80.

Cached CPU-info byte is an explicit OS input; its cold producer was independently
executed in §99. Original CPU getter, count getter, codec-capability check, Start
writes, installed get_format, sender/cache/protobuf/Frame and reset actor execute.
SDK defaults are 1/type3, capabilities 0x3022 as independently observed. SDK open
observes the original selected count, then retains that metadata at its declared
terminal; it never supplies an expected thread count. SDK callback opportunities,
software offers, send outcomes, OS/UI/encryption/Connection remain boundaries.
This is not full Qt/client/real GPU startup; §99 separately ran real SDK Start.
"""

import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "info", ROOT / "scripts/audit-steam-client-decoder-info.py"
)
info = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(info)
codec = info.codec
FUNCTIONS = dict(info.FUNCTIONS)
FUNCTIONS.update(
    {
        0x1A7350: "cpu_info_cached",
        0x326BE0: "decode_thread_count",
        0x2B5C80: "cache_info_string",
    }
)


class ThreadInfo(info.Info):
    def __init__(self, binary, case, patch=None):
        self.processors = case["processors"]
        self.seeded, self.original_patch, self.original_patch_hits = False, patch, 0
        self.thread_setups = []
        super().__init__(binary, dict(case, threads=1))

    def call(self, pc, *args):
        if not self.seeded and hasattr(self, "bootstrap_assertions"):
            self.seeded = True
            # An OS input boundary, not an internal policy result.
            self.wi(0x13BD860, 0x38)
            self.u.mem_write(0x13BD868, bytes([self.processors & 255]))
            if self.original_patch:
                address, before, after = self.original_patch
                assert bytes(self.u.mem_read(address, len(before))) == before
                assert len(before) == len(after)
                self.u.mem_write(address, after)
                self.u.ctl_remove_cache(address, address + len(after))
        return super().call(pc, *args)

    def hook(self, u, pc, size, data):
        if not self.seeded:
            return super().hook(u, pc, size, data)
        if self.original_patch and pc == self.original_patch[0]:
            self.original_patch_hits += 1
        name = self.names.get(pc)
        if name == "avcodec_open2":
            ctx = self.arg(0)
            self.sdk_threads = self.i(ctx + 0x290)
            self.thread_setups.append([self.sdk_threads, self.i(ctx + 0x294)])
        super().hook(u, pc, size, data)
        if name == "avcodec_alloc_context3":
            ctx = self.u.reg_read(codec.UC_X86_REG_RAX)
            self.wi(ctx + 0x290, 1)
            self.wi(ctx + 0x294, 3)
        elif name in ("avcodec_find_decoder", "av_codec_iterate"):
            selected = self.u.reg_read(codec.UC_X86_REG_RAX)
            if selected:
                self.wi(selected + 24, 0x3022)

    def snapshot(self):
        result = super().snapshot()
        result["thread_setups"] = [list(s) for s in self.thread_setups]
        return result


def scenarios():
    templates = [case for case in info.scenarios() if case.get("native_projection")]
    return [
        dict(case, name=f"cpu{count}_{case['name']}", processors=count)
        for count in (0, 1, 2, 3, 4, 8, 255, 256, 257)
        for case in templates
    ]


def run(binary, case, patch=None):
    r = ThreadInfo(binary, case, patch)
    assert not r.assertions, r.assertions
    result = dict(case, initial=r.snapshot())
    result["bootstrap_assertions"] = r.bootstrap_assertions
    result["states"] = [r.perform(*action) for action in case["actions"]]
    assert not r.assertions, r.assertions
    result["threads"] = r.sdk_threads
    result["cache_history"] = r.cache_history
    result["patch_hits"] = r.original_patch_hits
    return result


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == codec.SHA
    cases = [run(binary, c) for c in scenarios()]
    for c in cases:
        assert c["initial"]["info_history"] == []
        assert len(c["initial"]["thread_setups"]) == 1
        assert [len(s["thread_setups"]) for s in c["states"]] == [1, 1, 2, 2, 3, 3]
        assert [len(s["info_history"]) for s in c["states"]] == [1, 1, 1, 2, 3, 4]
        assert len(c["cache_history"]) == 7
    checks = []
    example = next(
        c
        for c in scenarios()
        if c["processors"] == 8 and c["config"] == "3800" and c["send_ok"]
    )
    reference = next(c for c in cases if c["name"] == example["name"])
    for name, address, before, after in [
        ("count_limit", 0x326BE9, "ba04000000", "ba02000000"),
        ("capability_guard", 0x32476B, "755b", "745b"),
        ("slice_mode", 0x3247E2, "c7879402000002000000", "90909090909090909090"),
        ("info_send", 0x324B7F, "e8bc91ffff", "9090909090"),
    ]:
        changed = run(
            binary, example, (address, bytes.fromhex(before), bytes.fromhex(after))
        )
        assert changed["patch_hits"] and (
            changed["states"] != reference["states"]
            or changed["initial"] != reference["initial"]
        ), name
        checks.append(dict(name=name, hits=changed["patch_hits"]))
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
        mutations=checks,
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    report = audit(a.binary.read_bytes())
    encoded = (json.dumps(report, indent=2) + "\n").encode()
    fixture = ROOT / "scripts/fixtures/steam-client-thread-reports-reference.json.gz"
    if a.refresh_reference:
        if fixture.exists():
            assert json.loads(gzip.decompress(fixture.read_bytes())) == report
        fixture.write_bytes(gzip.compress(encoded, mtime=0))
    else:
        assert json.loads(gzip.decompress(fixture.read_bytes())) == report
    a.output.write_bytes(encoded)
    print(
        "Official thread/info chain:",
        len(report["cases"]),
        "cases,",
        sum(len(c["states"]) for c in report["cases"]),
        "states,",
        len(report["functions"]),
        "FDEs,",
        len(report["mutations"]),
        "mutations",
    )


if __name__ == "__main__":
    main()
