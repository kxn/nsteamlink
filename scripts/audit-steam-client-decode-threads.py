#!/usr/bin/env python3
"""Execute the pinned official Linux client's decode-thread selection.

The complete CPU-info getter, thread-count getter and StartDecoding execute.
/proc/cpuinfo lines, SDK capability/default fields and successful SDK calls are
explicit inputs. File/string/SDL CPU-feature operations and CPU-brand helpers
are terminals; CPU counting, caching, cap checks and context writes are original
instructions. This is not physical threading, a Switch CPU-count mapping or a
full Qt/client startup. The separate actual-process probe covers real SDK start.
"""

import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "codec", ROOT / "scripts/audit-steam-client-avcodec.py"
)
codec = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(codec)
FUNCTIONS = {
    0x1A7350: "cpu_info",
    0x326BE0: "decode_thread_count",
    0x3246D0: "start_decoding",
}


class Client(codec.Client):
    def __init__(self, binary, case, patch=None):
        self.case, self.patch, self.patch_hits = case, patch, 0
        self.patched = False
        self.cursor, self.opens, self.count_calls = 0, 0, 0
        count = case["processors"]
        self.lines = [f"processor\t: {i}\n".encode() for i in range(count)]
        # Core/package IDs deliberately differ from logical processor count.
        self.lines += [b"core id\t: 0\n", b"physical id\t: 0\n"]
        super().__init__(binary)

    def call(self, pc, *args):
        if not self.patched:
            self.patched = True
            if self.patch:
                address, before, after = self.patch
                assert bytes(self.u.mem_read(address, len(before))) == before
                assert len(before) == len(after)
                self.u.mem_write(address, after)
        return super().call(pc, *args)

    def text(self, address):
        result = bytearray()
        while True:
            c = self.u.mem_read(address + len(result), 1)
            if c == b"\0":
                return bytes(result)
            result.extend(c)
            assert len(result) < 8192

    def hook(self, u, pc, size, data):
        if self.patch and pc == self.patch[0]:
            self.patch_hits += 1
        if pc == 0x326BE0:
            self.count_calls += 1
        if pc in (0x1A6FA0, 0x1A7100):
            self.ret(0)  # CPU brand/vendor strings, not the count producer.
            return
        name = self.names.get(pc)
        if name == "fopen":
            assert self.text(self.arg(0)) == b"/proc/cpuinfo"
            self.opens += 1
            self.cursor = 0
            self.ret(0xCAFE)
        elif name == "fgets":
            assert self.arg(2) == 0xCAFE
            if self.cursor == len(self.lines):
                self.ret(0)
            else:
                line = self.lines[self.cursor]
                assert len(line) < self.arg(1)
                self.cursor += 1
                self.u.mem_write(self.arg(0), line + b"\0")
                self.ret(self.arg(0))
        elif name == "fclose":
            self.ret(0)
        elif name == "strncasecmp":
            n = self.arg(2)
            a, b = (
                self.text(self.arg(0))[:n].lower(),
                self.text(self.arg(1))[:n].lower(),
            )
            self.ret((a > b) - (a < b))
        elif name == "strchr":
            pos = self.text(self.arg(0)).find(bytes([self.arg(1)]))
            self.ret(0 if pos < 0 else self.arg(0) + pos)
        elif name == "__isoc23_strtol":
            assert self.arg(1) == 0 and self.arg(2) == 10
            self.ret(int(self.text(self.arg(0))))
        elif name == "avcodec_alloc_context3":
            super().hook(u, pc, size, data)
            ctx = self.u.reg_read(codec.UC_X86_REG_RAX)
            self.wi(ctx + 0x290, self.case["default_count"])
            self.wi(ctx + 0x294, self.case["default_type"])
        elif name in ("avcodec_find_decoder", "av_codec_iterate"):
            super().hook(u, pc, size, data)
            selected = self.u.reg_read(codec.UC_X86_REG_RAX)
            if selected:
                self.wi(selected + 24, self.case["capabilities"])
        elif name == "avcodec_open2":
            ctx = self.arg(0)
            self.at_open = [self.i(ctx + 0x290), self.i(ctx + 0x294)]
            self.ret(0)
        else:
            super().hook(u, pc, size, data)


def scenarios():
    return [
        dict(
            processors=n,
            capabilities=cap,
            default_count=default,
            default_type=kind,
        )
        for n in (0, 1, 2, 3, 4, 8, 255, 256, 257)
        for cap in (0, 0x1000, 0x2000, 0x3000)
        for default, kind in ((1, 3), (7, 9))
    ]


def run(binary, case, patch=None):
    c = Client(binary, case, patch)
    assert not c.assertions, c.assertions
    calls_at_open = c.count_calls
    count = c.call(0x326BE0, c.dec)
    cached = c.call(0x326BE0, c.dec)
    assert not c.assertions and count == cached
    return dict(
        **case,
        at_open=c.at_open,
        source_cpu_byte=bytes(c.u.mem_read(0x13BD868, 1))[0],
        count_return=count,
        opens_after_cached_reads=c.opens,
        count_calls_at_open=calls_at_open,
        patch_hits=c.patch_hits,
    )


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == codec.SHA
    cases = [run(binary, case) for case in scenarios()]
    for case in cases:
        n = min(case["processors"] & 255, 4)
        assert case["source_cpu_byte"] == case["processors"] & 255
        assert case["count_return"] == n
        assert case["opens_after_cached_reads"] == 1
        capable = bool(case["capabilities"] & 0x2000)
        assert case["count_calls_at_open"] == int(capable)
        assert case["at_open"] == (
            [n, 2]
            if capable and n > 1
            else [case["default_count"], case["default_type"]]
        )
    mutations = []
    for name, address, before, after, index in [
        ("cpu_increment", 0x1A7441, "80052064210101", "80052064210102", 40),
        ("thread_cap", 0x326BE9, "ba04000000", "ba02000000", 40),
        ("capability_gate", 0x32476B, "755b", "eb5b", 40),
        ("thread_count_store", 0x3247DC, "898790020000", "909090909090", 44),
        (
            "slice_type_store",
            0x3247E2,
            "c7879402000002000000",
            "90909090909090909090",
            44,
        ),
    ]:
        reference = cases[index]
        modified = run(
            binary,
            scenarios()[index],
            (address, bytes.fromhex(before), bytes.fromhex(after)),
        )
        assert modified["patch_hits"] and any(
            modified[key] != reference[key]
            for key in (
                "source_cpu_byte",
                "count_return",
                "at_open",
                "count_calls_at_open",
            )
        ), name
        mutations.append(dict(name=name, case=index, hits=modified["patch_hits"]))
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
    fixture = ROOT / "scripts/fixtures/steam-client-decode-threads-reference.json.gz"
    if a.refresh_reference:
        if fixture.exists():
            assert json.loads(gzip.decompress(fixture.read_bytes())) == report
        fixture.write_bytes(gzip.compress(encoded, mtime=0))
    else:
        assert json.loads(gzip.decompress(fixture.read_bytes())) == report
    a.output.write_bytes(encoded)
    print(
        "Official decode threads:",
        len(report["cases"]),
        "cases,",
        len(report["functions"]),
        "FDEs,",
        len(report["mutations"]),
        "mutations",
    )


if __name__ == "__main__":
    main()
