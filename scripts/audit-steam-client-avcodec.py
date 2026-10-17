#!/usr/bin/env python3
"""Execute the official Linux client AVCodec initialization and complete submission.

Pinned Valve Steam Link 1.3.32.316 ELF, not a host or Android codec translation.
Original DLL function-table setup, decoder/base construction, software-capability
codec selection/StartDecoding, vtable FinalDecode, frame construction/metadata,
RecordFrameComplete and DataLost protobuf/Frame::Put/Send run. Stats are explicitly
seeded pending slots, not a full RecordFrameReceived/network/stats lifecycle.

AVCodec/parser/frame/packet APIs, input-buffer abstraction, OS locks/CPU/file/time,
logs and final player Put/Connection send are declared terminals. Codec status,
format, dimensions and output PTS are inputs; this does not physically decode,
render or prove NVTEGRA failure/status equivalence. COPY/TLS process initialization
is controlled; unused imported objects remain zero. No full Qt/client startup,
authentication, live Steam/UDP or device equivalence is claimed. Original
post-error placeholder frames are recorded as metadata, never invented pixels.
"""

import argparse
import gzip
from collections import Counter
from elftools.dwarf.callframe import FDE
import struct
import io
import json
import hashlib
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_FS_BASE,
    UC_X86_REG_RAX,
    UC_X86_REG_RSP,
    UC_X86_REG_RIP,
    UC_X86_REG_RDI,
    UC_X86_REG_RSI,
    UC_X86_REG_RDX,
    UC_X86_REG_RCX,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
)

ROOT = Path(__file__).resolve().parents[1]
SHA = "95482ca6120f90bb90798b27206b7946ab732e079f008d7fc90ea58a8b0074e1"
ARCHIVE_SHA = "cb12c08e14ce4dfd4c4544bc783e94c51c0a474e30cccbd98a6937e14aa5d8e8"
STOP = 0x40000000


class _ElfReplay:
    def __init__(self, binary):
        b = binary
        assert hashlib.sha256(b).hexdigest() == SHA
        e = ELFFile(io.BytesIO(b))
        self.u = Uc(UC_ARCH_X86, UC_MODE_64)
        self.u.mem_map(0, 0x1500000)
        self.u.mem_map(0x20000000, 0x2000000)
        self.u.mem_map(0x24000000, 0x1000)
        self.u.mem_map(0x30000000, 0x100000)
        self.u.mem_map(STOP, 0x10000)
        self.u.reg_write(UC_X86_REG_FS_BASE, 0x24000000)
        self.next = 0x20100000
        self.hooks = {}
        self.names = {}
        self.events = []
        self.send_status = 0
        self.receive_status = 0
        self.parse_delta = 0
        for s in e.iter_segments():
            if s["p_type"] == "PT_LOAD":
                self.u.mem_write(s["p_vaddr"], s.data())
        dyn = e.get_section_by_name(".dynsym")
        names = {}
        for section in (".rela.dyn", ".rela.plt"):
            for r in e.get_section_by_name(section).iter_relocations():
                typ = r["r_info_type"]
                s = dyn.get_symbol(r["r_info_sym"])
                n = s.name
                if typ == 8:
                    v = r["r_addend"]
                elif typ == 18:
                    v = 0
                elif typ == 5:
                    continue
                elif typ in (1, 6, 7):
                    if s["st_value"]:
                        v = s["st_value"] + r["r_addend"]
                    else:
                        if n not in names:
                            names[n] = STOP + 0x100 + len(names) * 16
                        v = names[n] + r["r_addend"]
                        self.names[names[n]] = n
                else:
                    raise AssertionError((typ, n))
                self.wq(r["r_offset"], v)
        self.u.hook_add(UC_HOOK_CODE, self.hook)
        self.dec = self.alloc(4096)
        self.client = self.alloc(0x22000)
        self.player, self.ctx, self.buffer, self.raw, self.vt = [
            self.alloc(4096) for _ in range(5)
        ]
        self.wq(self.buffer, self.vt)
        self.wq(self.vt + 16, STOP + 0xF000)
        self.wq(self.vt + 24, STOP + 0xF010)
        self.hooks[STOP + 0xF000] = self.getbuffer
        self.hooks[STOP + 0xF010] = lambda: self.ret()
        pvt = self.alloc(256)
        self.wq(self.player, pvt)
        self.wq(pvt + 72, STOP + 0xF020)
        self.hooks[STOP + 0xF020] = self.put
        self.hooks.update(
            {
                0x1A5930: lambda: self.ret(),
                0x318B50: self.complete,
                0x31F7F0: self.lost,
                0x319360: self.reset,
                0x326EE0: self.size,
                0x44B100: lambda: self.ret(1),
                0x44B110: lambda: self.ret(self.alloc(32)),
            }
        )
        self.call(0x173B10, 0x13BD3A0)

    def arg(self, n):
        return (
            self.u.reg_read(
                (
                    UC_X86_REG_RDI,
                    UC_X86_REG_RSI,
                    UC_X86_REG_RDX,
                    UC_X86_REG_RCX,
                    UC_X86_REG_R8,
                    UC_X86_REG_R9,
                )[n]
            )
            if n < 6
            else self.q(self.u.reg_read(UC_X86_REG_RSP) + 8 + (n - 6) * 8)
        )

    def q(self, a):
        return struct.unpack("<Q", self.u.mem_read(a, 8))[0]

    def i(self, a):
        return struct.unpack("<I", self.u.mem_read(a, 4))[0]

    def wq(self, a, v):
        self.u.mem_write(a, struct.pack("<Q", v & ((1 << 64) - 1)))

    def wi(self, a, v):
        self.u.mem_write(a, struct.pack("<I", v & 0xFFFFFFFF))

    def alloc(self, n):
        a = self.next
        self.next += (max(1, n) + 15) & ~15
        assert self.next < 0x21F00000
        return a

    def ret(self, v=0):
        sp = self.u.reg_read(UC_X86_REG_RSP)
        self.u.reg_write(UC_X86_REG_RAX, v & ((1 << 64) - 1))
        self.u.reg_write(UC_X86_REG_RIP, self.q(sp))
        self.u.reg_write(UC_X86_REG_RSP, sp + 8)

    def size(self):
        self.events.append(["size", self.arg(1), self.arg(2)])
        self.wi(self.dec + 0x184, self.arg(1))
        self.wi(self.dec + 0x188, self.arg(2))
        self.ret()

    def hook(self, u, a, z, d):
        if a == STOP:
            self.u.emu_stop()
            return
        if a in self.hooks:
            self.hooks[a]()
            return
        if a not in self.names:
            return
        n = self.names[a]
        if n.startswith(("pthread_mutex", "pthread_cond")) or n in (
            "_ZdlPv",
            "_ZdlPvm",
            "free",
        ):
            self.ret()
        elif n.startswith("SDL_Has"):
            self.ret(0)
        elif n == "SDL_GetNumLogicalCPUCores":
            self.ret(1)
        elif n == "fopen":
            self.ret(0)
        elif n == "_Znwm":
            self.ret(self.alloc(self.arg(0)))
        elif n == "av_log_set_callback":
            self.ret()
        elif n == "av_packet_alloc":
            self.packet_alloc()
        elif n == "av_new_packet":
            self.wq(self.arg(0) + 24, self.alloc(self.arg(1)))
            self.wi(self.arg(0) + 32, self.arg(1))
            self.ret()
        elif n == "av_frame_alloc":
            p = self.alloc(512)
            self.wi(p + 116, -1)
            self.ret(p)
        elif n == "av_frame_unref":
            self.u.mem_write(self.arg(0), bytes(512))
            self.wi(self.arg(0) + 116, -1)
            self.events.append(["unref"])
            self.ret()
        elif n == "av_packet_free":
            self.wq(self.arg(0), 0)
            self.ret()
        elif n == "memcpy":
            self.u.mem_write(
                self.arg(0), bytes(self.u.mem_read(self.arg(1), self.arg(2)))
            )
            self.ret(self.arg(0))
        elif n == "__stack_chk_fail":
            raise AssertionError("stack")
        else:
            raise AssertionError(
                (hex(a), n, hex(self.q(self.u.reg_read(UC_X86_REG_RSP))))
            )

    def call(self, pc, *args):
        sp = 0x300FF000 - 8
        self.u.reg_write(UC_X86_REG_RSP, sp)
        self.wq(sp, STOP)
        for i, a in enumerate(args):
            self.u.reg_write(
                (
                    UC_X86_REG_RDI,
                    UC_X86_REG_RSI,
                    UC_X86_REG_RDX,
                    UC_X86_REG_RCX,
                    UC_X86_REG_R8,
                    UC_X86_REG_R9,
                )[i],
                a,
            )
        self.u.emu_start(pc, STOP, count=200000)
        assert self.u.reg_read(UC_X86_REG_RIP) == STOP, hex(
            self.u.reg_read(UC_X86_REG_RIP)
        )
        return self.u.reg_read(UC_X86_REG_RAX)


class Client(_ElfReplay):
    def __init__(self, binary):
        self.entered = Counter()
        self.step = 0
        self.sdk_format = 0
        self.sdk_size = (128, 72)
        self.sdk_pts = 123456
        self.input_size = 2204
        self.parsed_size = None
        self.calls = []
        self.assertions = []
        super().__init__(binary)
        self.hooks.update(
            {
                0x1A9C80: lambda: self.ret(),
                0x1A4530: lambda: self.ret(1000000),
                0x845860: lambda: self.ret(self.alloc(16)),
                0x1A5610: self.assertion,
                0x1A5550: lambda: self.ret(0),
                0x19EC60: self.connection_send,
                0x19EBE0: self.connection_send,
            }
        )
        self.call(0x324610, self.dec, self.client, self.player, 4)
        assert self.q(self.dec) == 0x10FFAA8 and self.q(0x10FFAA8 + 14 * 8) == 0x324190
        self.wq(self.client + 0x28, self.dec)
        self.wq(self.client + 0x118, self.alloc(4096))
        self.wi(self.client + 256, 6)
        self.u.mem_write(self.client + 0x272, b"\x03")
        self.wi(self.dec + 0x184, 128)
        self.wi(self.dec + 0x188, 72)
        self.call(0x3246D0, self.dec, self.alloc(64))
        assert self.q(self.dec + 0x268) and self.q(self.dec + 0x270)
        self.ctx = self.q(self.dec + 0x268)
        self.raw = self.alloc(65536)
        self.payload = (ROOT / "app/tests/fixtures/video/sequential.h264").read_bytes()[
            :2204
        ]
        assert len(self.payload) == 2204
        self.u.mem_write(self.raw, self.payload)
        self.events = []

    def packet_alloc(self):
        p = self.alloc(256)
        self.wq(p + 8, 1 << 63)
        self.wq(p + 16, 1 << 63)
        self.ret(p)

    def assertion(self):
        self.assertions.append([self.arg(1), self.arg(2)])
        self.ret(1)

    def getbuffer(self):
        self.wi(self.arg(2), self.input_size)
        self.ret(self.raw)

    def complete(self):
        # Observe, then execute the original completion. The first non-pending
        # result is retained by that original function; observer does not decide it.
        self.events.append(["complete", self.arg(1), self.arg(2), self.arg(3)])

    def reset(self):
        self.events.append(["reset", self.arg(1)])

    def lost(self):
        self.events.append(["lost", self.arg(1), self.i(self.arg(2) + 16)])

    def connection_send(self):
        p = self.arg(1)
        self.events.append(
            [
                "feedback",
                self.arg(2),
                bytes(self.u.mem_read(self.q(p + 56) + 13, self.i(p + 52) - 13)).hex(),
            ]
        )
        self.ret(0)

    def put(self):
        f = self.arg(1)
        af = self.q(f + 48)
        self.events.append(
            [
                "put",
                self.i(f + 40) & 65535,
                self.i(f + 44),
                self.i(f + 16),
                self.i(f + 20),
                self.i(f + 24),
                self.i(af + 104),
                self.i(af + 108),
                self.i(af + 116),
                self.q(af + 136),
            ]
        )
        self.ret()

    def hook(self, u, a, z, d):
        if a in FUNCTIONS:
            self.entered[a] += 1
        n = self.names.get(a, "")
        if n == "av_codec_iterate":
            if self.q(self.arg(0)):
                self.ret(0)
            else:
                p = self.alloc(256)
                self.wi(p + 20, 27)
                name = self.alloc(16)
                self.u.mem_write(name, b"h264\0")
                self.wq(p, name)
                self.wq(self.arg(0), 1)
                self.ret(p)
        elif n == "av_codec_is_decoder":
            self.ret(1)
        elif n == "avcodec_get_hw_config":
            self.ret(0)  # Declared SW-only SDK capability.
        elif n == "avcodec_find_decoder":
            p = self.alloc(256)
            self.wi(p + 20, 27)
            self.ret(p)
        elif n == "avcodec_alloc_context3":
            p = self.alloc(1024)
            self.wi(p + 24, 27)
            self.ret(p)
        elif n == "avcodec_open2":
            self.ret(0)
        elif n == "av_parser_init":
            self.ret(self.alloc(512))
        elif n == "av_parser_parse2":
            size = self.arg(5) if self.parsed_size is None else self.parsed_size
            self.wq(self.arg(2), self.arg(4))
            self.wi(self.arg(3), size)
            self.events.append(
                ["parse", self.arg(5), size, self.arg(5) + self.parse_delta]
            )
            self.ret(self.arg(5) + self.parse_delta)
        elif n == "avcodec_send_packet":
            p = self.arg(1)
            self.events.append(
                ["send", self.send_status, self.i(p + 32), self.q(p + 8)]
            )
            self.ret(self.send_status)
        elif n == "avcodec_receive_frame":
            p = self.arg(1)
            self.events.append(["receive", self.receive_status])
            if self.receive_status == 0:
                self.wi(p + 104, self.sdk_size[0])
                self.wi(p + 108, self.sdk_size[1])
                self.wi(p + 116, self.sdk_format)
                self.wq(p + 136, self.sdk_pts)
            self.ret(self.receive_status)
        else:
            super().hook(u, a, z, d)

    def seed(self, fid):
        slot = self.client + 0x708C + 0x454 + (fid % 240) * 120
        self.u.mem_write(slot, bytes(120))
        self.u.mem_write(slot, struct.pack("<H", fid))
        self.wi(slot + 32, 900000)
        self.wi(self.client + 0x708C + 0x448, 1)
        return slot

    def feed(self, inp):
        fid = inp.get("id", 23)
        timestamp = inp.get("timestamp", 1000000)
        self.send_status = inp.get("send", 0)
        self.receive_status = inp.get("receive", 0)
        self.parse_delta = inp.get("parse_delta", 0)
        self.input_size = inp.get("size", 2204)
        self.parsed_size = inp.get("parsed_size")
        self.sdk_format = inp.get("format", 0)
        self.sdk_size = tuple(inp.get("dimensions", [128, 72]))
        self.sdk_pts = inp.get("output_pts", 123456)
        if "hardware_format" in inp:
            self.wi(
                self.dec + 0x2C8, inp["hardware_format"]
            )  # Controlled capability branch only.
        slot = self.seed(fid)
        self.events = []
        self.assertions = []
        self.call(0x324190, self.dec, fid, timestamp, self.buffer)
        assert not self.assertions, self.assertions
        return dict(
            events=self.events,
            stats_result=self.i(slot + 88),
            reset_requested=self.i(self.dec + 0x60),
            client_word_1d8=self.i(self.client + 0x1D8),
            client_byte_264=self.u.mem_read(self.client + 0x264, 1)[0],
            assertions=self.assertions,
        )


FUNCTIONS = {
    0x173B10: "avcodec_function_table_init",
    0x324610: "decoder_constructor",
    0x323C10: "h264_constructor",
    0x3273E0: "video_constructor",
    0x3246D0: "start_decoding",
    0x1780C0: "codec_selection",
    0x324190: "final_decode_vslot14",
    0x3240E0: "avcodec_frame_constructor",
    0x324180: "avcodec_frame_set_identity",
    0x2EE050: "video_frame_constructor",
    0x2EE080: "video_frame_set_format",
    0x318B50: "record_frame_complete",
    0x1963A0: "record_frame_event",
    0x319360: "reset_video_decoder",
    0x31F7F0: "send_data_lost",
    0x1945E0: "frame_constructor",
    0x194990: "frame_put",
    0x1947A0: "frame_send",
    0x451CC0: "data_lost_message_constructor",
}


def scenarios():
    cases = []

    def add(name, **inp):
        cases.append(dict(name=name, input=[inp]))

    add("normal")
    add("alternate_output_pts", output_pts=0xFFFFFFF0)
    add("no_output", receive=-11)
    add("native_no_output", id=1, receive=-11)
    add("eof", receive=-541478725)
    add("invalid_data", receive=-1094995529)
    add("receive_eio", receive=-5)
    add("send_again_then_output", send=-11)
    add("send_invalid_then_output", send=-1094995529)
    add("send_eio_then_output", send=-5)
    add("send_again_no_output", send=-11, receive=-11)
    add("parser_partial_consumption", parse_delta=-1)
    add("parser_reject", parse_delta=-2205)
    add("zero_parser_output", parsed_size=0, receive=-11)
    add("empty_input", size=0, receive=-541478725)
    add("zero_output_width", dimensions=[0, 72])
    add("zero_output_height", dimensions=[128, 0])
    for fmt in (12, 44, 98, 51, 157):
        add(f"format_{fmt}", format=fmt, hardware_format=fmt)
        add(f"format_{fmt}_no_output", format=fmt, hardware_format=fmt, receive=-11)
    cases.append(
        dict(
            name="after_no_output",
            input=[dict(id=23, receive=-11), dict(id=24, timestamp=1001000)],
        )
    )
    cases.append(
        dict(
            name="three_outputs",
            input=[
                dict(
                    id=i,
                    timestamp=1000000 + (i - 23) * 1000,
                    output_pts=5000 + (i - 23) * 100,
                )
                for i in (23, 24, 25)
            ],
        )
    )
    return cases


def run(binary, case, patch=None):
    r = Client(binary)
    if patch:
        pc, before, after = patch
        assert bytes(r.u.mem_read(pc, len(before))) == before
        r.u.mem_write(pc, after)
        r.u.ctl_remove_cache(pc, pc + len(after))
    result = dict(case, states=[r.feed(x) for x in case["input"]])
    result["entries"] = {
        FUNCTIONS[pc]: count for pc, count in sorted(r.entered.items())
    }
    return result


def inventory(binary):
    e = ELFFile(io.BytesIO(binary))
    fdes = {
        x["initial_location"]: x["address_range"]
        for x in e.get_dwarf_info().EH_CFI_entries()
        if isinstance(x, FDE)
    }
    t = e.get_section_by_name(".text")
    data = t.data()
    start = t["sh_addr"]
    result = {}
    for pc, name in FUNCTIONS.items():
        size = fdes[pc]
        body = data[pc - start : pc - start + size]
        assert len(body) == size
        result[name] = dict(
            address=pc, size=size, sha256=hashlib.sha256(body).hexdigest()
        )
    return result


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == SHA
    cases = [run(binary, x) for x in scenarios()]
    normal = cases[0]["states"][0]
    assert [x[0] for x in normal["events"]] == [
        "parse",
        "send",
        "receive",
        "put",
    ] and normal["stats_result"] == 0
    empty = next(x for x in cases if x["name"] == "no_output")["states"][0]
    assert [x[3] for x in empty["events"] if x[0] == "complete"] == [7, 5] and empty[
        "stats_result"
    ] == 7
    assert ["feedback", 3, "02"] in empty["events"]
    assert all(
        any(fn in case["entries"] for case in cases) for fn in FUNCTIONS.values()
    )
    checks = []
    for name, shape, pc, after in (
        ("omit_again_special", "no_output", 0x324453, b"\x90" * 6),
        ("omit_loss_feedback", "no_output", 0x3244A4, b"\x90" * 5),
        ("treat_error_as_output", "no_output", 0x324381, b"\x31\xc0"),
        ("omit_send_failure_reset", "send_again_then_output", 0x324543, b"\x90" * 5),
        ("omit_output_identity", "normal", 0x3243C3, b"\x90" * 5),
        ("omit_eio_config_change", "send_eio_then_output", 0x324537, b"\x90" * 6),
    ):
        base = next(x for x in cases if x["name"] == shape)
        before = binary[pc : pc + len(after)]
        changed = run(
            binary, dict(name=shape, input=base["input"]), (pc, before, after)
        )
        assert changed["states"] != base["states"], ("undetected", name)
        checks.append(name)
    return dict(
        binary_sha256=SHA,
        archive_sha256=ARCHIVE_SHA,
        archive_url="https://repo.steampowered.com/steamlink/1.3.32.316/steamlink-1.3.32.316.tgz",
        scope=__doc__,
        functions=inventory(binary),
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
    ref = ROOT / "scripts/fixtures/steam-client-avcodec-reference.json.gz"
    encoded = (json.dumps(report, indent=2) + "\n").encode()
    if a.refresh_reference:
        if ref.exists():
            assert json.loads(gzip.decompress(ref.read_bytes())) == report
        ref.write_bytes(gzip.compress(encoded, mtime=0))
    else:
        assert json.loads(gzip.decompress(ref.read_bytes())) == report
    a.output.write_bytes(encoded)
    print(
        "Official Linux AVCodec:",
        len(report["cases"]),
        "cases,",
        sum(len(x["states"]) for x in report["cases"]),
        "states,",
        len(report["functions"]),
        "functions,",
        len(report["mutation_checks"]),
        "mutations",
    )


if __name__ == "__main__":
    main()
