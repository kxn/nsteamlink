#!/usr/bin/env python3
"""Audit installed Switch SDK CPU input and H264 capability for the §99 policy.

This is target SDK evidence, not an official Steam Link Switch client or device
observation. Original av_cpu_count instructions execute with svcGetInfo/log as
explicit terminals. Actual masks/status are controlled inputs. The native CPU
adapter calls this unchanged SDK API; official selection policy comes from the
separate pinned Steam Link original-instruction audit.
"""

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import tempfile

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import (
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,
    UC_ARM64_REG_X3,
    UC_ARM64_REG_X30,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_PC,
)

ROOT = Path(__file__).resolve().parents[1]
STOP = 0x2000000


def symbol(binary, name):
    elf = ELFFile(io.BytesIO(binary))
    matches = [
        s
        for s in elf.get_section_by_name(".symtab").iter_symbols()
        if s.name == name and s["st_shndx"] != "SHN_UNDEF"
    ]
    assert len(matches) == 1, name
    s = matches[0]
    section = elf.get_section(s["st_shndx"])
    return s, section.data()[s["st_value"] : s["st_value"] + s["st_size"]]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def extract(ar, archive, member, function, directory):
    names = subprocess.check_output([ar, "t", str(archive)], text=True).splitlines()
    matches = []
    for index in range(1, names.count(member) + 1):
        subprocess.run(
            [ar, "xN", str(index), str(archive), member], cwd=directory, check=True
        )
        data = (directory / member).read_bytes()
        elf = ELFFile(io.BytesIO(data))
        if any(
            s.name == function and s["st_shndx"] != "SHN_UNDEF"
            for s in elf.get_section_by_name(".symtab").iter_symbols()
        ):
            matches.append(data)
    assert len(matches) == 1, function
    return matches[0]


class CPU:
    def __init__(self, binary, mask, status):
        self.u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.u.mem_map(0x100000, 0x200000)
        self.u.mem_map(0x40000000, 0x100000)
        self.u.mem_map(STOP, 0x1000)
        self.mask, self.status, self.calls, self.logs = mask, status, 0, 0
        elf = ELFFile(io.BytesIO(binary))
        sections = {}
        address = 0x100000
        for i, section in enumerate(elf.iter_sections()):
            if section["sh_flags"] & 2:
                sections[i] = address
                if section["sh_type"] != "SHT_NOBITS" and section.data():
                    self.u.mem_write(address, section.data())
                address += (max(section["sh_size"], 1) + 4095) & ~4095
        table = elf.get_section_by_name(".symtab")
        fn = next(
            s
            for s in table.iter_symbols()
            if s.name == "av_cpu_count" and s["st_shndx"] != "SHN_UNDEF"
        )
        self.entry = sections[fn["st_shndx"]] + fn["st_value"]
        imports = {"svcGetInfo": STOP + 0x100, "av_log": STOP + 0x200}
        for section in elf.iter_sections():
            if section.name != ".rela.text.av_cpu_count":
                continue
            for rel in section.iter_relocations():
                s = table.get_symbol(rel["r_info_sym"])
                target = (
                    imports[s.name]
                    if s["st_shndx"] == "SHN_UNDEF"
                    else sections[s["st_shndx"]] + s["st_value"]
                )
                target += rel["r_addend"]
                pc = self.entry + rel["r_offset"]
                word = struct.unpack("<I", self.u.mem_read(pc, 4))[0]
                kind = rel["r_info_type"]
                if kind == 275:  # ADR_PREL_PG_HI21
                    immediate = ((target >> 12) - (pc >> 12)) & 0x1FFFFF
                    word = (
                        (word & ~0x60FFFFE0)
                        | ((immediate & 3) << 29)
                        | ((immediate >> 2) << 5)
                    )
                elif kind == 277:  # ADD_ABS_LO12_NC
                    word = (word & ~0x003FFC00) | ((target & 4095) << 10)
                elif kind == 283:  # CALL26
                    assert (target - pc) % 4 == 0
                    assert -(1 << 27) <= target - pc < (1 << 27)
                    word = (word & 0xFC000000) | (((target - pc) >> 2) & 0x3FFFFFF)
                else:
                    raise AssertionError(kind)
                self.u.mem_write(pc, struct.pack("<I", word))
        self.u.hook_add(UC_HOOK_CODE, self.hook)

    def hook(self, u, pc, size, data):
        if pc == STOP + 0x100:
            self.calls += 1
            assert u.reg_read(UC_ARM64_REG_X1) == 0
            assert u.reg_read(UC_ARM64_REG_X2) == 0xFFFF8001
            assert u.reg_read(UC_ARM64_REG_X3) == 0
            if not self.status:
                u.mem_write(u.reg_read(UC_ARM64_REG_X0), struct.pack("<Q", self.mask))
            u.reg_write(UC_ARM64_REG_X0, self.status)
            u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_X30))
        elif pc == STOP + 0x200:
            self.logs += 1
            u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_X30))

    def run(self):
        self.u.reg_write(UC_ARM64_REG_SP, 0x400FF000)
        self.u.reg_write(UC_ARM64_REG_X30, STOP)
        self.u.emu_start(self.entry, STOP, count=2000)
        assert self.u.reg_read(UC_ARM64_REG_PC) == STOP
        return self.u.reg_read(UC_ARM64_REG_X0)

    def native_adapter(self, binary):
        elf = ELFFile(io.BytesIO(binary))
        fn, body = symbol(binary, "sl_system_video_cpu_count")
        address = 0x280000
        self.u.mem_write(address, body)
        calls = 0
        for section in elf.iter_sections():
            if section["sh_type"] != "SHT_RELA" or section["sh_info"] != fn["st_shndx"]:
                continue
            table = elf.get_section(section["sh_link"])
            for relocation in section.iter_relocations():
                offset = relocation["r_offset"] - fn["st_value"]
                if not 0 <= offset < len(body):
                    continue
                imported = table.get_symbol(relocation["r_info_sym"])
                assert imported.name == "av_cpu_count"
                assert relocation["r_info_type"] == 283
                pc = address + offset
                target = self.entry + relocation["r_addend"]
                assert -(1 << 27) <= target - pc < (1 << 27)
                word = struct.unpack("<I", self.u.mem_read(pc, 4))[0]
                word = (word & 0xFC000000) | (((target - pc) >> 2) & 0x3FFFFFF)
                self.u.mem_write(pc, struct.pack("<I", word))
                calls += 1
        assert calls == 1
        self.entry = address
        return dict(size=len(body), sha256=sha(body))


def audit(sdk, prefix, native=None):
    avutil, avcodec = sdk / "lib/libavutil.a", sdk / "lib/libavcodec.a"
    with tempfile.TemporaryDirectory(prefix="switch-thread-input-") as temp:
        directory = Path(temp)
        cpu = extract(prefix + "ar", avutil, "cpu.o", "av_cpu_count", directory)
        h264 = extract(
            prefix + "ar", avcodec, "h264dec.o", "ff_h264_decoder", directory
        )
        source = b"#include <stddef.h>\n#include <libavcodec/avcodec.h>\nconst unsigned nsl_layout[]={offsetof(AVCodec,capabilities),AV_CODEC_CAP_SLICE_THREADS,FF_THREAD_SLICE};\n"
        output = directory / "layout.o"
        subprocess.run(
            [
                prefix + "gcc",
                "-x",
                "c",
                "-c",
                "-",
                "-isystem",
                str(sdk / "include"),
                "-o",
                str(output),
            ],
            input=source,
            check=True,
        )
        _, layout = symbol(output.read_bytes(), "nsl_layout")
        offset, cap_slice, type_slice = struct.unpack("<III", layout)
    assert (offset, cap_slice, type_slice) == (24, 0x2000, 2)
    _, descriptor = symbol(h264, "ff_h264_decoder")
    capabilities = struct.unpack_from("<I", descriptor, offset)[0]
    assert capabilities & cap_slice
    cases = []
    for mask in (0, 1, 3, 7, 15, 0xF0, 1 << 63):
        for status in (0, 0x123):
            c = CPU(cpu, mask, status)
            values = [c.run(), c.run()]
            assert values == [mask.bit_count() if not status else 3] * 2
            assert c.calls == 2 and c.logs == 1
            cases.append(
                dict(
                    mask=mask,
                    status=status,
                    returns=values,
                    svc_calls=c.calls,
                    log_calls=c.logs,
                )
            )
    fn, body = symbol(cpu, "av_cpu_count")
    if native is not None:
        native_cases = []
        for case in cases:
            c = CPU(cpu, case["mask"], case["status"])
            function = c.native_adapter(native)
            values = [c.run(), c.run()]
            assert values == case["returns"] and c.calls == 2 and c.logs == 1
            native_cases.append(dict(case, returns=values))
        native_report = dict(
            scope="Compiled Native Switch getter → original target SDK CPU code → controlled svcGetInfo/log. Not a device observation or Steam Link policy producer.",
            object_sha256=sha(native),
            function=function,
            cases=native_cases,
        )
    else:
        native_report = None
    return dict(
        scope=__doc__,
        avutil_sha256=sha(avutil.read_bytes()),
        avcodec_sha256=sha(avcodec.read_bytes()),
        cpu_object_sha256=sha(cpu),
        h264_object_sha256=sha(h264),
        cpu_function=dict(size=fn["st_size"], sha256=sha(body)),
        public_layout=dict(
            capabilities_offset=offset,
            capability_slice=cap_slice,
            thread_type_slice=type_slice,
        ),
        h264_capabilities=capabilities,
        cases=cases,
    ), native_report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--sdk-directory", type=Path, default=Path("/opt/devkitpro/portlibs/switch")
    )
    p.add_argument(
        "--tool-prefix", default="/opt/devkitpro/devkitA64/bin/aarch64-none-elf-"
    )
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    p.add_argument("--native-object", type=Path)
    a = p.parse_args()
    report, native = audit(
        a.sdk_directory.resolve(),
        a.tool_prefix,
        a.native_object.read_bytes() if a.native_object else None,
    )
    encoded = (json.dumps(report, indent=2) + "\n").encode()
    fixture = ROOT / "scripts/fixtures/switch-decoder-thread-input-reference.json.gz"
    if a.refresh_reference:
        if fixture.exists():
            assert json.loads(gzip.decompress(fixture.read_bytes())) == report
        fixture.write_bytes(gzip.compress(encoded, mtime=0))
    else:
        assert json.loads(gzip.decompress(fixture.read_bytes())) == report
    a.output.write_bytes(encoded)
    if native is not None:
        a.output.with_suffix(".native.json").write_text(
            json.dumps(native, indent=2) + "\n"
        )
    print(
        "Switch SDK CPU input:",
        len(report["cases"]),
        "cases; H264 capabilities:",
        hex(report["h264_capabilities"]),
    )


if __name__ == "__main__":
    main()
