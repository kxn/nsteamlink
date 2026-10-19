#!/usr/bin/env python3
"""Execute installed Switch runtime's original cond/clock conversion instructions.

Link unmodified archive objects with GC. Only errno, hardware register reads,
svcWaitProcessWideKeyAtomic and timeout mutex reacquisition are terminals. Clock
arithmetic, attribute propagation, absolute-to-relative conversion, recursive
checks and errno mapping run original instructions. Boot anchor/ticks and kernel
results are explicit inputs. This does not prove physical OS timing or lifecycle.
"""
import argparse
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
    UC_ARM64_REG_LR,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_PC,
)

TOOL = Path("/opt/devkitpro/devkitA64/bin/aarch64-none-elf-")
SYS = Path("/opt/devkitpro/devkitA64/aarch64-none-elf/lib/libsysbase.a")
NX = Path("/opt/devkitpro/libnx/lib/libnx.a")
OBJECTS = [
    (SYS, "libsysbase_libsysbase_a-pthread.o"),
    (SYS, "libsysbase_libsysbase_a-clocks.o"),
    (SYS, "libsysbase_libsysbase_a-syscall_support.o"),
    (NX, "newlib.o"),
    (NX, "condvar.o"),
]


def run(tool, *args, cwd):
    return subprocess.check_output([str(TOOL) + tool, *map(str, args)], cwd=cwd)


def audit():
    with tempfile.TemporaryDirectory(prefix="nsl-switch-clock-") as temp:
        d = Path(temp)
        identities = []
        for archive, obj in OBJECTS:
            run("ar", "x", archive, obj, cwd=d)
            identities.append(
                dict(
                    archive=archive.name,
                    archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
                    object=obj,
                    sha256=hashlib.sha256((d / obj).read_bytes()).hexdigest(),
                )
            )
        (d / "terminal.s").write_text(
            "\n".join(
                f'.section .text.{n},"ax"\n.global {n}\n{n}: ret'
                for n in ("__errno", "svcWaitProcessWideKeyAtomic", "mutexLock")
            )
            + "\n"
        )
        run("as", "terminal.s", "-o", "terminal.o", cwd=d)
        roots = (
            "pthread_condattr_init",
            "pthread_condattr_setclock",
            "pthread_cond_init",
            "pthread_cond_timedwait",
            "clock_gettime",
        )
        run(
            "ld",
            "--gc-sections",
            "-Ttext=0x100000",
            "-e",
            "clock_gettime",
            *[f"--undefined={n}" for n in (*roots, "__syscall_clock_gettime")],
            *[obj for _, obj in OBJECTS],
            "terminal.o",
            "-o",
            "clock.elf",
            cwd=d,
        )
        binary = (d / "clock.elf").read_bytes()
        elf = ELFFile(io.BytesIO(binary))
        symbols = {
            s.name: s["st_value"]
            for s in elf.get_section_by_name(".symtab").iter_symbols()
            if s["st_shndx"] != "SHN_UNDEF"
        }
        functions = [
            dict(
                name=s.name,
                size=s["st_size"],
                sha256=hashlib.sha256(
                    elf.get_section(s["st_shndx"]).data()[
                        s["st_value"]
                        - elf.get_section(s["st_shndx"])["sh_addr"] : s["st_value"]
                        - elf.get_section(s["st_shndx"])["sh_addr"]
                        + s["st_size"]
                    ]
                ).hexdigest(),
            )
            for s in elf.get_section_by_name(".symtab").iter_symbols()
            if s["st_info"]["type"] == "STT_FUNC" and s["st_size"]
        ]
        u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        u.mem_map(0x100000, 0x400000)
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_LOAD":
                u.mem_write(seg["p_vaddr"], seg.data())
        u.mem_map(0x10000000, 0x200000)
        state = dict(ticks=19200000, kernel=0, waits=[], relocks=0)
        stop = 0x101FF000
        tls = 0x10010000
        u.mem_write(tls + 484, struct.pack("<I", 123))
        errno = 0x10020000

        def reg(n):
            return u.reg_read(UC_ARM64_REG_X0 + n)

        def ret(value):
            u.reg_write(UC_ARM64_REG_X0, value & ((1 << 64) - 1))
            u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))

        def hook(u, pc, size, data):
            if pc == symbols["__errno"]:
                ret(errno)
            elif pc == symbols["mutexLock"]:
                state["relocks"] += 1
                ret(0)
            elif pc == symbols["svcWaitProcessWideKeyAtomic"]:
                state["waits"].append([reg(2), reg(3)])
                ret(state["kernel"])
            else:
                ins = struct.unpack("<I", u.mem_read(pc, 4))[0]
                if ins & ~31 in (0xD53BE020, 0xD53BD060):
                    u.reg_write(
                        UC_ARM64_REG_X0 + (ins & 31),
                        state["ticks"] if ins & ~31 == 0xD53BE020 else tls,
                    )
                    u.reg_write(UC_ARM64_REG_PC, pc + 4)

        u.hook_add(UC_HOOK_CODE, hook)

        def call(name, *args):
            u.reg_write(UC_ARM64_REG_SP, 0x101F0000)
            u.reg_write(UC_ARM64_REG_LR, stop)
            for i, arg in enumerate(args):
                u.reg_write(UC_ARM64_REG_X0 + i, arg)
            u.emu_start(symbols[name], stop, count=100000)
            assert u.reg_read(UC_ARM64_REG_PC) == stop
            return reg(0) & 0xFFFFFFFF

        u.mem_write(symbols["__boottime"], struct.pack("<q", 1700000000))
        u.mem_write(symbols["__bootticks"], struct.pack("<Q", 0))
        timespec, attr, cond, mutex = 0x10030000, 0x10030100, 0x10030200, 0x10030300
        clocks = []
        for clock in (1, 4, 2):
            u.mem_write(errno, bytes(4))
            result = call("clock_gettime", clock, timespec)
            clocks.append(
                dict(
                    clock=clock,
                    result=result,
                    errno=struct.unpack("<i", u.mem_read(errno, 4))[0],
                    value=(
                        list(struct.unpack("<qq", u.mem_read(timespec, 16)))
                        if result == 0
                        else None
                    ),
                )
            )
        assert clocks[0]["value"] == clocks[1]["value"] == [1700000001, 0]
        assert clocks[2]["result"] == 0xFFFFFFFF and clocks[2]["errno"] == 22
        rows = []
        for clock in (1, 4):
            assert call("pthread_condattr_init", attr) == 0
            assert call("pthread_condattr_setclock", attr, clock) == 0
            assert call("pthread_cond_init", cond, attr) == 0
            actual_clock = struct.unpack("<q", u.mem_read(cond, 8))[0]
            assert actual_clock == clock
            for kind, depth in ((0, 0), (1, 1), (1, 2)):
                for ns in (0, 500000, 16000000, 1000000000, -1):
                    for kernel in (0, 0xEA01, 0x1234):
                        state.update(kernel=kernel, waits=[], relocks=0)
                        u.mem_write(mutex, struct.pack("<IIII", kind, 0, depth, 0))
                        end = 1700000001 * 1000000000 + ns
                        u.mem_write(
                            timespec,
                            struct.pack("<qq", end // 1000000000, end % 1000000000),
                        )
                        result = call("pthread_cond_timedwait", cond, mutex, timespec)
                        invalid = kind == 1 and depth == 2
                        assert result == (
                            9 if invalid else {0: 0, 0xEA01: 116, 0x1234: 5}[kernel]
                        )
                        assert state["waits"] == (
                            [] if invalid else [[123, max(0, ns)]]
                        ), (ns, state)
                        assert state["relocks"] == (not invalid and kernel == 0xEA01)
                        rows.append(
                            dict(
                                clock=clock,
                                kind=kind,
                                depth=depth,
                                nanoseconds=ns,
                                kernel=kernel,
                                result=result,
                                waits=state["waits"],
                                relocks=state["relocks"],
                            )
                        )
        return dict(
            boundary=__doc__,
            identities=identities,
            functions=sorted(functions, key=lambda x: x["name"]),
            clocks=clocks,
            cases=rows,
        )


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--write", type=Path)
    p.add_argument("--check", type=Path)
    a = p.parse_args()
    result = audit()
    if a.write:
        a.write.write_text(json.dumps(result, indent=2) + "\n")
    if a.check:
        assert result == json.loads(a.check.read_text())
    print(
        "Switch archive instructions: 3 clocks,",
        len(result["cases"]),
        "wait conversions",
    )
