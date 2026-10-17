#!/usr/bin/env python3
"""Replay official Android shell FEC policy, not an invented adaptive policy.

Requires unicorn and pyelftools. Preset factories, generated config constructors,
copy constructors/Clear, recommendation guards and UI events run original ARM64.
Qt presentation, file input/output, allocation and continuation events are doubles.
No actual Qt event loop, host connection, decoder or display is tested.
"""

import argparse
import hashlib
import io
import json
import struct
from functools import lru_cache
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc
from unicorn.arm64_const import (
    UC_ARM64_REG_CPACR_EL1,
    UC_ARM64_REG_PC,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_TPIDR_EL0,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X30,
)

ROOT = Path(__file__).resolve().parents[1]
SHA = "15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2"
STOP = 0x40000000
PANEL, APP, CONFIG = 0x20010000, 0x20020000, 0x20030000


@lru_cache(maxsize=1)
def load_image(binary):
    elf = ELFFile(io.BytesIO(binary))
    image = bytearray(0x2000000)
    for segment in elf.iter_segments():
        if segment["p_type"] == "PT_LOAD":
            start = segment["p_vaddr"]
            image[start : start + segment["p_filesz"]] = segment.data()
    dyn = elf.get_section_by_name(".dynsym")
    symbols = {s.name: s["st_value"] for s in dyn.iter_symbols()}
    qt_shared = []
    for relocation in elf.get_section_by_name(".rela.dyn").iter_relocations():
        typ = relocation["r_info_type"]
        symbol = dyn.get_symbol(relocation["r_info_sym"])
        if typ == 1027:  # R_AARCH64_RELATIVE, load base zero
            value = relocation["r_addend"]
        elif typ in (257, 1025) and symbol["st_value"]:  # ABS64 / GLOB_DAT
            value = symbol["st_value"] + relocation["r_addend"]
        else:
            if "shared_null" in symbol.name:
                qt_shared.append(relocation["r_offset"])
            continue
        struct.pack_into("<Q", image, relocation["r_offset"], value)
    # Double for completed process-wide protobuf initialization. Original
    # constructors still read scalar defaults from the original .rodata.
    for name, address in symbols.items():
        if name.startswith("scc_info_") and address:
            struct.pack_into("<I", image, address, 0)
    plt = elf.get_section_by_name(".plt")["sh_addr"]
    plts = {
        plt + 32 + i * 16: dyn.get_symbol(r["r_info_sym"]).name
        for i, r in enumerate(elf.get_section_by_name(".rela.plt").iter_relocations())
    }
    return bytes(image), symbols, plts, qt_shared


class Shell:
    def __init__(self, binary):
        self.u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.u.mem_map(0, 0x2000000)
        self.u.mem_map(0x20000000, 0x1000000)
        self.u.mem_map(0x30000000, 0x100000)
        self.u.mem_map(STOP, 0x1000)
        self.next = 0x20100000
        self.events = []
        self.texts = []
        self.qt_strings = {}
        self.saved = None
        self.loaded = None
        self.can4k = False
        self.uint = 0
        self.callbacks = {}
        image, self.symbols, self.plts, qt_shared = load_image(binary)
        self.u.mem_write(0, image)
        self.u.reg_write(UC_ARM64_REG_TPIDR_EL0, 0x20F00000)
        self.u.reg_write(UC_ARM64_REG_CPACR_EL1, 3 << 20)
        self.empty = self.qstring("")
        for offset in qt_shared:
            self.wq(offset, self.empty)
        self.wq(PANEL + 48, APP)
        self.wq(APP + 16, APP + 0x1000)
        self.u.hook_add(UC_HOOK_CODE, self.hook)

    def r(self, i):
        return self.u.reg_read(UC_ARM64_REG_X0 + i)

    def q(self, address):
        return struct.unpack("<Q", self.u.mem_read(address, 8))[0]

    def i(self, address):
        return struct.unpack("<I", self.u.mem_read(address, 4))[0]

    def wq(self, address, value):
        self.u.mem_write(address, struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))

    def wi(self, address, value):
        self.u.mem_write(address, struct.pack("<I", value & 0xFFFFFFFF))

    def b(self, address, value):
        self.u.mem_write(address, bytes([value]))

    def alloc(self, size):
        address = self.next
        self.next += (size + 15) & ~15
        assert self.next < 0x20E00000
        return address

    def ret(self, value=0):
        self.u.reg_write(UC_ARM64_REG_X0, value)
        self.jump(self.u.reg_read(UC_ARM64_REG_X30))

    def jump(self, address):
        self.u.reg_write(UC_ARM64_REG_PC, address)

    def cstring(self, address):
        data = bytearray()
        while (value := self.u.mem_read(address + len(data), 1)[0]) != 0:
            data.append(value)
            assert len(data) < 8192
        return data.decode()

    def qstring(self, text):
        address = self.alloc(32 + len(text) * 2)
        self.wi(address, -1)  # immortal Qt data, no refcount/deallocation effects
        self.wi(address + 4, len(text))
        self.wq(address + 16, 24)
        self.u.mem_write(address + 24, text.encode("utf-16le") + b"\0\0")
        self.qt_strings[address] = text
        return address

    def config(self, address, fec=None, quality=None):
        self.call(0xEB1DE0, address)
        if fec is not None:
            self.wi(address + 16, self.i(address + 16) | 0x4000)
            self.b(address + 113, int(fec))
        if quality is not None:
            self.wi(address + 16, self.i(address + 16) | 0x04000000)
            self.wi(address + 148, quality)

    def snapshot(self, address):
        limit = self.q(address + 72)
        mode = self.q(limit + 24) if limit else 0
        return {
            "fec": bool(self.u.mem_read(address + 113, 1)[0]),
            "fec_present": bool(self.i(address + 16) & 0x4000),
            "quality": self.i(address + 148),
            "hevc": bool(self.u.mem_read(address + 105, 1)[0]),
            "resolution": [self.i(mode + 24), self.i(mode + 28)] if mode else None,
        }

    def hook(self, uc, address, size, data):
        if address == STOP:
            uc.emu_stop()
            return
        if address in self.callbacks:
            self.callbacks[address]()
            return
        name = self.plts.get(address)
        if name is None:
            return
        if "LoadStreamingSettings" in name:
            assert self.loaded is not None
            self.events.append("load-settings")
            # Execute the generated copy constructor on known, valid input.
            self.u.reg_write(UC_ARM64_REG_X0, self.r(1))
            self.u.reg_write(UC_ARM64_REG_X0 + 1, self.loaded)
            self.jump(0xEB1E9C)
        elif "SaveStreamingSettings" in name:
            self.saved = self.snapshot(self.r(1))
            self.events.append("save-settings")
            self.ret()
        elif name == "SDL_IsTV":
            self.ret(0)
        elif name.startswith("_ZN12CNetworkTest5Start"):
            self.events.append({"start-network-test-mode": self.r(1)})
            self.ret()
        elif "CNetworkTest12SetAuthToken" in name:
            assert self.r(2) == 0  # no auth bytes in this guard-only fixture
            self.ret()
        elif any(
            token in name
            for token in (
                "SetUIStateNetworkTest",
                "QGraphicsScene12setSceneRect",
                "BWiredNetworkConnected",
            )
        ):
            self.ret()
        elif "BCanDisplay4KVideo" in name:
            self.ret(int(self.can4k))
        elif "GetStoragePath" in name:
            path = self.alloc(32)
            self.u.mem_write(path, b"/fixture/\0")
            self.ret(path)
        elif "BLoadFile" in name:
            self.events.append({"load-file": self.cstring(self.r(1))})
            self.ret(0)  # missing-file fixture
        elif "CUtlBufferC" in name:
            self.u.mem_write(self.r(0), bytes(64))
            self.ret()
        elif "QString6toUInt" in name:
            self.ret(self.uint)
        elif any(
            token in name
            for token in (
                "HideDialog",
                "ShowDialog",
                "SaveNetworkStats",
                "PopStateTo",
                "SetPanelStateConnecting",
                "UpdatePresetState",
            )
        ):
            self.events.append(name)
            self.ret()
        elif name in ("_Znwm", "malloc"):
            self.ret(self.alloc(self.r(0)))
        elif name in ("_ZdlPv", "free") or "CStreamingClientConfigD" in name:
            self.ret()
        elif "RepeatedPtrFieldBase9MergeFrom" in name:
            assert self.i(self.r(1) + 8) == 0
            self.ret()  # only empty repeated config limits in these inputs
        elif "RepeatedPtrFieldBase5Clear" in name:
            assert self.i(self.r(0) + 8) == 0
            self.ret()
        elif "InitSCCImpl" in name:
            raise AssertionError("Unexpected protobuf static initialization")
        elif "QMetaObject2tr" in name:
            text = self.cstring(self.r(1))
            self.texts.append(text)
            self.wq(self.r(8), self.qstring(text))
            self.ret()
        elif "QString6number" in name or "QString3arg" in name:
            self.wq(self.r(8), self.qstring("display-only"))
            self.ret()
        elif "QDateTime22currentMSecsSinceEpoch" in name:
            self.ret(1000)
        elif any(
            token in name
            for token in (
                "QWidgetC",
                "QVBoxLayoutC",
                "QLayout18setContentsMargins",
                "QLabelC",
                "QLabel11setWordWrap",
                "QBoxLayout9addWidget",
                "CPanelDialogC",
                "CPanelDialog8AddTitle",
                "CPanelDialog9AddWidget",
                "CPanelDialog10AddButtons",
                "QObject7connect",
                "ConnectionD",
            )
        ):
            self.ret()
        elif self.symbols.get(name):
            self.jump(self.symbols[name])
        else:
            raise AssertionError(f"Unimplemented external {name} at {address:#x}")

    def call(self, entry, *params):
        self.u.reg_write(UC_ARM64_REG_SP, 0x300FF000)
        self.u.reg_write(UC_ARM64_REG_X30, STOP)
        for i, value in enumerate(params):
            self.u.reg_write(UC_ARM64_REG_X0 + i, value)
        self.u.emu_start(entry, STOP + 4, count=300000)
        assert self.u.reg_read(UC_ARM64_REG_PC) == STOP, "instruction budget exceeded"
        return self.r(0)


def audit(binary):
    results = []
    for before in (False, True):
        for preset in (0, 1, 2, 3, "fast"):
            shell = Shell(binary)
            shell.config(CONFIG, before, 2)
            if preset == "fast":
                shell.call(0xC85B74, CONFIG)
            else:
                shell.call(0xC8562C, preset, CONFIG)
            results.append(
                {
                    "case": "preset",
                    "before": before,
                    "preset": preset,
                    "after": shell.snapshot(CONFIG),
                }
            )
    for value in (0, 1, 2):
        shell = Shell(binary)
        shell.config(PANEL + 200, not bool(value))
        shell.uint = value
        shell.call(0xC911A8, PANEL, 0, 0)
        results.append(
            {
                "case": "fec-ui-change",
                "value": value,
                "saved": shell.saved,
                "events": shell.events,
            }
        )
    for bitrate in (-1, 0, 20000):
        for quality in (1, 2, 3):
            shell = Shell(binary)
            shell.config(CONFIG, False, quality)
            shell.wi(CONFIG + 16, shell.i(CONFIG + 16) | 0x08000000)
            shell.wi(CONFIG + 152, bitrate)
            shell.loaded = CONFIG
            # Empty graph samples and an already-authorized server supply the
            # documented UI/API preconditions; no session is opened here.
            shell.wq(PANEL + 728, shell.empty)
            shell.wq(PANEL + 200, APP + 0x2000)
            shell.wi(APP + 0x2000 + 8, 6)
            shell.call(0xC7029C, PANEL)
            results.append(
                {
                    "case": "network-test-mode",
                    "bitrate_kbps": bitrate,
                    "quality": quality,
                    "mode": shell.i(PANEL + 272),
                    "target_kbps": shell.i(PANEL + 600),
                    "events": shell.events,
                }
            )
    # Full official result-page entry, including real recommendation guards.
    # Qt double records literal labels; it does not choose recommendations.
    for bandwidth in (99999, 100000, 100001):
        for quality in (1, 2, 3):
            shell = Shell(binary)
            shell.config(CONFIG, False, quality)
            shell.loaded = CONFIG
            shell.wi(PANEL + 272, 2)
            shell.wi(PANEL + 596, bandwidth)
            shell.call(0xC71078, PANEL)
            results.append(
                {
                    "case": "bandwidth-result",
                    "kbps": bandwidth,
                    "quality": quality,
                    "recommendation": shell.i(PANEL + 704),
                    "prompts": shell.texts,
                    "saved": shell.saved,
                }
            )
    for received, variance in ((1000, 0.0), (999, 8.0), (900, 16.0), (0, 0.0)):
        shell = Shell(binary)
        shell.config(CONFIG, False, 2)
        shell.loaded = CONFIG
        shell.wi(PANEL + 272, 1)
        shell.wi(PANEL + 316, received)
        shell.wi(PANEL + 612, 1000)
        shell.u.mem_write(PANEL + 412, struct.pack("<ff", 10.0, variance))
        shell.call(0xC71078, PANEL)
        results.append(
            {
                "case": "fixed-rate-result",
                "received": received,
                "expected": 1000,
                "variance_ms": variance,
                "recommendation": shell.i(PANEL + 704),
                "prompts": shell.texts,
                "saved": shell.saved,
            }
        )
    for before in (False, True):
        for preset in (1, 2, 3):
            for active in (False, True):
                shell = Shell(binary)
                shell.config(PANEL + 200, before, 2)
                widget = CONFIG + 0x1000
                shell.wi(widget + 48, preset)
                shell.wq(PANEL + 384, widget if active else 0)
                shell.call(0xC9182C, PANEL, widget)
                results.append(
                    {
                        "case": "preset-click",
                        "before": before,
                        "preset": preset,
                        "already_active": active,
                        "saved": shell.saved,
                        "events": shell.events,
                    }
                )
    shell = Shell(binary)
    shell.config(CONFIG, True, 3)
    shell.call(0xC999D8, APP, CONFIG)
    results.append(
        {
            "case": "missing-settings-file",
            "after": shell.snapshot(CONFIG),
            "events": shell.events,
        }
    )
    shell = Shell(binary)
    shell.config(CONFIG, True, 3)
    shell.wq(APP + 24, APP + 0x2000)
    shell.call(0xC9D7B4, APP, CONFIG)
    results.append(
        {"case": "reset-settings", "saved": shell.saved, "events": shell.events}
    )
    for accepted in (0, 1):
        for recommendation in (0, 1, 2):
            for can4k in (False, True):
                for before in (False, True):
                    shell = Shell(binary)
                    shell.config(CONFIG, before, 2)
                    shell.loaded = CONFIG
                    shell.can4k = can4k
                    shell.wi(PANEL + 704, recommendation)
                    shell.wi(PANEL + 208, 3)  # connect flow after result page
                    shell.b(PANEL + 212, 1)
                    shell.call(0xC72164, PANEL, accepted)
                    results.append(
                        {
                            "case": "result-dialog-callback",
                            "accepted": accepted,
                            "recommendation": recommendation,
                            "can4k": can4k,
                            "before": before,
                            "saved": shell.saved,
                            "events": shell.events,
                            "test_again": shell.u.mem_read(PANEL + 212, 1)[0],
                        }
                    )
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == SHA
    results = audit(binary)
    reference = ROOT / "scripts/fixtures/steam-client-fec-policy-reference.json"
    assert results == json.loads(
        reference.read_text()
    ), "official policy fixture mismatch"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps({"sha256": SHA, "cases": results}, indent=2) + "\n"
    )
    print(
        f"Official Android shell FEC policy: {len(results)} cases match fixed reference"
    )


if __name__ == "__main__":
    main()
