#!/usr/bin/env python3
"""Original Generic generator across input-disable/re-enable, no collect double.

Executes original generator constructor, BCollectReports/Parse/Filter/Pack,
SendBuffer/EncodeDelta, player focus event/config delegate and HID/control/frame
production. IHIDDevice::Read supplies explicit RAW72 v3 states; this is not the
actual Android SDL backend, Switch hardware, report-thread scheduling or Steam.
Player has no overlays/dialogs; focus comes from the original SDL3 0x20e event.
Allocator/libc/mutex, config save and crypto primitives remain explicit adapters;
the final Channel::Send records encrypted bodies (no reliable window/UDP).
"""
import argparse
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "hid", ROOT / "scripts/audit-steam-hid-producer.py"
)
hid = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hid)
c = hid.c
REFERENCE = ROOT / "scripts/fixtures/steam-hid-disabled-reference.json.gz"


def wire(state):
    data = bytearray(72)
    struct.pack_into("<6h", data, 0, *state["axes"])
    struct.pack_into("<I", data, 16, state["buttons"])
    data[27] = 3
    return bytes(data)


def state(enabled, buttons=0, axes=(0, 0, 0, 0, 0, 0)):
    return dict(enabled=enabled, buttons=buttons, axes=list(axes))


def scenarios():
    return {
        "ordinary": [state(True, v) for v in (0, 1, 1, 0, 2, 0)],
        "disabled_press": [
            state(True),
            state(False, 1),
            state(True, 1),
            state(True, 2),
            state(True),
        ],
        "disabled_release": [
            state(True),
            state(True, 1),
            state(False),
            state(True),
            state(True, 2),
            state(True),
        ],
        "disabled_multiple": [
            state(True),
            state(False, 1),
            state(False, 3),
            state(False),
            state(True),
            state(True, 4),
        ],
        "initial_disabled": [
            state(False),
            state(False, 1),
            state(True, 1),
            state(True),
        ],
        "unchanged_toggle": [state(True), state(False), state(True), state(True, 1)],
        "repeated_disabled": [
            state(True),
            state(False, 1),
            state(False, 1),
            state(True, 1),
            state(True, 1),
            state(True),
        ],
        "alternating": [
            state(True),
            state(False, 1),
            state(True, 2),
            state(False, 4),
            state(True, 8),
            state(True),
        ],
        "stick_threshold": [
            state(True),
            state(False, axes=(16384, 0, 0, 0, 0, 0)),
            state(True, axes=(16384, 0, 0, 0, 0, 0)),
            state(True, axes=(-16385, 0, 0, 0, 0, 0)),
            state(True),
        ],
        "trigger": [
            state(True),
            state(False, axes=(0, 0, 0, 0, 1, 0)),
            state(True, axes=(0, 0, 0, 0, 1, 0)),
            state(True, axes=(0, 0, 0, 0, 32767, 0)),
            state(True),
        ],
        "mixed": [
            state(True),
            state(False, 3, (20000, 4000, 0, 0, 0, 0)),
            state(True, 3, (20000, 4000, 0, 0, 0, 0)),
            state(True, 0, (-20000, 4000, 0, 0, 0, 0)),
            state(True),
        ],
        "six_axes": [
            state(True),
            state(False, 0x7FFF, (32767, -32768, 20000, -20000, 32767, 16384)),
            state(True, 0x7FFF, (32767, -32768, 20000, -20000, 32767, 16384)),
            state(True, 0xFFFF, (-32768, 32767, -20000, 20000, 0, 1)),
            state(True),
        ],
    }


class Generator(hid.HID):
    def __init__(self, binary):
        self.pending, self.reads = [], []
        super().__init__(binary)
        self.callbacks[c.STOP + 0x704] = self.read_device
        self.wi(c.CLIENT + 256, 6)
        self.wq(c.PLAYER + 8, c.CLIENT)
        self.generator, device, device_vt, array, info, player_vt = (
            self.alloc(4096) for _ in range(6)
        )
        self.wq(device, device_vt)
        self.wq(device_vt + 40, c.STOP + 0x704)
        assert self.parse(info, b"\x68\x01", "CHIDDeviceInfo")  # is_generic_gamepad
        self.call(0x7CF2BC, self.generator, c.PLAYER, 1, device, info, 0, 72)
        assert self.i(self.generator + 148) == 4
        assert self.q(self.generator + 336) == 9 and self.q(self.generator + 344)
        self.wq(array, self.generator)
        self.wq(c.PLAYER + 2088, array)
        self.wi(c.PLAYER + 2104, 1)
        self.wq(c.PLAYER, player_vt)
        self.wq(player_vt + 128, 0x7C5504)
        self.wq(c.CLIENT + 48, c.PLAYER)
        event = self.alloc(256)
        self.wi(event, 0x20E)
        assert self.call(0x7B8110, c.PLAYER, event) == 1
        assert self.u.mem_read(c.PLAYER + 1785, 1)[0] == 1

    def hook(self, u, pc, size, data):
        if self.plts.get(pc) == "memcmp":
            left = bytes(u.mem_read(self.r(0), self.r(2)))
            right = bytes(u.mem_read(self.r(1), self.r(2)))
            result = next((a - b for a, b in zip(left, right) if a != b), 0)
            self.ret(result & 0xFFFFFFFF)
        else:
            super().hook(u, pc, size, data)

    def read_device(self):
        value = self.pending.pop(0) if self.pending else b""
        assert len(value) <= self.r(2)
        self.reads.append(dict(capacity=self.r(2), input=value.hex()))
        if value:
            self.u.mem_write(self.r(1), value)
        self.ret(len(value))

    def step(self, inputs):
        config = self.alloc(256)
        assert self.parse(
            config, b"\x58" + bytes([inputs["enabled"]]), "CStreamingClientConfig"
        )
        self.call(
            self.symbols[
                "_ZN13CStreamClient24SetStreamingClientConfigERK22CStreamingClientConfigb"
            ],
            c.CLIENT,
            config,
            1,
        )
        assert self.u.mem_read(c.CLIENT + 615, 1)[0] == inputs["enabled"]
        self.pending, self.reads = [wire(inputs), b""], []
        start = len(self.observed)
        crypto = len(self.crypto)
        self.call(0x7BD838, c.PLAYER)
        assert not self.pending and not any(self.depth.values())
        current = self.q(self.generator + 328)
        assert self.i(current + 20) == 72
        baseline = bytes(self.u.mem_read(self.q(current), 72)).hex()
        return dict(
            bodies=[
                v["body"]
                for v in self.observed[start:]
                if v.get("event") == "channel_send"
            ],
            sequence=self.q(c.CLIENT + 128),
            baseline=baseline,
            crypto=self.crypto[crypto:],
            reads=self.reads,
        )


def inventory(binary):
    names = set(hid.inventory(binary))
    names.remove("_ZN40CHIDMessageFromRemote_DeviceInputReports8CopyFromERKS_")
    names.update(
        {
            "_ZN13CStreamPlayer25CHIDDeviceReportGeneratorC1EPS_jP10IHIDDeviceRK14CHIDDeviceInfoij",
            "_ZN13CStreamPlayer25CHIDDeviceReportGenerator10SendBufferEP10CUtlBuffer",
            "_ZN13CStreamPlayer25CHIDDeviceReportGenerator11EncodeDeltaEP10CUtlBufferS2_Pi",
            "_ZN13CStreamPlayer25CHIDDeviceReportGenerator32BParseGamepadStateGenericGamepadEPKhiP28HIDDeviceSDLGamepadStateV2_t",
            "_ZN13CStreamPlayer19BFilterGamepadStateEjiP28HIDDeviceSDLGamepadStateV2_tPbS2_",
            "_ZN13CStreamPlayer12BHandleEventER9SDL_Event",
            "_ZN13CStreamPlayer24SetStreamingClientConfigERK22CStreamingClientConfigb",
            "_ZN14CHIDDeviceInfoC1ERKS_",
        }
    )
    elf = ELFFile(io.BytesIO(binary))
    text, result = elf.get_section_by_name(".text"), {}
    for symbol in elf.get_section_by_name(".dynsym").iter_symbols():
        if symbol.name in names:
            offset = symbol["st_value"] - text["sh_addr"]
            code = text.data()[offset : offset + symbol["st_size"]]
            assert code and len(code) == symbol["st_size"]
            result[symbol.name] = dict(
                address=symbol["st_value"],
                size=len(code),
                sha256=hashlib.sha256(code).hexdigest(),
            )
    assert set(result) == names, names - set(result)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    args = p.parse_args()
    binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == c.SHA
    cases = []
    for name, steps in scenarios().items():
        generator = Generator(binary)
        observed = [generator.step(v) for v in steps]
        assert all(o["baseline"] == wire(v).hex() for v, o in zip(steps, observed))
        assert all(not o["bodies"] for v, o in zip(steps, observed) if not v["enabled"])
        cases.append(dict(name=name, input=steps, observed=observed))
    helpers = ["audit-steam-hid-disabled.py", *hid.HELPERS]
    report = dict(
        binary_sha256=c.SHA,
        scope=__doc__,
        cases=cases,
        functions=inventory(binary),
        helpers={
            name: hashlib.sha256((ROOT / "scripts" / name).read_bytes()).hexdigest()
            for name in helpers
        },
    )
    if args.refresh_reference:
        REFERENCE.write_bytes(
            gzip.compress(json.dumps(report, sort_keys=True).encode(), mtime=0)
        )
    else:
        assert report == json.loads(gzip.decompress(REFERENCE.read_bytes()))
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"Verified {len(cases)} original Generic generator sequences / {sum(len(v['input']) for v in cases)} steps"
    )


if __name__ == "__main__":
    main()
