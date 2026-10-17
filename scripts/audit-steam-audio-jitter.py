#!/usr/bin/env python3
"""Execute the pinned official client's complete float audio jitter buffer.

BOpenAudio, constructor, Push, Pop, endpoint search, fades, crossfades and stats
execute original ARM64. SDL device creation/output, libc allocation/storage and
sinf (host libm float adapter) are explicit boundaries. This does not prove an
Android physical audio device, SDL resampling, transport timing or thread races.
Natural schedules never write jitter policy/state after original BOpenAudio.
"""

import argparse
import base64
import ctypes
import ctypes.util
import hashlib
import gzip
import importlib.util
import json
from pathlib import Path
import struct
import zlib

from unicorn.arm64_const import UC_ARM64_REG_S0

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "config", ROOT / "scripts/audit-steam-client-config.py"
)
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)

BRANCHES = {
    0x7BFEC0: "priming_wait",
    0x7BFF2C: "priming_ready",
    0x7BF97C: "overrun_reject_all",
    0x7BF990: "overrun_recovery",
    0x7BF9C8: "overrun_blend",
    0x7C05A0: "shrink_crossfade",
    0x7C0754: "expand_crossfade",
    0x7C0874: "underflow_priming",
    0x7C08AC: "underflow_fade",
    0x7C0824: "underflow_adjust_guard",
    0x7C0834: "underflow_adjust",
    0x7BFE7C: "stats_adjust",
    0x7CA8AC: "expand_finish",
    0x7CA8C8: "shrink_finish",
    0x7C0340: "fade_finish",
    0x7CA9D4: "stats_publish",
}
SCALARS = {
    56: "channels",
    60: "capacity",
    64: "sentinel",
    68: "write",
    72: "read",
    108: "tracked_write",
    112: "attempts",
    120: "fade_bits",
    124: "fade_step_bits",
    128: "cross_bits",
    132: "cross_step_bits",
    136: "alternate_read",
    4236: "dropped",
    4240: "missing",
    4244: "last_queued",
    4248: "min",
    4252: "max",
    4256: "mean",
    4260: "variance",
    4264: "expands",
    4268: "shrinks",
    4272: "underflow_fades",
    4276: "running_min",
    4280: "running_max",
    4284: "observations",
    4288: "interval",
    4292: "running_mean_bits",
    4296: "running_m2_bits",
    4300: "adjustment",
}


def packed(raw):
    return dict(
        sha256=hashlib.sha256(raw).hexdigest(),
        zlib_base64=base64.b64encode(zlib.compress(raw)).decode(),
    )


def signal(count, channels, offset, kind):
    """Exact binary fractions; independent from host trigonometric rounding."""
    values = []
    for frame in range(count):
        for channel in range(channels):
            n = offset + frame
            if kind == "zero":
                value = 0.0
            elif kind == "constant":
                value = (channel + 1) / 16.0
            elif kind == "cancel":
                value = ((n * 37 % 257) - 128) / 256.0 * (-1 if channel & 1 else 1)
            else:
                value = (((n * 37 + channel * 71) % 257) - 128) / 256.0
            values.append(value)
    return struct.pack("<" + "f" * len(values), *values)


class Jitter(c.Core):
    def __init__(self, binary, frequency, channels, fmt=2):
        self.coverage = {}
        self.sdl_events = []
        self.outputs = []
        self.libm = ctypes.CDLL(ctypes.util.find_library("m"))
        self.libm.sinf.argtypes = [ctypes.c_float]
        self.libm.sinf.restype = ctypes.c_float
        super().__init__(binary)
        self.player, self.stream = self.alloc(4096), self.alloc(64)
        self.input, self.output = (
            self.alloc(65536 * 8 * 4 + 64),
            self.alloc(65536 * 8 * 4 + 64),
        )
        self.channels, self.frequency = channels, frequency
        self.wi(self.player + 1304, 0x3F800000)
        assert self.call(0x7BEC54, self.player, fmt, frequency, channels) == 1
        self.jitter = self.q(self.player + 1320)
        assert self.i(self.jitter + 60) == 16384
        self.params = [self.i(self.jitter + 4 * i) for i in range(10)]
        self.table = packed(bytes(self.u.mem_read(self.jitter + 140, 4096)))
        self.coverage.clear()

    def call(self, entry, *params):
        self.u.reg_write(c.SP, 0x300FF000)
        self.u.reg_write(c.LR, c.STOP)
        for i, value in enumerate(params):
            self.u.reg_write(c.X0 + i, value & 0xFFFFFFFFFFFFFFFF)
        self.u.emu_start(entry, c.STOP + 4, count=10000000)
        assert self.u.reg_read(c.BASE["UC_ARM64_REG_PC"]) == c.STOP, hex(
            self.u.reg_read(c.BASE["UC_ARM64_REG_PC"])
        )
        return self.r(0)

    def hook(self, uc, address, size, data):
        if address in BRANCHES:
            key = BRANCHES[address]
            self.coverage[key] = self.coverage.get(key, 0) + 1
        name = self.plts.get(address, "")
        if name == "sinf":
            value = struct.unpack(
                "<f", struct.pack("<I", uc.reg_read(UC_ARM64_REG_S0))
            )[0]
            result = struct.unpack("<I", struct.pack("<f", self.libm.sinf(value)))[0]
            uc.reg_write(UC_ARM64_REG_S0, result)
            self.ret()
        elif name == "SDL_SetHint":
            self.sdl_events.append(
                [name, self.cstring(self.r(0)), self.cstring(self.r(1))]
            )
            self.ret(1)
        elif name == "SDL_OpenAudioDeviceStream":
            self.sdl_events.append(
                [
                    name,
                    bytes(self.u.mem_read(self.r(1), 12)).hex(),
                    self.r(2),
                    self.r(3) == self.player,
                ]
            )
            self.ret(self.stream)
        elif name in (
            "SDL_GetAudioStreamDevice",
            "SDL_ResumeAudioDevice",
            "SDL_DestroyAudioStream",
        ):
            self.sdl_events.append([name])
            self.ret(1)
        elif name == "SDL_PutAudioStreamData":
            self.outputs.append(bytes(self.u.mem_read(self.r(1), self.r(2))))
            self.ret(1)
        else:
            super().hook(uc, address, size, data)

    def snapshot(self):
        result = {
            name: self.i(self.jitter + offset) for offset, name in SCALARS.items()
        }
        result["priming"] = bool(self.u.mem_read(self.jitter + 104, 1)[0])
        result["overrun"] = bool(self.u.mem_read(self.jitter + 116, 1)[0])
        result["queued"] = (result["write"] - result["read"] + 16384) % 16384
        raw = bytes(
            self.u.mem_read(self.q(self.jitter + 80), 16384 * self.channels * 4)
        )
        result["ring_sha256"] = hashlib.sha256(raw).hexdigest()
        result["branches"] = self.coverage
        self.coverage = {}
        return result

    def action(self, op, count, kind="wave", offset=0):
        assert 0 <= count <= 65536
        if op == "push":
            raw = signal(count, self.channels, offset, kind)
            if raw:
                self.u.mem_write(self.input, raw)
            result = self.call(0x7BF91C, self.jitter, self.input, count)
            output = b""
        elif op == "pop":
            self.u.mem_write(
                self.output, bytes([0xA5]) * (count * self.channels * 4 + 32)
            )
            result = self.call(0x7BFDD0, self.jitter, self.output, count)
            assert result <= count
            output = bytes(self.u.mem_read(self.output, result * self.channels * 4))
            tail = bytes(
                self.u.mem_read(
                    self.output + len(output), (count - result) * self.channels * 4 + 32
                )
            )
            assert tail == bytes([0xA5]) * len(tail), "Pop wrote beyond actual output"
        else:
            assert op == "play"
            self.outputs = []
            self.call(0x7BFCA4, self.player, self.stream, count * self.channels * 4)
            assert len(self.outputs) <= 1
            output = b"".join(self.outputs)
            result = len(output) // (self.channels * 4)
        assert [self.i(self.jitter + 4 * i) for i in range(10)] == self.params
        return dict(result=result, output=packed(output), state=self.snapshot())


def schedules(rate):
    initial = rate * 70 // 1000
    return {
        "prime_and_drain": [
            ("pop", 128),
            ("push", initial - 1),
            ("pop", 128),
            ("push", 1),
            ("pop", 128),
            ("pop", 512),
            ("pop", 512),
            ("pop", 512),
            ("push", initial),
            ("pop", 256),
        ],
        "overrun": [
            ("push", 16380),
            ("push", 16),
            ("push", 32),
            ("pop", 4096),
            ("push", 960),
            ("pop", 4096),
            ("push", 4096),
            ("pop", 12000),
        ],
        "overrun_blend_one": [
            ("push", 16384),
            ("pop", 4096),
            ("push", 1),
            ("pop", 256),
        ],
        "zero_count": [
            ("push", 0),
            ("pop", 0),
            ("push", initial),
            ("pop", 0),
            ("pop", 128),
        ],
        "wrap": [
            ("push", 8000),
            ("pop", 4000),
            ("push", 8000),
            ("pop", 8000),
            ("push", 8000),
            ("pop", 8000),
            ("push", 16000),
            ("pop", 16384),
        ],
        "underflow": [("push", 4800), ("pop", 512)]
        + [("pop", 256)] * 20
        + [("push", 2400), ("pop", 512)] * 8,
        "steady_low": [("push", 2400)] + [("push", 480), ("pop", 480)] * 120,
        "steady_high": [("push", 12000)] + [("push", 480), ("pop", 480)] * 120,
        "bursty": [("push", 2400)]
        + [
            ("push", 960),
            ("pop", 256),
            ("pop", 512),
            ("pop", 512),
            ("push", 480),
            ("pop", 256),
        ]
        * 35,
        "player": [
            ("play", 256),
            ("push", initial - 1),
            ("play", 256),
            ("push", initial + 1),
            ("play", 256),
            ("play", 512),
            ("play", 1024),
        ],
    }


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == c.SHA
    cases = []
    for rate, channels, kind in (
        (48000, 1, "wave"),
        (48000, 2, "wave"),
        (44100, 2, "wave"),
        (8000, 1, "wave"),
        (12000, 2, "wave"),
        (16000, 1, "wave"),
        (24000, 2, "wave"),
        (48000, 8, "wave"),
        (48000, 8, "cancel"),
        (48000, 2, "zero"),
        (48000, 2, "constant"),
        (48000, 2, "cancel"),
    ):
        for name, actions in schedules(rate).items():
            r = Jitter(binary, rate, channels)
            observed, controlled, offset = [], [], 0
            for op, count in actions:
                controlled.append([op, count, kind, offset])
                observed.append(r.action(op, count, kind, offset))
                if op == "push":
                    offset += count
            cases.append(
                dict(
                    name=f"{name}_{rate}_{channels}_{kind}",
                    frequency=rate,
                    channels=channels,
                    params=r.params,
                    table=r.table,
                    sdl=r.sdl_events,
                    actions=controlled,
                    observed=observed,
                )
            )
    return dict(
        binary_sha256=c.SHA,
        boundary="official Android 1.3.32 float jitter; host sinf and SDL adapters",
        branches={name: hex(pc) for pc, name in BRANCHES.items()},
        cases=cases,
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--write", type=Path)
    p.add_argument("--check", type=Path)
    a = p.parse_args()
    result = audit(a.binary.read_bytes())
    if a.write:
        raw = (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode()
        a.write.write_bytes(
            gzip.compress(raw, mtime=0) if a.write.suffix == ".gz" else raw
        )
    if a.check:
        raw = a.check.read_bytes()
        assert result == json.loads(
            gzip.decompress(raw) if a.check.suffix == ".gz" else raw
        ), "official jitter evidence drift"
    coverage = set()
    for case in result["cases"]:
        for state in case["observed"]:
            coverage.update(state["state"]["branches"])
    print(
        json.dumps(
            dict(
                cases=len(result["cases"]),
                steps=sum(len(case["actions"]) for case in result["cases"]),
                covered=sorted(coverage),
            ),
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
