#!/usr/bin/env python3
"""Execute pinned x64 Steam host adaptive-bitrate boundaries offline.

Original recomputation, loss/overflow and ping-window handlers, callback gates/latch, actual RTTI
bitrate getter and encoding-stage min/store execute original instructions. Time
and logging are providers. Loss/overflow fixtures omit sample/history buffers; ping-window fixtures provide
an explicit 500-sample input and critical-section terminals.
original absent-buffer branches skip them, not mocked return values. The optional independent
rate callback and downstream frame delivery are explicit endpoints. No Steam
process, packets, decoder/encoder hardware or real thread scheduling is touched.
Negative controls intentionally change decoder margin or encoder-state store
and must fail; they are not product code or adaptive strategies for Switch.
"""
import pefile, struct, json, hashlib, math, argparse
from pathlib import Path
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RIP,
    UC_X86_REG_RSP,
    UC_X86_REG_RCX,
    UC_X86_REG_XMM0,
    UC_X86_REG_EAX,
    UC_X86_REG_RDX,
    UC_X86_REG_R8,
)

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--binary", type=Path, required=True)
parser.add_argument(
    "--mutation",
    choices=["none", "decoder-margin", "encoder-store", "ping-recovery"],
    default="none",
    help="Negative controls: each mutation must fail the original-output oracle",
)
args = parser.parse_args()
P = args.binary
raw = P.read_bytes()
assert (
    hashlib.sha256(raw).hexdigest()
    == "1b9457943205dc3af0bd53463ba331cbd2a381388699705c02271aac7a2b1252"
)
pe = pefile.PE(data=raw)
base = pe.OPTIONAL_HEADER.ImageBase
image = pe.get_memory_mapped_image()


class M:
    def __init__(
        self, now, lower=1, upper=100, link=10, decoder=0, history=0, obj=0x200000
    ):
        u = self.u = Uc(UC_ARCH_X86, UC_MODE_64)
        u.mem_map(base, (len(image) + 4095) & ~4095)
        u.mem_write(base, image)
        u.mem_map(0x100000, 0x400000)
        self.obj = obj
        self.now = now
        self.calls = []
        if args.mutation == "decoder-margin":
            u.mem_write(0x13AC8B6C0, struct.pack("<f", 1.0))
        if args.mutation == "ping-recovery":
            u.mem_write(0x13AC8B6A4, struct.pack("<f", 0.0))
        if args.mutation == "encoder-store":
            assert bytes(u.mem_read(0x13A1A3038, 6)) == bytes.fromhex("87be68010000")
            u.mem_write(0x13A1A3038, b"\x90" * 6)
        self.q(0x13AC4B528, 0x110000)
        u.mem_write(0x110000, b"\xc3")
        u.mem_write(0x13A1A0560, b"\xc3")
        u.hook_add(UC_HOOK_CODE, self.hook)
        for off, val in [
            (0x98, link),
            (0xA0, 1),
            (0xA8, 10),
            (0xAC, lower),
            (0xB0, upper),
            (0xB4, decoder),
            (0xB8, history),
        ]:
            self.f(self.obj + off, val)

    def q(self, a, v):
        self.u.mem_write(a, struct.pack("<Q", v))

    def f(self, a, v):
        self.u.mem_write(a, struct.pack("<f", v))

    def d(self, a, v):
        self.u.mem_write(a, struct.pack("<d", v))

    def readf(self, off):
        return struct.unpack("<f", self.u.mem_read(self.obj + off, 4))[0]

    def readd(self, off):
        return struct.unpack("<d", self.u.mem_read(self.obj + off, 8))[0]

    def hook(self, u, pc, size, data):
        if pc == 0x110000:
            u.reg_write(
                UC_X86_REG_XMM0, int.from_bytes(struct.pack("<d", self.now), "little")
            )
        if pc in [0x13A170E80, 0x13A172500, 0x13A1A0560]:
            self.calls.append(hex(pc))

    def call(self, pc, ctx=None, frame=0):
        self.q(0x4FF008, 0x111000)
        self.u.reg_write(UC_X86_REG_RSP, 0x4FF008)
        self.u.reg_write(UC_X86_REG_RCX, self.obj if ctx is None else ctx)
        self.u.reg_write(UC_X86_REG_RDX, frame)
        self.u.emu_start(pc, 0x111000, count=100000)
        assert self.u.reg_read(UC_X86_REG_RIP) == 0x111000


cases = []
for name, now, opts, expected in [
    ("floor-at-loss", 0, {}, 1),
    ("ramp-quarter", 0.25, {}, 5),
    ("ramp-half", 0.5, {}, 10),
    ("ramp-capped", 2, {}, 10),
    ("upper", 2, {"upper": 6}, 6),
    ("decoder-headroom", 2, {"decoder": 5}, 4.8),
    ("history-cap", 2, {"history": 4}, 4),
    ("floor-wins", 2, {"link": 1, "lower": 2}, 2),
]:
    m = M(now, **opts)
    m.call(0x13A172500)
    after = m.readf(0xA8)
    assert math.isclose(after, expected, rel_tol=1e-6), (name, after)
    cases.append(dict(name=name, now=now, target=after, ramp=m.readf(0xA4)))
for entry in [0x13A170FC0, 0x13A171A10]:
    for now in [4.999, 5.0, 6.0]:
        m = M(now)
        m.call(entry)
        early = now < 5
        assert m.readd(0x90) == (0 if early else now)
        assert math.isclose(m.readf(0xA8), 10 if early else 1, rel_tol=1e-6)
        cases.append(
            dict(
                entry=hex(entry),
                now=now,
                early=early,
                last_event=m.readd(0x90),
                target=m.readf(0xA8),
                calls=m.calls,
            )
        )

for entry in [0x13A1907F0, 0x13A190740]:
    for gate in [0, 1]:
        parent = 0x200000
        m = M(6, obj=parent + 0x400)
        m.u.mem_write(parent + 0x408, bytes([gate]))
        m.call(entry, ctx=parent)
        assert m.readf(0xA8) == (1 if gate else 10)
        first = list(m.calls)
        if entry == 0x13A190740:
            m.call(entry, ctx=parent)
            assert m.calls == first  # pending-loss latch prevents repeat
        cases.append(
            dict(
                entry=hex(entry),
                enabled=bool(gate),
                target=m.readf(0xA8),
                calls=m.calls,
            )
        )
for enabled, target, other, expected in [
    (1, 5, 0, 5000),
    (1, 5, 3000, 3000),
    (0, 5, 0, 6000),
    (0, 5, 8000, 6000),
]:
    root = 0x200000
    m = M(0.25, obj=root + 0x4928)
    m.call(0x13A172500)
    assert m.readf(0xA8) == target
    m.u.mem_write(m.obj + 8, bytes([enabled]))
    m.u.mem_write(root + 0x4648, struct.pack("<I", 6000))
    m.call(0x13A18C4C0, ctx=root + 0x4538)
    got = m.u.reg_read(UC_X86_REG_EAX)
    assert got == (5000 if enabled else 6000)
    stage, encoder, vector, nextstage, fakevt, frame = (
        0x300000,
        0x310000,
        0x320000,
        0x330000,
        0x340000,
        0x350000,
    )
    m.q(stage, 0x13AC92060)
    m.q(stage + 0x30, encoder)
    m.q(stage + 0x10, nextstage)
    m.q(encoder + 0x68, vector)
    m.u.mem_write(encoder + 0x78, struct.pack("<I", 2 if other else 1))
    m.q(vector, root + 0x4538)
    m.q(root + 0x4538, 0x13AC8FA20)
    if other:
        # A second independent callback is an explicit provider; the minimum loop runs original instructions.
        callback, cv = 0x360000, 0x370000
        m.q(vector + 8, callback)
        m.q(callback, cv)
        m.q(cv + 0x28, 0x110100)
        m.u.mem_write(0x110100, b"\xb8" + struct.pack("<I", other) + b"\xc3")
    # Downstream frame delivery is the effect endpoint, not a real encoder/device.
    m.q(nextstage, fakevt)
    m.q(fakevt + 0x38, 0x110200)
    m.u.mem_write(0x110200, b"\xc3")
    m.call(0x13A1A2FE0, ctx=stage, frame=frame)
    chosen = struct.unpack("<I", m.u.mem_read(encoder + 0x168, 4))[0]
    assert chosen == expected, (enabled, other, chosen)
    cases.append(
        dict(
            name="original-encoder-stage",
            enabled=bool(enabled),
            estimator_mbps=target,
            configured_kbps=6000,
            other_callback_kbps=other,
            source_getter_kbps=got,
            chosen_encoder_state_kbps=chosen,
        )
    )
# The original ping-response callback converts 16.16-second ticks to float ms,
# then updates the original 500-slot window and recomputes the coefficient.
# Array contents and active-thread word are explicit inputs; lock effects are
# terminals, not a claim about real host scheduling or actual network history.
for (
    baseline,
    sample_ms,
    coefficient,
    enabled,
    index,
    active,
    expected_coefficient,
    expected_target,
) in [
    (10, 25, 1, 1, 0, 1, 0.5036091804504395, 5.0360918045043945),
    (10, 40, 1, 1, 0, 1, 0.08, 1),
    (200, 210, 1, 1, 0, 1, 1, 10),
    (10, 10, 0.5, 1, 0, 1, 0.54, 5.4),
    (10, 10, 0.99, 1, 0, 1, 1, 10),
    (10, 25, 1, 0, 0, 1, 1, 10),
    (10, 25, 1, 1, 500, 1, 1, 10),
    (10, 25, 1, 1, 0, 0, 1, 10),
]:
    parent = 0x200000
    m = M(2, obj=parent + 0x400)
    for iat, provider in [(0x13AC4A818, 0x110300), (0x13AC4A810, 0x110310)]:
        m.q(iat, provider)  # Enter/LeaveCriticalSection, single-thread boundary.
        m.u.mem_write(provider, b"\xc3")
    m.q(m.obj + 0x58, 0x380000)
    m.u.mem_write(0x380000, struct.pack("<500f", *([baseline] * 500)))
    m.f(m.obj + 0x54, 10)  # Explicit threshold input, not the host default.
    m.f(m.obj + 0xA0, coefficient)
    m.u.mem_write(m.obj + 0x0C, struct.pack("<I", active))
    m.u.mem_write(parent + 0x408, bytes([enabled]))
    ticks = round(sample_ms * 65536 / 1000)
    m.u.reg_write(UC_X86_REG_R8, ticks)
    m.call(0x13A18E8F0, ctx=parent, frame=index)
    actual = m.readf(0xA0)
    assert math.isclose(actual, expected_coefficient, rel_tol=1e-6), (
        "ping coefficient",
        actual,
        expected_coefficient,
    )
    assert math.isclose(m.readf(0xA8), expected_target, rel_tol=1e-6)
    cases.append(
        dict(
            name="original-ping-window",
            baseline_ms=baseline,
            new_sample_ticks=ticks,
            initial_coefficient=coefficient,
            enabled=bool(enabled),
            slot=index,
            active_thread_word=active,
            coefficient=actual,
            target=m.readf(0xA8),
            window_mean=m.readf(0xC8),
        )
    )

print(
    json.dumps(
        {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "adapters": [
                "Plat_FloatTime",
                "logging",
                "optional second bitrate callback",
                "downstream frame delivery",
                "Enter/LeaveCriticalSection for explicit single-thread ping-window cases",
            ],
            "input_boundary": "Loss/overflow estimators with absent sample buffers/histogram; ping-response cases have an explicit 500-slot sample window and active-thread word. Source gate/latch, ping conversion/window/coefficient, recomputation, actual session RTTI bitrate getter and real stage min/store execute original instructions. No actual host packets/encoder device/runtime evidence.",
            "cases": cases,
            "source_ranges": {
                hex(a): hashlib.sha256(image[a - base : z - base]).hexdigest()
                for a, z in [
                    (0x13A172500, 0x13A1725B9),
                    (0x13A18E8F0, 0x13A18E93A),
                    (0x13A171820, 0x13A171A04),
                    (0x13A1907F0, 0x13A190806),
                    (0x13A18C4C0, 0x13A18C4E6),
                    (0x13A1A2FE0, 0x13A1A3058),
                ]
            },
        },
        indent=2,
    )
)
