#!/usr/bin/env python3
"""Execute pinned x64 Steam host adaptive-bitrate boundaries offline.

Original recomputation, loss/overflow and ping-window handlers, callback gates/latch, actual RTTI
bitrate getter and encoding-stage min/store execute original instructions. Time
and logging are providers. Fixtures distinguish absent buffers from explicit
30-slot rate, 190-bin event and 500-slot ping storage. Original lookup, update
and pooling branches execute, with declared critical-section/memset terminals. The optional independent
rate callback, downstream frame delivery and frame deletion are explicit endpoints.
Unencrypted frame metadata also enters the real sender and FPS enters the real
frame-period setter before ping feedback. A bounded original probe-worker/request
loop observes integer protobuf objects at Frame::Put, not serialized packets.
Original response gates/list lookup consume explicit decoded fields before the
actual RTTI callback and rate recomputation. No Steam
process, packets, decoder/encoder hardware or real thread scheduling is touched.
Negative controls change original instructions/constants and must fail output
oracles; they are not product code or adaptive strategies for Switch.
"""
import pefile, struct, json, hashlib, math, argparse
from pathlib import Path
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RIP,
    UC_X86_REG_RSP,
    UC_X86_REG_RCX,
    UC_X86_REG_XMM0,
    UC_X86_REG_XMM1,
    UC_X86_REG_XMM2,
    UC_X86_REG_RAX,
    UC_X86_REG_EAX,
    UC_X86_REG_RDX,
    UC_X86_REG_R8,
)

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--binary", type=Path, required=True)
parser.add_argument(
    "--mutation",
    choices=[
        "none",
        "decoder-margin",
        "encoder-store",
        "ping-recovery",
        "history-pool",
        "sender-rate",
        "fps-threshold",
        "ping-slot-expiry",
        "ping-auto-sequence",
        "ping-response-size",
        "ping-ledger-expiry",
    ],
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
        self.rate_inputs = []
        self.sender_endpoints = []
        self.sender_results = []
        self.probe_messages = []
        self.probe_sleeps = []
        self.response_callbacks = []
        if args.mutation == "decoder-margin":
            u.mem_write(0x13AC8B6C0, struct.pack("<f", 1.0))
        if args.mutation == "ping-recovery":
            u.mem_write(0x13AC8B6A4, struct.pack("<f", 0.0))
        if args.mutation == "history-pool":
            assert bytes(u.mem_read(0x13A171096, 5)) == bytes.fromhex("e8350f0000")
            u.mem_write(0x13A171096, b"\x90" * 5)
        if args.mutation == "encoder-store":
            assert bytes(u.mem_read(0x13A1A3038, 6)) == bytes.fromhex("87be68010000")
            u.mem_write(0x13A1A3038, b"\x90" * 6)
        if args.mutation == "sender-rate":
            assert bytes(u.mem_read(0x13A192D4E, 5)) == bytes.fromhex("e89de3fdff")
            u.mem_write(0x13A192D4E, b"\x90" * 5)
        if args.mutation == "fps-threshold":
            assert bytes(u.mem_read(0x13A171E78, 4)) == bytes.fromhex("f30f5ec1")
            u.mem_write(0x13A171E78, b"\x90" * 4)
        if args.mutation == "ping-slot-expiry":
            assert bytes(u.mem_read(0x13A171D9C, 7)) == bytes.fromhex("c70498000080bf")
            u.mem_write(0x13A171D9C, b"\x90" * 7)
        if args.mutation == "ping-auto-sequence":
            assert bytes(u.mem_read(0x13A1EB03F, 6)) == bytes.fromhex("ff876c020000")
            u.mem_write(0x13A1EB03F, b"\x90" * 6)
        if args.mutation == "ping-response-size":
            assert bytes(u.mem_read(0x13A1F058C, 2)) == bytes.fromhex("7411")
            u.mem_write(0x13A1F058C, b"\xeb\x11")
        if args.mutation == "ping-ledger-expiry":
            assert bytes(u.mem_read(0x13A1EB093, 2)) == bytes.fromhex("786a")
            u.mem_write(0x13A1EB093, bytes.fromhex("7e6a"))
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

    def critical_sections(self):
        for iat, provider in [(0x13AC4A818, 0x110300), (0x13AC4A810, 0x110310)]:
            self.q(iat, provider)
            self.u.mem_write(provider, b"\xc3")

    def histogram_storage(self):
        self.critical_sections()
        self.q(self.obj + 0xF8, 0x3A0000)
        self.u.mem_write(0x3A0000, struct.pack("<190f", *([1] * 190)))
        # Original pooling calls this memset primitive; no pooling replacement.
        self.u.mem_write(0x13AC31740, b"\xc3")
        self.provide_memset = True

    def rate_storage(self):
        self.critical_sections()
        self.q(self.obj + 0x18, 0x380000)
        self.q(self.obj + 0x20, 0x390000)
        self.u.mem_write(0x380000, struct.pack("<30f", *([1.0] * 30)))
        self.u.mem_write(
            0x390000,
            struct.pack("<30d", *[self.now - (29 - i) * 0.1 for i in range(30)]),
        )
        self.u.mem_write(self.obj + 0x28, struct.pack("<I", 29))
        self.f(self.obj + 0x54, 1000 / 60)
        self.f(self.obj + 0x9C, 10)
        self.f(self.obj + 0xA4, 1)

    def probe_storage(self, root):
        self.critical_sections()
        self.probe_root = root
        self.q(root + 0x280, 0x330000)
        self.u.mem_write(root + 0x288, struct.pack("<8i", 16, 0, -1, -1, -1, 0, 0, 0))
        self.q(root + 0x2A8, 0x330000)
        self.q(self.obj + 0x58, 0x380000)
        self.u.mem_write(0x380000, struct.pack("<500f", *([10.0] * 500)))
        # Packet timestamp, frame storage/serialization/destruction and global
        # send guards are declared boundaries. Request construction, linked-list
        # allocation/linking, sequence selection and mode checks stay original.
        ticks = round(self.now * 65536) & 0xFFFFFFFF
        self.u.mem_write(0x13A1E9F50, b"\xb8" + struct.pack("<I", ticks) + b"\xc3")
        for terminal in [
            0x13A1DFDD0,
            0x13A1E20C0,
            0x13A1DFE40,
            0x13A47AC40,
            0x13A1F6E60,
            0x13A1F6E70,
        ]:
            self.u.mem_write(terminal, b"\xc3")

    def response_boundary(self, values):
        self.decoded_response = values
        self.critical_sections()
        # Explicit decoded fields and copied frame metadata, not real wire or
        # a claim to execute the C++ protobuf parser/authentication/socket.
        for terminal in [0x13A1DFE10, 0x13A1E1420, 0x13A1DFE40, 0x13A47AC80]:
            self.u.mem_write(terminal, b"\xc3")
        self.q(0x13AC4B5A0, 0x110350)
        self.u.mem_write(0x110350, b"\xc3")

    def hook(self, u, pc, size, data):
        if pc == 0x110500 and hasattr(self, "probe_iterations"):
            self.probe_sleeps.append(u.reg_read(UC_X86_REG_RCX))
            if len(self.probe_sleeps) == self.probe_iterations:
                # Bound the original loop at an OS sleep boundary. No actual
                # thread scheduling or wall-clock 20ms interval is claimed.
                u.mem_write(self.obj + 0x0C, struct.pack("<I", 0))
        if pc == 0x13A1E20C0 and hasattr(self, "probe_root"):
            message = u.reg_read(UC_X86_REG_RDX)
            self.probe_messages.append(
                dict(
                    vtable=hex(struct.unpack("<Q", u.mem_read(message, 8))[0]),
                    presence=struct.unpack("<I", u.mem_read(message + 0x10, 4))[0],
                    sequence=struct.unpack("<I", u.mem_read(message + 0x18, 4))[0],
                    requested=struct.unpack("<I", u.mem_read(message + 0x1C, 4))[0],
                    length_prefix=bool(u.reg_read(UC_X86_REG_R8) & 255),
                )
            )
        if hasattr(self, "decoded_response"):
            values = self.decoded_response
            if pc == 0x13A1DFE10:
                dest = u.reg_read(UC_X86_REG_RCX)
                u.mem_write(dest + 0x18, b"\x00\x02")
                u.mem_write(dest + 0x28, struct.pack("<I", values["received_ticks"]))
            if pc == 0x13A1E1420:
                message = u.reg_read(UC_X86_REG_RDX)
                u.mem_write(message + 0x10, struct.pack("<I", 3))
                u.mem_write(
                    message + 0x18,
                    struct.pack("<II", values["sequence"], values["size"]),
                )
                u.reg_write(UC_X86_REG_RAX, int(values.get("parsed", True)))
            if pc == 0x13A18E8F0:
                self.response_callbacks.append(
                    dict(
                        sequence=u.reg_read(UC_X86_REG_RDX) & 0xFFFFFFFF,
                        elapsed_ticks=u.reg_read(UC_X86_REG_R8) & 0xFFFFFFFF,
                    )
                )
        if pc == 0x13A1710F0:
            self.rate_inputs.append(
                dict(
                    bytes=u.reg_read(UC_X86_REG_RDX) & 0xFFFFFFFF,
                    hint=struct.unpack(
                        "<f",
                        (u.reg_read(UC_X86_REG_XMM2) & 0xFFFFFFFF).to_bytes(
                            4, "little"
                        ),
                    )[0],
                )
            )
        if pc in getattr(self, "sender_terminals", ()):
            self.sender_endpoints.append(hex(pc))
        if pc == 0x13A1F20BF and hasattr(self, "sender_terminals"):
            # Original forwarding code has already formed its bool return.
            self.sender_results.append(u.reg_read(UC_X86_REG_RAX) & 255)
        if pc == 0x13AC31740 and getattr(self, "provide_memset", False):
            address = u.reg_read(UC_X86_REG_RCX)
            value = u.reg_read(UC_X86_REG_RDX) & 255
            count = u.reg_read(UC_X86_REG_R8)
            assert count <= 100000
            u.mem_write(address, bytes([value]) * count)
            u.reg_write(UC_X86_REG_RAX, address)
        if pc == 0x110000:
            u.reg_write(
                UC_X86_REG_XMM0,
                int.from_bytes(struct.pack("<d", self.now), "little"),
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

# Nonempty event histograms: the original event handler updates a raw bin and
# original monotone pooling runs over all 190 bins. Initial exposure=1/event=0
# for every bin is explicit input, not a real network history or fitted model.
for entry in [0x13A170FC0, 0x13A171A10]:
    for initial_target, expected_bin in [(10, 0), (100, 10), (2000, 189)]:
        m = M(6)
        m.histogram_storage()
        m.f(m.obj + 0xA8, initial_target)
        m.call(entry)
        event_counts = struct.unpack("<190f", m.u.mem_read(0x3A02F8, 190 * 4))
        exposure = struct.unpack("<190f", m.u.mem_read(0x3A05F0, 190 * 4))
        pooled = struct.unpack("<190f", m.u.mem_read(0x3A08E8, 190 * 4))
        assert event_counts == tuple(
            1.0 if i == expected_bin else 0.0 for i in range(190)
        )
        assert exposure == tuple(
            1.0 if i < expected_bin else float(190 - expected_bin) for i in range(190)
        ), ("history pooling", entry, initial_target, exposure)
        assert pooled == tuple(0.0 if i < expected_bin else 1.0 for i in range(190))
        cases.append(
            dict(
                name="original-event-histogram",
                entry=hex(entry),
                initial_target=initial_target,
                raw_event_bin=expected_bin,
                pooled_exposure=list(exposure),
                pooled_events=list(pooled),
                target=m.readf(0xA8),
            )
        )

# Complete original rate-sample update (including real nonempty rate lookup).
# The 30-slot ring, its cursor/times, link estimate and pressure state are inputs.
for name, last_event, pressure, coefficient, hint, expected_link, expected_target in [
    ("stable-rate-growth", 0, 0, 1, 0, 10.012001037597656, 10.012001037597656),
    ("recent-loss-recompute", 9.99, 0, 1, 0, 10, 1),
    ("pressure-rate-reduction", 0, 1, 0.5, 0, 9.925, 4.9625),
    ("rate-hint-path", 0, 0, 1, 5000, 10.01200008392334, 10.01200008392334),
]:
    m = M(10)
    m.critical_sections()
    m.q(m.obj + 0x18, 0x380000)
    m.q(m.obj + 0x20, 0x390000)
    m.u.mem_write(0x380000, struct.pack("<30f", *([1.0] * 30)))
    m.u.mem_write(
        0x390000, struct.pack("<30d", *[10 - (29 - i) * 0.1 for i in range(30)])
    )
    m.u.mem_write(m.obj + 0x28, struct.pack("<I", 29))
    m.f(m.obj + 0x54, 1000 / 60)
    m.f(m.obj + 0x9C, 10)
    m.f(m.obj + 0xA0, coefficient)
    m.f(m.obj + 0xA4, 1)
    m.u.mem_write(m.obj + 0x8C, bytes([pressure]))
    m.d(m.obj + 0x90, last_event)
    m.u.reg_write(UC_X86_REG_XMM2, int.from_bytes(struct.pack("<f", hint), "little"))
    m.call(0x13A1710F0, frame=125000)
    assert math.isclose(m.readf(0x98), expected_link, rel_tol=1e-6), (
        name,
        m.readf(0x98),
    )
    assert math.isclose(m.readf(0xA8), expected_target, rel_tol=1e-6), (
        name,
        m.readf(0xA8),
    )
    assert struct.unpack("<I", m.u.mem_read(m.obj + 0x28, 4))[0] == 0
    assert struct.unpack("<f", m.u.mem_read(0x380000 + 29 * 4, 4))[0] == 1.0
    assert struct.unpack("<d", m.u.mem_read(0x390000 + 29 * 8, 8))[0] == 10.0
    cases.append(
        dict(
            name=name,
            last_event=last_event,
            pressure=bool(pressure),
            coefficient=coefficient,
            hint=hint,
            ring_cursor=0,
            inserted_sample_mbits=1.0,
            link=m.readf(0x98),
            target=m.readf(0xA8),
        )
    )

# Enter the real single-frame sender, not the rate-update consumer directly.
# A valid UNENCRYPTED body and buffer metadata are explicit inputs. Only final
# frame deletion and OS/global send guards are terminals. The actual forwarder
# runs with an explicitly absent connection and returns false itself; header
# subtraction, key-frame/mode gates, sequence and rate update run original code.
for name, enabled, keyframe, mode, header_flag16, header_flag17, offset, quantity in [
    ("delta-body", 1, 0, 0, 0, 0, 0, 125000),
    ("delta-body-extra-headers", 1, 0, 0, 1, 1, 5, 125000),
    ("delta-body-smaller", 1, 0, 0, 0, 0, 0, 50000),
    ("key-body-excluded", 1, 1, 0, 0, 0, 0, 125000),
    ("mode9-key-body-included", 1, 1, 9, 0, 0, 0, 125000),
    ("disabled-sender", 0, 0, 0, 0, 0, 0, 125000),
]:
    root, packet, buffer, data = 0x200000, 0x300000, 0x310000, 0x320000
    m = M(10, obj=root + 0x4928)
    m.rate_storage()
    m.u.mem_write(m.obj + 8, bytes([enabled]))
    m.u.mem_write(root + 0x51B0, struct.pack("<I", mode))
    m.u.mem_write(root + 0x51D0, struct.pack("<H", 7))
    # Explicit channel identifiers avoid unrelated retransmission/statistics
    # bookkeeping in the actual forwarder. They are not inferred defaults.
    m.u.mem_write(root + 0x2FD, b"\x01\x02")
    m.q(packet + 8, buffer)
    m.u.mem_write(packet + 0x10, bytes([header_flag16, header_flag17]))
    m.u.mem_write(packet + 0x14, struct.pack("<I", offset))
    m.u.mem_write(packet + 0x18, b"\x03")
    headers = 13 + header_flag16 + 12 * header_flag17 + offset
    m.u.mem_write(buffer + 0x34, struct.pack("<I", headers + quantity))
    m.q(buffer + 0x38, data)
    m.u.mem_write(data + headers + 2, bytes([0x08 | (0x10 if keyframe else 0)]))
    m.sender_terminals = (0x13A1F6E60, 0x13A1F6E70, 0x13A1EC710)
    for terminal in m.sender_terminals:
        # Single-thread send guards and frame deletion are explicit boundaries;
        # the original no-connection branch decides the forwarding result.
        m.u.mem_write(terminal, b"\x31\xc0\xc3")
    m.call(0x13A192B90, ctx=root, frame=packet)
    counted = bool(enabled and (not keyframe or mode == 9))
    assert m.sender_endpoints == [hex(pc) for pc in m.sender_terminals]
    assert m.sender_results == [0], ("original no-connection send", m.sender_results)
    assert m.rate_inputs == ([dict(bytes=quantity, hint=0.0)] if counted else []), (
        name,
        m.rate_inputs,
    )
    cursor = struct.unpack("<I", m.u.mem_read(m.obj + 0x28, 4))[0]
    inserted = struct.unpack("<f", m.u.mem_read(0x380000 + 29 * 4, 4))[0]
    assert cursor == (0 if counted else 29)
    assert math.isclose(
        inserted, quantity * 8 / 1000000 if counted else 1, rel_tol=1e-6
    )
    assert struct.unpack("<H", m.u.mem_read(data + headers, 2))[0] == 7
    assert struct.unpack("<H", m.u.mem_read(root + 0x51D0, 2))[0] == 8
    cases.append(
        dict(
            name="original-sender-" + name,
            enabled=bool(enabled),
            key_frame=bool(keyframe),
            mode_field=mode,
            transport_headers_and_offset=headers,
            body_bytes=quantity,
            rate_inputs=m.rate_inputs,
            ring_cursor=cursor,
            inserted_sample_mbits=inserted,
            effect_endpoints=m.sender_endpoints,
            original_forwarder_results=m.sender_results,
        )
    )

# The actual host setter derives the ping-growth threshold from frame period.
# The caller's real FPS lookup/fallback is statically bound separately; these
# FPS values are consumer-boundary inputs, not measured host frame rates.
for fps, expected_coefficient in [(30, 1.0), (60, 1.0), (120, 0.2043309211730957)]:
    parent = 0x200000
    m = M(2, obj=parent + 0x400)
    m.critical_sections()
    m.q(m.obj + 0x58, 0x380000)
    m.u.mem_write(0x380000, struct.pack("<500f", *([10.0] * 500)))
    m.u.mem_write(m.obj + 0x0C, struct.pack("<I", 1))
    m.u.mem_write(parent + 0x408, b"\x01")
    m.u.reg_write(UC_X86_REG_XMM1, int.from_bytes(struct.pack("<f", fps), "little"))
    m.call(0x13A171E70)
    threshold = m.readf(0x54)
    assert math.isclose(threshold, 1000 / fps, rel_tol=1e-6), (
        "fps threshold",
        fps,
        threshold,
    )
    m.u.reg_write(
        UC_X86_REG_R8, 1638
    )  # 24.993896ms, same 16.16 quantization as earlier.
    m.call(0x13A18E8F0, ctx=parent, frame=0)
    coefficient = m.readf(0xA0)
    assert math.isclose(coefficient, expected_coefficient, rel_tol=1e-6), (
        "fps-bound coefficient",
        fps,
        coefficient,
        expected_coefficient,
    )
    cases.append(
        dict(
            name="original-fps-threshold-to-ping",
            fps=fps,
            threshold_ms=threshold,
            baseline_ms=10.0,
            new_sample_ticks=1638,
            coefficient=coefficient,
            target=m.readf(0xA8),
        )
    )

# The thread member and estimator callback vtables are those installed by the
# actual constructors. The worker's OS sleep is bounded; the original worker,
# callback, request/list producer and integer protobuf constructor all execute.
# Frame::Put is the observation boundary, NOT serialized packets or delivery.
for name, slot, counter, active, iterations, sequences, final_counter in [
    ("zero-slot-auto-sequence", 0, 0, 1, 1, [1], 1),
    ("ordinary-slots", 1, 700, 1, 2, [1, 2], 700),
    ("wrap-slot-zero-auto", 499, 700, 1, 2, [499, 701], 701),
    ("inactive-no-probe", 0, 700, 0, 0, [], 700),
]:
    root = 0x200000
    m = M(2, obj=root + 0x4928)
    m.probe_storage(root)
    thread = m.obj + 0x100
    m.q(thread, 0x13AC8B458)
    m.q(thread + 0x48, m.obj)
    m.q(m.obj, root + 0x4548)
    m.q(root + 0x4548, 0x13AC8FB38)
    m.u.mem_write(m.obj + 0x0C, struct.pack("<I", active))
    m.u.mem_write(m.obj + 0x60, struct.pack("<I", slot))
    m.u.mem_write(root + 0x26C, struct.pack("<I", counter))
    m.q(0x13AC4B4E8, 0x110500)
    m.u.mem_write(0x110500, b"\xc3")
    m.probe_iterations = iterations
    worker = struct.unpack("<Q", m.u.mem_read(0x13AC8B468, 8))[0]
    assert worker == 0x13A171D60
    m.call(worker, ctx=thread)
    assert m.probe_sleeps == [20] * iterations
    assert m.probe_messages == [
        dict(
            vtable="0x13ad5c9f0",
            presence=3,
            sequence=seq,
            requested=0,
            length_prefix=True,
        )
        for seq in sequences
    ], (name, m.probe_messages)
    window = struct.unpack("<500f", m.u.mem_read(0x380000, 500 * 4))
    expired = {(slot + i) % 500 for i in range(iterations)}
    assert window == tuple(-1.0 if i in expired else 10.0 for i in range(500)), (
        "worker slot expiry",
        name,
    )
    cursor = struct.unpack("<I", m.u.mem_read(m.obj + 0x60, 4))[0]
    assert cursor == (slot + iterations) % 500
    assert struct.unpack("<I", m.u.mem_read(root + 0x26C, 4))[0] == final_counter
    count = struct.unpack("<I", m.u.mem_read(root + 0x29C, 4))[0]
    nodes = [
        struct.unpack("<6I", m.u.mem_read(0x330000 + i * 24, 24)) for i in range(count)
    ]
    assert count == iterations and [node[0] for node in nodes] == sequences
    assert all(node[1] == 0 and node[2] == 131072 and node[3] == 0 for node in nodes)
    cases.append(
        dict(
            name="original-probe-worker-" + name,
            initial_slot=slot,
            requested_sleeps_ms=m.probe_sleeps,
            next_slot=cursor,
            invalidated_slots=sorted(expired),
            messages_at_put=m.probe_messages,
            pending_requests=count,
            initial_auto_counter=counter,
            final_auto_counter=final_counter,
            boundary="No wall-clock thread, Frame serialization, socket or client receipt",
        )
    )

# Exact original outstanding-request timeout boundaries, with preallocated
# list storage and one old request. No helper/free-list algorithm is replaced.
for now, expected_count, expected_used in [
    (30 - 1 / 65536, 2, 2),
    (30, 1, 1),
    (30 + 1 / 65536, 1, 1),
]:
    root = 0x200000
    m = M(now, obj=root + 0x4928)
    m.probe_storage(root)
    m.u.mem_write(root + 0x290, struct.pack("<5i", 0, 0, -1, 1, 1))
    m.u.mem_write(0x330000, struct.pack("<6I", 17, 0, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF))
    m.u.reg_write(UC_X86_REG_R8, 5)
    m.call(0x13A1EB010, ctx=root)
    count = struct.unpack("<I", m.u.mem_read(root + 0x29C, 4))[0]
    used = struct.unpack("<I", m.u.mem_read(root + 0x2A0, 4))[0]
    assert (count, used) == (expected_count, expected_used), (
        "request ledger expiry",
        now,
        count,
        used,
    )
    assert m.probe_messages == [
        dict(
            vtable="0x13ad5c9f0",
            presence=3,
            sequence=5,
            requested=0,
            length_prefix=True,
        )
    ]
    tail = struct.unpack("<I", m.u.mem_read(root + 0x294, 4))[0]
    assert struct.unpack("<I", m.u.mem_read(0x330000 + tail * 24, 4))[0] == 5
    # Now deliver a decoded reply for the old sequence through the real
    # receiver. It is eligible just before expiry, absent at/after expiry.
    m.q(root + 0x38, root + 0x4528)
    m.q(root + 0x4528, 0x13AC8F8B0)
    m.u.mem_write(m.obj + 8, b"\x01")
    m.u.mem_write(m.obj + 0x0C, struct.pack("<I", 1))
    m.u.reg_write(UC_X86_REG_XMM1, int.from_bytes(struct.pack("<f", 60), "little"))
    m.call(0x13A171E70)
    current_ticks = round(now * 65536)
    m.response_boundary(dict(sequence=17, size=0, received_ticks=current_ticks))
    m.u.reg_write(UC_X86_REG_R8, 0x300000)
    m.call(0x13A1F04D0, ctx=root)
    assert m.response_callbacks == (
        [dict(sequence=17, elapsed_ticks=current_ticks)] if expected_count == 2 else []
    )
    assert m.readf(0xA8) == (1 if expected_count == 2 else 10)
    cases.append(
        dict(
            name="original-outstanding-expiry",
            old_sent_ticks=0,
            current_ticks=round(now * 65536),
            pending_count=count,
            used_slots=used,
            tail_slot=tail,
            messages_at_put=m.probe_messages,
            old_reply_callbacks=m.response_callbacks,
            target_after_old_reply=m.readf(0xA8),
        )
    )

# Decoded response fields/frame metadata and the outstanding list are inputs.
# Execute the real receiver's lookup, size check, timestamp clamp and actual
# session RTTI callback -> ping window -> recomputation. The parser/copy and
# destructors are explicit terminals, not an authenticated wire experiment.
for (
    name,
    requested,
    size,
    sequence,
    received,
    parsed,
    enabled,
    repeats,
    nodes_count,
    admitted,
) in [
    ("zero-size", 0, 0, 17, 65536 + 1638, True, 1, 1, 1, True),
    ("zero-request-ignores-size", 0, 1472, 17, 65536 + 1638, True, 1, 1, 1, True),
    ("matching-size", 64, 64, 17, 65536 + 1638, True, 1, 1, 1, True),
    ("size-mismatch", 64, 65, 17, 65536 + 1638, True, 1, 1, 1, False),
    ("unknown-sequence", 0, 0, 18, 65536 + 1638, True, 1, 1, 1, False),
    ("negative-time-clamped", 0, 0, 17, 65535, True, 1, 1, 1, True),
    ("duplicate-response", 0, 0, 17, 65536 + 1638, True, 1, 2, 1, True),
    ("newest-duplicate-request", 0, 0, 17, 65536 + 1638, True, 1, 1, 2, True),
    ("disabled-estimator", 0, 0, 17, 65536 + 1638, True, 0, 1, 1, True),
    ("parse-failure", 0, 0, 17, 65536 + 1638, False, 1, 1, 1, False),
]:
    root, requests = 0x200000, 0x330000
    m = M(2, obj=root + 0x4928)
    m.response_boundary(
        dict(sequence=sequence, size=size, received_ticks=received, parsed=parsed)
    )
    m.q(root + 0x280, requests)
    m.u.mem_write(root + 0x294, struct.pack("<I", nodes_count - 1))
    m.u.mem_write(root + 0x29C, struct.pack("<I", nodes_count))
    for i in range(nodes_count):
        m.u.mem_write(
            requests + i * 24,
            struct.pack(
                "<6I",
                17,
                requested,
                65536 if i == nodes_count - 1 else 0,
                0,
                i - 1 if i else 0xFFFFFFFF,
                i + 1 if i + 1 < nodes_count else 0xFFFFFFFF,
            ),
        )
    m.q(root + 0x38, root + 0x4528)
    m.q(root + 0x4528, 0x13AC8F8B0)
    m.u.mem_write(m.obj + 8, bytes([enabled]))
    m.u.mem_write(m.obj + 0x0C, struct.pack("<I", 1))
    m.q(m.obj + 0x58, 0x380000)
    m.u.mem_write(0x380000, struct.pack("<500f", *([10.0] * 500)))
    m.f(m.obj + 0xA0, 0.5)
    m.u.reg_write(UC_X86_REG_XMM1, int.from_bytes(struct.pack("<f", 60), "little"))
    m.call(0x13A171E70)
    for _ in range(repeats):
        m.u.reg_write(UC_X86_REG_R8, 0x300000)
        m.call(0x13A1F04D0, ctx=root)
    expected_callbacks = (
        [dict(sequence=17, elapsed_ticks=max(received - 65536, 0))] * repeats
        if admitted
        else []
    )
    assert m.response_callbacks == expected_callbacks, (name, m.response_callbacks)
    expected_coefficient = 0.5 + repeats * 0.04 if admitted and enabled else 0.5
    expected_target = expected_coefficient * 10 if admitted and enabled else 10
    assert math.isclose(m.readf(0xA0), expected_coefficient, rel_tol=1e-6), (
        name,
        m.readf(0xA0),
    )
    assert math.isclose(m.readf(0xA8), expected_target, rel_tol=1e-6), (
        name,
        m.readf(0xA8),
    )
    stamps = [
        struct.unpack("<I", m.u.mem_read(requests + i * 24 + 12, 4))[0]
        for i in range(nodes_count)
    ]
    assert stamps == [0] * (nodes_count - 1) + (
        [max(received, 65536)] if admitted else [0]
    )
    assert struct.unpack("<I", m.u.mem_read(root + 0x29C, 4))[0] == nodes_count
    cases.append(
        dict(
            name="original-response-" + name,
            outstanding_requested=requested,
            response_size=size,
            response_sequence=sequence,
            parsed=parsed,
            received_ticks=received,
            enabled=bool(enabled),
            repeats=repeats,
            callbacks=m.response_callbacks,
            outstanding_count=nodes_count,
            stored_receive_stamps=stamps,
            coefficient=m.readf(0xA0),
            target=m.readf(0xA8),
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
                "Enter/LeaveCriticalSection for explicit single-thread fixtures",
                "memset for event-histogram storage",
                "single-thread global send guards and frame deletion",
                "bounded worker Sleep with no actual delay or thread scheduling",
                "packet timestamp; Frame construction/Put/destruction for request-object observation only",
                "explicit decoded response fields and copied frame metadata; parser and destructors are terminals",
            ],
            "input_boundary": "Fixtures separately cover empty buffers, nonempty 190-bin event histograms, an explicit 30-slot rate ring and 500-slot ping windows. A valid unencrypted frame buffer enters the real sender and forwarder. Connection absent and nonmatching channel IDs are explicit inputs; the original forwarder returns false. Global guards and frame deletion are terminals, not remote delivery. Header subtraction, key-frame/mode gates, sequence and rate update run original code. Explicit FPS inputs enter the real frame-period setter and ping feedback. A bounded original worker executes callback/request/list/sequence selection and original request construction; Frame::Put is an object observation boundary, not protobuf serialization. The actual response receiver consumes explicit decoded fields/copied frame metadata and executes lookup/size/time gates plus the original RTTI callback/window/recompute. Storage, clocks, pressure/enable/thread fields remain explicit inputs; no complete constructor/concurrent worker/history lifecycle is claimed. No actual host packets/encoder device/runtime evidence.",
            "probe_bindings": {
                "session_constructor": "0x13a189cc0",
                "estimator_member_offset": "0x4928",
                "request_callback_member_offset": "0x4548",
                "request_callback_vtable": "0x13ac8fb38",
                "request_callback_entry": hex(
                    struct.unpack("<Q", image[0xC8FB40:0xC8FB48])[0]
                ),
                "worker_thread_vtable": "0x13ac8b458",
                "worker_entry": hex(struct.unpack("<Q", image[0xC8B468:0xC8B470])[0]),
                "outstanding_expiry_ticks": struct.unpack(
                    "<I", image[0x10BBEE0:0x10BBEE4]
                )[0],
            },
            "cases": cases,
            "source_ranges": {
                hex(a): hashlib.sha256(image[a - base : z - base]).hexdigest()
                for a, z in [
                    (0x13A172500, 0x13A1725B9),
                    (0x13A1710F0, 0x13A171811),
                    (0x13A170E80, 0x13A170FA2),
                    (0x13A192B90, 0x13A192DA6),
                    (0x13A1F1EB0, 0x13A1F20C7),
                    (0x13A171E70, 0x13A171E82),
                    (0x13A171D60, 0x13A171DEB),
                    (0x13A18B320, 0x13A18B331),
                    (0x13A1EB010, 0x13A1EB335),
                    (0x13A1EAD10, 0x13A1EAE8C),
                    (0x13A1F5950, 0x13A1F5A16),
                    (0x13A4797A0, 0x13A4797BC),
                    (0x13A4797C0, 0x13A4797DC),
                    (0x13A1F04D0, 0x13A1F063A),
                    (0x13A189D53, 0x13A189D62),
                    (0x13A189F54, 0x13A189FAD),
                    (0x13A171FD0, 0x13A172500),
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
