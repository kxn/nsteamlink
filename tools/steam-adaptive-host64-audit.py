#!/usr/bin/env python3
"""Execute pinned x64 Steam host adaptive-bitrate boundaries offline.

Original recomputation, loss/overflow and ping-window handlers, callback gates/latch, actual RTTI
bitrate getter and encoding-stage min/store execute original instructions. Time
and logging are providers. Fixtures distinguish absent buffers from explicit
30-slot rate, 190-bin event and 500-slot ping storage. Original lookup, update
and pooling branches execute, with declared critical-section/memset terminals. The optional independent
rate callback, downstream frame delivery and frame deletion are explicit endpoints.
Unencrypted frame metadata also enters the real sender and FPS enters the real
frame-period setter before ping feedback. No Steam
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

    def hook(self, u, pc, size, data):
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
            ],
            "input_boundary": "Fixtures separately cover empty buffers, nonempty 190-bin event histograms, an explicit 30-slot rate ring and 500-slot ping windows. A valid unencrypted frame buffer enters the real sender and forwarder. Connection absent and nonmatching channel IDs are explicit inputs; the original forwarder returns false. Global guards and frame deletion are terminals, not remote delivery. Header subtraction, key-frame/mode gates, sequence and rate update run original code. Explicit FPS inputs enter the real frame-period setter and ping feedback. Storage, clocks, pressure/enable/thread fields remain explicit inputs; no full constructor/worker/history lifecycle is claimed. Source gate/latch, ping conversion/window/coefficient, recomputation, actual session RTTI bitrate getter and real stage min/store execute original instructions. No actual host packets/encoder device/runtime evidence.",
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
