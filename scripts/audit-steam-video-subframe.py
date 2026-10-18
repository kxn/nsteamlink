#!/usr/bin/env python3
"""Execute official subframe range parsing, ordered partials and finishing identity.

Original constructors/DecodeFrame/RunDecodeLoop/OnThink/AppendBuffer/crypto and
Android SDK input execute. OS Wait is a bounded scheduler terminal: wait1 permits
another real loop; wait0/reset or UINT_MAX/idle returns to the harness, preserving
active state for later actions. No claim of physical timing/concurrent threads.
SDK/JNI/NAL parameter metadata, platform primitives, network/control/statistics
endpoints inherit explicit boundaries from the crypto audit. Full partial lists,
32-bit range state, sequence, bytes, feedback order and submitted identity are
read from actual storage/SDK calls, not an observer policy model. Host producer
reachability/all slice grammar/physical decode/statistics outcome remain separate.
"""

import argparse
import hashlib
import importlib.util
import json
import struct
import io
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "crypto", ROOT / "scripts/audit-steam-video-crypto.py"
)
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
c = v.c


class Range(v.Crypto):
    def __init__(self, binary, inp):
        self.waits = []
        self.overflows = []
        super().__init__(
            binary, dict(keylen=16, backend=inp["backend"], codec=inp["codec"])
        )
        self.waits.clear()

    def hook(self, u, a, z, ctx):
        if a == 0xC0E110 and self.r(1) == 148:
            copy = self.freeze(self.r(2), 64)
            entry = ["overflow", self.action, None]
            self.flow.append(entry)
            self.overflows.append((entry, copy))
            self.ret()
            return
        if self.plts.get(a) == "_ZN16SteamThreadTools17CThreadSyncObject4WaitEj":
            delay = self.r(1) & 0xFFFFFFFF
            self.waits.append([self.action, delay])
            if delay in (0, 0xFFFFFFFF):
                self.b(self.video + 24, 0)
            assert len(self.waits) < 80
            self.ret(1)
            return
        super().hook(u, a, z, ctx)

    def feed(self, fid, seq, flags, payload, think=True, start=0, end=0):
        body = (
            b"\1"
            + struct.pack("<HIHI", fid, 1000000, 0, 0)
            + struct.pack("<HBHH", seq, flags, start, end)
            + payload
        )
        packet = self.packet(5, 3, False, 12, 34, len(body))
        self.labels[packet] = f"input_{fid}_{seq}"
        self.u.mem_write(self.q(packet + 40) + 13, body)
        frame = self.alloc(64)
        self.call(self.symbols["_ZN12CStreamFrameC1EP13CStreamPacket"], frame, packet)
        self.call(0x7B2000, self.video, frame)
        self.call(self.symbols["_ZN12CStreamFrameD1Ev"], frame)
        self.refs[f"input_{fid}_{seq}"] = packet
        if think:
            self.call(0x766D50, self.video)
            self.b(self.video + 24, 1)

    def h(self, p):
        return struct.unpack("<H", self.u.mem_read(p, 2))[0]

    def observe(self):
        for entry, copy in self.overflows:
            if entry[2] is None:
                entry[2] = self.serialize(copy, "CStreamVideoOverflowMsg").hex()
        state = super().observe()
        rows = []
        idx = self.i(self.video + 440)
        base = self.q(self.video + 424)
        while idx != 0xFFFFFFFF:
            p = base + idx * 40
            packet = self.q(p + 24)
            off = self.i(p + 20)
            size = self.i(packet + 52) - off
            rows.append(
                [
                    self.h(p),
                    self.h(p + 2),
                    self.u.mem_read(p + 8, 1)[0],
                    self.i(p + 12),
                    self.i(p + 16),
                    bytes(self.u.mem_read(self.q(packet + 56) + off, size)).hex(),
                ]
            )
            idx = self.i(p + 36)
            assert len(rows) < 100
        state.update(
            next_range=self.i(self.video + 420),
            partial=rows,
            next_seq=self.h(self.video + 416),
            overflow_span=self.i(self.video + 412),
            waits=list(self.waits),
        )
        return state


def run(binary, inp, ops):
    x = Range(binary, inp)
    states = []
    for n, a in enumerate(ops):
        x.action = n
        if a[0] == "S":
            _, fid, seq, flags, start, end, body = a
            x.feed(fid, seq, flags, bytes.fromhex(body), start=start, end=end)
        elif a[0] == "R":
            x.call(0x7A5FF8, c.CLIENT)
        elif a[0] == "Q":
            x.call(0x7AD394, c.CLIENT, 0)
        else:
            raise ValueError(a)
        states.append(x.observe())
        assert not x.assertions, (inp, n, x.assertions)
    return dict(input=inp, actions=ops, states=states)


def op(fid, seq, flags, start, end, body):
    return ["S", fid, seq, flags, start, end, body]


def static(binary):
    elf = ELFFile(io.BytesIO(binary))
    text = elf.get_section_by_name(".text")
    base = text["sh_addr"]
    data = text.data()
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    return [
        dict(
            name=name,
            instructions=[
                [i.address, i.mnemonic, i.op_str, i.bytes.hex()]
                for i in md.disasm(data[at - base : at - base + size], at)
            ],
        )
        for name, at, size in [
            ("DecodeFrame", 0x7B2000, 1244),
            ("OnThink", 0x7B24DC, 808),
            ("RunDecodeLoop", 0x766D50, 276),
        ]
    ]


def negative_checks(binary, cases):
    constructor = Range.__init__

    def selected(shape):
        return next(
            c for c in cases if c["input"] == dict(codec=4, backend=True, shape=shape)
        )

    def rules(end, advance, start):
        return next(
            c
            for c in cases
            if c["input"]
            == dict(
                codec=4,
                backend=True,
                shape="range_rules",
                end=end,
                advance=advance,
                finish=0,
                start=start,
            )
        )

    checks = [
        (
            "truncate_next_to_uint16",
            [(0x7B256C, 0x79000000 | (210 << 10) | (19 << 5) | 8)],
            rules(65535, 4, 0),
        ),
        ("bypass_range_mismatch", [(0x7B2558, 0xD503201F)], rules(1, 4, 0)),
        (
            "sort_equal_boundary_before",
            [
                (
                    0x7B22DC,
                    0x54000000 | (((0x7B22B0 - 0x7B22DC) // 4 & 0x7FFFF) << 5) | 11,
                )
            ],
            selected("equal_boundary_no_insert"),
        ),
        ("use_first_identity", [(0x7B261C, 0x52800037)], rules(0, 0, 0)),
        (
            "advance_without_bit2",
            [(0x7B2560, 0xD503201F)],
            selected("carry_finish_without_bit2"),
        ),
        ("check_zero_end", [(0x7B2548, 0xD503201F)], selected("end_zero_bypass")),
    ]
    found = []
    keys = ("next_range", "partial", "body", "flow")
    try:
        for name, patches, baseline in checks:

            def modified(self, *args, **kwargs):
                constructor(self, *args, **kwargs)
                for pc, word in patches:
                    self.u.mem_write(pc, struct.pack("<I", word))
                    self.u.ctl_remove_cache(pc, pc + 4)

            Range.__init__ = modified
            got = run(binary, baseline["input"], baseline["actions"])

            def projection(c):
                return [{k: s[k] for k in keys} for s in c["states"]]

            assert projection(got) != projection(baseline), (
                "undetected original mutation",
                name,
            )
            found.append(name)
    finally:
        Range.__init__ = constructor
    return found


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == c.SHA
    cases = []
    for codec in (4, 5):
        for backend in (False, True):
            base = dict(codec=codec, backend=backend)
            for end in (0, 1, 65535):
                for advance in (0, 4):
                    for finish in (0, 8):
                        for start in (0, 2):
                            inp = dict(
                                base,
                                shape="range_rules",
                                end=end,
                                advance=advance,
                                finish=finish,
                                start=start,
                            )
                            cases.append(
                                run(
                                    binary,
                                    inp,
                                    [
                                        op(1, 1, 16 | advance | finish, 0, end, "41"),
                                        op(2, 2, 8, start, 3, "42"),
                                        op(3, 3, 24, 0, 0, "43"),
                                    ],
                                )
                            )
            variants = {
                "queued_finishes": [
                    op(1, 1, 28, 2, 3, "42"),
                    op(2, 2, 12, 0, 1, "43"),
                    op(1, 3, 4, 0, 1, "41"),
                ],
                "reverse_repair": [
                    op(1, 1, 16, 2, 3, "42"),
                    op(1, 2, 4, 0, 1, "41"),
                    op(1, 3, 12, 2, 3, "43"),
                ],
                "strict_order_before": [
                    op(1, 1, 16, 3, 4, "42"),
                    op(1, 2, 4, 0, 2, "41"),
                    op(1, 3, 12, 3, 4, "43"),
                ],
                "equal_boundary_no_insert": [
                    op(1, 1, 16, 3, 4, "42"),
                    op(1, 2, 4, 0, 3, "41"),
                    op(1, 3, 12, 3, 4, "43"),
                ],
                "different_id_no_sort": [
                    op(1, 1, 16, 2, 3, "42"),
                    op(2, 2, 4, 0, 1, "41"),
                    op(2, 3, 12, 2, 3, "43"),
                ],
                "end_zero_bypass": [
                    op(1, 1, 20, 0, 65535, "41"),
                    op(2, 2, 12, 65535, 0, "42"),
                ],
                "carry_finish_without_bit2": [
                    op(1, 1, 20, 0, 1, "41"),
                    op(1, 2, 8, 2, 3, "42"),
                    op(2, 3, 12, 0, 1, "43"),
                ],
                "carry_finish_then_matching": [
                    op(1, 1, 20, 0, 1, "41"),
                    op(1, 2, 8, 2, 3, "42"),
                    op(2, 3, 12, 2, 3, "43"),
                ],
                "finish_bit2_resets": [
                    op(1, 1, 20, 0, 1, "41"),
                    op(1, 2, 12, 2, 3, "42"),
                    op(2, 3, 12, 0, 1, "43"),
                ],
                "reversed_numeric_range": [
                    op(1, 1, 16, 0, 0, "41"),
                    op(2, 2, 12, 0, 65535, "42"),
                ],
                "wire_sequence_wrap": [
                    op(1, 65535, 16, 0, 0, "41"),
                    op(2, 0, 8, 0, 0, "42"),
                ],
                "sequence_gap": [op(1, 1, 16, 0, 0, "41"), op(2, 3, 8, 0, 0, "42")],
                "reset_partial": [
                    op(1, 1, 20, 0, 1, "41"),
                    ["Q"],
                    ["R"],
                    op(2, 2, 24, 0, 0, "42"),
                ],
                "pending_cross_identity": [
                    ["Q"],
                    op(1, 1, 16, 0, 0, "41"),
                    op(2, 2, 8, 0, 0, "42"),
                    op(3, 3, 8, 0, 0, "43"),
                    ["R"],
                    op(4, 4, 24, 0, 0, "44"),
                ],
            }
            for shape, ops in variants.items():
                ops = ops + [op(5, 5, 24, 0, 0, "45")]
                cases.append(run(binary, dict(base, shape=shape), ops))
            for encrypted in (False, True):
                payload = v.m.PAYLOAD
                ops = []
                for n in range(4):
                    piece = payload[n * 551 : (n + 1) * 551]
                    flags = 4 | (16 if n == 0 else 0) | (8 if n == 3 else 0)
                    if encrypted:
                        flags |= 32
                        piece = v.encrypt(v.padded(piece), bytes(range(16)))
                    ops.append(
                        op(
                            1 if n < 2 else 2,
                            n + 1,
                            flags,
                            n * 2,
                            n * 2 + 1,
                            piece.hex(),
                        )
                    )
                cases.append(
                    run(
                        binary,
                        dict(base, shape="real_fixture", encrypted=encrypted),
                        ops,
                    )
                )
    return dict(
        binary_sha256=c.SHA,
        boundary=__doc__,
        cases=cases,
        static=static(binary),
        mutation_checks=negative_checks(binary, cases),
    )


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--write", type=Path)
    p.add_argument("--check", type=Path)
    a = p.parse_args()
    r = audit(a.binary.read_bytes())
    if a.write:
        a.write.write_text(json.dumps(r, indent=2) + "\n")
    if a.check:
        assert r == json.loads(a.check.read_text())
    print(
        "Official subframe:",
        len(r["cases"]),
        "cases/",
        sum(len(x["states"]) for x in r["cases"]),
        "states",
    )
