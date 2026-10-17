#!/usr/bin/env python3
"""Execute original NAL assembly, suffix reads, CPU selector and SDK input bytes.

Original constructors/CPU-bit selection, DecodeFrame/OnThink/H264 AppendBuffer,
both CopyAndEscapeNAL bodies, buffer growth/Read and Android SDK input execute.
Crypto uses the original helper too. CPU features at GetCPUInformation's ctor
call, SDK/JNI/NAL metadata/libc/ref primitives/OS/network are declared boundaries.
Owned output-history reads are checked separately from Source assert cases and
reads before the encoded allocation. Those unsafe contexts are evidence, never
an assumed zero-history protocol rule. HEVC is the same original class/constructor
input; availability has a separate actual control/factory capability probe. No
physical HEVC/GPU/host producer/all slice grammar or other factories proof.
"""

import argparse
import hashlib
import importlib.util
import json
import io
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from elftools.elf.elffile import ELFFile
import re
from pathlib import Path
from unicorn import UC_HOOK_MEM_READ
from unicorn.arm64_const import UC_ARM64_REG_PC

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "crypto", ROOT / "scripts/audit-steam-video-crypto.py"
)
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
c = v.c


class Nal(v.Crypto):
    def __init__(self, binary, inp):
        self.cpu = inp["cpu"]
        self.history_reads = 0
        self.outside = []
        self.helper_calls = []
        super().__init__(
            binary,
            dict(
                keylen=16,
                backend=True,
                codec=inp["codec"],
                threads=inp.get("threads", True),
            ),
        )
        self.u.hook_add(UC_HOOK_MEM_READ, self.memory)
        self.selected = self.q(self.video + 608)
        assert self.selected == (0x802A3C if self.cpu & 16 else 0x8029F0)

    def hook(self, u, address, size, ctx):
        if address == 0xC0E860:
            # System CPU-information terminal. The real constructor tests bit
            # 0x10 and installs its real scalar/SIMD function pointer.
            p = self.alloc(128)
            self.wi(p + 4, self.cpu)
            self.ret(p)
            return
        if address in (0x8029F0, 0x802A3C) and self.tracing:
            self.helper_calls.append([self.action, address, self.r(2) & 0xFFFFFFFF])
        super().hook(u, address, size, ctx)

    def memory(self, u, access, address, size, value, ctx):
        pc = u.reg_read(UC_ARM64_REG_PC)
        if pc in (0x802A20, 0x802A28, 0x802A6C, 0x802A74):
            self.history_reads += 1
            base = self.q(self.video + 480)
            if address < base:
                self.outside.append(
                    [
                        self.action,
                        pc,
                        address - base,
                        bytes(u.mem_read(address, size)).hex(),
                    ]
                )

    def observe(self):
        s = super().observe()
        s.update(
            history_reads=self.history_reads,
            outside=list(self.outside),
            helper_calls=list(self.helper_calls),
        )
        return s


def run(binary, inp, actions, source_only=False):
    x = Nal(binary, inp)
    states = []
    for n, a in enumerate(actions):
        x.action = n
        if a[0] == "F":
            x.feed(*a[1:4], bytes.fromhex(a[4]))
        elif a[0] == "Q":
            x.call(0x7AD394, c.CLIENT, 0)
        elif a[0] == "R":
            x.call(0x7A5FF8, c.CLIENT)
        else:
            raise ValueError(a)
        states.append(x.observe())
        if not source_only:
            assert not x.assertions and not x.outside, (inp, n, x.assertions, x.outside)
    if source_only:
        assert x.assertions or x.outside, (inp, "expected explicit unsafe boundary")
    return dict(input=inp, actions=actions, states=states, selected=x.selected)


def factory(binary):
    sp = importlib.util.spec_from_file_location(
        "start", ROOT / "scripts/audit-steam-video-start.py"
    )
    st = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(st)

    class F(st.Video):
        def __init__(self):
            self.availability = []
            super().__init__(binary, True, True, True, fallback=5)

        def hook(self, u, a, z, ctx):
            if self.plts.get(a) == "AMediaCodec_createDecoderByType":
                self.availability.append(self.cstring(self.r(0)))
                self.ret(
                    self.alloc(64)
                )  # Explicit SDK capability input, not physical support.
            else:
                super().hook(u, a, z, ctx)

    x = F()
    schema = st.r.d.o.audio.schema(binary)
    msg = schema("CStartVideoDataMsg", channel=3, codec=5, width=1280, height=720)
    x.control(52, msg.SerializeToString())
    s = x.snapshot()
    assert not s["assertions"] and s["decoder"]["codec"] == 5
    return dict(
        input=msg.SerializeToString().hex(),
        sdk_available=True,
        mime=x.availability,
        state=s,
    )


def fixture_actions(encrypted):
    payload = v.m.PAYLOAD
    starts = list(re.finditer(b"\x00\x00\x00\x01|\x00\x00\x01", payload))
    expected = b""
    pieces = []
    boundaries = 0
    for n, marker in enumerate(starts):
        end = starts[n + 1].start() if n + 1 < len(starts) else len(payload)
        original = payload[marker.end() : end]
        expected += b"\0\0\0\1" + original
        raw, zeros = bytearray(), 0
        for byte in original:
            if zeros == 2 and byte == 3:
                zeros = 0
                continue
            raw.append(byte)
            zeros = zeros + 1 if byte == 0 else 0
        cut = next(
            (
                i
                for i in range(3, len(raw))
                if raw[i - 2 : i] == b"\0\0" and raw[i] <= 3
            ),
            None,
        )
        if cut is not None:
            boundaries += 1
        else:
            cut = max(1, len(raw) // 2)
        chunks = [bytes(raw[:cut]), bytes(raw[cut:])]
        for j, chunk in enumerate(chunks):
            if not chunk:
                continue
            flags = 2 | (1 if j == 0 else 0)
            if not pieces:
                flags |= 16
            if encrypted:
                flags |= 32
                chunk = v.encrypt(v.padded(chunk), bytes(range(16)))
            pieces.append(["F", 1, len(pieces) + 1, flags, chunk.hex()])
    assert boundaries > 0
    pieces[-1][3] |= 8
    return pieces, expected.hex(), boundaries


def static(binary):
    elf = ELFFile(io.BytesIO(binary))
    text = elf.get_section_by_name(".text")
    base, data = text["sh_addr"], text.data()
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    result = []
    for name, address, length in (
        ("H264_constructor", 0x7B0960, 104),
        ("H264_AppendBuffer", 0x7B09D0, 548),
        ("CopyAndEscapeNAL", 0x8029F0, 76),
        ("CopyAndEscapeNAL_SIMD", 0x802A3C, 76),
    ):
        code = data[address - base : address - base + length]
        result.append(
            dict(
                name=name,
                address=address,
                instructions=[
                    [i.address, i.mnemonic, i.op_str, i.bytes.hex()]
                    for i in md.disasm(code, address)
                ],
            )
        )
    assert len(result[2]["instructions"]) == len(result[3]["instructions"]) == 19
    return result


def negative_checks(binary, cases):
    constructor = Nal.__init__
    checks = []
    for cpu, helper in ((0, 0x802A30), (16, 0x802A7C)):
        baseline = next(
            case
            for case in cases
            if case["input"]
            == dict(codec=4, cpu=cpu, shape="continuation", suffix="0000", tail="01")
        )
        checks.append(
            ("omit_suffix_insertion_" + str(cpu), [(helper, 0xD503201F)], baseline)
        )
    baseline = next(
        case
        for case in cases
        if case["input"] == dict(codec=4, cpu=0, shape="new_start", body="000001")
    )
    checks.append(
        (
            "escape_after_two_start_bytes",
            [
                (0x7B0B58, 0x51000AB5),  # sub w21,w21,#2, rather than #3
                (0x7B0B5C, 0x14000003),  # b 0x7b0b68: omit raw third-byte copy
            ],
            baseline,
        )
    )
    detected = []
    try:
        for name, patches, baseline in checks:

            def modified(self, *args, **kwargs):
                constructor(self, *args, **kwargs)
                for pc, word in patches:
                    self.u.mem_write(pc, struct.pack("<I", word))
                    self.u.ctl_remove_cache(pc, pc + 4)

            Nal.__init__ = modified
            # No catch-as-success: original valid owned context must still run
            # without assert/outside reads, and actual SDK bytes must differ.
            got = run(binary, baseline["input"], baseline["actions"])
            actual = [s["flow"] for s in got["states"]]
            expected = [s["flow"] for s in baseline["states"]]
            assert actual != expected, ("undetected original byte mutation", name)
            detected.append(name)
    finally:
        Nal.__init__ = constructor
    return detected


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == c.SHA
    cases, unsafe = [], []
    for codec in (4, 5):
        head = b"\x65" if codec == 4 else b"\x26\x01"
        for cpu in (0, 16):
            for suffix in (b"", b"\0", b"\0\0", b"\0\0\0", b"\0\0\0\0", b"\xff\0"):
                for tail in (b"", b"\0", b"\1", b"\2\3", b"\4\0\0\1", b"\0\0\0\1"):
                    inp = dict(
                        codec=codec,
                        cpu=cpu,
                        shape="continuation",
                        suffix=suffix.hex(),
                        tail=tail.hex(),
                    )
                    cases.append(
                        run(
                            binary,
                            inp,
                            [
                                ["F", 1, 1, 19, (head + suffix).hex()],
                                ["F", 1, 2, 10, tail.hex()],
                            ],
                        )
                    )
            # Prefix lengths 1/2/3 bypass scalar escape, and a fresh start resets
            # the suffix even after the previous NAL ended in zeros.
            for body in (
                b"\x65",
                b"\x65\0",
                b"\0\0\1",
                b"\0\0\0\1",
                b"\x26\1\0\0\1",
                b"\x65\0\0\3\0\0\2",
            ):
                inp = dict(codec=codec, cpu=cpu, shape="new_start", body=body.hex())
                cases.append(
                    run(
                        binary,
                        inp,
                        [
                            ["F", 1, 1, 19, (head + b"\0\0").hex()],
                            ["F", 1, 2, 11, body.hex()],
                        ],
                    )
                )
            for bits in (0, 1):
                inp = dict(codec=codec, cpu=cpu, shape="raw", bits=bits)
                cases.append(
                    run(
                        binary,
                        inp,
                        [
                            ["F", 1, 1, 16 | bits, "00000001"],
                            ["F", 1, 2, 8 | bits, "00010203"],
                        ],
                    )
                )
            # Previous completed frames are cleared normally, but pending-reset
            # encoded data is retained. Both actor and key purge discard history.
            for request in (False, True):
                inp = dict(codec=codec, cpu=cpu, shape="epochs", request=request)
                ops = ([["Q"]] if request else []) + [
                    ["F", 1, 1, 27, (head + b"\0\0").hex()],
                    ["F", 2, 2, 3, (head + b"\0\0").hex()],
                    ["F", 2, 3, 10, "01"],
                    ["F", 3, 4, 27, (head + b"\0\0").hex()],
                    ["R"],
                    ["F", 4, 5, 27, (head + b"\0\0\1").hex()],
                ]
                cases.append(run(binary, inp, ops))
            # AES independently decrypts each fragment before the same NAL rules.
            inp = dict(codec=codec, cpu=cpu, shape="encrypted")
            key = bytes(range(16))
            cases.append(
                run(
                    binary,
                    inp,
                    [
                        ["F", 1, 1, 51, v.encrypt(v.padded(head + b"\0\0"), key).hex()],
                        ["F", 1, 2, 42, v.encrypt(v.padded(b"\1"), key).hex()],
                    ],
                )
            )
            for shape, ops in (
                ("no_history", [["F", 1, 1, 26, "000001"]]),
                ("empty_start", [["F", 1, 1, 27, ""]]),
                ("raw_then_escape", [["F", 1, 1, 16, "65"], ["F", 1, 2, 10, "000001"]]),
                (
                    "escape_then_raw",
                    [["F", 1, 1, 19, (head + b"\0\0").hex()], ["F", 1, 2, 8, "000001"]],
                ),
            ):
                unsafe.append(
                    run(binary, dict(codec=codec, cpu=cpu, shape=shape), ops, True)
                )
    for cpu in (0, 16):
        for encrypted in (False, True):
            ops, expected, boundaries = fixture_actions(encrypted)
            case = run(
                binary,
                dict(codec=4, cpu=cpu, shape="real_fixture", encrypted=encrypted),
                ops,
            )
            assert case["states"][-1]["flow"][-1] == [
                "decode",
                len(ops) - 1,
                1,
                expected,
            ]
            case["fixture_boundaries"] = boundaries
            cases.append(case)
    return dict(
        binary_sha256=c.SHA,
        boundary=__doc__,
        cases=cases,
        source_only=unsafe,
        hevc_factory=factory(binary),
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
        "Official NAL:",
        len(r["cases"]),
        "cases/",
        sum(len(c["states"]) for c in r["cases"]),
        "states;",
        len(r["source_only"]),
        "source-only cases",
    )
