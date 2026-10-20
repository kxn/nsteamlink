#!/usr/bin/env python3
"""Original CLIENT Opus recovery and audio-frame identity at large sequence gaps.

Original Start/Decode/Stop plus CreateAudioFrame/Frame constructor/SetFrame run.
The stereo48kHz decoder/player descriptor and channel3 are controlled inputs;
no BOpenAudio or negotiated device configuration is executed here.
Codec decode is an explicit API terminal returning480; no PCM is synthesized or
read. One80B frame allocation and64KiB write area are reused after synchronous
terminal submit. This is a control-flow/identity proof, not real Opus work, frame
allocation lifetime/peak, transport/worker timing, natural loss or a device test.
"""
import argparse
from collections import Counter
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import types

from elftools.elf.elffile import ELFFile
from unicorn import UC_HOOK_MEM_WRITE
from unicorn.arm64_const import UC_ARM64_REG_PC

ROOT = Path(__file__).resolve().parents[1]
SHA = "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"


def module(name, file):
    s = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


opus = module("gap_opus", "audit-steam-opus-recovery.py")
stim = module("audio_gap_stimuli", "audio-gap-stimuli.py")
FUNCTIONS = stim.FUNCTIONS


class Policy(opus.Opus):
    def __init__(self, binary):
        self.factory_active = False
        self.entries = set()
        self.hits = Counter()
        self.state_writes = Counter()
        super().__init__(binary, 2)
        self.pool = self.alloc(4096)
        self.output = self.alloc(65536)
        self.wq(self.player + 8, opus.c.CLIENT)
        self.wi(self.player + 16, 2)
        self.wi(self.player + 20, 48000)
        self.wi(self.player + 24, 2)
        self.b(opus.c.CLIENT + 625, 3)
        assert (
            dict(
                frequency=self.i(self.decoder + 392),
                channels=self.i(self.decoder + 396),
                player_format=self.i(self.player + 16),
                channel=self.u.mem_read(opus.c.CLIENT + 625, 1)[0],
            )
            == stim.DESCRIPTOR
        )
        assert self.i(self.player + 20) == 48000 and self.i(self.player + 24) == 2
        self.entries = {self.symbols[name] for name in FUNCTIONS}
        self.u.hook_add(UC_HOOK_MEM_WRITE, self.write)
        self.reset_observer()

    def reset_observer(self):
        # The inherited return observer updates this one slot. No per-decode history
        # or original decoder state is replaced by this observation reset.
        self.decodes = [{}]
        self.count = self.sinks = 0
        self.digest = hashlib.sha256()
        self.first_step = self.last_step = ""

    def write(self, u, access, address, size, value, data):
        if address < self.decoder + 412 and self.decoder + 408 < address + size:
            pc = u.reg_read(UC_ARM64_REG_PC)
            assert 0x7B134C <= pc < 0x7B1770, (
                hex(pc),
                "adapter changed recovery state",
            )
            self.state_writes[pc] += 1

    def create(self):
        self.frames[self.pool] = dict(size=0, capacity=65536, data=self.output)
        self.active = self.pool
        self.factory_active = True
        self.jump(0x7679C4)

    def area(self):
        assert self.r(0) == self.pool + 24 and self.r(1) <= 65536
        self.ret(self.output)

    def submit(self):
        assert self.r(1) == self.pool
        self.sinks += 1
        self.ret()

    def hook(self, u, address, size, data):
        if address in self.entries:
            self.hits[address] += 1
        if address in (0x7B14E4, 0x7B15FC):
            self.factory_active = False
        name = self.plts.get(address, "")
        if self.factory_active and name == "_Znwm" and self.r(0) == 80:
            self.ret(self.pool)
            return
        if name == "opus_multistream_decode_float":
            fid, stamp = struct.unpack("<HI", self.u.mem_read(self.pool + 50, 6))
            use = bool(self.r(1))
            size = self.r(2)
            assert (
                use
                and size == 3
                and bytes(self.u.mem_read(self.r(1), size)) == bytes.fromhex("f0fffe")
            ) or (not use and size == 0)
            token = struct.pack("<HIIBB", fid, stamp, self.r(4), use, self.r(5))
            self.digest.update(token)
            self.count += 1
            self.last_step = token.hex()
            if self.count == 1:
                self.first_step = token.hex()
            self.ret(480)
            return
        super().hook(u, address, size, data)

    def snapshot_policy(self):
        assert self.sinks == self.count and not self.assertions
        return dict(
            first=bool(self.u.mem_read(self.decoder + 408, 1)[0]),
            next=struct.unpack("<H", self.u.mem_read(self.decoder + 410, 2))[0],
            steps=self.count,
            trace_sha256=self.digest.hexdigest(),
            first_step=self.first_step,
            last_step=self.last_step,
        )


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def helpers():
    found = {}

    def visit(m):
        p = Path(getattr(m, "__file__", "")).resolve()
        if p.parent != ROOT / "scripts" or p in found:
            return
        found[p] = digest(p)
        for v in vars(m).values():
            if isinstance(v, types.ModuleType):
                visit(v)

    visit(opus)
    visit(stim)
    for n in ("audit-steam-audio-gap-policy.py", "audit-steam-client-fec-policy.py"):
        p = ROOT / "scripts" / n
        found[p] = digest(p)
    return {str(p.relative_to(ROOT)): h for p, h in sorted(found.items())}


def identities(binary):
    e = ELFFile(io.BytesIO(binary))
    syms = {s.name: s for s in e.get_section_by_name(".dynsym").iter_symbols()}
    result = []
    for name in FUNCTIONS:
        s = syms[name]
        a = s["st_value"]
        n = s["st_size"]
        assert a and n
        seg = next(
            p
            for p in e.iter_segments()
            if p["p_type"] == "PT_LOAD"
            and p["p_vaddr"] <= a < a + n <= p["p_vaddr"] + p["p_filesz"]
        )
        offset = a - seg["p_vaddr"]
        code = seg.data()[offset : offset + n]
        result.append(
            dict(name=name, address=a, size=n, sha256=hashlib.sha256(code).hexdigest())
        )
    return result


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == SHA
    initial_helpers = helpers()
    cases = []
    for inp in stim.plans():
        r = Policy(binary)
        r.start()
        assert r.decoder_config == [48000, 2, 1, 1, 0, 1]
        observed = []
        for action, count in zip(inp["actions"], inp["counts"], strict=True):
            r.reset_observer()
            if action[0] == "R":
                r.call(0x7B16FC, r.decoder)
                r.start()
                assert r.decoder_config == [48000, 2, 1, 1, 0, 1]
            else:
                r.feed(action[1], action[2], bytes.fromhex("f0fffe"))
            state = r.snapshot_policy()
            assert state["steps"] == count, (inp, state)
            observed.append(state)
        r.call(0x7B16FC, r.decoder)
        assert not r.q(r.decoder + 400) and not r.assertions
        assert r.entries == set(r.hits)
        cases.append(
            dict(
                input=inp,
                observed=observed,
                function_hits={str(k): v for k, v in r.hits.items()},
                state_write_pcs={str(k): v for k, v in r.state_writes.items()},
            )
        )
        print(inp["name"], [s["steps"] for s in observed], flush=True)
    assert helpers() == initial_helpers, "Evidence helpers changed during capture"
    return dict(
        binary_sha256=SHA,
        scope=__doc__,
        descriptor=stim.DESCRIPTOR,
        functions=identities(binary),
        helpers=initial_helpers,
        cases=cases,
    )


def main():
    if not __debug__:
        raise SystemExit("Original evidence audit requires Python assertions")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    r = audit(a.binary.read_bytes())
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(r, indent=2) + "\n")


if __name__ == "__main__":
    main()
