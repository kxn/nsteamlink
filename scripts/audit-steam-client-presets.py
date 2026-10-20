#!/usr/bin/env python3
"""Official complete preset transformations, including retained field presence.

Pinned Android factory, preservation helper, generated config Clear/Copy/parser/
serializer execute original instructions. Allocation/libc++ string storage,
process-wide protobuf initialization and assertion formatting are adapters.
Inputs are explicit configs; this is not a UI trigger, filesystem, negotiated
Switch capability, host response, hardware or background-thread experiment.
Nine policy cases also reuse §116's original UI/control/timeout/result chain
with its explicit authorization/clock/Qt/send adapters and signed target94 inputs;
these do not claim real host bitrate or natural user event delivery.
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
    "config", ROOT / "scripts/audit-steam-client-config.py"
)
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)
SHA = config.BASE["SHA"]
CONFIG = config.BASE["CONFIG"]
REFERENCE = ROOT / "scripts/fixtures/steam-client-presets-reference.json.gz"
FAST = "_Z31CreateStreamingConfigFastPresetP22CStreamingClientConfig"
FACTORY = (
    "_Z27CreateStreamingConfigPreset22EStreamingConfigPresetP22CStreamingClientConfig"
)
HELPER, HELPER_SIZE = 0xC85868, 780


class Presets(config.Core):
    def __init__(self, binary, patch=None):
        self.entered, self.entries, self.assertions = set(), {}, []
        self.patch, self.patch_hits = patch, []
        super().__init__(binary)
        for name, address in self.symbols.items():
            if address and (
                "CStreamingClientConfig" in name
                or name.startswith("_ZNK6google8protobuf11MessageLite")
                or name.startswith("_ZN6google8protobuf11MessageLite")
                or name in (FAST, FACTORY)
            ):
                self.entries.setdefault(address, []).append(name)
        self.entries[HELPER] = ["local_preserve_fields"]
        if patch:
            pc, before, after = patch
            assert bytes(self.u.mem_read(pc, 4)) == struct.pack("<I", before)
            self.u.mem_write(pc, struct.pack("<I", after))

    def hook(self, u, pc, size, unused):
        self.entered.update(self.entries.get(pc, []))
        if self.patch and pc == self.patch[0]:
            self.patch_hits.append(pc)
        name = self.plts.get(pc, "")
        if "basic_string" in name and ("aSERKS5_" in name or "6__initEPKcm" in name):
            # Storage adapter, not the original factory's retain/drop decision.
            dest, src = self.r(0), self.r(1)
            if "6__initEPKcm" in name:
                length, ptr = self.r(2), src
            else:
                tag = u.mem_read(src, 1)[0]
                length = self.q(src + 8) if tag & 1 else tag >> 1
                ptr = self.q(src + 16) if tag & 1 else src + 1
            value = bytes(u.mem_read(ptr, length))
            p = self.alloc(length + 1)
            u.mem_write(p, value + b"\0")
            self.wq(dest, (length + 1) | 1)
            self.wq(dest + 8, length)
            self.wq(dest + 16, p)
            self.ret(dest)
        elif "AssertFailed" in name or name == "__assert2":
            self.assertions.append(dict(name=name, line=self.r(1)))
            self.ret(1)
        elif "basic_string" in name and "D1Ev" in name:
            self.ret()
        elif name == "__memmove_chk":
            assert self.r(2) <= self.r(3)
            if self.r(2):
                u.mem_write(self.r(0), bytes(u.mem_read(self.r(1), self.r(2))))
            self.ret(self.r(0))
        else:
            super().hook(u, pc, size, unused)


def varint(n):
    out = bytearray()
    while n > 127:
        out.append((n & 127) | 128)
        n >>= 7
    return bytes(out) + bytes([n])


def run(binary, name, wire, preset, patch=None):
    r = Presets(binary, patch)
    assert r.parse(CONFIG, wire)
    if preset == 4:
        r.call(r.symbols[FAST], CONFIG)
    else:
        r.call(r.symbols[FACTORY], preset, CONFIG)
    result = r.serialize(CONFIG).hex()
    assert not r.assertions
    return dict(
        name=name,
        input=wire.hex(),
        preset=preset,
        output=result,
        executed=sorted(r.entered),
        source_assertions=r.assertions,
        patch_hits=r.patch_hits,
    )


def inventory(binary, cases):
    elf = ELFFile(io.BytesIO(binary))
    section = elf.get_section_by_name(".text")
    code, base = section.data(), section["sh_addr"]
    names = {n for c in cases for n in c["executed"]}
    result = {}
    for s in elf.get_section_by_name(".dynsym").iter_symbols():
        if s.name in names and s["st_size"]:
            start = s["st_value"] - base
            raw = code[start : start + s["st_size"]]
            result[s.name] = dict(
                address=s["st_value"],
                size=len(raw),
                sha256=hashlib.sha256(raw).hexdigest(),
            )
    raw = code[HELPER - base : HELPER - base + HELPER_SIZE]
    result["local_preserve_fields"] = dict(
        address=HELPER, size=len(raw), sha256=hashlib.sha256(raw).hexdigest()
    )
    assert set(result) == names
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    binary = a.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == SHA
    source = json.loads(
        (ROOT / "scripts/fixtures/steam-client-config-reference.json").read_text()
    )
    fields = [
        (c["case"], bytes.fromhex(c["observed"]["config"]))
        for c in source["cases"]
        if c["case"].startswith("field_")
    ]
    full = b"".join(wire for _, wire in fields) + bytes.fromhex("980607")
    hotkey = "controller-字母".encode() * 256
    inputs = (
        [("empty", b"")]
        + fields
        + [
            ("all_and_unknown", full),
            ("empty_hotkey", bytes.fromhex("820100")),
            ("long_hotkey", bytes.fromhex("8201") + varint(len(hotkey)) + hotkey),
            ("disabled_fec", bytes.fromhex("c80100")),
            ("unknown_only", bytes.fromhex("980607")),
        ]
    )
    cases = [
        run(binary, name, wire, preset) for name, wire in inputs for preset in range(5)
    ]
    # Preserve helper's field7 presence branch: TB[N]Z bit28 -> TBZ. This
    # drops explicit hardware=false when present, while every function returns.
    pc, before = 0xC85884, Presets(binary).i(0xC85884)
    original = run(binary, "hardware_false", bytes.fromhex("3800"), 4)
    mutant = run(
        binary,
        "hardware_false",
        bytes.fromhex("3800"),
        4,
        (pc, before, before ^ (1 << 24)),
    )
    assert mutant["patch_hits"] == [pc] and original["output"] != mutant["output"]
    policy_spec = importlib.util.spec_from_file_location(
        "policy", ROOT / "scripts/audit-steam-network-test-fec-flow.py"
    )
    policy = importlib.util.module_from_spec(policy_spec)
    policy_spec.loader.exec_module(policy)
    extra_policy = [
        policy.run(
            binary,
            dict(
                quality=quality, before=False, accepted=0, bitrate=-1, targets=[target]
            ),
        )[0]
        for quality in (1, 2, 3)
        for target in (0, 0xFFFFFFFF, 0x80000000)
    ]
    report = dict(
        binary_sha256=SHA,
        scope=__doc__,
        cases=cases,
        functions=inventory(binary, cases),
        extra_policy=extra_policy,
        mutation=dict(
            pc=pc,
            before=before,
            after=before ^ (1 << 24),
            original=original,
            mutant=mutant,
        ),
    )
    if a.refresh_reference:
        if REFERENCE.exists():
            assert json.loads(gzip.decompress(REFERENCE.read_bytes())) == report
        REFERENCE.write_bytes(
            gzip.compress((json.dumps(report, indent=2) + "\n").encode(), mtime=0)
        )
    else:
        assert json.loads(gzip.decompress(REFERENCE.read_bytes())) == report
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"Original presets: {len(cases)} complete transforms, {len(report['functions'])} entered method identities; 1 executed counterfactual"
    )


if __name__ == "__main__":
    main()
