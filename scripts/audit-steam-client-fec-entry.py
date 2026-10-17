#!/usr/bin/env python3
"""Bound official client FEC entry evidence to two SHA-pinned Android libraries.

Static evidence enumerates all aligned B/BL instructions in .text, matching PLT
entries and dynamic relocations for the selected functions. Original connection
constructors, percentage setters and send routing execute. Mutexes, registration,
clock, channel lookup and terminal sends are adapters. An explicitly forced gate
is a capability counterexample, never evidence of a product activation trigger.
No indirect-call, alias/inlined-write, other-library/version or device coverage
is claimed. This does not establish an automatic loss-triggered FEC policy.
"""

import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile
from unicorn import UC_HOOK_MEM_WRITE
from unicorn.arm64_const import UC_ARM64_REG_PC

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "policy", ROOT / "scripts/audit-steam-client-fec-policy.py"
)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
SHA = {
    "core": "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e",
    "shell": policy.SHA,
}
TARGETS = (
    "_ZN17CStreamConnection23SetChannelFECPercentageEhi",
    "_ZN17CStreamConnection14SendUnreliableEP13CStreamPacketh",
    "_ZN14CStreamChannel17SendUnreliableFECEP13CStreamPacket",
    "_ZN17CFECOutgoingQueue9AddPacketEP13CStreamPacketi",
    "_ZN17CFECOutgoingQueue11SendPacketsEP17CStreamConnectionP13CStreamSocket",
    "_ZN13CStreamClient24SetStreamingClientConfigERK22CStreamingClientConfigb",
)
CTOR = "_ZN17CStreamConnectionC1EP13CStreamSocket"


def static(binary):
    elf = ELFFile(io.BytesIO(binary))
    dyn = elf.get_section_by_name(".dynsym")
    symbols = list(dyn.iter_symbols())
    functions = [
        s for s in symbols if s["st_info"]["type"] == "STT_FUNC" and s["st_value"]
    ]
    selected = {s.name: s for s in functions if s.name in TARGETS}
    targets = {s["st_value"]: name for name, s in selected.items()}
    plt = elf.get_section_by_name(".plt")["sh_addr"]
    entries = []
    for i, relocation in enumerate(
        elf.get_section_by_name(".rela.plt").iter_relocations()
    ):
        name = symbols[relocation["r_info_sym"]].name
        if name in TARGETS:
            address = plt + 32 + 16 * i
            targets[address] = name
            entries.append(dict(address=address, symbol=name))

    def owners(pc):
        return sorted(
            s.name
            for s in functions
            if s["st_value"] <= pc < s["st_value"] + s["st_size"]
        )

    text = elf.get_section_by_name(".text")
    code, start = text.data(), text["sh_addr"]
    assert start % 4 == 0 and len(code) % 4 == 0
    calls = []
    for offset in range(0, len(code), 4):
        word = struct.unpack_from("<I", code, offset)[0]
        if word >> 26 not in (5, 37):
            continue
        imm = word & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        pc = start + offset
        destination = pc + 4 * imm
        if destination in targets:
            calls.append(
                dict(
                    pc=pc,
                    word=word,
                    kind="BL" if word >> 26 == 37 else "B",
                    owners=owners(pc),
                    destination=destination,
                    symbol=targets[destination],
                )
            )
    references = []
    for section in (".rela.dyn", ".rela.plt"):
        for rel in elf.get_section_by_name(section).iter_relocations():
            symbol = symbols[rel["r_info_sym"]]
            relative_target = rel["r_addend"] if rel["r_info_type"] == 1027 else None
            if symbol.name in selected or relative_target in targets:
                references.append(
                    dict(
                        section=section,
                        offset=rel["r_offset"],
                        type=rel["r_info_type"],
                        symbol=symbol.name,
                        addend=rel["r_addend"],
                    )
                )
    return dict(
        text_start=start,
        text_size=len(code),
        aligned_instructions=len(code) // 4,
        exported_targets={
            name: dict(address=s["st_value"], size=s["st_size"])
            for name, s in sorted(selected.items())
        },
        plt=entries,
        direct_calls=calls,
        relocations=references,
    )


class Entry(policy.Shell):
    def __init__(self, binary):
        self.conn, self.sock, self.channel = 0x20080000, 0x20090000, 0x200A0000
        self.writes, self.routes = [], []
        super().__init__(binary)
        self.u.hook_add(UC_HOOK_MEM_WRITE, self.write)

    def write(self, uc, access, address, size, value, data):
        if address <= self.conn + 11 < address + size:
            self.writes.append(
                dict(
                    pc=uc.reg_read(UC_ARM64_REG_PC),
                    relative_address=address - self.conn,
                    size=size,
                    value=value,
                )
            )

    def hook(self, uc, address, size, data):
        name = self.plts.get(address, "")
        if name == "_Z18GetStreamTimestampv":
            self.ret(1000000)
        elif name == "_ZN17CStreamConnection19GetNextConnectionIDEv":
            self.ret(12)
        elif name == "_ZN13CStreamSocket13AddConnectionEP17CStreamConnection":
            assert self.r(0) == self.sock and self.r(1) == self.conn
            self.ret()
        elif name == "_ZN17CStreamConnection10GetChannelEh":
            assert self.r(0) == self.conn and self.r(1) == 3
            self.ret(self.channel)
        elif name.startswith("_ZN16SteamThreadTools12CThreadMutexC"):
            self.ret()
        elif name in (
            "_ZN14CStreamChannel14SendUnreliableEP13CStreamPacket",
            "_ZN14CStreamChannel17SendUnreliableFECEP13CStreamPacket",
        ):
            self.routes.append(name)
            self.ret()
        else:
            super().hook(uc, address, size, data)

    def gate(self):
        return self.u.mem_read(self.conn + 11, 1)[0]


def replay(binary):
    cases = []
    for percentage in (0, 5, 20, 50, 100, -1, 2147483647, -2147483648):
        r = Entry(binary)
        # Dirty storage makes the original constructor's explicit clear visible.
        r.u.mem_write(r.conn + 8, b"\xa5" * 8)
        r.call(r.symbols[CTOR], r.conn, r.sock)
        assert r.gate() == 0 and len(r.writes) == 1
        constructor_writes = list(r.writes)
        r.writes.clear()
        r.call(r.symbols[TARGETS[0]], r.conn, 3, percentage & 0xFFFFFFFF)
        assert r.gate() == 0 and not r.writes
        assert r.i(r.channel + 32) == percentage & 0xFFFFFFFF
        # Connected state is controlled; this test does not reproduce negotiation.
        r.wi(r.conn + 16, 1)
        packet = r.alloc(4096)
        r.call(r.symbols[TARGETS[1]], r.conn, packet, 3)
        assert r.routes == ["_ZN14CStreamChannel14SendUnreliableEP13CStreamPacket"]
        assert r.gate() == 0 and not r.writes
        normal = list(r.routes)
        # This is an explicitly injected capability control, NOT a trigger.
        r.b(r.conn + 11, 1)
        r.routes.clear()
        r.call(r.symbols[TARGETS[0]], r.conn, 3, percentage & 0xFFFFFFFF)
        r.call(r.symbols[TARGETS[1]], r.conn, packet, 3)
        assert r.routes == [TARGETS[2]] and r.gate() == 1 and not r.writes
        cases.append(
            dict(
                percentage=percentage,
                constructor_gate=0,
                constructor_writes=constructor_writes,
                percentage_and_send_gate_writes=list(r.writes),
                normal_routes=normal,
                forced_gate_routes=list(r.routes),
            )
        )
    return cases


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--core", type=Path, required=True)
    p.add_argument("--shell", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    args = p.parse_args()
    report = dict(scope=__doc__, libraries={})
    for name in SHA:
        binary = getattr(args, name).read_bytes()
        assert hashlib.sha256(binary).hexdigest() == SHA[name]
        report["libraries"][name] = dict(
            sha256=SHA[name], static=static(binary), replay=replay(binary)
        )
    ref = ROOT / "scripts/fixtures/steam-client-fec-entry-reference.json"
    if args.refresh_reference:
        if ref.exists():
            assert json.loads(ref.read_text()) == report
        ref.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert json.loads(ref.read_text()) == report
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("Official core/shell FEC entries: 2 static scans, 16 original-code cases")


if __name__ == "__main__":
    main()
