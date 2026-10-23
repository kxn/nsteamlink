#!/usr/bin/env python3
"""Audit pinned Linux AVCodec client's compressed-video overflow producer.

Execute original CheckOverflow, SendVideoOverflow, protobuf and Frame Put/Send;
use existing player/codec audit terminals for SDK, clock, locks, logging, storage
and final Connection delivery. Frame encryption is an explicit success terminal
that leaves plaintext unchanged; recorded feedback is NOT a ciphertext/wire or
peer-acceptance claim. Partial-list metadata and scheduling are explicit
inputs, not a full receiver lifecycle or measured decoder capacity. Scan original
executable sections for direct call/jump references, without treating an absent
direct caller as proof that indirect/inlined producers cannot exist. No Steam,
Switch, physical codec, host rate controller or live network is started.
"""

import argparse
import hashlib
import importlib.util
import io
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "avcodec_player", ROOT / "scripts/audit-steam-client-avcodec-player.py"
)
player = importlib.util.module_from_spec(spec)
spec.loader.exec_module(player)
codec = player.codec
CHECK, SEND = 0x326C60, 0x31F740
codec.FUNCTIONS.update(
    {
        CHECK: "compressed_overflow_check",
        SEND: "send_video_overflow",
        0x31AF60: "send_control",
        0x451C00: "overflow_constructor",
        0x437F90: "overflow_destructor",
    }
)


class Feedback(player.Player):
    def __init__(self, binary, *, mutation=False):
        super().__init__(binary)
        self.hooks[0x194B60] = lambda: self.ret(1)
        self.wi(self.dec + 0x190, 0)  # Explicit initial recovery-time input.
        self.partial = self.alloc(80)
        self.wq(self.dec + 0x1A0, self.partial)
        self.wi(self.dec + 0x1B0, 0)
        self.wi(self.dec + 0x1B4, 1)
        if mutation:
            assert bytes(self.u.mem_read(0x326D2D, 5)) == bytes.fromhex("e80e8affff")
            self.u.mem_write(0x326D2D, b"\x90" * 5)
            self.u.ctl_remove_cache(0x326D2D, 0x326D32)

    def step_overflow(self, **values):
        # Two valid CUtlLinkedList endpoints are provided at the consumer boundary.
        # Their original producer/allocation/ordering is outside this audit.
        for offset, value in (
            (0x1BC, values.get("count", 2)),
            (0x194, values.get("previous_span", self.i(self.dec + 0x194))),
        ):
            self.wi(self.dec + offset, value)
        self.u.mem_write(self.dec + 0x18C, bytes([values.get("waiting_key", 0)]))
        self.u.mem_write(self.dec + 0x18D, bytes([values.get("syncing", 0)]))
        for offset, fid, stamp in (
            (0, values.get("first", 100), 1000000),
            (40, values.get("last", 102), 1000000 + values.get("ticks", 5000)),
        ):
            self.u.mem_write(self.partial + offset + 2, struct.pack("<H", fid))
            self.wi(self.partial + offset + 4, stamp)
        self.wi(self.client + 0x100, values.get("phase", 6))
        self.events = []
        self.call(CHECK, self.dec)
        return dict(
            feedback=[event[1:] for event in self.events if event[0] == "feedback"],
            span=self.i(self.dec + 0x194),
            syncing=self.u.mem_read(self.dec + 0x18D, 1)[0],
            last_recovery=self.i(self.dec + 0x190),
            assertions=list(self.assertions),
        )


def inventory(binary):
    elf = ELFFile(io.BytesIO(binary))
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.skipdata = True
    refs = []
    sections = []
    for section in elf.iter_sections():
        if not section["sh_flags"] & 4 or not section["sh_size"]:
            continue
        end = section["sh_addr"]
        for pc, size, mnemonic, operands in decoder.disasm_lite(
            section.data(), section["sh_addr"]
        ):
            end = pc + size
            if mnemonic in ("call", "jmp") and operands == hex(SEND):
                refs.append(dict(address=pc, instruction=f"{mnemonic} {operands}"))
        assert end == section["sh_addr"] + section["sh_size"]
        sections.append(section.name)
    relocations = []
    for section in elf.iter_sections():
        if section["sh_type"] == "SHT_RELA":
            for relocation in section.iter_relocations():
                if relocation["r_addend"] == SEND:
                    relocations.append(relocation["r_offset"])
    assert refs == [dict(address=0x326D2D, instruction="call 0x31f740")], refs
    return dict(
        executable_sections=sections,
        direct_references=refs,
        rela_addend_references=relocations,
        limitation="Does not exclude indirect/inlined producers or other versions/platforms",
    )


def audit(binary, mutation):
    assert hashlib.sha256(binary).hexdigest() == codec.SHA
    cases = []

    def run(name, actions, expected):
        replay = Feedback(binary, mutation=mutation)
        states = [replay.step_overflow(**action) for action in actions]
        assert not any(state["assertions"] for state in states), (name, states)
        for state, oracle in zip(states, expected, strict=True):
            for field, value in oracle.items():
                assert state[field] == value, (name, field, state[field], value)
        cases.append(
            dict(
                name=name,
                input=actions,
                states=states,
                entries={
                    codec.FUNCTIONS[pc]: count
                    for pc, count in sorted(replay.entered.items())
                },
            )
        )

    for field in ("waiting_key", "syncing"):
        run(field, [{field: 1}], [dict(feedback=[], span=0)])
    for count in (0, 1):
        run(f"count_{count}", [dict(count=count)], [dict(feedback=[], span=0)])
    run(
        "equal_range_repeats",
        [{}, {}],
        [dict(feedback=[[1, "9408641066"]], span=3)] * 2,
    )
    run(
        "shrink_then_grow",
        [{}, dict(last=101), {}],
        [
            dict(feedback=[[1, "9408641066"]], span=3),
            dict(feedback=[], span=2),
            dict(feedback=[[1, "9408641066"]], span=3),
        ],
    )
    run(
        "recovery_threshold_equal",
        [dict(ticks=9830)],
        [dict(feedback=[[1, "9408641066"]], span=3, syncing=0, last_recovery=0)],
    )
    run(
        "recovery_threshold_above",
        [dict(ticks=9831)],
        [
            dict(
                feedback=[[3, "02"], [1, "9408641066"]],
                span=3,
                syncing=1,
                last_recovery=1000000,
            )
        ],
    )
    run(
        "frame_id_wrap_signed_range",
        [dict(first=65535, last=0), dict(first=65535, last=0)],
        [
            dict(feedback=[], span=(-65534 & 0xFFFFFFFF)),
            dict(feedback=[[1, "9408ffff031000"]], span=(-65534 & 0xFFFFFFFF)),
        ],
    )
    run("not_streaming", [dict(phase=5)], [dict(feedback=[], span=3)])
    run(
        "already_positive_previous_range",
        [dict(previous_span=5)],
        [dict(feedback=[], span=3)],
    )
    return dict(
        binary_sha256=codec.SHA,
        cases=cases,
        function_ranges={
            name: body
            for name, body in codec.inventory(binary).items()
            if any(name in case["entries"] for case in cases)
        },
        callers=inventory(binary),
        terminals=__doc__,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--mutation",
        action="store_true",
        help="Omit original overflow send; must fail oracle",
    )
    args = parser.parse_args()
    report = audit(args.binary.read_bytes(), args.mutation)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"{len(report['cases'])} cases / {sum(len(c['states']) for c in report['cases'])} states passed"
    )


if __name__ == "__main__":
    main()
