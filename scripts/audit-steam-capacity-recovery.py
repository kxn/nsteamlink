#!/usr/bin/env python3
"""Replay actual retained UDP inputs at the official decoder/SDK-gate boundary.

The capture contains real Native UDP/FFmpeg/queue retirement observations. Its
retained IDs, 64KiB AUs and SDK consumption boundaries enter original Android
FIFO/DecodeFrame/OnThink/submission. A second original execution restores the
retired inputs, under declared SDK gates. These projections are not the official
FIFO drop policy or natural wall-clock, hardware/pixel or Steam-host evidence.
Allocator, packet storage, SDK capacity/results, JNI/NAL and OS terminals are
explicit; packet bytes live separately from the packet's pool callback fields.
"""

import argparse
import gzip
import hashlib
import importlib.util
import json
import io
from pathlib import Path
from types import ModuleType
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


overlap = module("capacity_overlap", "audit-steam-decoder-overlap.py")
stim = module("capacity_stim", "media-pressure-stimuli.py")


class Source(overlap.Slow):
    def __init__(self, binary):
        self.recovery_inputs, self.current_id, self.current_expected, self.count = (
            [],
            0,
            0,
            0,
        )
        super().__init__(binary)
        # Explicit allocator arena, separate from fixture TLS and existing data.
        self.u.mem_map(0x22000000, 0x8000000)
        self.next = 0x22000000
        self.input = self.alloc(131072)
        self.scenario["capacity"] = 131072

    def alloc(self, size):
        if self.next < 0x22000000:
            return super().alloc(size)
        size = max(size, 16)
        address = self.next
        self.next += (size + 15) & ~15
        assert self.next < 0x2A000000
        self.allocations[address] = size
        return address

    def packet(self, *args, **kwargs):
        packet = super().packet(*args, **kwargs)
        size = self.i(packet + 52)
        raw = self.alloc(size + 64)
        self.u.mem_write(raw, bytes(self.u.mem_read(self.q(packet + 40), size)))
        self.wq(packet + 40, raw)
        self.wq(packet + 56, raw)
        return packet

    def observe(self):
        # Same read-only assembled-body observer, with room for a full 64KiB AU.
        state, parts, length = self.state(), [], self.alloc(4)
        for index in range(self.call(0x7B2BE0, self.video + 472)):
            ptr = self.call(0x7B2BF8, self.video + 472, index, length)
            size = self.i(length)
            assert size <= 2097152
            parts.append(bytes(self.u.mem_read(ptr, size)).hex())
        state["body"] = "".join(parts)
        return state

    def hook(self, machine, pc, size, data):
        if pc == 0x7B2000 and self.enabled:
            self.current_id = self.h(self.r(1) + 26)
            self.current_expected = self.h(self.video + 416)
            self.count += 1
        if pc == 0xC0E090 and self.enabled:
            self.recovery_inputs.append(
                dict(
                    id=self.current_id,
                    consumed=self.count,
                    expected=self.current_expected,
                )
            )
        super().hook(machine, pc, size, data)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def programs():
    found, visited = {}, set()

    def visit(value):
        if not isinstance(value, ModuleType) or id(value) in visited:
            return
        visited.add(id(value))
        path = Path(getattr(value, "__file__", ""))
        if not path.is_file() or not path.resolve().is_relative_to(ROOT / "scripts"):
            return
        found[str(path.relative_to(ROOT))] = digest(path)
        for child in vars(value).values():
            visit(child)

    visit(overlap)
    visit(stim)
    found[str(Path(__file__).relative_to(ROOT))] = digest(Path(__file__))
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--native-capture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path)
    args = parser.parse_args()
    binary = args.binary.read_bytes()
    assert digest(args.binary) == overlap.c.SHA
    native = [
        row
        for row in json.loads(args.native_capture.read_text())
        if row["name"].startswith("pressure_capacity_crc")
    ]
    assert len(native) == 2 and [r["name"] for r in native] == [
        "pressure_capacity_crc0",
        "pressure_capacity_crc1",
    ]
    payloads, cases = stim.aus(), []

    def frame(fid):
        index = fid - 100
        return [
            fid,
            index,
            24 if index % 6 == 0 else 8,
            1000000 + index * 1092,
            payloads[index % 6].hex(),
        ]

    for captured in native:
        load = captured["native"]["load"]
        ids, retired = load["consumed_ids"], load["retired_ids"]
        assert not set(ids) & set(retired)
        assert sorted(ids + retired) == load["rx_ids"] == list(range(100, 402))
        bounds = sorted({s["consumed"] for s in load["sdk"]})
        assert bounds[0] == 1 and bounds[-1] == len(ids)
        batches = [ids[a:b] for a, b in zip([0] + bounds, bounds)]
        full = [
            list(range(a, b[-1] + 1))
            for a, b in zip([100] + [v[-1] + 1 for v in batches], batches)
        ]
        case = dict(
            name=captured["name"], native_capture=captured, port_projection=None
        )
        for key, selected in (("source", batches), ("source_full", full)):
            instance = Source(binary)
            initial = [frame(fid) for fid in selected[0]]
            waves = [[frame(fid) for fid in batch] for batch in selected[1:]]
            observed = instance.run(initial, waves)
            assert [g["id"] for g in observed["gates"]] == [
                s["id"] for s in load["sdk"]
            ]
            assert [g["payload"] for g in observed["gates"]] == [
                s["sha256"] for s in load["sdk"]
            ]
            if key == "source":
                expected = [
                    {k: r[k] for k in ("id", "consumed")}
                    for r in instance.recovery_inputs
                ]
                assert (
                    expected == load["recovery_inputs"]
                    and len(expected) == load["datalost"]
                )
                case.update(
                    initial=initial,
                    waves=waves,
                    source_recovery_inputs=instance.recovery_inputs,
                )
            else:
                assert not instance.recovery_inputs
            case[key] = observed
        cases.append(case)
        print(
            case["name"],
            "retired",
            len(retired),
            "recovery",
            case["source_recovery_inputs"],
            flush=True,
        )
    functions = {}
    for filename in (
        "steam-decoder-overlap-reference.json.gz",
        "steam-decoder-queue-reference.json",
    ):
        raw = (ROOT / "scripts/fixtures" / filename).read_bytes()
        reference = json.loads(
            gzip.decompress(raw) if filename.endswith(".gz") else raw
        )
        functions.update({f["address"]: f for f in reference["functions"]})
    elf = ELFFile(io.BytesIO(binary))
    section = elf.get_section_by_name(".text")
    code, base = section.data(), section["sh_addr"]
    selected = {
        "_ZN13CStreamPacketD1Ev",
        "_ZN12CStreamFrameC1EP13CStreamPacket",
        "_ZN12CStreamFrameD1Ev",
    }
    for symbol in elf.get_section_by_name(".dynsym").iter_symbols():
        if symbol.name in selected:
            at, size = symbol["st_value"], symbol["st_size"]
            functions[at] = dict(
                name=symbol.name,
                address=at,
                size=size,
                sha256=hashlib.sha256(code[at - base : at - base + size]).hexdigest(),
            )
    for f in functions.values():
        at, size = f["address"], f["size"]
        assert (
            hashlib.sha256(code[at - base : at - base + size]).hexdigest()
            == f["sha256"]
        )
    report = dict(
        scope=__doc__,
        binary_sha256=digest(args.binary),
        functions=list(functions.values()),
        programs=programs(),
        native_observer_sha256=digest(ROOT / "app/tests/udp_video_load.h"),
        native_capture_sha256=digest(args.native_capture),
        pressure_reference_sha256=digest(
            ROOT / "scripts/fixtures/steam-client-pressure-process-reference.json.gz"
        ),
        cases=cases,
    )
    data = (json.dumps(report, indent=2) + "\n").encode()
    args.output.write_bytes(data)
    if args.snapshot:
        args.snapshot.write_bytes(gzip.compress(data, mtime=0))


if __name__ == "__main__":
    main()
