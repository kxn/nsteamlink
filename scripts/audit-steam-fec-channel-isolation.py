#!/usr/bin/env python3
"""Original CLIENT Socket/CRC/connection/channel factory/windows/FEC/RS isolation.

Two opaque bodies use the original Android encoder's k3/m2/S32 codewords.
Controlled post-connection state, packet/container/allocator/refcounts, locks,
clock, terminal transport and delivered-body delegates remain explicit adapters.
No audio/video role, decoder, OS UDP, Steam sender or device timing is proved.
"""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import types

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
SHA = "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"
ADDRESSES = (
    0x7FF3E0,
    0x7FACFC,
    0x7FBA34,
    0x7F8630,
    0x7F9250,
    0x7F9940,
    0x7F7FCC,
    0x7F7EEC,
    0x7F84DC,
    0x7F609C,
    0x7F9C9C,
)


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


loss = module("channel_loss", "audit-steam-network-loss.py")
resources = module("channel_resources", "audit-steam-fec-resources.py")
stim = module("channel_stimuli", "fec-channel-stimuli.py")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def codewords(binary):
    _, fec = resources.load(binary)
    result = []
    for multiplier, offset in ((37, 11), (11, 43)):
        body = bytes((i * multiplier + offset) & 255 for i in range(80))
        f = fec(mtu=64)
        wires = f.encode(body, 50)
        assert len(wires) == 5
        assert all(struct.unpack_from("<IHH", w, 13) == (80, 32, 2) for w in wires)
        assert [struct.unpack_from("<H", w, 5)[0] for w in wires] == list(range(5))
        result.append(dict(body=body.hex(), wires=[w.hex() for w in wires]))
    fixed = json.loads((ROOT / "scripts/fixtures/steam-fec-reference.json").read_text())
    assert result[0] == dict(
        body=fixed["vector"]["payload"], wires=fixed["vector"]["wires"]
    )
    return result


class Receiver(loss.Loss):
    def __init__(self, *args):
        self.full_deliveries, self.rs, self.action, self.channel = [], [], -1, 0
        self.wire_inputs, self.hits = [], {}
        super().__init__(*args)

    def hook(self, uc, address, size, data):
        if address in ADDRESSES:
            self.hits[address] = self.hits.get(address, 0) + 1
        if address == 0x7FF3E0:
            p = self.r(1)
            self.wire_inputs.append(
                dict(
                    action=self.action,
                    wire=bytes(self.u.mem_read(self.q(p + 40), self.i(p + 52))).hex(),
                )
            )
        if address == 0x7F609C:
            self.rs.append(dict(action=self.action, channel=self.channel))
        super().hook(uc, address, size, data)

    def deliver(self):
        p = self.r(2)
        raw = self.q(p + 40)
        self.full_deliveries.append(
            dict(
                action=self.action,
                channel=self.u.mem_read(raw + 4, 1)[0],
                group=struct.unpack("<H", self.u.mem_read(raw + 7, 2))[0],
                body=bytes(self.u.mem_read(raw + 13, self.i(p + 52) - 13)).hex(),
            )
        )
        super().deliver()


def identities(binary):
    elf = ELFFile(io.BytesIO(binary.read_bytes()))
    funcs = list(elf.get_section_by_name(".dynsym").iter_symbols())
    values = []
    for address in ADDRESSES:
        matches = [
            s
            for s in funcs
            if s["st_info"]["type"] == "STT_FUNC"
            and s["st_value"] == address
            and s["st_size"]
        ]
        assert matches, address
        symbol = matches[0]
        size = symbol["st_size"]
        segment = next(
            p
            for p in elf.iter_segments()
            if p["p_type"] == "PT_LOAD"
            and p["p_vaddr"] <= address < p["p_vaddr"] + p["p_filesz"]
        )
        offset = address - segment["p_vaddr"]
        code = segment.data()[offset : offset + size]
        assert len(code) == size
        values.append(
            dict(
                address=address,
                size=size,
                names=sorted(s.name for s in matches),
                sha256=hashlib.sha256(code).hexdigest(),
            )
        )
    return values


def helpers():
    found = {}

    def visit(m):
        path = Path(getattr(m, "__file__", "")).resolve()
        if path.parent != ROOT / "scripts" or path in found:
            return
        found[path] = digest(path)
        for v in vars(m).values():
            if isinstance(v, types.ModuleType):
                visit(v)

    visit(loss)
    visit(resources)
    visit(stim)
    for name in (
        "audit-steam-fec-channel-isolation.py",
        "audit-steam-fec.py",
        "audit-steam-video-recovery.py",
        "audit-steam-client-fec-policy.py",
    ):
        p = ROOT / "scripts" / name
        found[p] = digest(p)
    return {str(p.relative_to(ROOT)): h for p, h in sorted(found.items())}


def audit(binary):
    assert digest(binary) == SHA
    bank = codewords(binary)
    cases = []
    for inp in stim.schedules(bank):
        r = Receiver(binary.read_bytes(), inp["crc"])
        observed = []
        for n, op in enumerate(inp["actions"]):
            r.action = n
            r.entries.clear()
            r.frames.clear()
            r.delivered.clear()
            r.now = op[1]
            r.channel = op[3] if op[0] == "W" else op[2]
            if op[0] == "W":
                r.receive_packet(*op[2:])
            else:
                r.call(0x7F9C9C, r.channels[op[2]], r.now)
            observed.append(dict(r.observe(), delivered=list(r.delivered)))
        case = dict(
            input=inp,
            observed=observed,
            deliveries=r.full_deliveries,
            rs=r.rs,
            channels_distinct=r.channels[3] != r.channels[4],
            created_channels=sorted(r.channels),
            wire_inputs=r.wire_inputs,
            function_hits={str(k): v for k, v in r.hits.items()},
            source_assertions=list(r.asserts),
        )
        stim.verify(case, bank)
        cases.append(case)
        print(
            inp["name"],
            [(v["channel"], v["group"]) for v in r.full_deliveries],
            "RS",
            len(r.rs),
            flush=True,
        )
    return dict(
        binary_sha256=SHA,
        scope=__doc__,
        functions=identities(binary),
        helpers=helpers(),
        bank=bank,
        cases=cases,
    )


def main():
    if not __debug__:
        raise SystemExit("Original evidence audit requires Python assertions")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    report = audit(a.binary)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
