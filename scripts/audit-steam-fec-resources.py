#!/usr/bin/env python3
"""Record fixed official FEC receive/allocation instructions, not a device peak.

Packet/container/allocator/refcount/libc terminals and initial queue state are
explicit adapters. Coding runs original RS instructions. Only the new[] and
calloc terminals are recorded, excluding packet/CUtl scratch and other malloc
sites; these requests never establish live/RSS/GPU memory or a device peak.
No artificial new[] NULL return is used to infer an official OOM policy.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
SHA = "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"
HELPERS = {
    "scripts/audit-steam-video-recovery.py": "b08713bad09c3e7984aaa792171717d89a36f9a1620aeb6fbc9135dea56f5892",
    "scripts/audit-steam-fec.py": "1089e134fdf7d09020fbe9e6cda5ab45a2549f260b089232303a8fa716aa9d42",
}


def load(binary):
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == SHA
    for name, digest in HELPERS.items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest
    path = ROOT / "scripts/audit-steam-video-recovery.py"
    source = path.read_text()
    base = {"__file__": str(path)}
    previous = sys.argv
    try:
        sys.argv = [str(path), "--binary", str(binary)]
        exec(compile(source[: source.index("\ndef decoder(")], str(path), "exec"), base)
    finally:
        sys.argv = previous
    path = ROOT / "scripts/audit-steam-fec.py"
    node = next(
        n
        for n in ast.parse(path.read_text()).body
        if isinstance(n, ast.ClassDef) and n.name == "FEC"
    )
    namespace = dict(Run=base["Run"], STOP=base["STOP"], base=base, struct=struct)
    exec(
        compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec"), namespace
    )
    return base, namespace["FEC"]


def audit(binary):
    base, fec_class = load(binary)
    fixed = json.loads((ROOT / "scripts/fixtures/steam-fec-reference.json").read_text())
    assert fixed["binary_sha256"] == SHA
    specs = [
        dict(name="small_systematic", length=80, shard=32, parity=2),
        dict(
            name="small_two_erasures",
            length=80,
            shard=32,
            parity=2,
            fixed_wires=[fixed["vector"]["wires"][i] for i in (2, 3, 4)],
        ),
        dict(name="padded_within_mtu", length=1, shard=1440, parity=254),
        dict(name="padded_post_admission", length=1, shard=17000, parity=254),
    ]
    specs.extend(
        dict(name=f"zero_parity_{n}", length=n, shard=1440, parity=0)
        for n in (2097151, 2097152, 2097153, 2097172)
    )
    rows = []
    for spec in specs:
        f = fec_class(mtu=1472)
        r = f.r
        # Scratch placement, not an Android or Switch available-memory claim.
        r.u.mem_map(0x20400000, 0x4000000)
        r.next = 0x20400000
        allocations = []

        def allocate(kind, size):
            allocations.append(dict(kind=kind, bytes=size))
            r.ret(r.alloc(size))

        r.callbacks[0xC09AB0] = lambda: allocate("array_new", r.r(0))
        r.callbacks[0xC0BAE0] = lambda: allocate("calloc", r.r(0) * r.r(1))
        payload = bytes((i * 37 + 11) & 255 for i in range(spec["length"]))
        if "fixed_wires" in spec:
            payload = bytes.fromhex(fixed["vector"]["payload"])
            wires = [bytes.fromhex(w) for w in spec["fixed_wires"]]
        else:
            count = (spec["length"] + spec["shard"] - 1) // spec["shard"]
            wires = [
                struct.pack("<BBBBBHHI", 11, 0, 7, 1, 3, index, 1, 1000000)
                + struct.pack("<IHH", spec["length"], spec["shard"], spec["parity"])
                + payload[index * spec["shard"] : (index + 1) * spec["shard"]].ljust(
                    spec["shard"], b"\0"
                )
                for index in range(count)
            ]
        out = None
        for index, wire in enumerate(wires):
            out = f.add(wire)
            if index + 1 < len(wires):
                assert out is None
        assert out is not None and out[13:] == payload
        original_packet = r.q(0x20050000)
        rows.append(
            dict(
                input=spec,
                observed=dict(
                    bytes=len(out) - 13,
                    sha256=hashlib.sha256(out[13:]).hexdigest(),
                    packet_capacity_including_header=r.i(original_packet + 48),
                    coding_calls=f.coding_calls,
                    allocation_requests=allocations,
                    last_delivered=r.h(f.inc),
                    wire_count=len(wires),
                ),
            )
        )
    # Actual generic sender trigger, separate from incoming allocation probes.
    # Increase only the emulator instruction ceiling; do not patch instructions.
    sender = fec_class(mtu=1472)
    runtime = sender.r
    runtime.u.mem_map(0x20400000, 0x4000000)
    runtime.next = 0x20400000

    def invoke(entry, *arguments):
        for index, value in enumerate(arguments):
            runtime.w(index, value)
        runtime.u.emu_start(entry, base["STOP"] + 4, count=4000000)
        assert runtime.u.reg_read(base["UC_ARM64_REG_PC"]) == base["STOP"]

    runtime.run = invoke
    body = bytes((i * 37 + 11) & 255 for i in range(2097172))
    encoded = sender.encode(body, 5)
    assert len(encoded) == 1457 and not sender.coding_calls
    assert all(struct.unpack_from("<IHH", w, 13) == (2097172, 1440, 0) for w in encoded)
    assert b"".join(w[21:] for w in encoded)[: len(body)] == body
    received = None
    for wire in encoded:
        received = sender.add(wire)
    assert received is not None and received[13:] == body and not sender.coding_calls
    sender_probe = dict(
        controlled_mtu=1472,
        injected_percentage=5,
        length=len(body),
        data_shards=len(encoded),
        parity=0,
        shard=1440,
        rs_calls=sender.coding_calls,
        source_body_sha256=hashlib.sha256(body).hexdigest(),
        source_received_sha256=hashlib.sha256(received[13:]).hexdigest(),
        wire_bank_sha256=hashlib.sha256(b"".join(encoded)).hexdigest(),
        scope="Original generic client encoder/receiver with adapters; not Steam video producer, host default, real socket or codec",
    )
    return dict(
        binary_sha256=SHA,
        helpers=HELPERS,
        controlled_mtu=1472,
        scope=__doc__,
        sender_probe=sender_probe,
        cases=rows,
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--refresh-reference", action="store_true")
    args = p.parse_args()
    report = audit(args.binary)
    path = ROOT / "scripts/fixtures/steam-fec-resources-reference.json"
    if args.refresh_reference:
        if path.exists():
            old = json.loads(path.read_text())
            assert old["binary_sha256"] == report["binary_sha256"]
            assert old["helpers"] == report["helpers"]
            assert report["cases"][: len(old["cases"])] == old["cases"]
        path.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert json.loads(path.read_text()) == report
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Original FEC resource paths: {len(report['cases'])} cases matched")


if __name__ == "__main__":
    main()
