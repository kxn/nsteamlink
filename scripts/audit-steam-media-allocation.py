#!/usr/bin/env python3
"""Execute fixed official ordinary receive/window assembly and record allocations.

Original HandleDataPacket/BInsert/PopHead/Advance/Update instructions execute.
Channel/window initial state, initial packet capacity2200, allocator/refcount/
copy/socket and final raw-packet callback are explicit adapters. Consumer hash
is a byte projection after the known 13B media envelope, not a codec execution.
No real Steam host, OS allocation failure, decoder, Switch or peak is proved.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SHA = "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"
HELPERS = {
    "scripts/audit-steam-video-recovery.py": "b08713bad09c3e7984aaa792171717d89a36f9a1620aeb6fbc9135dea56f5892",
    "scripts/compare-steam-video-recovery.py": "d88190e688504d3a206ca80f0d737850b0f6f5c8f92645db775d49b213c11304",
}
INPUTS = [
    (100, 100),
    (200, 100),
    (2400, 1200),
    (3600, 1200),
    (1228800, 1200),
    (2097151, 1200),
    (2097152, 1200),
    (2097153, 1200),
]


def load(binary):
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == SHA
    for name, digest in HELPERS.items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest, name
    path = ROOT / "scripts/audit-steam-video-recovery.py"
    text = path.read_text()
    namespace = {"__file__": str(path)}
    before = sys.argv
    try:
        sys.argv = [str(path), "--binary", str(binary)]
        # Load the pinned emulator/ELF support only; do not run its unrelated cases.
        exec(
            compile(text[: text.index("\ndef decoder(")], str(path), "exec"), namespace
        )
    finally:
        sys.argv = before
    path = ROOT / "scripts/compare-steam-video-recovery.py"
    tree = ast.parse(path.read_text())
    node = next(
        v for v in tree.body if isinstance(v, ast.ClassDef) and v.name == "Receiver"
    )
    env = {"original": namespace, "Run": namespace["Run"], "STOP": namespace["STOP"]}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec"), env)
    return namespace, env["Receiver"]


def audit(binary):
    original, receiver_class = load(binary)
    rows = []
    for length, chunk in INPUTS:
        receiver = receiver_class(656, 656, 1000000)
        r = receiver.r
        # Scratch addresses avoid the fixed TLS region. This is not a device budget.
        r.u.mem_map(0x20400000, 0x4000000)
        r.next = 0x20400000
        allocations = []

        def allocate():
            size = r.r(0)
            allocations.append(size)
            r.ret(r.alloc(size))

        def frame():
            packet = r.r(2)
            payload = bytes(r.u.mem_read(r.q(packet + 40) + 13, r.i(packet + 52) - 13))
            receiver.events.append(
                {
                    "frame": r.h(r.q(packet + 40) + 7),
                    "bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "consumer_projection_sha256": hashlib.sha256(
                        payload[13:]
                    ).hexdigest(),
                    "capacity_including_transport_header": r.i(packet + 48),
                }
            )
            r.ret()

        r.callbacks[0xC09AB0] = allocate
        r.callbacks[original["STOP"] + 0x280] = frame
        count = (length + chunk - 1) // chunk
        expected = bytearray()
        for index in range(count):
            size = min(chunk, length - len(expected))
            payload = b"\1" + bytes(size - 1)
            expected.extend(payload)
            packet = r.alloc(4096)
            r.packet(
                packet,
                typ=4 if index else 3,
                stamp=1000000,
                received=1000000,
                retry=0,
                id=index,
            )
            r.wh(packet + 69, index - 1 if index else count - 1)
            r.w32(packet + 52, 13 + size)
            r.u.mem_write(packet + 77, payload)
            r.run(0x7F9400, receiver.p, receiver.p + 176, packet)
        frames = [v for v in receiver.step("U") if "frame" in v]
        assert len(frames) == 1 and frames[0]["bytes"] == length
        assert frames[0]["sha256"] == hashlib.sha256(expected).hexdigest()
        capacity = max(2200, count * 1472) if count > 1 else 2200
        assert frames[0]["capacity_including_transport_header"] == capacity
        assert allocations == ([capacity] if capacity > 2200 else [])
        assert r.h(receiver.window + 8) == count
        rows.append(
            {
                "input": {"bytes": length, "chunk": chunk},
                "fragments": count,
                "observed": frames[0],
                "array_new_requests": allocations,
                "head_after": count,
            }
        )
    return {"binary_sha256": SHA, "helpers": HELPERS, "scope": __doc__, "cases": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--refresh-reference", action="store_true")
    args = parser.parse_args()
    report = audit(args.binary)
    reference = ROOT / "scripts/fixtures/steam-media-allocation-reference.json"
    if args.refresh_reference:
        if reference.exists():
            previous = json.loads(reference.read_text())
            assert previous["binary_sha256"] == report["binary_sha256"]
            assert previous["helpers"] == report["helpers"]
            assert report["cases"][: len(previous["cases"])] == previous["cases"]
        reference.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert json.loads(reference.read_text()) == report
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Original media allocation: {len(report['cases'])} cases matched")


if __name__ == "__main__":
    main()
