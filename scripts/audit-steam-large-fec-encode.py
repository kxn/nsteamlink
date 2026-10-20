#!/usr/bin/env python3
"""Original AddPacket with MTU1200/5% and 337 data shards: parity becomes zero.

Allocator/packet/container terminals are explicit. Heap is moved clear of fixed
TLS; original stack checks and all coding/branch instructions stay intact.
This is a capability input, not proof of a Steam video producer/enable policy.
"""

import argparse
import ast
import contextlib
import gc
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import runpy
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "large", ROOT / "scripts/media-large-stimuli.py"
)
large = importlib.util.module_from_spec(spec)
spec.loader.exec_module(large)
SHA = "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def encode(binary, output):
    assert digest(binary) == SHA
    script = ROOT / "scripts/audit-steam-video-recovery.py"
    previous = sys.argv
    try:
        sys.argv = [
            str(script),
            "--binary",
            str(binary),
            "--output",
            str(output.with_suffix(".base.json")),
        ]
        with contextlib.redirect_stdout(io.StringIO()):
            base = runpy.run_path(str(script))
    finally:
        sys.argv = previous
    helper = ROOT / "scripts/audit-steam-fec.py"
    node = next(
        n
        for n in ast.parse(helper.read_text()).body
        if isinstance(n, ast.ClassDef) and n.name == "FEC"
    )
    namespace = dict(Run=base["Run"], STOP=base["STOP"], base=base, struct=struct)
    exec(
        compile(ast.Module(body=[node], type_ignores=[]), str(helper), "exec"),
        namespace,
    )
    groups = []
    for index in range(26):
        f = namespace["FEC"](mtu=1200)
        f.r.u.mem_map(0x20400000, 0x1000000)
        f.r.next = 0x20400000  # Avoid fixture TLS at 0x20300000.

        def run(entry, *args, runtime=f.r):
            for n, value in enumerate(args):
                runtime.w(n, value)
            runtime.u.emu_start(entry, base["STOP"] + 4, count=20000000)
            assert runtime.u.reg_read(base["UC_ARM64_REG_PC"]) == base["STOP"]

        f.r.run = run
        body = large.body(index)
        wires = f.encode(body, 5, previous=index)
        assert struct.unpack_from("<IHH", wires[0], 13) == (393236, 1168, 0)
        assert len(wires) == 337 and not f.coding_calls
        groups.append(
            dict(
                index=index,
                body_sha256=hashlib.sha256(body).hexdigest(),
                coding_calls=list(f.coding_calls),
                wires=[w.hex() for w in wires],
            )
        )
        f.r.callbacks.clear()
        del f
        gc.collect()
    report = dict(
        scope=__doc__,
        binary_sha256=SHA,
        generator_sha256=digest(Path(__file__)),
        helper_sha256=digest(helper),
        recovery_helper_sha256=digest(script),
        stimulus_sha256=digest(ROOT / "scripts/media-large-stimuli.py"),
        mtu=1200,
        percentage=5,
        k=337,
        m=0,
        shard=1168,
        groups=groups,
    )
    output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    encode(args.binary, args.output)
    print("Original AddPacket: 26 k337/m0 groups, no RS calls")
