#!/usr/bin/env python3
"""Run original Android FEC AddPacket/RS for 26 large complete video payloads.

Outgoing FEC percentage5/MTU1200 are explicit capability inputs, not an Android
video producer or Host activation trigger. Containers/allocator/packet builder
are the existing declared adapters; every parity byte runs original coding.
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
    "stim", ROOT / "scripts/media-pressure-stimuli.py"
)
stim = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stim)


def encode(binary, output):
    script = ROOT / "scripts/audit-steam-video-recovery.py"
    old = sys.argv
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
        sys.argv = old
    path = ROOT / "scripts/audit-steam-fec.py"
    tree = ast.parse(path.read_text())
    node = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "FEC")
    namespace = dict(Run=base["Run"], STOP=base["STOP"], base=base, struct=struct)
    exec(
        compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec"), namespace
    )
    groups = []
    for index in range(26):
        f = namespace["FEC"](mtu=1200)

        def run(entry, *args, runtime=f.r):
            r = runtime
            for n, v in enumerate(args):
                r.w(n, v)
            r.u.emu_start(entry, base["STOP"] + 4, count=20000000)
            assert r.u.reg_read(base["UC_ARM64_REG_PC"]) == base["STOP"]

        f.r.run = run
        data = stim.body(index)
        wires = f.encode(data, 5, previous=index)
        size, shard, parity = struct.unpack_from("<IHH", wires[0], 13)
        assert (size, shard, parity, len(wires)) == (
            65556,
            1168,
            3,
            60,
        ) and f.coding_calls == ["encode"]
        assert all(struct.unpack_from("<H", w, 7)[0] == index + 1 for w in wires)
        groups.append(
            dict(
                index=index,
                body_sha256=hashlib.sha256(data).hexdigest(),
                wires=[w.hex() for w in wires],
            )
        )
        f.r.callbacks.clear()
        del f
        gc.collect()
        if index % 4 == 1:
            print("Original FEC groups encoded", index + 1, flush=True)
    result = dict(
        scope=__doc__,
        binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        helper_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        recovery_helper_sha256=hashlib.sha256(script.read_bytes()).hexdigest(),
        generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        stimulus_sha256=hashlib.sha256(
            (ROOT / "scripts/media-pressure-stimuli.py").read_bytes()
        ).hexdigest(),
        mtu=1200,
        percentage=5,
        k=57,
        m=3,
        shard=1168,
        groups=groups,
    )
    output.write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    encode(a.binary, a.output)
    print("Original encoder: 26 large k57/m3 codewords")
