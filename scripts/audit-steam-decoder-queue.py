#!/usr/bin/env python3
"""Run the official input FIFO and decoder loop with prequeued video batches.

Original OnReceiveFrame/copy/AddToTail/pop/DecodeFrame/Release/OnThink and SDK
input execute. OS Wait advances a bounded scheduling fixture: wait1 permits the
next loop; wait0 or infinite returns to the driver, preserving pending state.
The driver resumes the same decoder for the next prequeued batch. Key's SDK,
JNI/allocator/OS/NAL metadata terminals remain explicit. This proves consumer
ordering, not natural scheduler timing, Steam producer behavior or real pixels.
"""

import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "range_audit", ROOT / "scripts/audit-steam-video-subframe.py"
)
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class Queue(r.Range):
    def __init__(self, binary):
        self.waits = []
        self.dequeued = []
        super().__init__(binary, dict(backend=True, codec=4))

    def queue(self, fid, seq, flags, payload):
        body = (
            b"\x01"
            + struct.pack("<HIHI", fid, 1000000, 0, 0)
            + struct.pack("<HBHH", seq, flags, 0, 0)
            + payload
        )
        p = self.packet(5, 3, False, 12, 34, len(body))
        label = f"queued_{self.action}_{len(self.refs)}"
        self.labels[p] = label
        self.u.mem_write(self.q(p + 40) + 13, body)
        f = self.alloc(64)
        self.call(self.symbols["_ZN12CStreamFrameC1EP13CStreamPacket"], f, p)
        self.call(0x76727C, self.video, f)
        self.call(self.symbols["_ZN12CStreamFrameD1Ev"], f)
        self.refs[label] = p

    def hook(self, u, pc, size, data):
        if pc == 0x7B2000 and self.tracing:
            f = self.r(1)
            self.dequeued.append(
                [self.action, int.from_bytes(u.mem_read(f + 26, 2), "little")]
            )
        super().hook(u, pc, size, data)


def cases(payload):
    def frame(fid, seq, flags, body=payload):
        return [fid, seq, flags, body.hex()]

    def full(fid, seq, key=False):
        return frame(fid, seq, 8 | (16 if key else 0))

    a, b = payload[:1102], payload[1102:]
    return {
        "two_keys": [[full(1, 1, True), full(2, 2, True)]],
        "key_then_delta": [[full(1, 1, True), full(2, 2)]],
        "delta_then_key": [[full(1, 1), full(2, 2, True)]],
        "two_delta": [[full(1, 1), full(2, 2)]],
        "four_delta": [[full(i, i) for i in range(1, 5)]],
        "key_middle": [[full(1, 1), full(2, 2, True), full(3, 3)]],
        "key_at_end": [[full(1, 1), full(2, 2), full(3, 3, True)]],
        "separate_keys": [[full(1, 1, True)], [full(2, 2, True)]],
        "split_one_batch": [[frame(1, 1, 16, a), frame(1, 2, 8, b)]],
        "split_two_batches": [[frame(1, 1, 16, a)], [frame(1, 2, 8, b)]],
        "replace_partial": [[frame(1, 1, 16, a), full(2, 2, True)]],
        "gap_then_key": [[full(1, 2), full(2, 3), full(3, 4, True)]],
        "gap_next_batch_key": [[full(1, 2), full(2, 3)], [full(3, 4, True)]],
        "two_split_frames": [
            [
                frame(1, 1, 16, a),
                frame(1, 2, 8, b),
                frame(2, 3, 0, a),
                frame(2, 4, 8, b),
            ]
        ],
        "partial_after_full": [[full(1, 1), frame(2, 2, 0, a)], [frame(2, 3, 8, b)]],
        "key_burst": [[full(i, i, True) for i in range(1, 17)]],
    }


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == r.c.SHA
    payload = (ROOT / "app/tests/fixtures/video/sequential.h264").read_bytes()[:2204]
    results = []
    for name, batches in cases(payload).items():
        x = Queue(binary)
        states = []
        for index, batch in enumerate(batches):
            x.action = index
            x.b(x.video + 24, 1)
            for fid, seq, flags, raw in batch:
                x.queue(fid, seq, flags, bytes.fromhex(raw))
            assert x.snapshot()["input_queue"]["ids"] == [f[0] for f in batch]
            x.call(0x766D50, x.video)
            state = x.observe()
            states.append(
                dict(
                    strict=state["strict"],
                    soft=state["soft"],
                    request=state["request"],
                    flow=state["flow"],
                    player=state["player"],
                    body=state["body"],
                    waits=list(x.waits),
                    dequeued=list(x.dequeued),
                )
            )
            assert not x.assertions, (name, x.assertions)
            assert not x.snapshot()["input_queue"]["ids"]
        results.append(dict(name=name, batches=batches, states=states))
    elf = ELFFile(io.BytesIO(binary))
    section = elf.get_section_by_name(".text")
    code, base = section.data(), section["sh_addr"]
    functions = []
    for name, at, size in [
        ("RunDecodeLoop", 0x766D50, 276),
        ("OnReceiveFrame", 0x76727C, 236),
        ("OnStreamStopped", 0x767160, 80),
        ("AddToTail", 0x767368, 212),
        ("DecodeFrame", 0x7B2000, 1244),
        ("OnThink", 0x7B24DC, 808),
    ]:
        functions.append(
            dict(
                name=name,
                address=at,
                size=size,
                sha256=hashlib.sha256(code[at - base : at - base + size]).hexdigest(),
            )
        )
    return dict(
        binary_sha256=r.c.SHA, boundary=__doc__, functions=functions, cases=results
    )


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--write", type=Path)
    p.add_argument("--check", type=Path)
    a = p.parse_args()
    result = audit(a.binary.read_bytes())
    if a.write:
        a.write.write_text(json.dumps(result, indent=2) + "\n")
    if a.check:
        assert result == json.loads(a.check.read_text())
    print("Official decoder input queue:", len(result["cases"]), "cases")
