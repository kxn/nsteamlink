#!/usr/bin/env python3
"""Execute official reliable ring fill/growth and assembled frame digests.

Real ctor, BInsert, EnsureCapacity, PopHead, Channel Update and feedback Socket/CRC
run from the pinned Android ELF. Allocation,
mutex/refcounts/destruction, terminal raw-frame digest, stats/final UDP are adapters.
No host, decryption or decoder runs. Bodies are deterministic controlled inputs.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "feedback", ROOT / "scripts/audit-steam-reliable-feedback.py"
)
feedback = importlib.util.module_from_spec(spec)
spec.loader.exec_module(feedback)


def audit(base):
    feedback.audit(base)

    class Receiver(feedback.audit.Receiver):
        def __init__(self, crc):
            super().__init__(crc)
            self.callbacks[0xC11110] = lambda: self.jump(0x7FD204)
            self.callbacks[0xC09980] = self.memset
            self.callbacks[0xC09AC0] = lambda: self.ret()

        def memset(self):
            if self.r(2):
                self.u.mem_write(self.r(0), bytes([self.r(1) & 255]) * self.r(2))
            self.ret(self.r(0))

        def constructed(self):
            pass  # Keep the actual constructor's empty ring; grow with original code.

        def deliver(self):
            p = self.r(2)
            body = bytes(self.u.mem_read(self.q(p + 56) + 13, self.i(p + 52) - 13))
            self.delivered.append(
                dict(bytes=len(body), sha256=hashlib.sha256(body).hexdigest())
            )
            self.ret()

    cases = []
    scenarios = [
        (crc, count, False)
        for crc in (0, 1)
        for count in (15, 16, 17, 19, 63, 64, 65, 1100)
    ]
    scenarios += [(crc, 64, True) for crc in (0, 1)]
    for crc, count, missing_first in scenarios:
        r = Receiver(crc)
        r.u.mem_map(0x20400000, 0x1000000)
        r.now = 1000100
        for i in range(int(missing_first), count):
            p = r.alloc(4096)
            r.packet(
                p,
                typ=(5 if i == 0 else 6) | (128 if crc else 0),
                id=i,
                stamp=900000,
                received=r.now,
                retry=0,
            )
            r.b(p + 66, 34)
            r.b(p + 67, 12)
            r.b(p + 68, 1)
            r.wh(p + 69, count - 1 if i == 0 else i - 1)
            body = bytearray([i % 251] * 1024)
            if i == 0:
                body[0] = 6
            r.u.mem_write(p + 77, bytes(body))
            r.w32(p + 52, 13 + len(body))
            r.call(0x7F9250, r.ch, p, r.now)
        before = dict(
            span=(r.h(r.ch + 154) - r.h(r.ch + 152)) & 65535,
            capacity=r.i(r.ch + 148) + 1,
        )
        r.now = 1000200
        r.call(0x7F9C9C, r.ch, r.now)
        inp = dict(crc=crc, count=count, chunk_bytes=1024)
        if missing_first:
            inp["missing_first"] = True
        cases.append(
            dict(
                input=inp,
                before=before,
                observed=r.observe(),
            )
        )
    return cases


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    base = feedback.wire.outgoing.load(
        a.binary, a.output.with_name("reliable-large-base.json")
    )
    report = dict(
        binary_sha256=feedback.wire.outgoing.SHA, scope=__doc__, cases=audit(base)
    )
    ref = ROOT / "scripts/fixtures/steam-reliable-large-frame-reference.json"
    if a.refresh_reference:
        if ref.exists():
            old = json.loads(ref.read_text())
            assert old["binary_sha256"] == report["binary_sha256"]
            assert old["cases"] == report["cases"][: len(old["cases"])]
        ref.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert json.loads(ref.read_text()) == report
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"Official reliable full-ring/large-frame: {len(report['cases'])} cases passed"
    )


if __name__ == "__main__":
    main()
