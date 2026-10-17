#!/usr/bin/env python3
"""Execute the official negotiation's initial reliable_data copy checkpoint.

Real C++ constructors, Frame::Get/parser, initial OnNegotiationInit instructions
and partial CNegotiatedConfig serialization run from the pinned Android ELF.
Execution stops at 0x7ad720 before codec selection or final SetConfig. A plaintext
Frame is seeded after the normal decrypt boundary. Allocation/libc and checkpoint
exit are adapters. No complete negotiation, sender, host or decoder is claimed.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "config", ROOT / "scripts/audit-steam-client-config.py"
)
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == config.SHA
    cases = []
    for payload in (b"", b"\x08\x00", b"\x08\x01"):
        r = config.Core(binary)
        r.call(r.symbols["_ZN17CNegotiatedConfigC1Ev"], config.CLIENT + 288)
        frame, packet, raw = (r.alloc(4096) for _ in range(3))
        data = bytes(13) + b"\x03" + payload
        r.u.mem_write(raw, data)
        r.wq(frame + 8, packet)
        r.b(frame + 16, 1)
        r.wq(packet + 40, raw)
        r.wq(packet + 56, raw)
        r.wi(packet + 48, 4096)
        r.wi(packet + 52, len(data))
        observed = {}

        def checkpoint():
            observed.update(
                checkpoint=0x7AD720,
                input_hasbits=r.i(r.u.reg_read(config.SP) + 64),
                reliable=bool(r.u.mem_read(config.CLIENT + 344, 1)[0]),
                output_hasbits=r.i(config.CLIENT + 304),
            )
            r.jump(config.STOP)

        r.callbacks[0x7AD720] = checkpoint
        r.call(0x7AD698, config.CLIENT, frame)
        assert observed["checkpoint"] == 0x7AD720
        del r.callbacks[0x7AD720]
        observed["partial_config"] = r.serialize(
            config.CLIENT + 288, "CNegotiatedConfig"
        ).hex()
        cases.append(dict(input=dict(protobuf=payload.hex()), observed=observed))
    return cases


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    args = p.parse_args()
    report = dict(
        binary_sha256=config.SHA, scope=__doc__, cases=audit(args.binary.read_bytes())
    )
    ref = ROOT / "scripts/fixtures/steam-negotiated-reliable-reference.json"
    if args.refresh_reference:
        if ref.exists():
            assert json.loads(ref.read_text()) == report
        ref.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert json.loads(ref.read_text()) == report
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"Official reliable_data copy checkpoint: {len(report['cases'])} cases passed"
    )


if __name__ == "__main__":
    main()
