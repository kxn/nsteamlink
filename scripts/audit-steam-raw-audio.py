#!/usr/bin/env python3
"""Execute official Raw audio format parser and signed-16 to float conversion.

Original StartDecoding/CAudioFormat parser and DecodeFrame execute. The decoder's
player pointer and decrypted Frame are seeded; player start/create/submit,
GetWriteArea storage, allocation and protobuf process initialization are adapters.
No transport, actual audio device or complete decoder lifecycle is claimed.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "config", ROOT / "scripts/audit-steam-client-config.py"
)
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == config.SHA
    cases = []
    scenarios = [
        (channels, count) for channels in (1, 2) for count in (1, 8, 9, 16, 17, 33)
    ]
    scenarios += [(channels, 6000) for channels in (1, 2)]
    for channels, count in scenarios:
        r = config.Core(binary)
        decoder, player, vtable, buf = (r.alloc(4096) for _ in range(4))
        frame, packet, audio = (r.alloc(4096) for _ in range(3))
        raw = r.alloc(max(4096, count * channels * 2 + 64))
        samples = (
            [-32768, -16384, -1, 0, 1, 16384, 32767] * ((count * channels + 6) // 7)
        )[: count * channels]
        payload = struct.pack("<" + "h" * len(samples), *samples)
        # CAudioFormat: format=16bit LE, frequency=48000, channels.
        fmt = bytes.fromhex("08011080f70218") + bytes([channels])
        r.u.mem_write(raw, fmt)
        r.wq(buf, raw)
        r.wi(buf + 20, len(fmt))
        r.wq(decoder + 16, player)
        r.wq(player, vtable)
        r.wq(vtable + 24, config.STOP + 0x300)
        r.wq(vtable + 48, config.STOP + 0x310)
        observed = {}
        output = {}

        def start():
            observed["start"] = [r.r(1), r.r(2), r.r(3)]
            r.ret()

        def create():
            observed["metadata"] = [r.r(1), r.r(2)]
            r.ret(audio)

        def area():
            output["size"] = r.r(1)
            output["ptr"] = r.alloc(max(r.r(1), 16))
            r.ret(output["ptr"])

        def submit():
            assert r.r(1) == audio
            observed["float_pcm"] = bytes(
                r.u.mem_read(output["ptr"], output["size"])
            ).hex()
            r.ret()

        r.callbacks.update(
            {
                config.STOP + 0x300: start,
                config.STOP + 0x310: submit,
                0xC0BA20: create,
                0xC0BA50: area,
            }
        )
        r.call(0x7B178C, decoder, buf)
        # No tag/extended header; 13-byte transport header precedes raw PCM.
        r.u.mem_write(raw, bytes(13) + payload)
        r.wq(frame + 8, packet)
        r.wq(packet + 56, raw)
        r.wi(packet + 52, 13 + len(payload))
        r.u.mem_write(frame + 26, struct.pack("<HI", 123, 456789))
        r.call(0x7B1838, decoder, frame)
        cases.append(
            dict(
                input=dict(channels=channels, codec_data=fmt.hex(), pcm=payload.hex()),
                observed=observed,
            )
        )
    return cases


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    report = dict(
        binary_sha256=config.SHA, scope=__doc__, cases=audit(a.binary.read_bytes())
    )
    ref = ROOT / "scripts/fixtures/steam-raw-audio-reference.json"
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
    print(f"Official Raw audio parser/conversion: {len(report['cases'])} cases passed")


if __name__ == "__main__":
    main()
