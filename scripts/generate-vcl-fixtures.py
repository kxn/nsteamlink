#!/usr/bin/env python3
"""Author deterministic AVC I_PCM key/skip-P fixtures, with no filler NAL.

These are decoder capability stimuli, not Steam producer samples. Baseline
CAVLC, 8-bit 4:2:0, no interlace/B-frames, deblocking disabled. The visible
sample formula is independent of any decoder; compressed storage is packaging.
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class Bits:
    def __init__(self):
        self.data = bytearray()
        self.byte = self.count = 0

    def u(self, value, width):
        assert 0 <= value < 1 << width
        for bit in range(width - 1, -1, -1):
            self.byte = self.byte * 2 + ((value >> bit) & 1)
            self.count += 1
            if self.count == 8:
                self.data.append(self.byte)
                self.byte = self.count = 0

    def ue(self, value):
        width = (value + 1).bit_length()
        self.u(0, width - 1)
        self.u(value + 1, width)

    def se(self, value):
        self.ue(2 * abs(value) - (value > 0))

    def align(self):
        if self.count:
            self.u(0, 8 - self.count)

    def raw(self, data):
        assert not self.count
        self.data.extend(data)

    def finish(self):
        self.u(1, 1)
        self.align()
        return bytes(self.data)


def nal(header, rbsp):
    data, zeros = bytearray([0, 0, 0, 1, header]), 0
    for byte in rbsp:
        if zeros >= 2 and byte <= 3:
            data.append(3)
            zeros = 0
        data.append(byte)
        zeros = zeros + 1 if byte == 0 else 0
    return bytes(data)


def sample(plane, x, y):
    if plane == 0:
        return 16 + (3 * (x // 16) + 5 * (y // 16)) % 220
    return 64 + ((x if plane == 1 else y) // 8) % 128


def build(width, height):
    assert width % 16 == 0 and height % 2 == 0
    mw, mh = width // 16, (height + 15) // 16
    s = Bits()
    for value in (66, 0, 42):
        s.u(value, 8)  # baseline, unconstrained flags, level4.2
    for value in (0, 0, 2, 1):
        s.ue(value)  # SPS id, frame_num bits-4, POC type2, one reference
    s.u(0, 1)  # no gaps
    s.ue(mw - 1)
    s.ue(mh - 1)
    s.u(1, 1)  # frame_mbs_only
    s.u(1, 1)  # direct_8x8_inference
    crop = mh * 16 - height
    s.u(bool(crop), 1)
    if crop:
        for value in (0, 0, 0, crop // 2):
            s.ue(value)
    s.u(0, 1)  # no VUI
    sps = nal(0x67, s.finish())
    p = Bits()
    p.ue(0)
    p.ue(0)  # PPS/SPS id
    p.u(0, 1)
    p.u(0, 1)  # CAVLC, no field POC
    for value in (0, 0, 0):
        p.ue(value)  # one slice group, default reference counts
    p.u(0, 1)
    p.u(0, 2)  # no weighted prediction
    for _ in range(3):
        p.se(0)  # QP/QS/chroma offsets
    p.u(1, 1)
    p.u(0, 1)
    p.u(0, 1)  # deblock present, unconstrained intra, no redundant count
    pps = nal(0x68, p.finish())
    b = Bits()
    for value in (0, 2, 0):
        b.ue(value)  # first MB, I slice, PPS id
    b.u(0, 4)
    b.ue(0)  # frame_num, IDR id
    b.u(0, 1)
    b.u(0, 1)  # IDR reference flags
    b.se(0)
    b.ue(1)  # QP delta, disable deblocking
    for my in range(mh):
        for mx in range(mw):
            b.ue(25)  # I_PCM (I slice)
            b.align()
            b.raw(
                bytes([sample(0, mx * 16, my * 16)]) * 256
                + bytes([sample(1, mx * 8, my * 8)]) * 64
                + bytes([sample(2, mx * 8, my * 8)]) * 64
            )
    vcl = nal(0x65, b.finish())
    key = nal(9, b"\x10") + sps + pps + vcl
    p = Bits()
    for _ in range(3):
        p.ue(0)  # first MB, P slice, PPS id
    p.u(1, 4)
    for _ in range(3):
        p.u(0, 1)  # reference override/list modification/marking
    p.se(0)
    p.ue(1)
    p.ue(mw * mh)  # skip entire frame: same visible image
    following = nal(9, b"\x30") + nal(0x41, p.finish())
    pixels = bytes(
        sample(plane, x, y)
        for plane in range(3)
        for y in range(height if not plane else height // 2)
        for x in range(width if not plane else width // 2)
    )
    return key + following, dict(
        name=f"pcm{height}",
        width=width,
        height=height,
        macroblocks=mw * mh,
        sizes=[len(key), len(following)],
        nal_types=[9, 7, 8, 5, 9, 1],
        vcl_bytes=len(vcl) - 4,
        fixture_sha256=hashlib.sha256(key + following).hexdigest(),
        visible_yuv_md5=hashlib.md5(pixels).hexdigest(),
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, default=ROOT / "app/tests/fixtures/video/vcl")
    p.add_argument("--check", action="store_true")
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    cases = []
    for width, height in ((1280, 720), (1920, 1080)):
        data, row = build(width, height)
        path = args.output / (row["name"] + ".h264.gz")
        if args.check:
            assert gzip.decompress(path.read_bytes()) == data
        else:
            output = io.BytesIO()
            with gzip.GzipFile(
                fileobj=output, mode="wb", filename="", mtime=0
            ) as stream:
                stream.write(data)
            path.write_bytes(output.getvalue())
        row["archive_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        cases.append(row)
    report = dict(scope=__doc__, cases=cases)
    path = args.output / "manifest.json"
    if args.check:
        assert json.loads(path.read_text()) == report
    else:
        path.write_text(json.dumps(report, indent=2) + "\n")
    print("VCL fixtures: two deterministic I_PCM key/skip-P streams, no filler")


if __name__ == "__main__":
    main()
