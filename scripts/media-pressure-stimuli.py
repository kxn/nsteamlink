"""Byte-rate stimuli only: codec bytes, ordinary fragments and erasure plans.

No receiver or FEC policy model lives here. FEC codewords are supplied separately
by the SHA-pinned original encoder. CRC wrappers are transport endpoints.
"""

import hashlib
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
BOUNDARIES = [
    (0, 2204),
    (2204, 411),
    (2615, 425),
    (3040, 486),
    (3526, 461),
    (3987, 565),
]


def aus():
    raw = (ROOT / "app/tests/fixtures/video/sequential.h264").read_bytes()
    result = []
    for begin, size in BOUNDARIES:
        au = raw[begin : begin + size]
        padding = 65536 - len(au)
        result.append(au + b"\0\0\0\1\x0c" + b"\xff" * (padding - 6) + b"\x80")
    return result


def body(index):
    return (
        struct.pack(
            "<BHIHIHBHH",
            1,
            100 + index,
            1000000 + index * 1092,
            0,
            0,
            index,
            24 if index % 6 == 0 else 8,
            0,
            0,
        )
        + aus()[index % 6]
    )


def ordinary(index):
    data = body(index)
    chunks = [data[k : k + 1200] for k in range(0, len(data), 1200)]
    first = index * len(chunks)
    return [
        struct.pack(
            "<BBBBBhHI",
            3 if n == 0 else 4,
            0,
            7,
            0,
            3,
            len(chunks) - 1 if n == 0 else n - 1,
            first + n,
            1000000 + index * 1092,
        )
        + part
        for n, part in enumerate(chunks)
    ]


def plans():
    return [
        dict(
            name=f"pressure_{profile}_crc{int(crc)}",
            profile=profile,
            crc=crc,
            frames=302 if profile == "capacity" else 26,
            rate=60,
            delay_us=3000000 if profile == "capacity" else 0,
            hole_pid=73 if profile in ("repair", "drop") else -1,
        )
        for crc in (False, True)
        for profile in ("full", "capacity", "repair", "drop", "fec_recover", "fec_drop")
    ]


def erasures(profile, index):
    if profile == "fec_recover":
        return {0, 17, 55}
    if profile == "fec_drop" and index == 1:
        return {0, 17, 30, 55}
    return set()


def requested(wire, pid):
    """Previously audited type10: cumulative watermark, present base, bitmap."""
    if wire[0] & 127 != 10 or wire[4] != 3 or len(wire) < 19:
        return False
    base = struct.unpack_from("<H", wire, 7)[0]
    confirmed = struct.unpack_from("<H", wire, 17)[0]
    if 0 < (pid - confirmed) & 65535 < 32768 and 0 < (base - pid) & 65535 < 32768:
        return True
    offset = (pid - base) & 65535
    bitmap = wire[19:]
    return offset < len(bitmap) * 8 and not (bitmap[offset // 8] & (1 << (offset % 8)))


def verify_ordinals(frames):
    for index, wires in enumerate(frames):
        assert len(wires) == 55
        assert [struct.unpack_from("<h", w, 5)[0] for w in wires] == [54, *range(54)]
        assert [struct.unpack_from("<H", w, 7)[0] for w in wires] == list(
            range(index * 55, (index + 1) * 55)
        )
        assert b"".join(w[13:] for w in wires) == body(index)


def payloads():
    return [dict(size=len(au), sha256=hashlib.sha256(au).hexdigest()) for au in aus()]
