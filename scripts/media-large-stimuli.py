"""Declared large no-parity inputs, not a sender activation/receiver model.

337 data shards exceed the GF total limit even before adding 5% parity. All
codewords are supplied by original AddPacket separately. Tail pacing is an
explicit recovery input; the preceding burst remains unpaced in burst cases.
"""

import hashlib
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
SIZE, STEP, SHARDS, SPACING = 393216, 13107, 337, 250
BOUNDARIES = [
    (0, 2204),
    (2204, 411),
    (2615, 425),
    (3040, 486),
    (3526, 461),
    (3987, 565),
]


def aus():
    data = (ROOT / "app/tests/fixtures/video/sequential.h264").read_bytes()
    result = []
    for begin, size in BOUNDARIES:
        au = data[begin : begin + size]
        padding = SIZE - len(au)
        result.append(au + b"\0\0\0\1\x0c" + b"\xff" * (padding - 6) + b"\x80")
    return result


def body(index):
    return (
        struct.pack(
            "<BHIHIHBHH",
            1,
            100 + index,
            1000000 + index * STEP,
            0,
            0,
            index,
            24 if index % 6 == 0 else 8,
            0,
            0,
        )
        + aus()[index % 6]
    )


def payloads():
    return [dict(size=len(au), sha256=hashlib.sha256(au).hexdigest()) for au in aus()]


def erasures(case, index):
    return {17} if case["profile"] == "fec_drop" and index == 1 else set()


def plans():
    return [
        dict(
            name=f"large_{profile}_{'burst' if burst else 'paced'}_crc{int(crc)}",
            profile=profile,
            crc=crc,
            frames=26,
            rate=5,
            delay_us=0,
            hole_pid=-1,
            spacing_us=0 if burst else SPACING,
            tail_spacing_us=SPACING,
            burst=burst,
        )
        for crc in (False, True)
        for burst, profile in (
            (False, "fec_full"),
            (False, "fec_drop"),
            (True, "fec_full"),
        )
    ]


def frames(case, bank):
    result = []
    for index in range(case["frames"]):
        group = []
        for wire in bank["groups"][index]["wires"]:
            raw = bytearray.fromhex(wire)
            if struct.unpack_from("<H", raw, 5)[0] in erasures(case, index):
                continue
            raw[2:4] = bytes([7, 0])
            struct.pack_into("<I", raw, 9, 1000000 + index * STEP)
            group.append(bytes(raw))
        result.append(group)
    return result
