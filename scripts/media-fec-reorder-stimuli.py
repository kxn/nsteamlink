"""Declared peer schedules, not a receiver model or FEC activation policy.

Codewords are the pinned official Android encoder's k57/m3/S1168 output.
Only endpoints/timestamps/CRC and send order/erasures are fixture inputs.
Empty producer ticks represent no datagram, not a zero-byte UDP packet.
"""

import hashlib
import importlib.util
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "pressure_stim", ROOT / "scripts/media-pressure-stimuli.py"
)
pressure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pressure)
PROFILES = (
    "reverse_repair",
    "rollback_loss",
    "rollback_retry",
    "late_old",
    "two_holes",
)


def plans():
    return [
        dict(
            name=f"fec_reorder_{profile}_crc{int(crc)}",
            profile=profile,
            crc=crc,
            frames=26,
            rate=5,
            delay_us=0,
            hole_pid=-1,
            spacing_us=250,
            tail_spacing_us=250,
        )
        for crc in (False, True)
        for profile in PROFILES
    ]


def bank_check(bank):
    assert (
        bank["binary_sha256"]
        == "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"
    )
    assert (bank["k"], bank["m"], bank["shard"], len(bank["groups"])) == (
        57,
        3,
        1168,
        26,
    )
    for key, file in (
        ("generator_sha256", "audit-steam-pressure-fec-encode.py"),
        ("helper_sha256", "audit-steam-fec.py"),
        ("recovery_helper_sha256", "audit-steam-video-recovery.py"),
        ("stimulus_sha256", "media-pressure-stimuli.py"),
    ):
        assert (
            bank[key]
            == hashlib.sha256((ROOT / "scripts" / file).read_bytes()).hexdigest()
        )
    for index, group in enumerate(bank["groups"]):
        assert group["index"] == index and len(group["wires"]) == 60
        assert group["body_sha256"] == hashlib.sha256(pressure.body(index)).hexdigest()


def batches(case, bank):
    groups = []
    for index, group in enumerate(bank["groups"]):
        row = []
        for shard, hexwire in enumerate(group["wires"]):
            wire = bytearray.fromhex(hexwire)
            assert wire[0] == 11 and wire[4] == 3
            assert struct.unpack_from("<HH", wire, 5) == (shard, index + 1)
            assert struct.unpack_from("<IHH", wire, 13) == (65556, 1168, 3)
            wire[2:4] = bytes((7, 0))
            struct.pack_into("<I", wire, 9, 1000000 + index * 1092)
            row.append(bytes(wire))
        groups.append(row)
    result = [list(g) for g in groups]
    profile = case["profile"]
    if profile == "reverse_repair":
        result[1] = [groups[1][i] for i in reversed(range(60)) if i not in (0, 17, 55)]
    elif profile in ("rollback_loss", "rollback_retry"):
        result[1] = groups[1][:28] + groups[2][:28] + groups[1][28:] + groups[2][28:]
        result[2] = []
        if profile == "rollback_retry":
            result[1] += groups[1] + groups[2]
    elif profile == "late_old":
        result[1] = groups[1][:28]
        result[2] = groups[2] + groups[1][28:] + groups[1][:28]
    elif profile == "two_holes":
        for index in (1, 2):
            result[index] = [
                w for i, w in enumerate(groups[index]) if i not in (0, 17, 30, 55)
            ]
    else:
        raise ValueError(profile)
    return result


def expected_ids(profile):
    missing = (
        {101, 102}
        if profile in ("rollback_loss", "two_holes")
        else {101} if profile == "late_old" else set()
    )
    return [i for i in range(100, 126) if i not in missing]
