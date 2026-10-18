#!/usr/bin/env python3
"""Observe original client UDP missing-fragment feedback -> repair -> SDK pixels.

Pinned original sockets/workers/window/crypto/decoder/SDK/player execute. Peer
withholds one of three fragments and repairs only after actual matching NACK.
No parsed packet/frame, function/return, phase or SDK replacement. Controlled
peer retry is not Steam host timing, FEC activation or physical Switch rendering.
"""

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile

from elftools.dwarf.callframe import FDE
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


media = module("media", "audit-steam-client-media-process.py")
check = module("check", "check-steam-retry-process.py")
neg = media.neg


class Peer(neg.Peer):
    def __init__(self, *args):
        super().__init__(*args)
        self.started = self.stopped = self.repaired = False
        self.missing = None

    def __call__(self, raw, address):
        super().__call__(raw, address)
        data = neg.udp.without_crc(raw)
        kind = data[0] & 127
        if kind in (8, 10) and data[4] == 3 and not self.repaired:
            # An early feedback may describe only the first arrived fragment.
            # Wait for the complete declared gap, without assuming timer/count.
            if check.normalize(raw) != check.expected_feedback(self.case):
                return
            assert self.missing is not None
            self.repaired = True
            self.case["repair_feedback"] = raw.hex()
            self.case["repair_sent_index"] = len(self.sent)
            self.missing[1] = 1
            self.send(self.missing, address)
        if kind != 5 or data[4] != 1:
            return
        if data[13] == 5 and not self.started:
            self.started = True
            self.send(
                bytearray(
                    struct.pack("<BBBBBhHI", 5, 0, 7, raw[2], 1, 0, 4, 1000000)
                    + bytes([52])
                    + neg.encrypted(bytes.fromhex("080310042080012848"), 2)
                ),
                address,
            )
            pieces = [media.BODY[:800], media.BODY[800:1600], media.BODY[1600:]]
            for i, piece in enumerate(pieces):
                wire = bytearray(
                    struct.pack(
                        "<BBBBBhHI",
                        (5 if i == 0 else 6)
                        if self.case["reliable"]
                        else (3 if i == 0 else 4),
                        0,
                        7,
                        raw[2],
                        3,
                        2 if i == 0 else i - 1,
                        i,
                        1000000,
                    )
                    + piece
                )
                if i == self.case["missing"]:
                    self.missing = wire
                    self.case["withheld"] = wire.hex()
                else:
                    self.send(wire, address)
        elif data[13] == 80 and not self.stopped:
            assert self.repaired
            self.stopped = True
            self.send(
                bytearray(
                    struct.pack("<BBBBBhHI", 5, 0, 7, raw[2], 1, 0, 5, 1000000)
                    + bytes([53])
                    + neg.encrypted(b"", 3)
                ),
                address,
            )


def verify(case):
    expected = (
        [check.INITIAL_GAP_ASSERTION]
        if case["reliable"] and case["missing"] == 0
        else []
    )
    media.verify(case, expected_assertions=expected)
    check.verify_source(case, media.PAYLOAD, media.MD5)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--sdk-directory", type=Path, required=True)
    p.add_argument("--qt-library-directory", type=Path, action="append", required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--snapshot", type=Path)
    args = p.parse_args()
    binary, sdk, qt = (
        args.binary.resolve(),
        args.sdk_directory.resolve(),
        [d.resolve() for d in args.qt_library_directory],
    )
    assert neg.udp.process.digest(binary) == neg.udp.process.boundary.codec.SHA
    assert (
        neg.udp.process.digest(sdk / "libavcodec.so.61")
        == neg.udp.process.boundary.CODEC_SHA
    )
    assert (
        neg.udp.process.digest(sdk / "libavutil.so.59")
        == neg.udp.process.boundary.codec.SDK_SHA
    )
    cases = []
    for reliable in (False, True):
        for crc in (False, True):
            for missing in (0, 1):
                case = dict(
                    name=f"retry_reliable{int(reliable)}_crc{int(crc)}_missing{missing}",
                    reliable=reliable,
                    crc=crc,
                    missing=missing,
                    fec=False,
                    order=[i for i in range(3) if i != missing] + [missing],
                    settings="3800c80101",
                    bad_mac=False,
                    server="070a0308c00b",
                    response="0208001001",
                    duplicate=False,
                    bad_length=False,
                )
                output = args.output.with_name(
                    args.output.stem + "-" + case["name"] + ".json"
                )
                with tempfile.TemporaryDirectory(prefix="source-retry-settings-") as d:
                    settings = Path(d) / "streaming_settings.bin"
                    settings.write_bytes(bytes.fromhex(case["settings"]))
                    result = neg.udp.audit(
                        binary,
                        sdk,
                        qt,
                        output,
                        case,
                        helper=ROOT / "scripts/steam-client-retry-gdb.py",
                        reactor=Peer,
                        probe_config=dict(
                            udp_helper=str(ROOT / "scripts/steam-client-udp-gdb.py"),
                            negotiation_helper=str(
                                ROOT / "scripts/steam-client-negotiation-gdb.py"
                            ),
                            media_helper=str(
                                ROOT / "scripts/steam-client-media-gdb.py"
                            ),
                            settings_file=str(settings),
                            sdk_directory=str(sdk),
                        ),
                        validate=verify,
                    )
                    assert settings.read_bytes() == bytes.fromhex(case["settings"])
                cases.append(result)
                print(
                    case["name"],
                    "actual NACK -> repair -> SDK/pixel/Stop/exit verified",
                    flush=True,
                )
    # Bind complete containing FDE identities for all actual feedback stack frames.
    source = binary.read_bytes()
    elf = ELFFile(io.BytesIO(source))
    fdes = [e for e in elf.get_dwarf_info().EH_CFI_entries() if isinstance(e, FDE)]
    functions = dict(media.FUNCTIONS)
    for case in cases:
        for entry in case["process"]["feedback_sends"]:
            for frame in entry["stack"]:
                pc = frame["source_relative"]
                if pc is not None:
                    entry = next(
                        e
                        for e in fdes
                        if e["initial_location"]
                        <= pc - 1
                        < e["initial_location"] + e["address_range"]
                    )
                    start = entry["initial_location"]
                    functions.setdefault(start, f"feedback_caller_{start:x}")
    report = dict(
        scope=__doc__,
        client_sha256=neg.udp.process.digest(binary),
        codec_sha256=neg.udp.process.digest(sdk / "libavcodec.so.61"),
        util_sha256=neg.udp.process.digest(sdk / "libavutil.so.59"),
        source_functions=neg.udp.process.boundary.inventory(source, functions),
        helpers={
            name: neg.udp.process.digest(ROOT / "scripts" / name)
            for name in (
                "steam-client-retry-gdb.py",
                "steam-client-media-gdb.py",
                "steam-client-negotiation-gdb.py",
                "steam-client-udp-gdb.py",
                "steam-client-sdk-gdb.py",
            )
        },
        qt_dependency_sha256={
            name: neg.udp.process.digest(
                next(
                    d / f"libQt6{name}.so.6"
                    for d in qt
                    if (d / f"libQt6{name}.so.6").is_file()
                )
            )
            for name in ("Core", "Gui", "Widgets", "Svg")
        },
        fixture_sha256=hashlib.sha256(media.PAYLOAD).hexdigest(),
        pixel_md5=media.MD5,
        cases=cases,
    )
    data = (json.dumps(report, indent=2) + "\n").encode()
    args.output.write_bytes(data)
    if args.snapshot:
        args.snapshot.write_bytes(gzip.compress(data, mtime=0))
    print(
        "Original real UDP repair: 8 cases verified; 2 exact nonfatal original diagnostics preserved"
    )


if __name__ == "__main__":
    main()
