#!/usr/bin/env python3
"""Original CLIENT real UDP/RS/video recovery across reordered FEC groups.

Fixed Android client codewords, controlled peer pacing/erasures/retries and
headless driver are explicit inputs. Original Linux constructors, socket/CRC,
one-group FEC receiver, worker, decoder, SDK, requests and cleanup execute.
No client flags, results or decoder entry points are substituted. No genuine
Steam sender, Switch, hardware/physical rendering or timing equivalence claim.
"""
import argparse
import ctypes
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import time

from elftools.dwarf.callframe import FDE
from elftools.elf.elffile import ELFFile

import importlib.util

ROOT = Path(__file__).resolve().parents[1]


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


pressure = module("source_pressure", "audit-steam-client-pressure-process.py")
check = module("reorder_check", "check-steam-fec-reorder-process.py")
stim = check.stim
BANK = None


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Peer(pressure.Peer):
    def __init__(self, *args):
        pressure.load.Peer.__init__(self, *args)
        self.frames = stim.batches(self.case, BANK)
        self.withheld, self.repaired = None, False
        self.case["initial"] = [
            [self.decorate(w).hex() for w in row] for row in self.frames
        ]
        self.case["feedback"] = []

    def transmit(self, wire):
        super().transmit(wire)
        time.sleep(self.case["spacing_us"] / 1000000)

    def __call__(self, raw, address):
        wire = pressure.load.neg.udp.without_crc(raw)
        if wire[0] & 127 == 5 and wire[4] == 1:
            path = Path(self.case["port_file"])
            if not path.exists():
                path.write_text(str(address[1]))
            ack = bytearray(wire[:13] + wire[9:13])
            ack[:5] = bytes((7, 0, 7, wire[2], 1))
            ack[5:7] = bytes(2)
            ack[9:13] = (1000000).to_bytes(4, "little")
            self.send(ack, address)
        super().__call__(raw, address)


def main():
    global BANK
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", required=True, type=Path)
    p.add_argument("--sdk-directory", required=True, type=Path)
    p.add_argument("--qt-library-directory", required=True, action="append", type=Path)
    p.add_argument("--fec-bank", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--snapshot", type=Path)
    a = p.parse_args()
    binary, sdk = a.binary.resolve(), a.sdk_directory.resolve()
    qt = [d.resolve() for d in a.qt_library_directory]
    boundary = pressure.load.neg.udp.process.boundary
    assert digest(binary) == boundary.codec.SHA
    assert digest(sdk / "libavcodec.so.61") == boundary.CODEC_SHA
    assert digest(sdk / "libavutil.so.59") == boundary.codec.SDK_SHA
    BANK = json.loads(a.fec_bank.read_text())
    stim.bank_check(BANK)
    cases = []
    with tempfile.TemporaryDirectory(prefix="source-fec-reorder-adapters-") as td:
        folder = Path(td)
        shim = ROOT / "app/tests/fixtures/transport/sdk_delay.c"
        crc_source = ROOT / "third_party/ihslib/src/crc32c.c"
        library, crc = folder / "sdk-delay.so", folder / "crc.so"
        for source, target in ((shim, library), (crc_source, crc)):
            subprocess.run(
                [
                    "cc",
                    "-O2",
                    "-shared",
                    "-fPIC",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    str(source),
                    "-o",
                    str(target),
                ],
                capture_output=True,
                check=True,
            )
        adapter_sha, crc_sha = digest(library), digest(crc)
        native = ctypes.CDLL(str(crc))
        fn = native.IHS_CRC32C
        fn.argtypes, fn.restype = [ctypes.c_char_p, ctypes.c_size_t], ctypes.c_uint32

        def fast(data):
            raw = bytes(data)
            return int(fn(raw, len(raw)))

        old = pressure.load.neg.udp.crc32c
        for size in (0, 13, 1213, 65536):
            data = bytes((n * 37 + 11) & 255 for n in range(size))
            assert fast(data) == old(data)
        assert fast(b"123456789") == 0xE3069283
        pressure.load.neg.udp.crc32c = fast
        for case in stim.plans():
            case.update(
                reliable=False,
                settings="3800c80101",
                bad_mac=False,
                server="070a0308c00b",
                response="0208001001",
                duplicate=False,
                bad_length=False,
            )
            with tempfile.TemporaryDirectory(prefix="source-fec-reorder-") as run:
                directory = Path(run)
                settings = directory / "settings.bin"
                settings.write_bytes(bytes.fromhex(case["settings"]))
                case["stage_file"], case["port_file"] = str(directory / "stage"), str(
                    directory / "client-port"
                )
                result = pressure.load.neg.udp.audit(
                    binary,
                    sdk,
                    qt,
                    a.output.with_name(a.output.stem + "-" + case["name"] + ".json"),
                    case,
                    helper=ROOT / "scripts/steam-client-fec-reorder-gdb.py",
                    reactor=Peer,
                    probe_config=dict(
                        udp_helper=str(ROOT / "scripts/steam-client-udp-gdb.py"),
                        negotiation_helper=str(
                            ROOT / "scripts/steam-client-negotiation-gdb.py"
                        ),
                        media_helper=str(ROOT / "scripts/steam-client-media-gdb.py"),
                        load_helper=str(ROOT / "scripts/steam-client-load-gdb.py"),
                        pressure_helper=str(
                            ROOT / "scripts/steam-client-pressure-gdb.py"
                        ),
                        large_helper=str(ROOT / "scripts/steam-client-large-gdb.py"),
                        gap_helper=str(ROOT / "scripts/steam-client-gap-gdb.py"),
                        settings_file=str(settings),
                        stage_file=case["stage_file"],
                        port_file=case["port_file"],
                        delay_library=str(library),
                        delay_us=0,
                        last_id=125,
                    ),
                    validate=check.verify_source,
                )
                assert settings.read_bytes() == bytes.fromhex(case["settings"])
            cases.append(result)
            print(
                case["name"],
                "RX",
                result["process"]["load_frames"],
                "SDK",
                [p["id"] for p in result["process"]["pictures"]],
                "DataLost",
                len(result["process"]["gap_sends"]),
                flush=True,
            )
    functions = {
        **pressure.load.media.FUNCTIONS,
        0x3260D0: "decode_frame",
        0x2EDA20: "decoder_loop",
        0x2EDE20: "fifo_pop",
        0x326F30: "video_think",
    }
    source = binary.read_bytes()
    fdes = [
        e
        for e in ELFFile(io.BytesIO(source)).get_dwarf_info().EH_CFI_entries()
        if isinstance(e, FDE)
    ]
    for case in cases:
        for event in case["process"]["gap_sends"]:
            for frame in event["stack"]:
                pc = frame["source_relative"]
                if pc is not None:
                    fde = next(
                        e
                        for e in fdes
                        if e["initial_location"]
                        <= pc - 1
                        < e["initial_location"] + e["address_range"]
                    )
                    functions.setdefault(
                        fde["initial_location"],
                        f"recovery_caller_{fde['initial_location']:x}",
                    )
    files = [
        "scripts/" + name
        for name in (
            "audit-steam-client-fec-reorder-process.py",
            "check-steam-fec-reorder-process.py",
            "media-fec-reorder-stimuli.py",
            "audit-steam-client-pressure-process.py",
            "check-steam-pressure-process.py",
            "check-steam-large-process.py",
            "media-pressure-stimuli.py",
            "audit-steam-client-load-process.py",
            "audit-steam-client-media-process.py",
            "audit-steam-client-negotiation-process.py",
            "audit-steam-client-auth-process.py",
            "audit-steam-client-udp-process.py",
            "audit-steam-client-sdk-process.py",
            "audit-steam-client-sdk-boundary.py",
        )
    ]
    files += [
        "scripts/steam-client-" + name + "-gdb.py"
        for name in (
            "fec-reorder",
            "gap",
            "large",
            "pressure",
            "load",
            "media",
            "negotiation",
            "udp",
            "sdk",
        )
    ]
    files += [
        "app/tests/fixtures/transport/sdk_delay.c",
        "third_party/ihslib/src/crc32c.c",
        "app/tests/fixtures/video/sequential.h264",
        "app/tests/fixtures/video/sequential.framemd5",
    ]
    report = dict(
        scope=__doc__,
        client_sha256=digest(binary),
        codec_sha256=digest(sdk / "libavcodec.so.61"),
        util_sha256=digest(sdk / "libavutil.so.59"),
        source_functions=boundary.inventory(source, functions),
        fixture_programs={file: digest(ROOT / file) for file in files},
        qt_dependency_sha256={
            name: digest(
                next(
                    d / f"libQt6{name}.so.6"
                    for d in qt
                    if (d / f"libQt6{name}.so.6").is_file()
                )
            )
            for name in ("Core", "Gui", "Widgets", "Svg")
        },
        adapter_library_sha256=adapter_sha,
        crc_library_sha256=crc_sha,
        fec_encoder=BANK,
        cases=cases,
    )
    raw = (json.dumps(report, indent=2) + "\n").encode()
    a.output.write_bytes(raw)
    if a.snapshot:
        a.snapshot.write_bytes(gzip.compress(raw, mtime=0))
    print(
        "Original client:10 cross-group FEC UDP/worker/SDK/pixels/recovery/cleanup cases passed"
    )


if __name__ == "__main__":
    main()
