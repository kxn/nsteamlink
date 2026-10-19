#!/usr/bin/env python3
"""Actual official client/SDK handling large type11 groups with zero parity.

Controlled peer, pacing/erasures, configured-decoder start barrier and headless
drain are explicit. Original methods/results/clock are unchanged. Burst cases
keep first24 groups unpaced and pace the final key/P tail for recovery. No real
Steam video producer, physical decoder/display, or throughput equivalence claim.
"""

import argparse
import ctypes
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


pressure = module("source_pressure", "audit-steam-client-pressure-process.py")
check = module("check_large", "check-steam-large-process.py")
large = check.large
BANK = None


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Peer(pressure.Peer):
    def __init__(self, *args):
        # Reuse the controlled negotiation/pacing reactor, with this input bank.
        pressure.load.Peer.__init__(self, *args)
        self.frames = large.frames(self.case, BANK)
        self.withheld, self.repaired = None, False
        self.case["initial"] = [
            [self.decorate(wire).hex() for wire in group] for group in self.frames
        ]
        self.case["feedback"] = []

    def __call__(self, raw, address):
        wire = pressure.load.neg.udp.without_crc(raw)
        if wire[0] & 127 == 5 and wire[4] == 1:
            path = Path(self.case["port_file"])
            if not path.exists():
                path.write_text(str(address[1]))
            # Explicit peer input, also replayed by the native large fixture.
            # ACK the received cumulative control ID with its actual timestamp.
            ack = bytearray(wire[:13] + wire[9:13])
            ack[:5] = bytes((7, 0, 7, wire[2], 1))
            ack[5:7] = bytes(2)
            ack[9:13] = (1000000).to_bytes(4, "little")
            self.send(ack, address)
        super().__call__(raw, address)

    def transmit(self, wire):
        super().transmit(wire)
        spacing = (
            self.case["tail_spacing_us"]
            if self.next > self.case["frames"] - 2
            else self.case["spacing_us"]
        )
        if spacing:
            time.sleep(spacing / 1000000)


def main():
    global BANK
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--sdk-directory", required=True, type=Path)
    parser.add_argument(
        "--qt-library-directory", required=True, action="append", type=Path
    )
    parser.add_argument("--fec-bank", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--snapshot", type=Path)
    args = parser.parse_args()
    binary, sdk = args.binary.resolve(), args.sdk_directory.resolve()
    qt = [p.resolve() for p in args.qt_library_directory]
    boundary = pressure.load.neg.udp.process.boundary
    assert digest(binary) == boundary.codec.SHA
    assert digest(sdk / "libavcodec.so.61") == boundary.CODEC_SHA
    assert digest(sdk / "libavutil.so.59") == boundary.codec.SDK_SHA
    BANK = json.loads(args.fec_bank.read_text())
    assert (BANK["k"], BANK["m"], BANK["shard"]) == (337, 0, 1168)
    assert BANK["generator_sha256"] == digest(
        ROOT / "scripts/audit-steam-large-fec-encode.py"
    )
    assert BANK["stimulus_sha256"] == digest(ROOT / "scripts/media-large-stimuli.py")
    shim = ROOT / "app/tests/fixtures/transport/sdk_delay.c"
    crc_source = ROOT / "third_party/ihslib/src/crc32c.c"
    cases = []
    with tempfile.TemporaryDirectory(prefix="source-large-adapters-") as td:
        folder = Path(td)
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
        compiled = ctypes.CDLL(str(crc))
        fn = compiled.IHS_CRC32C
        fn.argtypes, fn.restype = [ctypes.c_char_p, ctypes.c_size_t], ctypes.c_uint32

        def fast(data):
            raw = bytes(data)
            return int(fn(raw, len(raw)))

        original = pressure.load.neg.udp.crc32c
        for size in (0, 13, 1213, 65536, large.SIZE):
            data = bytes((n * 37 + 11) & 255 for n in range(size))
            assert fast(data) == original(data)
        assert fast(b"123456789") == 0xE3069283
        pressure.load.neg.udp.crc32c = fast
        for case in large.plans():
            case.update(
                reliable=False,
                settings="3800c80101",
                bad_mac=False,
                server="070a0308c00b",
                response="0208001001",
                duplicate=False,
                bad_length=False,
            )
            with tempfile.TemporaryDirectory(prefix="source-large-") as run_dir:
                directory = Path(run_dir)
                settings = directory / "settings.bin"
                settings.write_bytes(bytes.fromhex(case["settings"]))
                case["stage_file"], case["port_file"] = str(directory / "stage"), str(
                    directory / "client-port"
                )
                result = pressure.load.neg.udp.audit(
                    binary,
                    sdk,
                    qt,
                    args.output.with_name(
                        args.output.stem + "-" + case["name"] + ".json"
                    ),
                    case,
                    helper=ROOT / "scripts/steam-client-large-gdb.py",
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
                        port_file=case["port_file"],
                        settings_file=str(settings),
                        stage_file=case["stage_file"],
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
                result["process"]["load_receive_count"],
                "SDK",
                len(result["process"]["pictures"]),
                "socket",
                result["process"]["large_socket"],
                flush=True,
            )
    files = [
        "scripts/audit-steam-client-large-process.py",
        "scripts/check-steam-large-process.py",
        "scripts/check-steam-pressure-process.py",
        "scripts/media-large-stimuli.py",
        "scripts/audit-steam-client-pressure-process.py",
        "scripts/audit-steam-client-load-process.py",
        "scripts/audit-steam-client-media-process.py",
        "scripts/audit-steam-client-negotiation-process.py",
        "scripts/audit-steam-client-auth-process.py",
        "scripts/audit-steam-client-udp-process.py",
        "scripts/audit-steam-client-sdk-process.py",
        "scripts/audit-steam-client-sdk-boundary.py",
        "app/tests/fixtures/transport/sdk_delay.c",
        "third_party/ihslib/src/crc32c.c",
        "app/tests/fixtures/video/sequential.h264",
        "app/tests/fixtures/video/sequential.framemd5",
    ] + [
        "scripts/steam-client-" + name + "-gdb.py"
        for name in ("large", "pressure", "load", "media", "negotiation", "udp", "sdk")
    ]
    report = dict(
        scope=__doc__,
        client_sha256=digest(binary),
        codec_sha256=digest(sdk / "libavcodec.so.61"),
        util_sha256=digest(sdk / "libavutil.so.59"),
        source_functions=boundary.inventory(
            binary.read_bytes(),
            {
                **pressure.load.media.FUNCTIONS,
                0x3260D0: "decode_frame",
                0x2EDA20: "decoder_loop",
                0x2EDE20: "fifo_pop",
                0x326F30: "video_think",
            },
        ),
        fixture_programs={path: digest(ROOT / path) for path in files},
        qt_dependency_sha256={
            name: digest(
                next(
                    p / f"libQt6{name}.so.6"
                    for p in qt
                    if (p / f"libQt6{name}.so.6").is_file()
                )
            )
            for name in ("Core", "Gui", "Widgets", "Svg")
        },
        adapter_library_sha256=adapter_sha,
        crc_library_sha256=crc_sha,
        payloads=large.payloads(),
        fec_encoder=BANK,
        cases=cases,
    )
    check.verify_metadata(report)
    data = (json.dumps(report, indent=2) + "\n").encode()
    args.output.write_bytes(data)
    if args.snapshot:
        args.snapshot.write_bytes(gzip.compress(data, mtime=0))
    print("Official large no-parity:", len(cases), "actual processes verified")


if __name__ == "__main__":
    main()
