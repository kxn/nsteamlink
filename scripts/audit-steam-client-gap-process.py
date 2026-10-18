#!/usr/bin/env python3
"""Original CLIENT UDP unrepaired video gap -> strict wait -> key/P pixels.

Four real processes cover CRC and reliable/unreliable media. A controlled peer
omits a fragment; file barriers choose subsequent fixture input/Stop only. Real
client/network/crypto/windows/decoder/SDK/player execute. Reliable observation
is bounded, not a claim of infinite waiting or a measured host retransmission
threshold. No Steam identity/host adaptation, SDL renderer/GPU or Switch proof.
"""

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
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
check = module("check", "check-steam-gap-process.py")
neg = media.neg
VIDEO = (ROOT / "app/tests/fixtures/video/sequential.h264").read_bytes()


def body(fid, sequence, timestamp, start, size, flags):
    return (
        bytes([1])
        + struct.pack("<HIHI", fid, timestamp, 0, 0)
        + struct.pack("<HBHH", sequence, flags, 0, 0)
        + VIDEO[start : start + size]
    )


class Peer(neg.Peer):
    def __init__(self, *args):
        super().__init__(*args)
        self.started = self.seeded = self.stopped = self.sent_key = self.sent_post = (
            False
        )
        self.address = self.local = None

    def data(self, packet_id, payload, timestamp=1000000, fragment=0, head=True):
        kind = (5 if head else 6) if self.case["reliable"] else (3 if head else 4)
        self.send(
            bytearray(
                struct.pack(
                    "<BBBBBhHI",
                    kind,
                    0,
                    7,
                    self.local,
                    3,
                    fragment,
                    packet_id,
                    timestamp,
                )
                + payload
            ),
            self.address,
        )

    def recovery(self):
        if self.sent_key:
            return
        self.sent_key = True
        self.case["key_sent_index"] = len(self.sent)
        value = body(29, 4, 1040000, 4552, 1953, 24)
        self.data(6, value[:1200], 1040000, 1)
        self.data(7, value[1200:], 1040000, head=False)

    def __call__(self, raw, address):
        # Continuous client traffic must not starve a fixture barrier.
        self.on_idle()
        super().__call__(raw, address)
        data = neg.udp.without_crc(raw)
        kind = data[0] & 127
        if (
            data[4] == 3
            and kind in (3, 8)
            and check.normalize(raw) == check.expected_feedback(self.case)
        ):
            if "gap_feedback" not in self.case:
                self.case["gap_feedback"] = raw.hex()
                if self.case["reliable"]:
                    Path(self.case["stage_file"] + ".feedback").write_text(raw.hex())
                else:
                    assert self.seeded
                    self.recovery()
        if kind == 5 and data[4] == 1 and data[13] == 5 and not self.started:
            self.started = True
            self.address, self.local = address, raw[2]
            self.send(
                bytearray(
                    struct.pack("<BBBBBhHI", 5, 0, 7, raw[2], 1, 0, 4, 1000000)
                    + bytes([52])
                    + neg.encrypted(bytes.fromhex("080310042080012848"), 2)
                ),
                address,
            )
            value = body(23, 0, 1000000, 0, 2204, 24)
            self.data(0, value[:1200], fragment=1)
            self.data(1, value[1200:], head=False)

    def on_idle(self):
        path = Path(self.case["stage_file"])
        stage = path.read_text() if path.exists() else ""
        if stage == "seed" and not self.seeded:
            assert self.started
            self.seeded = True
            self.case["fault_sent_index"] = len(self.sent)
            lost = body(24, 1, 1005000, 2204, 411, 8)
            self.case["withheld_tail"] = lost[200:].hex()
            self.data(2, lost[:200], 1005000, 1)
            self.data(4, body(25, 2, 1010000, 2615, 425, 8), 1010000)
            self.data(5, body(26, 3, 1030000, 3040, 486, 8), 1030000)
            if self.case["reliable"]:
                self.recovery()
        if stage == "post_key" and not self.sent_post:
            assert not self.case["reliable"] and self.sent_key
            self.sent_post = True
            self.case["post_key_sent_index"] = len(self.sent)
            self.data(8, body(30, 5, 1040100, 6505, 501, 8), 1040100)
        if stage == "stop" and not self.stopped:
            self.stopped = True
            self.send(
                bytearray(
                    struct.pack("<BBBBBhHI", 5, 0, 7, self.local, 1, 0, 5, 1000000)
                    + bytes([53])
                    + neg.encrypted(b"", 3)
                ),
                self.address,
            )


def verify(case):
    controls = {}
    for item in case["received"]:
        raw = neg.udp.without_crc(bytes.fromhex(item["data"]))
        if raw[0] & 127 == 5 and raw[4] == 1 and raw[13] in (4, 5, 80):
            sequence, plain = neg.decrypted(raw[14:])
            value = dict(sequence=sequence, plain=(raw[13:14] + plain).hex())
            if raw[13] in controls:
                assert controls[raw[13]] == value
            controls[raw[13]] = value
    case["outputs"] = [controls[k] for k in (4, 5, 80)]
    case["native_projection"] = []
    for index, item in enumerate(case["outputs"]):
        plain = (
            bytes.fromhex(neg.projection.platform_frame(item["plain"]))
            if index == 0
            else bytes.fromhex(item["plain"])
        )
        case["native_projection"].append(
            dict(
                sequence=index,
                plain=plain.hex(),
                cipher=(plain[:1] + neg.encrypted(plain[1:], index)).hex(),
            )
        )
    case["media_input"] = [
        p for p in case["sent"] if neg.udp.without_crc(bytes.fromhex(p["data"]))[4] == 3
    ]
    check.verify_source(case)


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
    packets = json.loads(
        subprocess.check_output(
            [
                "ffprobe",
                "-v",
                "error",
                "-select_streams",
                "v:0",
                "-show_packets",
                "-show_entries",
                "packet=pos,size,flags",
                "-of",
                "json",
                str(ROOT / "app/tests/fixtures/video/sequential.h264"),
            ]
        )
    )["packets"]
    assert [(int(v["pos"]), int(v["size"])) for v in packets[:8]] == [
        (0, 2204),
        (2204, 411),
        (2615, 425),
        (3040, 486),
        (3526, 461),
        (3987, 565),
        (4552, 1953),
        (6505, 501),
    ]
    assert [i for i, v in enumerate(packets) if v["flags"].startswith("K")] == [0, 6]
    cases = []
    for reliable in (False, True):
        for crc in (False, True):
            case = dict(
                name=f"gap_reliable{int(reliable)}_crc{int(crc)}",
                reliable=reliable,
                crc=crc,
                settings="3800c80101",
                bad_mac=False,
                server="070a0308c00b",
                response="0208001001",
                duplicate=False,
                bad_length=False,
            )
            with tempfile.TemporaryDirectory(prefix="source-gap-") as d:
                settings = Path(d) / "streaming_settings.bin"
                settings.write_bytes(bytes.fromhex(case["settings"]))
                case["stage_file"] = str(Path(d) / "stage")
                output = args.output.with_name(
                    args.output.stem + "-" + case["name"] + ".json"
                )
                result = neg.udp.audit(
                    binary,
                    sdk,
                    qt,
                    output,
                    case,
                    helper=ROOT / "scripts/steam-client-gap-gdb.py",
                    reactor=Peer,
                    probe_config=dict(
                        udp_helper=str(ROOT / "scripts/steam-client-udp-gdb.py"),
                        negotiation_helper=str(
                            ROOT / "scripts/steam-client-negotiation-gdb.py"
                        ),
                        media_helper=str(ROOT / "scripts/steam-client-media-gdb.py"),
                        settings_file=str(settings),
                        stage_file=case["stage_file"],
                        reliable=reliable,
                        sdk_directory=str(sdk),
                    ),
                    validate=verify,
                )
                assert settings.read_bytes() == bytes.fromhex(case["settings"])
            cases.append(result)
            print(
                case["name"],
                "reliable gap blocks later key"
                if reliable
                else "DataLost -> key/P exact pixels",
                "Stop/exit verified",
                flush=True,
            )
    source = binary.read_bytes()
    elf = ELFFile(io.BytesIO(source))
    fdes = [e for e in elf.get_dwarf_info().EH_CFI_entries() if isinstance(e, FDE)]
    functions = {**media.FUNCTIONS, 0x3260D0: "decode_frame"}
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
                    start = fde["initial_location"]
                    functions.setdefault(start, f"gap_send_caller_{start:x}")
    report = dict(
        scope=__doc__,
        client_sha256=neg.udp.process.digest(binary),
        codec_sha256=neg.udp.process.digest(sdk / "libavcodec.so.61"),
        util_sha256=neg.udp.process.digest(sdk / "libavutil.so.59"),
        source_functions=neg.udp.process.boundary.inventory(source, functions),
        helpers={
            name: neg.udp.process.digest(ROOT / "scripts" / name)
            for name in (
                "steam-client-gap-gdb.py",
                "steam-client-media-gdb.py",
                "steam-client-negotiation-gdb.py",
                "steam-client-udp-gdb.py",
                "steam-client-sdk-gdb.py",
            )
        },
        runner_sha256=neg.udp.process.digest(
            ROOT / "scripts/audit-steam-client-udp-process.py"
        ),
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
        fixture_sha256=hashlib.sha256(VIDEO).hexdigest(),
        au_boundaries=packets,
        cases=cases,
    )
    data = (json.dumps(report, indent=2) + "\n").encode()
    args.output.write_bytes(data)
    if args.snapshot:
        args.snapshot.write_bytes(gzip.compress(data, mtime=0))
    print(
        "Original UDP unrepaired gap: 4 client processes/strict states/SDK/pixels/Stop verified"
    )


if __name__ == "__main__":
    main()
