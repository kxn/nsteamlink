#!/usr/bin/env python3
"""Official UDP large-AU fragmentation, byte pressure, NACK repair and FEC.

Original client/SDK/RS run; peer, pacing, SDK latency and erasures are explicit
inputs. A native CRC utility only constructs/checks fixture transport checksums;
original Socket CRC validation remains active. FEC parity is original Android
encoder output at a declared capability boundary, not a video enable strategy.
No genuine Steam sender, physical pixels/decoder capacity or wall-time claim.
"""
import argparse
import ctypes
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


load = module("load", "audit-steam-client-load-process.py")
stim = module("stim", "media-pressure-stimuli.py")
AUS = stim.aus()
BANK = None


def frames(case):
    if not case["profile"].startswith("fec_"):
        result = [stim.ordinary(i) for i in range(case["frames"])]
        stim.verify_ordinals(result)
        return result
    result = []
    for i in range(case["frames"]):
        chosen = []
        for wire in BANK["groups"][i]["wires"]:
            raw = bytearray.fromhex(wire)
            index = struct.unpack_from("<H", raw, 5)[0]
            if index in stim.erasures(case["profile"], i):
                continue
            raw[2:4] = bytes([7, 0])
            struct.pack_into("<I", raw, 9, 1000000 + i * 1092)
            chosen.append(bytes(raw))
        result.append(chosen)
    return result


class Peer(load.Peer):
    def __init__(self, *args):
        super().__init__(*args)
        self.frames = frames(self.case)
        self.withheld = None
        self.repaired = False
        self.case["initial"] = [
            [self.decorate(raw).hex() for raw in group] for group in self.frames
        ]
        self.case["feedback"] = []

    def decorate(self, raw):
        raw = bytearray(raw)
        if self.case["crc"]:
            raw[0] |= 128
            raw += struct.pack("<I", load.neg.udp.crc32c(raw))
        return bytes(raw)

    def transmit(self, raw):
        raw = bytearray(raw)
        raw[3] = self.local
        self.send(raw, self.address)

    def __call__(self, raw, address):
        super().__call__(raw, address)
        wire = load.neg.udp.without_crc(raw)
        if wire[4] == 3 and wire[0] & 127 == 10:
            self.case["feedback"].append(raw.hex())
            if (
                self.case["profile"] == "repair"
                and self.withheld
                and not self.repaired
                and stim.requested(wire, self.case["hole_pid"])
            ):
                packet = bytearray(self.withheld)
                packet[1] = 1
                self.case["repair_feedback"] = raw.hex()
                self.case["repair_sent_index"] = len(self.sent)
                self.transmit(packet)
                self.repaired = True
                self.case["repaired"] = True

    def on_idle(self):
        if not self.started:
            return
        path = Path(self.case["stage_file"])
        stage = path.read_text() if path.exists() else ""
        if stage == "start" and self.begin is None:
            self.begin = time.monotonic()
            self.case["producer_times"] = []
        if self.begin is not None and not self.stopped:
            while (
                self.next < self.case["frames"]
                and time.monotonic() - self.begin >= self.next / self.case["rate"]
            ):
                index = self.next
                self.next += 1
                for raw in self.frames[index]:
                    if (
                        self.case["hole_pid"] >= 0
                        and struct.unpack_from("<H", raw, 7)[0] == self.case["hole_pid"]
                    ):
                        assert self.withheld is None
                        self.withheld = raw
                        self.case["withheld"] = self.decorate(raw).hex()
                    else:
                        self.transmit(raw)
                self.case["producer_times"].append(time.monotonic() - self.begin)
        if stage == "stop" and not self.stopped:
            self.stopped = True
            self.send(
                bytearray(
                    struct.pack("<BBBBBhHI", 5, 0, 7, self.local, 1, 0, 5, 1000000)
                    + bytes([53])
                    + load.neg.encrypted(b"", 3)
                ),
                self.address,
            )


def verify_source(case):
    r = case["process"]
    count = case["frames"]
    last = 100 + count - 1
    ids = r["load_frames"]
    assert r["exit_code"] == 0 and r["cleanup_complete"] and not r["source_assertions"]
    assert (
        r["load_table_restored"]
        and r["load_adapter_closed"]
        and r["media_final"]["decoder"] == 0
        and r["media_final"]["phase"] == 6
    )
    assert (
        ids == sorted(set(ids))
        and ids[-2:] == [last - 1, last]
        and r["load_receive_count"] == len(ids)
    )
    expected = set(range(100, last + 1))
    if case["profile"] in ("drop", "fec_drop"):
        expected.remove(101)
    if case["profile"] == "drop":
        assert set(ids) <= expected and 101 not in ids
    else:
        assert set(ids) == expected
    if case["profile"] == "repair":
        assert case.get("repaired") and case.get("repair_feedback")
    if case["profile"].startswith("fec_"):
        assert not case["feedback"]
    if case["profile"] in ("repair", "drop"):
        assert case["feedback"]
    if case["delay_us"]:
        assert (
            r["load_receive_busy"] > 0
            and max(s["count"] or 0 for s in r["load_sdk_samples"]) > 64
        )
    pictures = r["pictures"]
    assert [p["id"] for p in pictures[-2:]] == [last - 1, last]
    decoded = [p["id"] for p in pictures]
    assert decoded == sorted(set(decoded)) and set(decoded) <= set(ids)
    hashes = [
        line.split(",")[-1].strip()
        for line in (ROOT / "app/tests/fixtures/video/sequential.framemd5")
        .read_text()
        .splitlines()
        if not line.startswith("#")
    ]
    assert all(p["md5"] == hashes[(p["id"] - 100) % 6] for p in pictures)
    packets = [e for e in r["media_events"] if e["name"] == "sdk_send"]
    assert len(packets) == len(pictures) == len(r["load_sdk_samples"])
    for event, picture in zip(packets, pictures):
        assert (
            event["size"] == 65536
            and event["sha256"]
            == hashlib.sha256(AUS[(picture["id"] - 100) % 6]).hexdigest()
        )
    for name in ("sdk_send_return", "sdk_receive_return"):
        assert [e["result"] for e in r["media_events"] if e["name"] == name] == [
            0
        ] * len(pictures)
    assert r["load_adapter_final"] == [
        0,
        len(pictures),
        len(pictures),
        case["delay_us"] * len(pictures),
    ]
    assert [e["result"] for e in r["media_events"] if e["name"] == "decoder_join"] == [
        0
    ]
    assert [
        (e["value"], e["phase"])
        for e in r["module_events"]
        if e["name"].startswith("module_force")
    ] == [(7, "original_exit"), (0, "original_exit")]
    assert not {
        p for p, s in r["tasks_after_shutdown"].items() if s not in ("X", "Z")
    } - set(r["tasks_before"])
    assert (
        len(case["producer_times"]) == count
        and case["producer_times"][-1] >= (count - 1) / case["rate"] - 0.005
    )


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
    binary = a.binary.resolve()
    sdk = a.sdk_directory.resolve()
    qt = [d.resolve() for d in a.qt_library_directory]
    assert (
        load.neg.udp.process.digest(binary) == load.neg.udp.process.boundary.codec.SHA
    )
    assert (
        load.neg.udp.process.digest(sdk / "libavcodec.so.61")
        == load.neg.udp.process.boundary.CODEC_SHA
    )
    assert (
        load.neg.udp.process.digest(sdk / "libavutil.so.59")
        == load.neg.udp.process.boundary.codec.SDK_SHA
    )
    BANK = json.loads(a.fec_bank.read_text())
    assert (
        BANK["binary_sha256"]
        == "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"
    )
    assert (BANK["k"], BANK["m"], BANK["shard"]) == (57, 3, 1168) and len(
        BANK["groups"]
    ) == 26
    assert BANK["generator_sha256"] == load.neg.udp.process.digest(
        ROOT / "scripts/audit-steam-pressure-fec-encode.py"
    )
    for i, g in enumerate(BANK["groups"]):
        assert g["body_sha256"] == hashlib.sha256(stim.body(i)).hexdigest()
    cases = []
    shim = ROOT / "app/tests/fixtures/transport/sdk_delay.c"
    crc_source = ROOT / "third_party/ihslib/src/crc32c.c"
    with tempfile.TemporaryDirectory(prefix="source-pressure-adapters-") as d:
        folder = Path(d)
        library = folder / "sdk-delay.so"
        crc = folder / "crc.so"
        for src, out in [(shim, library), (crc_source, crc)]:
            subprocess.run(
                [
                    "cc",
                    "-O2",
                    "-shared",
                    "-fPIC",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    str(src),
                    "-o",
                    str(out),
                ],
                check=True,
                capture_output=True,
            )
        adapter = load.neg.udp.process.digest(library)
        crc_sha = load.neg.udp.process.digest(crc)
        native = ctypes.CDLL(str(crc))
        fn = native.IHS_CRC32C
        fn.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
        fn.restype = ctypes.c_uint32

        def fast(data):
            raw = bytes(data)
            return int(fn(raw, len(raw)))

        original = load.neg.udp.crc32c
        for size in (0, 1, 13, 1213, 65536):
            raw = bytes((n * 37 + 11) & 255 for n in range(size))
            assert fast(raw) == original(raw)
        assert fast(b"123456789") == 0xE3069283
        load.neg.udp.crc32c = fast
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
            with tempfile.TemporaryDirectory(prefix="source-pressure-") as td:
                settings = Path(td) / "settings.bin"
                settings.write_bytes(bytes.fromhex(case["settings"]))
                case["stage_file"] = str(Path(td) / "stage")
                result = load.neg.udp.audit(
                    binary,
                    sdk,
                    qt,
                    a.output.with_name(a.output.stem + "-" + case["name"] + ".json"),
                    case,
                    helper=ROOT / "scripts/steam-client-pressure-gdb.py",
                    reactor=Peer,
                    probe_config=dict(
                        udp_helper=str(ROOT / "scripts/steam-client-udp-gdb.py"),
                        negotiation_helper=str(
                            ROOT / "scripts/steam-client-negotiation-gdb.py"
                        ),
                        media_helper=str(ROOT / "scripts/steam-client-media-gdb.py"),
                        load_helper=str(ROOT / "scripts/steam-client-load-gdb.py"),
                        settings_file=str(settings),
                        stage_file=case["stage_file"],
                        delay_library=str(library),
                        delay_us=case["delay_us"],
                        last_id=100 + case["frames"] - 1,
                    ),
                    validate=verify_source,
                )
                assert settings.read_bytes() == bytes.fromhex(case["settings"])
            cases.append(result)
            print(
                case["name"],
                "received",
                result["process"]["load_receive_count"],
                "SDK",
                len(result["process"]["pictures"]),
                "NACKs",
                len(case["feedback"]),
                "clean Stop/exit",
                flush=True,
            )
    report = dict(
        scope=__doc__,
        client_sha256=load.neg.udp.process.digest(binary),
        codec_sha256=load.neg.udp.process.digest(sdk / "libavcodec.so.61"),
        util_sha256=load.neg.udp.process.digest(sdk / "libavutil.so.59"),
        source_functions=load.neg.udp.process.boundary.inventory(
            binary.read_bytes(),
            {
                **load.media.FUNCTIONS,
                0x3260D0: "decode_frame",
                0x2EDA20: "decoder_loop",
                0x2EDE20: "fifo_pop",
                0x326F30: "video_think",
            },
        ),
        helpers={
            name: load.neg.udp.process.digest(ROOT / "scripts" / name)
            for name in (
                "steam-client-pressure-gdb.py",
                "steam-client-load-gdb.py",
                "steam-client-media-gdb.py",
                "steam-client-negotiation-gdb.py",
                "steam-client-udp-gdb.py",
                "steam-client-sdk-gdb.py",
            )
        },
        runner_sha256=load.neg.udp.process.digest(
            ROOT / "scripts/audit-steam-client-udp-process.py"
        ),
        generator_sha256=load.neg.udp.process.digest(Path(__file__)),
        stimulus_sha256=load.neg.udp.process.digest(
            ROOT / "scripts/media-pressure-stimuli.py"
        ),
        adapter_source_sha256=load.neg.udp.process.digest(shim),
        adapter_library_sha256=adapter,
        crc_source_sha256=load.neg.udp.process.digest(crc_source),
        crc_library_sha256=crc_sha,
        qt_dependency_sha256={
            name: load.neg.udp.process.digest(
                next(
                    d / f"libQt6{name}.so.6"
                    for d in qt
                    if (d / f"libQt6{name}.so.6").is_file()
                )
            )
            for name in ("Core", "Gui", "Widgets", "Svg")
        },
        fec_encoder=BANK,
        fixture_sha256=load.neg.udp.process.digest(
            ROOT / "app/tests/fixtures/video/sequential.h264"
        ),
        payloads=stim.payloads(),
        cases=cases,
    )
    data = (json.dumps(report, indent=2) + "\n").encode()
    a.output.write_bytes(data)
    if a.snapshot:
        a.snapshot.write_bytes(gzip.compress(data, mtime=0))
    print("Official byte pressure:", len(cases), "processes verified")


if __name__ == "__main__":
    main()
