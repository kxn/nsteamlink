#!/usr/bin/env python3
"""Official real UDP video under paced input and a slow SDK forwarding endpoint.

Only top-level driver, peer input and SDK latency adapter are controlled. Real
constructors, socket/crypto/window/FIFO/worker/decoder and original SDK execute.
The adapter changes latency, never status or pixels; no genuine Steam producer,
Switch, high-bitrate capacity or natural wall-time performance claim is made.
"""
import argparse
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
spec = importlib.util.spec_from_file_location(
    "media", ROOT / "scripts/audit-steam-client-media-process.py"
)
media = importlib.util.module_from_spec(spec)
spec.loader.exec_module(media)
neg = media.neg
CLIP = (ROOT / "app/tests/fixtures/video/sequential.h264").read_bytes()
BOUNDARIES = [
    (0, 2204),
    (2204, 411),
    (2615, 425),
    (3040, 486),
    (3526, 461),
    (3987, 565),
]
AUS = [CLIP[a : a + n] for a, n in BOUNDARIES]


def plans():
    return [
        dict(
            name=f"load_d{delay}_crc{int(crc)}",
            crc=crc,
            delay_us=delay,
            frames=302,
            rate=60,
        )
        for crc in (False, True)
        for delay in (0, 30000, 80000)
    ]


class Peer(neg.Peer):
    def __init__(self, *args):
        super().__init__(*args)
        args[0].settimeout(0.001)  # Explicit paced-fixture polling, not a client timer.
        self.started = self.stopped = False
        self.begin = None
        self.next = 0
        self.pid = 0
        self.address = None

    def __call__(self, raw, address):
        self.on_idle()
        super().__call__(raw, address)
        data = neg.udp.without_crc(raw)
        if data[0] & 127 == 5 and data[4] == 1 and data[13] == 5 and not self.started:
            self.started = True
            self.address = address
            self.local = raw[2]
            self.send(
                bytearray(
                    struct.pack("<BBBBBhHI", 5, 0, 7, self.local, 1, 0, 4, 1000000)
                    + bytes([52])
                    + neg.encrypted(bytes.fromhex("080310042080012848"), 2)
                ),
                address,
            )

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
                au = index % 6
                stamp = 1000000 + index * 1092
                body = (
                    struct.pack(
                        "<BHIHIHBHH",
                        1,
                        100 + index,
                        stamp,
                        0,
                        0,
                        index,
                        24 if au == 0 else 8,
                        0,
                        0,
                    )
                    + AUS[au]
                )
                chunks = [body[k : k + 1200] for k in range(0, len(body), 1200)]
                for j, chunk in enumerate(chunks):
                    self.send(
                        bytearray(
                            struct.pack(
                                "<BBBBBhHI",
                                3 if j == 0 else 4,
                                0,
                                7,
                                self.local,
                                3,
                                len(chunks) - 1 if j == 0 else 0,
                                self.pid,
                                stamp,
                            )
                            + chunk
                        ),
                        self.address,
                    )
                    self.pid += 1
                self.case["producer_times"].append(time.monotonic() - self.begin)
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


def verify_source(case):
    r = case["process"]
    count = case["frames"]
    pictures = r["pictures"]
    assert r["exit_code"] == 0 and r["cleanup_complete"] and not r["source_assertions"]
    assert r["load_table_restored"] and r["load_adapter_closed"]
    assert r["load_frames"] == list(range(100, 100 + count))
    assert r["load_receive_count"] == count
    if case["delay_us"]:
        assert r["load_receive_busy"] > 0
    assert r["load_adapter_final"] == [
        0,
        len(pictures),
        len(pictures),
        case["delay_us"] * len(pictures),
    ]
    assert pictures and pictures[-1]["id"] == 100 + count - 1
    ids = [p["id"] for p in pictures]
    assert ids == sorted(set(ids))
    hashes = [
        line.split(",")[-1].strip()
        for line in (ROOT / "app/tests/fixtures/video/sequential.framemd5")
        .read_text()
        .splitlines()
        if not line.startswith("#")
    ]
    assert all(p["md5"] == hashes[(p["id"] - 100) % 6] for p in pictures)
    inputs = [e for e in r["media_events"] if e["name"] == "sdk_send"]
    assert len(inputs) == len(pictures) == len(r["load_sdk_samples"])
    for event, picture in zip(inputs, pictures):
        payload = AUS[(picture["id"] - 100) % 6]
        assert (
            event["size"] == len(payload)
            and event["sha256"] == hashlib.sha256(payload).hexdigest()
        )
    for name in ("sdk_send_return", "sdk_receive_return"):
        assert [e["result"] for e in r["media_events"] if e["name"] == name] == [
            0
        ] * len(pictures)
    for name in ("start_video", "stop_video", "decoder_ctor", "decoder_dtor"):
        assert sum(e["name"] == name for e in r["media_events"]) == 1
    assert [e["result"] for e in r["media_events"] if e["name"] == "decoder_join"] == [
        0
    ]
    assert r["media_final"]["decoder"] == 0 and r["media_final"]["phase"] == 6
    assert [
        (e["value"], e["phase"])
        for e in r["module_events"]
        if e["name"].startswith("module_force")
    ] == [(7, "original_exit"), (0, "original_exit")]
    assert not {
        p for p, s in r["tasks_after_shutdown"].items() if s not in ("X", "Z")
    } - set(r["tasks_before"])
    assert len(case["producer_times"]) == count and case["producer_times"][-1] >= 4.9


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", required=True, type=Path)
    p.add_argument("--sdk-directory", required=True, type=Path)
    p.add_argument("--qt-library-directory", required=True, action="append", type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--snapshot", type=Path)
    a = p.parse_args()
    binary = a.binary.resolve()
    sdk = a.sdk_directory.resolve()
    qt = [d.resolve() for d in a.qt_library_directory]
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
    shim = ROOT / "app/tests/fixtures/transport/sdk_delay.c"
    with tempfile.TemporaryDirectory(prefix="official-load-shim-") as temporary:
        library = Path(temporary) / "sdk-delay.so"
        compile_command = [
            "cc",
            "-O2",
            "-shared",
            "-fPIC",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(shim),
            "-o",
            str(library),
        ]
        subprocess.run(compile_command, check=True, capture_output=True)
        adapter_digest = neg.udp.process.digest(library)
        for case in plans():
            case.update(
                reliable=False,
                settings="3800c80101",
                bad_mac=False,
                server="070a0308c00b",
                response="0208001001",
                duplicate=False,
                bad_length=False,
            )
            with tempfile.TemporaryDirectory(prefix="original-load-") as d:
                settings = Path(d) / "settings.bin"
                settings.write_bytes(bytes.fromhex(case["settings"]))
                case["stage_file"] = str(Path(d) / "stage")
                result = neg.udp.audit(
                    binary,
                    sdk,
                    qt,
                    a.output.with_name(a.output.stem + "-" + case["name"] + ".json"),
                    case,
                    helper=ROOT / "scripts/steam-client-load-gdb.py",
                    reactor=Peer,
                    probe_config=dict(
                        udp_helper=str(ROOT / "scripts/steam-client-udp-gdb.py"),
                        negotiation_helper=str(
                            ROOT / "scripts/steam-client-negotiation-gdb.py"
                        ),
                        media_helper=str(ROOT / "scripts/steam-client-media-gdb.py"),
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
                len(result["process"]["pictures"]),
                "SDK/pixels; paced 302 frames, clean Stop/exit",
                flush=True,
            )
    report = dict(
        scope=__doc__,
        client_sha256=neg.udp.process.digest(binary),
        codec_sha256=neg.udp.process.digest(sdk / "libavcodec.so.61"),
        util_sha256=neg.udp.process.digest(sdk / "libavutil.so.59"),
        source_functions=neg.udp.process.boundary.inventory(
            binary.read_bytes(),
            {
                **media.FUNCTIONS,
                0x3260D0: "decode_frame",
                0x2EDA20: "decoder_loop",
                0x2EDE20: "fifo_pop",
            },
        ),
        helpers={
            name: neg.udp.process.digest(ROOT / "scripts" / name)
            for name in (
                "steam-client-load-gdb.py",
                "steam-client-media-gdb.py",
                "steam-client-negotiation-gdb.py",
                "steam-client-udp-gdb.py",
                "steam-client-sdk-gdb.py",
            )
        },
        runner_sha256=neg.udp.process.digest(
            ROOT / "scripts/audit-steam-client-udp-process.py"
        ),
        load_runner_sha256=neg.udp.process.digest(Path(__file__)),
        adapter_source_sha256=neg.udp.process.digest(shim),
        adapter_library_sha256=adapter_digest,
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
        fixture_sha256=neg.udp.process.digest(
            ROOT / "app/tests/fixtures/video/sequential.h264"
        ),
        au_boundaries=BOUNDARIES,
        cases=cases,
    )
    data = (json.dumps(report, indent=2) + "\n").encode()
    a.output.write_bytes(data)
    if a.snapshot:
        a.snapshot.write_bytes(gzip.compress(data, mtime=0))
    print("Official paced load: six processes verified")


if __name__ == "__main__":
    main()
