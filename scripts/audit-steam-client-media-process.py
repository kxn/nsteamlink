#!/usr/bin/env python3
"""Original UDP negotiation -> video fragments/FEC -> SDK pixels -> StopVideo.

Pinned Linux client runs its real sockets, workers, constructors, crypto, parser,
window/FEC, decoder factory, bundled SDK and Generic player. A controlled peer
provides settings/auth/control/video inputs; there is no genuine Steam identity,
host activation/adaptation, physical renderer/GPU, audio or device claim. FEC
fixture shards execute pinned Android CLIENT encoder/RS with declared adapters.
"""

import argparse
import ast
import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import runpy
import struct
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "neg", ROOT / "scripts/audit-steam-client-negotiation-process.py"
)
neg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(neg)
FUNCTIONS = {
    **neg.FUNCTIONS,
    **{
        0x31BBD0: "on_stream_packet",
        0x194520: "frame_packet_constructor",
        0x194400: "frame_assign_packet",
        0x3212E0: "on_start_video",
        0x3214D0: "on_stop_video",
        0x318640: "video_factory",
        0x318910: "stop_video_owner",
        0x324610: "avcodec_constructor",
        0x323FC0: "avcodec_deleting_destructor",
        0x2ED830: "submit_video",
        0x2EDF70: "player_put",
        0x2EF250: "player_queue_pop",
        0x324190: "final_decode",
        0x324D00: "sdk_format_callback",
    },
}
PAYLOAD = (ROOT / "app/tests/fixtures/video/sequential.h264").read_bytes()[:2204]
BODY = (
    bytes([1])
    + struct.pack("<HIHI", 23, 1000000, 0, 0)
    + struct.pack("<HBHH", 0, 24, 0, 0)
    + PAYLOAD
)
MD5 = (
    (ROOT / "app/tests/fixtures/video/sequential.framemd5")
    .read_text()
    .splitlines()[10]
    .split(",")[-1]
    .strip()
)


def fec_fixture(android, directory):
    """Reuse only the original encoder class; no Native RS generates these bytes."""
    assert (
        neg.udp.process.digest(android)
        == "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"
    )
    old = sys.argv
    path = ROOT / "scripts/audit-steam-video-recovery.py"
    sys.argv = [
        str(path),
        "--binary",
        str(android),
        "--output",
        str(directory / "branches.json"),
    ]
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            base = runpy.run_path(str(path))
    finally:
        sys.argv = old
    path = ROOT / "scripts/audit-steam-fec.py"
    tree = ast.parse(path.read_text())
    node = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "FEC")
    namespace = dict(Run=base["Run"], STOP=base["STOP"], base=base, struct=struct)
    exec(
        compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec"), namespace
    )
    encoder = namespace["FEC"](mtu=1200)
    wires = encoder.encode(BODY, 20)
    size, shard, parity = struct.unpack_from("<IHH", wires[0], 13)
    assert (size, shard, parity, len(wires)) == (len(BODY), 1168, 1, 3)
    assert encoder.coding_calls == ["encode"]
    return dict(
        binary_sha256=neg.udp.process.digest(android),
        helper_sha256=neg.udp.process.digest(path),
        recovery_helper_sha256=neg.udp.process.digest(
            ROOT / "scripts/audit-steam-video-recovery.py"
        ),
        payload=BODY.hex(),
        wires=[w.hex() for w in wires],
        coding_calls=encoder.coding_calls,
        k=2,
        m=1,
        shard_size=shard,
    )


class Peer(neg.Peer):
    def __init__(self, *args):
        super().__init__(*args)
        self.started = self.stopped = False

    def __call__(self, raw, address):
        super().__call__(raw, address)
        if (
            not self.case.get("source_decode", True)
            and raw[0] & 127 == 7
            and raw[4] == 1
            and struct.unpack_from("<H", raw, 7)[0] >= 4
            and not self.stopped
        ):
            self.stopped = True
            self.send(
                bytearray(
                    struct.pack("<BBBBBhHI", 5, 0, 7, raw[2], 1, 0, 5, 1000000)
                    + bytes([53])
                    + neg.encrypted(b"", 3)
                ),
                address,
            )
        if raw[0] & 127 != 5:
            return
        data = neg.udp.without_crc(raw)
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
            if self.case["fec"]:
                wires = [bytes.fromhex(w) for w in self.case["fec_wires"]]
                for i in self.case["order"]:
                    p = bytearray(wires[i])
                    p[2:4] = bytes([7, raw[2]])
                    struct.pack_into("<I", p, 9, 1000000)
                    self.send(p, address)
            else:
                pieces = [BODY[:1200], BODY[1200:]]
                for i in self.case["order"]:
                    p = bytearray(
                        struct.pack(
                            "<BBBBBhHI",
                            (5 if i == 0 else 6)
                            if self.case["reliable"]
                            else (3 if i == 0 else 4),
                            0,
                            7,
                            raw[2],
                            3,
                            1 if i == 0 else 0,
                            i,
                            1000000,
                        )
                        + pieces[i]
                    )
                    self.send(p, address)
        elif data[13] == 80 and not self.stopped:
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
    r = case["process"]
    assert r["exit_code"] == 0 and r["cleanup_complete"] and not r["source_assertions"]
    assert r["settings_reads"] == [dict(loaded=True, bytes=case["settings"])]
    decode = case.get("source_decode", True)
    assert r["media_final"] == dict(phase=6, decoder=0, rx=4, tx=3 if decode else 2)
    events = r["media_events"]
    for name in (
        "start_video",
        "stop_video",
        "decoder_ctor",
        "decoder_dtor",
        "submit",
        "sdk_send",
        "sdk_send_return",
        "sdk_receive_return",
        "player_put",
        "decoder_join",
    ):
        expected = (
            1
            if decode
            or name
            in (
                "start_video",
                "stop_video",
                "decoder_ctor",
                "decoder_dtor",
                "decoder_join",
            )
            else 0
        )
        assert sum(e["name"] == name for e in events) == expected, (
            case["name"],
            name,
            events,
        )
    if decode:
        assert next(e for e in events if e["name"] == "sdk_send") == dict(
            name="sdk_send",
            thread=next(e["thread"] for e in events if e["name"] == "sdk_send"),
            size=len(PAYLOAD),
            sha256=hashlib.sha256(PAYLOAD).hexdigest(),
        )
    assert all(
        e["result"] == 0
        for e in events
        if e["name"] in ("sdk_send_return", "sdk_receive_return", "decoder_join")
    )
    assert len(r["pictures"]) == int(decode)
    if decode:
        assert {k: v for k, v in r["pictures"][0].items() if k != "timestamp"} == dict(
            id=23, shape=[128, 72, 0], md5=MD5
        )
    else:
        packets = [e for e in events if "body_prefix" in e]
        assert (
            len(packets) == 1
            and packets[0]["wire_size"] == len(BODY) + 13
            and packets[0]["body_sha256"] != hashlib.sha256(BODY).hexdigest()
        )
        assert (
            packets[0]["body_prefix"]
            == bytes.fromhex(case["fec_wires"][2])[21:53].hex()
        )
    force = [e for e in r["module_events"] if e["name"].startswith("module_force")]
    assert [(e["value"], e["phase"]) for e in force] == [
        (7, "original_exit"),
        (0, "original_exit"),
    ]
    assert "__run_exit_handlers" in force[0]["stack"]
    assert r["module_refs"] == [0, 7]
    assert not {
        pid
        for pid, state in r["tasks_after_shutdown"].items()
        if state not in ("X", "Z")
    } - set(r["tasks_before"])
    assert any(e[0] == "join_completed" and e[2] == 0 for e in r["trace"])
    controls = {}
    for item in case["received"]:
        raw = neg.udp.without_crc(bytes.fromhex(item["data"]))
        if raw[0] & 127 == 5 and raw[4] == 1 and raw[13] in (4, 5, 80):
            sequence, plain = neg.decrypted(raw[14:])
            value = dict(sequence=sequence, plain=bytes([raw[13]]).hex() + plain.hex())
            if raw[13] in controls:
                assert controls[raw[13]] == value
            controls[raw[13]] = value
    kinds = (4, 5, 80) if decode else (4, 5)
    assert [controls[k]["sequence"] for k in kinds] == list(range(len(kinds)))
    if decode:
        info = neg.fields(bytes.fromhex(controls[80]["plain"])[1:])
        assert (2, 0, 4) in info and any(
            n == 1 and k == 2 and v == b"libavcodec software decoding with 4 threads"
            for n, k, v in info
        )
    case["outputs"] = [controls[k] for k in kinds]
    # Only the already-declared mandatory Raw platform capability differs.
    case["native_projection"] = []
    for i, item in enumerate(case["outputs"]):
        plain = (
            bytes.fromhex(neg.projection.platform_frame(item["plain"]))
            if i == 0
            else bytes.fromhex(item["plain"])
        )
        case["native_projection"].append(
            dict(
                sequence=i,
                plain=plain.hex(),
                cipher=(plain[:1] + neg.encrypted(plain[1:], i)).hex(),
            )
        )
    case["media_input"] = [
        p for p in case["sent"] if neg.udp.without_crc(bytes.fromhex(p["data"]))[4] == 3
    ]
    assert len(case["media_input"]) == len(case["order"])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--sdk-directory", type=Path, required=True)
    p.add_argument("--qt-library-directory", type=Path, action="append", required=True)
    p.add_argument("--android-binary", type=Path, required=True)
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
    functions = neg.udp.process.boundary.inventory(binary.read_bytes(), FUNCTIONS)
    scenarios = [
        dict(
            name=f"ordinary_reliable{int(reliable)}_crc{int(crc)}_reverse{int(reverse)}",
            reliable=reliable,
            crc=crc,
            fec=False,
            order=[1, 0] if reverse else [0, 1],
        )
        for reliable in (False, True)
        for crc in (False, True)
        for reverse in (False, True)
    ]
    with tempfile.TemporaryDirectory(prefix="media-encoder-") as d:
        encoder = fec_fixture(args.android_binary.resolve(), Path(d))
    scenarios += [
        dict(
            name=f"fec_{name}_crc{int(crc)}",
            reliable=False,
            crc=crc,
            fec=True,
            order=order,
            fec_wires=encoder["wires"],
        )
        for crc in (False, True)
        for name, order in [
            ("all", [0, 1, 2]),
            ("erase0", [1, 2]),
            ("erase1", [0, 2]),
            ("parity_first", [2, 1]),
        ]
    ]
    scenarios += [
        dict(
            name=f"fec_duplicate_guard_crc{int(crc)}",
            reliable=False,
            crc=crc,
            fec=True,
            order=[2, 2, 1],
            fec_wires=encoder["wires"],
            source_decode=False,
        )
        for crc in (False, True)
    ]
    cases = []
    for case in scenarios:
        case.update(
            settings="3800c80101",
            bad_mac=False,
            server="070a0308c00b",
            response="0208001001",
            duplicate=False,
            bad_length=False,
        )
        output = args.output.with_name(args.output.stem + "-" + case["name"] + ".json")
        with tempfile.TemporaryDirectory(prefix="source-media-settings-") as d:
            settings = Path(d) / "streaming_settings.bin"
            settings.write_bytes(bytes.fromhex(case["settings"]))
            result = neg.udp.audit(
                binary,
                sdk,
                qt,
                output,
                case,
                helper=ROOT / "scripts/steam-client-media-gdb.py",
                reactor=Peer,
                probe_config=dict(
                    udp_helper=str(ROOT / "scripts/steam-client-udp-gdb.py"),
                    negotiation_helper=str(
                        ROOT / "scripts/steam-client-negotiation-gdb.py"
                    ),
                    settings_file=str(settings),
                    source_decode=case.get("source_decode", True),
                ),
                validate=verify,
            )
            assert settings.read_bytes() == bytes.fromhex(case["settings"])
        cases.append(result)
        print(
            case["name"],
            "real UDP -> exact SDK packet/pixel; Stop/exit verified"
            if case.get("source_decode", True)
            else "original duplicate-count counterexample; no SDK submit, Stop/exit verified",
            flush=True,
        )
    report = dict(
        scope=__doc__,
        client_sha256=neg.udp.process.digest(binary),
        codec_sha256=neg.udp.process.digest(sdk / "libavcodec.so.61"),
        util_sha256=neg.udp.process.digest(sdk / "libavutil.so.59"),
        source_functions=functions,
        encoder=encoder,
        helpers={
            name: neg.udp.process.digest(ROOT / "scripts" / name)
            for name in (
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
        fixture_sha256=hashlib.sha256(PAYLOAD).hexdigest(),
        pixel_md5=MD5,
        cases=cases,
    )
    data = (json.dumps(report, indent=2) + "\n").encode()
    args.output.write_bytes(data)
    if args.snapshot:
        args.snapshot.write_bytes(gzip.compress(data, mtime=0))
    print(
        "Original real UDP video: 16 fragment/FEC/SDK/pixel/Stop cases and 2 duplicate-count counterexamples verified"
    )


if __name__ == "__main__":
    main()
