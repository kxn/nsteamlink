#!/usr/bin/env python3
"""Observe original saved FEC choice through real UDP encrypted negotiation.

Pinned official client/file/crypto/SDK capability/stage/exit instructions execute.
A loopback peer supplies controlled handshake/auth and encrypted negotiation, with
no parsed-frame/phase/callback/method replacement. Settings are real files loaded
by the same original API called by SDL --settings. This is not the shell UI, a
Steam identity/server, actual host FEC activation/media, renderer or device proof.
"""

import argparse
import gzip
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "auth", ROOT / "scripts/audit-steam-client-auth-process.py"
)
auth = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(auth)
udp = auth.udp
KEY = bytes(range(32))
PROJECTION_SPEC = importlib.util.spec_from_file_location(
    "projection", ROOT / "scripts/check-steam-negotiation.py"
)
projection = importlib.util.module_from_spec(PROJECTION_SPEC)
PROJECTION_SPEC.loader.exec_module(projection)
FUNCTIONS = {
    **auth.FUNCTIONS,
    0x3179E0: "set_settings_file",
    0x317920: "load_settings",
    0x173B10: "table_init",
    0x173C40: "table_release",
    0x173C60: "table_force_release",
    0x1780C0: "codec_factory",
    0x194B60: "encrypt_control",
    0x194E60: "decrypt_control",
}


def fields(raw):
    offset = 0

    def varint():
        nonlocal offset
        value = 0
        for n in range(10):
            byte = raw[offset]
            offset += 1
            value |= (byte & 127) << (7 * n)
            if byte < 128:
                return value
        raise AssertionError("varint")

    result = []
    while offset < len(raw):
        tag = varint()
        kind = tag & 7
        number = tag >> 3
        if kind == 0:
            value = varint()
        elif kind == 2:
            size = varint()
            value = raw[offset : offset + size]
            offset += size
        elif kind in (1, 5):
            size = 8 if kind == 1 else 4
            value = raw[offset : offset + size]
            offset += size
        else:
            raise AssertionError(kind)
        result.append((number, kind, value))
    assert offset == len(raw)
    return result


def encrypted(data, sequence, bad_mac=False):
    plain = struct.pack("<Q", sequence) + data
    iv = hmac.new(KEY, plain, hashlib.md5).digest()
    if bad_mac:
        iv = bytes([iv[0] ^ 1]) + iv[1:]
    pad = 16 - len(plain) % 16
    plain += bytes([pad]) * pad
    enc = Cipher(algorithms.AES(KEY), modes.CBC(iv)).encryptor()
    return iv + enc.update(plain) + enc.finalize()


def decrypted(data):
    assert len(data) > 16 and len(data) % 16 == 0
    iv = data[:16]
    dec = Cipher(algorithms.AES(KEY), modes.CBC(iv)).decryptor()
    plain = dec.update(data[16:]) + dec.finalize()
    pad = plain[-1]
    assert 1 <= pad <= 16 and plain[-pad:] == bytes([pad]) * pad
    plain = plain[:-pad]
    assert hmac.compare_digest(iv, hmac.new(KEY, plain, hashlib.md5).digest())
    return struct.unpack("<Q", plain[:8])[0], plain[8:]


class Peer(auth.Peer):
    def __init__(self, *args):
        super().__init__(*args)
        self.init_sent = self.config_sent = False

    def __call__(self, raw, address):
        super().__call__(raw, address)
        if raw[0] & 127 != 5:
            return
        data = udp.without_crc(raw)
        if data[13] == 1 and self.response and not self.init_sent:
            init = (
                bytes.fromhex("080110031804")
                if self.case["reliable"]
                else bytes.fromhex("080010031804")
            )
            self.init_sent = True
            if self.case["bad_mac"]:
                packet = bytearray(
                    struct.pack("<BBBBBhHI", 5, 0, 7, raw[2], 1, 0, 2, 1000000)
                    + bytes([3])
                    + encrypted(init, 0, True)
                )
                self.send(packet, address)
            sequence = int(self.case["bad_mac"])
            packet = bytearray(
                struct.pack("<BBBBBhHI", 5, 0, 7, raw[2], 1, 0, 2 + sequence, 1000000)
                + bytes([3])
                + encrypted(init, sequence)
            )
            self.send(packet, address)
        elif data[13] == 4 and not self.config_sent:
            sequence, plain = decrypted(data[14:])
            assert sequence == 0
            negotiated = next(
                value
                for number, kind, value in fields(plain)
                if number == 1 and kind == 2
            )
            assert len(negotiated) < 128
            response = bytes([10, len(negotiated)]) + negotiated
            shift = int(self.case["bad_mac"])
            packet = bytearray(
                struct.pack("<BBBBBhHI", 5, 0, 7, raw[2], 1, 0, 3 + shift, 1000000)
                + bytes([4])
                + encrypted(response, 1 + shift)
            )
            self.send(packet, address)
            self.config_sent = True


def verify(case):
    r = case["process"]
    assert r["exit_code"] == 0 and r["cleanup_complete"] and not r["source_assertions"]
    assert r["settings_reads"] == [dict(loaded=True, bytes=case["settings"])]
    assert r["connected_state"] == dict(
        client_phase=6,
        transport_state=1,
        crc=int(case["crc"]),
        outgoing_fec=0,
        receive_sequence=2 + int(case["bad_mac"]),
        send_sequence=2,
    )
    assert [e[2] for e in r["trace"] if e[0] == "frame_send"] == [6, 1, 4, 5]
    events = r["module_events"]
    assert [e["value"] for e in events if e["name"] == "module_init"] == list(range(5))
    assert r["module_refs"] == [0, 5] and r["module_refs_before_original_main"] == 5
    force = [e for e in events if e["name"].startswith("module_force")]
    assert [(e["name"], e["value"], e["phase"]) for e in force] == [
        ("module_force_enter", 5, "original_exit"),
        ("module_force_return", 0, "original_exit"),
    ]
    assert "__run_exit_handlers" in force[0]["stack"]
    assert any(e[0] == "join_completed" and e[2] == 0 for e in r["trace"])
    assert not {
        pid
        for pid, state in r["tasks_after_shutdown"].items()
        if state not in ("X", "Z")
    } - set(r["tasks_before"])
    outputs = {}
    for item in case["received"]:
        wire = bytes.fromhex(item["data"])
        if wire[0] & 127 != 5:
            continue
        raw = udp.without_crc(wire)
        kind = raw[13]
        assert bool(raw[0] & 128) == case["crc"]
        if kind in (4, 5):
            sequence, body = decrypted(raw[14:])
            value = dict(sequence=sequence, plain=bytes([kind]).hex() + body.hex())
            if kind in outputs:
                assert outputs[kind] == value
            outputs[kind] = value
    assert outputs[5] == dict(sequence=1, plain="05") and outputs[4]["sequence"] == 0
    body = bytes.fromhex(outputs[4]["plain"])[1:]
    config = next(v for n, k, v in fields(body) if n == 2 and k == 2)
    assert config == bytes.fromhex(case["settings"])
    negotiated = next(v for n, k, v in fields(body) if n == 1 and k == 2)
    assert next(v for n, k, v in fields(negotiated) if n == 1 and k == 0) == int(
        case["reliable"]
    )
    case["outputs"] = [outputs[4], outputs[5]]
    projected = bytes.fromhex(projection.platform_frame(outputs[4]["plain"]))
    case["native_projection"] = [
        dict(
            sequence=0,
            plain=projected.hex(),
            cipher=(bytes([4]) + encrypted(projected[1:], 0)).hex(),
        ),
        dict(sequence=1, plain="05", cipher=(bytes([5]) + encrypted(b"", 1)).hex()),
    ]


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
        [q.resolve() for q in args.qt_library_directory],
    )
    assert udp.process.digest(binary) == udp.process.boundary.codec.SHA
    assert (
        udp.process.digest(sdk / "libavcodec.so.61") == udp.process.boundary.CODEC_SHA
    )
    assert (
        udp.process.digest(sdk / "libavutil.so.59")
        == udp.process.boundary.codec.SDK_SHA
    )
    functions = udp.process.boundary.inventory(binary.read_bytes(), FUNCTIONS)
    cases = []
    scenarios = [
        dict(
            name=f"fec_{fec or 'absent'}_reliable{int(reliable)}_crc{int(crc)}",
            settings="3800" + fec,
            reliable=reliable,
            crc=crc,
            bad_mac=False,
        )
        for fec in ("", "c80100", "c80101")
        for reliable in (False, True)
        for crc in (False, True)
    ]
    scenarios.append(
        dict(
            name="hevc_preference_does_not_set_legacy",
            settings="38006801c80101",
            reliable=True,
            crc=False,
            bad_mac=False,
        )
    )
    scenarios.append(
        dict(
            name="bad_mac_then_next_sequence",
            settings="3800c80101",
            reliable=False,
            crc=False,
            bad_mac=True,
        )
    )
    for case in scenarios:
        case.update(
            server="070a0308c00b",
            response="0208001001",
            duplicate=False,
            bad_length=False,
        )
        path = args.output.with_name(args.output.stem + "-" + case["name"] + ".json")
        with tempfile.TemporaryDirectory(prefix="original-settings-") as directory:
            settings = Path(directory) / "streaming_settings.bin"
            settings.write_bytes(bytes.fromhex(case["settings"]))
            result = udp.audit(
                binary,
                sdk,
                qt,
                path,
                case,
                helper=ROOT / "scripts/steam-client-negotiation-gdb.py",
                reactor=Peer,
                probe_config=dict(
                    udp_helper=str(ROOT / "scripts/steam-client-udp-gdb.py"),
                    settings_file=str(settings),
                ),
                validate=verify,
            )
            assert settings.read_bytes() == bytes.fromhex(case["settings"])
        cases.append(result)
        print(
            case["name"],
            "Streaming; encrypted config/complete verified, original atexit refs5->0",
            flush=True,
        )
    report = dict(
        scope=__doc__,
        client_sha256=udp.process.digest(binary),
        archive_url="https://repo.steampowered.com/steamlink/1.3.32.316/steamlink-1.3.32.316.tgz",
        source_functions=functions,
        qt_dependency_sha256={
            name: udp.process.digest(
                next(
                    p / f"libQt6{name}.so.6"
                    for p in qt
                    if (p / f"libQt6{name}.so.6").is_file()
                )
            )
            for name in ("Core", "Gui", "Widgets", "Svg")
        },
        qt_required_controller_patch=udp.process.QT_PATCH,
        helper_sha256=udp.process.digest(
            ROOT / "scripts/steam-client-negotiation-gdb.py"
        ),
        udp_helper_sha256=udp.process.digest(ROOT / "scripts/steam-client-udp-gdb.py"),
        bootstrap_helper_sha256=udp.process.digest(
            ROOT / "scripts/steam-client-sdk-gdb.py"
        ),
        cases=cases,
    )
    data = (json.dumps(report, indent=2) + "\n").encode()
    args.output.write_bytes(data)
    if args.snapshot:
        args.snapshot.write_bytes(gzip.compress(data, mtime=0))
    print(
        f"Original real UDP negotiation: {len(cases)} settings/FEC/CRC/reliability/crypto cases passed"
    )


if __name__ == "__main__":
    main()
