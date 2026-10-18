#!/usr/bin/env python3
"""Original CLIENT local microphone APIs -> encrypted control and UDP fragments.

Real constructor/settings/socket/crypto/dispatcher/channel/final sender execute.
Caller-provided encoded payload/Opus metadata and peer inputs are fixtures, not
microphone capture or codec output. Registered Native callbacks are ownership
adapters; no Source SDK/device/renderer/Steam host activation claim is made.
"""

import argparse
import gzip
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


neg = module("neg", "audit-steam-client-negotiation-process.py")
check = module("check", "check-steam-microphone-process.py")
FUNCTIONS = {
    **neg.FUNCTIONS,
    0x31B480: "start_microphone",
    0x31AE90: "send_microphone",
    0x31BD50: "stop_microphone",
    0x318960: "allocate_channel",
    0x19ED10: "set_channel_priority",
    0x194620: "frame_set_data_header",
    0x194730: "frame_resize",
    0x31BBD0: "on_stream_packet",
    0x322B90: "drain_incoming_control",
}


class Peer(neg.Peer):
    def __init__(self, *args):
        super().__init__(*args)
        self.injected = self.stop_injected = False
        self.ids = set()

    def rpc(self, address, local, packet_id, sequence, tag, body):
        self.send(
            bytearray(
                struct.pack("<BBBBBhHI", 5, 0, 7, local, 1, 0, packet_id, 1000000)
                + bytes([tag])
                + neg.encrypted(body, sequence)
            ),
            address,
        )

    def __call__(self, raw, address):
        super().__call__(raw, address)
        data = neg.udp.without_crc(raw)
        kind = data[0] & 127
        if kind == 5 and data[4] == 1 and data[13] == 5 and not self.injected:
            self.injected = True
            self.rpc(address, raw[2], 4, 2, 107, bytes.fromhex("100318032880f7023002"))
            self.rpc(address, raw[2], 5, 3, 108, b"")
        if data[4] == 3 and kind in (3, 4, 5, 6):
            self.ids.add(int.from_bytes(data[7:9], "little"))
            if len(self.ids) == 5 and not self.stop_injected:
                self.stop_injected = True
                self.rpc(address, raw[2], 6, 4, 108, b"")


def verify(case):
    controls, initial, events = {}, {}, []
    for item in case["received"]:
        raw = neg.udp.without_crc(bytes.fromhex(item["data"]))
        if raw[0] & 127 == 5 and raw[4] == 1 and raw[13] in (4, 5, 107, 108):
            sequence, plain = neg.decrypted(raw[14:])
            value = dict(sequence=sequence, plain=(raw[13:14] + plain).hex())
            if sequence in controls:
                assert controls[sequence] == value
            elif sequence >= 2:
                events.append(f"control:{raw[13]}:{sequence}")
            controls[sequence] = value
        if 3 <= raw[4] <= 5 and raw[0] & 127 in (3, 4, 5, 6) and raw[1] == 0:
            key = (raw[4], int.from_bytes(raw[7:9], "little"))
            if key in initial:
                assert initial[key] == item["data"]
            else:
                events.append(f"data:{key[0]}:{key[1]}")
            initial[key] = item["data"]
    case["mic_initial_wires"] = [
        initial[k] for k in [(3, i) for i in range(5)] + [(4, 0), (5, 0)]
    ]
    case["outputs"] = [controls[i] for i in range(7)]
    case["events"] = events
    case["native_projection"] = []
    for i, value in enumerate(case["outputs"]):
        plain = (
            bytes.fromhex(neg.projection.platform_frame(value["plain"]))
            if i == 0
            else bytes.fromhex(value["plain"])
        )
        case["native_projection"].append(
            dict(
                sequence=i,
                plain=plain.hex(),
                cipher=(plain[:1] + neg.encrypted(plain[1:], i)).hex(),
            )
        )
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
    cases = []
    for crc in (False, True):
        for reliable in (False, True):
            for fec in (False, True):
                case = dict(
                    name=f"microphone_crc{int(crc)}_reliable{int(reliable)}_fec{int(fec)}",
                    crc=crc,
                    reliable=reliable,
                    fec=fec,
                    settings="3800c801" + ("01" if fec else "00"),
                    bad_mac=False,
                    server="070a0308c00b",
                    response="0208001001",
                    duplicate=False,
                    bad_length=False,
                )
                with tempfile.TemporaryDirectory(prefix="source-microphone-") as d:
                    settings = Path(d) / "streaming_settings.bin"
                    settings.write_bytes(bytes.fromhex(case["settings"]))
                    result = neg.udp.audit(
                        binary,
                        sdk,
                        qt,
                        args.output.with_name(
                            args.output.stem + "-" + case["name"] + ".json"
                        ),
                        case,
                        helper=ROOT / "scripts/steam-client-microphone-gdb.py",
                        reactor=Peer,
                        probe_config=dict(
                            udp_helper=str(ROOT / "scripts/steam-client-udp-gdb.py"),
                            negotiation_helper=str(
                                ROOT / "scripts/steam-client-negotiation-gdb.py"
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
                    "local 107/108, peer-ignore, seven UDP datagrams, Stop/exit verified",
                    flush=True,
                )
    source = binary.read_bytes()
    elf = ELFFile(io.BytesIO(source))
    fdes = [e for e in elf.get_dwarf_info().EH_CFI_entries() if isinstance(e, FDE)]
    functions = dict(FUNCTIONS)
    for case in cases:
        for event in case["process"]["mic_sends"]:
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
                    functions.setdefault(start, f"microphone_caller_{start:x}")
    report = dict(
        scope=__doc__,
        client_sha256=neg.udp.process.digest(binary),
        codec_sha256=neg.udp.process.digest(sdk / "libavcodec.so.61"),
        util_sha256=neg.udp.process.digest(sdk / "libavutil.so.59"),
        source_functions=neg.udp.process.boundary.inventory(source, functions),
        helpers={
            name: neg.udp.process.digest(ROOT / "scripts" / name)
            for name in (
                "steam-client-microphone-gdb.py",
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
        cases=cases,
    )
    data = (json.dumps(report, indent=2) + "\n").encode()
    args.output.write_bytes(data)
    if args.snapshot:
        args.snapshot.write_bytes(gzip.compress(data, mtime=0))
    print(
        "Original microphone UDP: 8 API/direction/CRC/reliability/FEC-request/restart cases verified"
    )


if __name__ == "__main__":
    main()
