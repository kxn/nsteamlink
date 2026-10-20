#!/usr/bin/env python3
"""Official Linux CLIENT scheduling counterexample through authenticated real UDP.

Encoded bytes are API inputs. An external DSO calls original Stop/Start/Send and
rate/clock methods; it never patches instructions, replaces returns or directly
writes Source object memory.
Only the reliable rate is temporarily set to 16384 through the original setter.
For locked cases GDB suspends other threads during that batch. Network resumes
before OnThink drains queued output. This proves an allowed Source trace under
explicit scheduling inputs, not natural timing/fairness or arbitrary equivalence.
"""

import argparse
import gzip
import io
import json
from pathlib import Path
import subprocess
import tempfile

from elftools.dwarf.callframe import FDE
from elftools.elf.elffile import ELFFile

from importlib.util import module_from_spec, spec_from_file_location

ROOT = Path(__file__).resolve().parents[1]
_spec = spec_from_file_location(
    "mic", ROOT / "scripts/audit-steam-client-microphone-process.py"
)
mic = module_from_spec(_spec)
_spec.loader.exec_module(mic)
neg = mic.neg


class Peer(mic.Peer):
    def __init__(self, *args):
        super().__init__(*args)
        self.schedule_ids = set()

    def __call__(self, raw, address):
        super().__call__(raw, address)
        wire = neg.udp.without_crc(raw)
        if wire[4] in (4, 5) and wire[0] & 127 in (3, 4, 5, 6):
            self.schedule_ids.add(wire[4])
            if self.schedule_ids == {4, 5}:
                Path(self.case["schedule_done"]).write_text("done")


def verify(case):
    process = case["process"]
    assert process["source_assertions"] == [] and process["exit_code"] == 0
    assert (
        process["cleanup_complete"]
        and process["schedule_lock_network"] == case["lock_network_thread"]
    )
    trace = process["schedule_trace"]
    assert len(trace) == 8 and [s[3] for s in trace] == [3, 0, 4, 4, 5, 5, 5, 5]
    assert [s[4] for s in trace] == [3, 3, 0, 1, 0, 0, 1, 1]
    assert trace[0][2] == trace[-1][2] == 625000
    assert all(s[2] == 16384 for s in trace[1:-1])
    controls, data, events = {}, {}, []
    for item in case["received"]:
        wire = neg.udp.without_crc(bytes.fromhex(item["data"]))
        kind, channel, packet_id = (
            wire[0] & 127,
            wire[4],
            int.from_bytes(wire[7:9], "little"),
        )
        if kind == 5 and channel == 1 and wire[13] in (4, 5, 107, 108):
            sequence, plain = neg.decrypted(wire[14:])
            value = (wire[13:14] + plain).hex()
            if sequence not in controls and sequence >= 2:
                events.append(f"control:{wire[13]}:{sequence}")
            assert controls.get(sequence, value) == value
            controls[sequence] = value
        if 3 <= channel <= 5 and kind in (5, 6) and wire[1] == 0:
            key = (channel, packet_id)
            if key not in data:
                events.append(f"data:{channel}:{packet_id}")
            data[key] = item["data"]
    assert set(controls) == set(range(7)) and len(data) == 7
    assert [controls[n] for n in range(2, 7)] == [
        "6b100318032880f7023002",
        "6c",
        "6b100418032880f7023002",
        "6b100518032880f7023002",
        "6c",
    ]
    for wire in data.values():
        neg.udp.without_crc(
            bytes.fromhex(wire)
        )  # Verifies actual CRC before body normalization.
    if case["lock_network_thread"]:
        assert (
            events.index("data:5:0")
            < events.index("control:107:4")
            < events.index("control:107:5")
        ), events
        # Source clock/deadline readback: Start4, Send4 and Start5 ran before
        # the shared quota reopened; Send5 crossed its restored deadline.
        assert all(((s[0] - s[1]) & 0xFFFFFFFF) >= 0x80000000 for s in trace[2:5]), (
            trace
        )
    case["events"] = events
    case["mic_initial_wires"] = [
        data[k] for k in [(3, n) for n in range(5)] + [(4, 0), (5, 0)]
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
        [d.resolve() for d in args.qt_library_directory],
    )
    digest = neg.udp.process.digest
    assert digest(binary) == neg.udp.process.boundary.codec.SHA
    assert digest(sdk / "libavcodec.so.61") == neg.udp.process.boundary.CODEC_SHA
    assert digest(sdk / "libavutil.so.59") == neg.udp.process.boundary.codec.SDK_SHA
    driver_source = ROOT / "scripts/steam-client-microphone-schedule-driver.c"
    cases = []
    with tempfile.TemporaryDirectory(prefix="source-schedule-") as temporary:
        directory = Path(temporary)
        driver = directory / "caller.so"
        subprocess.run(
            ["cc", "-shared", "-fPIC", "-O2", str(driver_source), "-o", str(driver)],
            check=True,
        )
        driver_sha = digest(driver)
        for crc in (False, True):
            for locked in (False, True):
                case = dict(
                    name=f"schedule_crc{int(crc)}_locked{int(locked)}",
                    crc=crc,
                    reliable=True,
                    lock_network_thread=locked,
                    settings="3800c80101",
                    bad_mac=False,
                    server="070a0308c00b",
                    response="0208001001",
                    duplicate=False,
                    bad_length=False,
                    schedule_done=str(directory / f"done-{int(crc)}-{int(locked)}"),
                )
                settings = directory / "streaming_settings.bin"
                settings.write_bytes(bytes.fromhex(case["settings"]))
                result = neg.udp.audit(
                    binary,
                    sdk,
                    qt,
                    args.output.with_name(
                        args.output.stem + "-" + case["name"] + ".json"
                    ),
                    case,
                    helper=ROOT / "scripts/steam-client-microphone-schedule-gdb.py",
                    reactor=Peer,
                    probe_config=dict(
                        udp_helper=str(ROOT / "scripts/steam-client-udp-gdb.py"),
                        negotiation_helper=str(
                            ROOT / "scripts/steam-client-negotiation-gdb.py"
                        ),
                        mic_helper=str(ROOT / "scripts/steam-client-microphone-gdb.py"),
                        settings_file=str(settings),
                        sdk_directory=str(sdk),
                        driver=str(driver),
                        lock_network_thread=locked,
                        schedule_done=case["schedule_done"],
                    ),
                    validate=verify,
                )
                assert settings.read_bytes() == bytes.fromhex(case["settings"])
                cases.append(result)
                print(case["name"], result["events"], flush=True)
    raw = binary.read_bytes()
    functions = dict(mic.FUNCTIONS)
    functions.update(
        {
            0x19FD00: "set_shaper_rate",
            0x19FD60: "can_send_class",
            0x19FD70: "can_send_packet",
            0x19FDB0: "charge_class",
            0x19FDF0: "note_sent_packet",
            0x1A4530: "packet_timestamp",
        }
    )
    fdes = [
        e
        for e in ELFFile(io.BytesIO(raw)).get_dwarf_info().EH_CFI_entries()
        if isinstance(e, FDE)
    ]
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
                    functions.setdefault(
                        fde["initial_location"],
                        f"schedule_caller_{fde['initial_location']:x}",
                    )
    helpers = (
        "steam-client-microphone-schedule-gdb.py",
        "steam-client-microphone-gdb.py",
        "steam-client-negotiation-gdb.py",
        "steam-client-udp-gdb.py",
        "steam-client-sdk-gdb.py",
    )
    report = dict(
        scope=__doc__,
        client_sha256=digest(binary),
        codec_sha256=digest(sdk / "libavcodec.so.61"),
        util_sha256=digest(sdk / "libavutil.so.59"),
        driver_source_sha256=digest(driver_source),
        driver_sha256=driver_sha,
        source_functions=neg.udp.process.boundary.inventory(raw, functions),
        helpers={name: digest(ROOT / "scripts" / name) for name in helpers},
        runner_sha256=digest(ROOT / "scripts/audit-steam-client-udp-process.py"),
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
        cases=cases,
    )
    data = (json.dumps(report, indent=2) + "\n").encode()
    args.output.write_bytes(data)
    if args.snapshot:
        args.snapshot.write_bytes(gzip.compress(data, mtime=0))
    print(f"Official real UDP schedule: {len(cases)} processes verified")


if __name__ == "__main__":
    main()
