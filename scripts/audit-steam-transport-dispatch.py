#!/usr/bin/env python3
"""Audit original ARM64 connection/channel dispatch, not native implementation.

Source IDs, destination IDs and the CRC-required flag execute original branches.
Address comparison results, stats, channel lookup and handler actions are stubs.
Socket CRC arithmetic, real Disconnect cleanup and actual networking are excluded.
"""
import argparse
import contextlib
import io
import json
import runpy
import sys
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--binary", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
saved_argv = sys.argv
sys.argv = [
    str(Path(__file__).with_name("audit-steam-video-recovery.py")),
    "--binary",
    str(args.binary),
    "--output",
    str(args.output.with_name("official-branches.json")),
]
with contextlib.redirect_stdout(io.StringIO()):
    base = runpy.run_path(sys.argv[0])
sys.argv = saved_argv
Run, STOP = base["Run"], base["STOP"]
results = []


def run(
    kind,
    *,
    connection=True,
    state=1,
    source=34,
    dest=12,
    address=True,
    crc_required=False,
    crc_present=False,
    channel=3
):
    r = Run()
    conn, ch, p = 0x20000000, 0x20010000, 0x20020000
    r.w32(conn + 16, state)
    r.b(conn + 12, 12)
    r.b(conn + 13, 34)
    r.b(conn + 10, int(crc_required))
    r.w32(conn + 1212, 0xFFFFFFFF)
    r.packet(p, typ=kind | (128 if crc_present else 0), retry=0)
    r.b(p + 64 + 2, source)
    r.b(p + 64 + 3, dest)
    r.b(p + 64 + 4, channel)
    events = []

    def jump(entry):
        r.u.reg_write(base["UC_ARM64_REG_PC"], entry)

    def action(name):
        events.append(name)
        r.ret(0)

    r.callbacks.update(
        {
            0xC0DC80: lambda: r.ret(int(address)),
            0xC11360: lambda: r.ret(),
            0xC11370: lambda: r.ret(),
            0xC0E030: lambda: action("Disconnect"),
            0xC0DA00: lambda: r.ret(),
            0xC0E390: lambda: r.ret(ch),
            0xC11250: lambda: jump(0x7F9250),
            0xC11260: lambda: action("FEC"),
            0xC11280: lambda: action("ACK"),
            0xC11290: lambda: action("NACK"),
            0xC11100: lambda: action("Insert"),
        }
    )
    r.run(0x7FACFC if connection else 0x7F9250, conn if connection else ch, p, 1000000)
    return events


for name, options, expected in [
    ("connection_type9_disconnect", dict(kind=9), ["Disconnect"]),
    ("connection_type9_bad_source", dict(kind=9, source=35), []),
    ("connection_type9_bad_destination", dict(kind=9, dest=13), []),
    ("connection_type9_bad_address", dict(kind=9, address=False), []),
    ("connection_type9_not_connected", dict(kind=9, state=3), []),
    ("channel_type9_ignored_only_at_channel", dict(kind=9, connection=False), []),
    ("type11_routes_to_FEC", dict(kind=11), ["FEC"]),
    ("type11_bad_source", dict(kind=11, source=35), []),
    ("type11_bad_destination", dict(kind=11, dest=13), []),
    ("type11_bad_address", dict(kind=11, address=False), []),
    ("type11_CRC_required_absent", dict(kind=11, crc_required=True), []),
    (
        "type11_CRC_required_present",
        dict(kind=11, crc_required=True, crc_present=True),
        ["FEC"],
    ),
    ("type10_routes_to_unreliable_NACK", dict(kind=10), ["NACK"]),
    ("type8_routes_to_reliable_NACK", dict(kind=8), ["NACK"]),
    ("type7_routes_to_ACK", dict(kind=7), ["ACK"]),
    ("out_of_range_channel_rejected", dict(kind=11, channel=32), []),
]:
    actual = run(**options)
    assert actual == expected, (name, actual, expected)
    results.append(dict(case=name, input=options, actions=actual))
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(
    json.dumps(
        dict(
            scope=__doc__,
            binary_sha256="50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e",
            cases=results,
        ),
        indent=2,
    )
    + "\n"
)
print(json.dumps(dict(cases=len(results), result="passed", output=str(args.output))))
