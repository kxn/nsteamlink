#!/usr/bin/env python3
"""Execute original media clock conversion and sampling before decoder handoff.

Real Socket/CRC/windows/RS, OnStreamPacket/OnDataPacket, pending replay and video
sampling execute in the pinned client. O explicitly controls connection offset;
T executes original ProcessTimestamp and Ping/TimeOffset queues. Decoder-terminal
metadata is copied immediately; D only reads this history to compare native's
explicitly delayed FIFO consumer, not to move Source decoder execution. Platform
locks/refcounts/vector storage, decoder bodies and final IO remain adapters.
"""

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "early", ROOT / "scripts/audit-steam-early-media.py"
)
e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e)
c = e.c


class Clock(e.Early):
    def __init__(self, binary, crc):
        super().__init__(binary, crc)
        self.accepted, self.history = [], []

    def decoded(self):
        f = self.r(1)
        p = self.q(f + 8)
        value = dict(
            id=struct.unpack("<H", self.u.mem_read(f + 26, 2))[0],
            frame=self.i(f + 28),
            sent=self.i(f + 32),
            received=self.i(f + 40),
            first=self.i(p + 28),
            input=struct.unpack("<H", self.u.mem_read(f + 44, 2))[0],
            input_received=self.i(f + 48),
            size=self.i(p + 52) - 26,
        )
        self.accepted.append(value)
        self.history.append(value)
        self.ret()


def schedules(binary):
    encoder = e.a.video.Encoder(binary)
    cases = []
    for crc in (False, True):
        for carrier in (3, 5, 11):
            for mode in ("latched", "pending", "negative", "zero", "feedback"):
                actions = [] if mode == "pending" else [["C", 3]]
                if mode == "feedback":
                    actions += [["T", 1100000, 1100500, 1100100]]
                else:
                    actions += [["O", -200 if mode == "negative" else 100]]
                for fid in (1, 2):
                    sent = 1101000 + (fid - 1) * 5000
                    data = e.a.video.payload(fid, sent, 87)
                    data = (
                        b"\x01"
                        + struct.pack(
                            "<HIHI",
                            fid,
                            0 if mode == "zero" else sent - 1,
                            23,
                            0 if mode == "zero" else sent - 3,
                        )
                        + data[13:]
                    )
                    if carrier == 11:
                        wires = encoder.encode(data)
                        for n in (0, 1, 4, 5):
                            w = wires[n]
                            frag, group = struct.unpack_from("<HH", w, 5)
                            actions += [
                                [
                                    "W",
                                    sent + 10 + n,
                                    11,
                                    3,
                                    group,
                                    n + 1,
                                    frag,
                                    sent + n,
                                    w[13:].hex(),
                                ]
                            ]
                    else:
                        actions += [
                            [
                                "W",
                                sent + 20,
                                carrier,
                                3,
                                fid - 1,
                                0,
                                0,
                                sent,
                                data.hex(),
                            ]
                        ]
                    actions += [["U", sent + 30, 3]]
                    if mode == "pending" and fid == 1:
                        actions += [["O", 200], ["C", 3]]
                    if mode == "feedback":
                        actions += [
                            ["T", sent + 1000, sent + 1700 + fid * 200, sent + 1100]
                        ]
                    else:
                        actions += [
                            ["O", -800 if mode == "negative" else 900 + fid * 100]
                        ]
                    actions += [["D"]]
                cases.append(
                    dict(
                        name=f"clock_{carrier}_{mode}_{int(crc)}",
                        crc=crc,
                        actions=actions,
                    )
                )
    for original in list(cases):
        if "_feedback_" not in original["name"]:
            continue
        for full in (False, True):
            case = copy.deepcopy(original)
            case["name"] += f"_report{int(full)}"
            case["full"] = full
            case["actions"] += [["V", 1, 1110000], ["V", 2, 1111000], ["S", 1200000]]
            cases.append(case)
    for original in list(cases):
        if "_latched_" not in original["name"]:
            continue
        case = copy.deepcopy(original)
        case["name"] = case["name"].replace("_latched_", "_wrap_")
        first = True
        for op in case["actions"]:
            if op[0] == "O":
                op[1] = 2147483632 if first else -2147483632
                first = False
        cases.append(case)
    return cases


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == c.SHA
    cases = []
    for inp in schedules(binary):
        r = Clock(binary, inp["crc"])
        r.b(c.CLIENT + 636, int(inp.get("full", False)))
        observed = []
        for op, *v in inp["actions"]:
            r.entries.clear()
            r.writes.clear()
            r.wires.clear()
            r.accepted.clear()
            r.frames.clear()
            consumed = []
            if op == "W":
                r.now, *args = v
                r.receive_packet(*args)
            elif op == "U":
                r.now, ch = v
                r.call(0x7F9C9C, r.channels[ch], r.now)
            elif op == "C":
                r.configure(v[0])
            elif op == "O":
                r.wi(r.connection + 848, v[0])
            elif op == "T":
                r.now = v[2]
                r.call(0x7F9A2C, r.connection, *v)
            elif op == "V":
                fid, r.now = v
                r.call(0x7AC3F8, c.CLIENT, 1, fid, 1)
            elif op == "S":
                r.now = v[0]
                r.call(0x7A7140, c.CLIENT)
            else:
                assert op == "D"
                consumed = r.history
                r.history = []
            rx = r.channels[3]
            head, tail = struct.unpack("<HH", r.u.mem_read(rx + 288, 4))
            state = r.observe()
            state.update(
                video=r.observe_collectors()["video"],
                wires=list(r.wires),
                client=r.i(c.CLIENT + 256),
                client_paused=False,
                pending=r.pending(),
                receiver=dict(head=head, tail=tail, delay=r.i(rx + 28)),
                accepted=list(r.accepted),
                decoded=consumed,
                offset=struct.unpack("<i", r.u.mem_read(r.connection + 848, 4))[0],
            )
            if "full" in inp:
                state.update(
                    frames=list(r.frames),
                    frame_events_time=r.i(c.CLIENT + 0x1C678),
                    keepalive_time=r.i(c.CLIENT + 0x1F6F0),
                    sequence=r.q(c.CLIENT + 128),
                    reported=r.i(r.ring(1) + 8) >> 16,
                )
            observed.append(state)
        assert not r.asserts and not r.history, (inp["name"], r.asserts)
        assert sum(len(s["accepted"]) for s in observed) == 2
        cases.append(dict(input=inp, observed=observed))
    return cases


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    args = p.parse_args()
    report = dict(
        binary_sha256=c.SHA, scope=__doc__, cases=audit(args.binary.read_bytes())
    )
    ref = ROOT / "scripts/fixtures/steam-media-clock-reference.json"
    if args.refresh_reference:
        if ref.exists():
            old = json.loads(ref.read_text())
            assert old["cases"] == report["cases"][: len(old["cases"])]
        ref.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert json.loads(ref.read_text()) == report
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Official media clock: {len(report['cases'])} cases")


if __name__ == "__main__":
    main()
