#!/usr/bin/env python3
"""Execute official early media through transport windows, FEC and complete pending.

Pinned Socket/CRC, channel/Pop/RS, OnStreamPacket/OnDataPacket, pending snapshot
replay and video collectors execute. Configured channel IDs, phase/paused and
clocks are controlled; configuration calls real delay setter and HandlePending,
not the full StartVideoData handler. CUtlVector snapshot storage, packet refs,
mutexes, decoder terminal and final IO are adapters. No UI reachability, real
Steam, hardware decoder or outgoing FEC enable policy is claimed.
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
    "admission", ROOT / "scripts/audit-steam-media-admission.py"
)
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
c = a.c


class Early(a.Admission):
    def __init__(self, binary, crc):
        super().__init__(binary, crc)
        self.b(c.CLIENT + 625, 0)
        self.b(c.CLIENT + 626, 0)
        self.call(0x7FBC98, self.connection, 3, 65)
        vt = self.alloc(4096)
        self.wq(c.CLIENT, vt)
        self.wq(vt + 48, 0x7ACFA8)
        self.callbacks[0xC0E770] = lambda: self.jump(0x7AD148)
        self.callbacks[0xC0B930] = self.decoded
        self.callbacks[0xC0E7E0] = self.copy_pending
        self.callbacks[0xC0E030] = lambda: self.jump(0x7FB724)

    def decoded(self):
        self.admitted.append(struct.unpack("<H", self.u.mem_read(self.r(1) + 26, 2))[0])
        self.ret()

    def copy_pending(self):
        dest, src, count = (self.r(i) for i in range(3))
        memory = self.alloc(max(4096, count * 8))
        if count:
            self.u.mem_write(memory, bytes(self.u.mem_read(src, count * 8)))
        self.wq(dest, memory)
        self.wi(dest + 8, count)
        self.wi(dest + 12, 0)
        self.wi(dest + 16, count)
        self.ret()

    def configure(self, channel):
        self.call(0x7FBC98, self.connection, channel, 6553)
        self.b(c.CLIENT + 626, channel)
        self.wq(c.CLIENT + 40, self.alloc(4096))
        self.call(0x7AFF74, c.CLIENT)

    def pending(self):
        items = []
        for i in range(self.i(c.CLIENT + 760)):
            p = self.q(self.q(c.CLIENT + 744) + i * 8)
            raw = self.q(p + 40)
            wire = bytes(self.u.mem_read(raw, self.i(p + 52)))
            kind, retry, src, dest, channel, frag, ident, sent = struct.unpack(
                "<BBBBBHHI", wire[:13]
            )
            items.append(
                dict(
                    kind=kind,
                    channel=channel,
                    fragment=frag,
                    id=ident,
                    sent=sent,
                    first=self.i(p + 28),
                    received=self.i(p + 32),
                    body=wire[13:].hex(),
                )
            )
        return items


def schedules(binary):
    encoder = a.video.Encoder(binary)
    cases = []
    for crc in (False, True):
        for carrier in (3, 5, 11):
            for mode in (
                "early",
                "partial",
                "paused_arrival",
                "paused_config",
                "other_config",
                "gap",
            ):
                actions = []
                if mode == "paused_arrival":
                    actions += [["Q", 6, 1]]
                for fid in (1, 2):
                    sent = 1100000 + fid * (400 if mode == "gap" else 1000)
                    data = a.video.payload(fid, sent, 87)
                    if carrier == 11:
                        pieces = []
                        wires = encoder.encode(data)
                        for n in (0, 1, 4, 5):
                            wire = wires[n]
                            frag, group = struct.unpack_from("<HH", wire, 5)
                            pieces.append(
                                [
                                    "W",
                                    sent + 10 + n,
                                    11,
                                    3,
                                    group,
                                    n + 1,
                                    frag,
                                    sent + n,
                                    wire[13:].hex(),
                                ]
                            )
                    else:
                        pid = (fid - 1) * 2
                        pieces = [
                            [
                                "W",
                                sent + 10,
                                carrier,
                                3,
                                pid,
                                0,
                                1,
                                sent,
                                data[:16].hex(),
                            ],
                            [
                                "W",
                                sent + 20,
                                carrier + 1,
                                3,
                                pid + 1,
                                0,
                                0,
                                sent,
                                data[16:].hex(),
                            ],
                        ]
                    if mode == "partial" and fid == 1:
                        actions += pieces[:-1] + [["C", 3]] + pieces[-1:]
                    elif mode == "gap" and fid == 1:
                        actions += pieces[:1]
                    else:
                        actions += pieces
                    actions += [["U", sent + 100, 3]]
                if mode == "paused_config":
                    actions += [["Q", 6, 1]]
                if mode == "other_config":
                    actions += [["C", 4]]
                actions += [["C", 3]]
                if mode.startswith("paused"):
                    actions += [["Q", 6, 0]]
                actions += [["U", 1200000, 3]]
                cases.append(
                    dict(
                        name=f"early_{carrier}_{mode}_{int(crc)}",
                        crc=crc,
                        actions=actions,
                    )
                )
    # Replay an old completed frame after a second decoder configuration.
    # Connection receive/FEC watermarks must outlive both consumer instances.
    for original in list(cases):
        if "_early_" not in original["name"]:
            continue
        case = copy.deepcopy(original)
        case["name"] = case["name"].replace("_early_", "_late_duplicate_")
        first = []
        for op in original["actions"]:
            if op[0] == "U":
                break
            if op[0] == "W":
                first.append(copy.deepcopy(op))
        for n, op in enumerate(first):
            op[1] = 1200000 + n
        case["actions"][-1:] = [["C", 3], *first, ["U", 1200100, 3]]
        cases.append(case)
    for original in list(cases):
        if "_11_partial_" not in original["name"]:
            continue
        for paused in (False, True):
            case = copy.deepcopy(original)
            case["name"] = case["name"].replace(
                "_partial_", f"_closing_p{int(paused)}_"
            )
            case["closing"] = True
            edge = next(i for i, op in enumerate(case["actions"]) if op[0] == "C") + 1
            case["actions"][edge:edge] = ([["Q", 6, 1]] if paused else []) + [["X"]]
            cases.append(case)
    return cases


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == c.SHA
    cases = []
    for inp in schedules(binary):
        r = Early(binary, inp["crc"])
        observed = []
        for op, *v in inp["actions"]:
            r.entries.clear()
            r.writes.clear()
            r.wires.clear()
            r.admitted.clear()
            if op == "W":
                r.now, *args = v
                r.receive_packet(*args)
            elif op == "U":
                r.now, channel = v
                r.call(0x7F9C9C, r.channels[channel], r.now)
            elif op == "C":
                r.configure(v[0])
            elif op == "X":
                r.receive_packet(9, 0, 0, 0, 0, r.now, "")
            else:
                assert op == "Q"
                r.wi(c.CLIENT + 256, v[0])
                r.b(c.CLIENT + 19, v[1])
            state = r.observe()
            rx = r.channels[3]
            head, tail = struct.unpack("<HH", r.u.mem_read(rx + 288, 4))
            state.update(
                video=r.observe_collectors()["video"],
                admitted=list(r.admitted),
                wires=list(r.wires),
                client=r.i(c.CLIENT + 256),
                client_paused=bool(r.u.mem_read(c.CLIENT + 19, 1)[0]),
                pending=r.pending(),
                receiver=dict(head=head, tail=tail, delay=r.i(rx + 28)),
            )
            if inp.get("closing"):
                state["connection"] = r.i(r.connection + 16)
            observed.append(state)
        assert not r.asserts, (inp["name"], r.asserts)
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
    ref = ROOT / "scripts/fixtures/steam-early-media-reference.json"
    if args.refresh_reference:
        if ref.exists():
            old = json.loads(ref.read_text())
            assert old["cases"] == report["cases"][: len(old["cases"])]
        ref.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert json.loads(ref.read_text()) == report
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Official early media: {len(report['cases'])} cases")


if __name__ == "__main__":
    main()
