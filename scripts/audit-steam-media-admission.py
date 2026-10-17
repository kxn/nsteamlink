#!/usr/bin/env python3
"""Execute official media admission after real CRC, windows and FEC reconstruction.

Pinned Android Socket/channel/Pop/RS -> OnStreamPacket -> OnDataPacket and video
collectors execute. Client phase and client+19 are controlled at action boundaries,
not inferred UI reachability. Source decoder/stats scoring, locks/refcounts and IO
remain the video-network audit's adapters. Compare transport counters/feedback,
OnDataPacket frame IDs and video collectors; transport delegate ownership differs
from native FIFO, so its pre-gate delivered/metadata lists are not compared here.
No Pause/Resume message producer, hardware decoder or real Steam test is claimed.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "video", ROOT / "scripts/audit-steam-video-network.py"
)
video = importlib.util.module_from_spec(spec)
spec.loader.exec_module(video)
c = video.config


class Admission(video.Video):
    def __init__(self, binary, crc):
        super().__init__(binary, crc)
        self.admitted = []
        self.wires = []
        self.callbacks[0xC11170] = lambda: self.jump(0x7FF1DC)
        self.callbacks[0xC0E770] = self.data_packet

    def write(self):
        p = self.r(1)
        raw = self.q(p + 40)
        crc = bool(self.u.mem_read(raw, 1)[0] & 128)
        self.wires.append(
            bytes(self.u.mem_read(raw, self.i(p + 52) + (4 if crc else 0))).hex()
        )
        super().write()

    def data_packet(self):
        self.admitted.append(struct.unpack("<H", self.u.mem_read(self.r(1) + 26, 2))[0])
        self.jump(0x7AD148)


def schedules(binary, update_modes=False):
    encoder = video.Encoder(binary)
    cases = []
    for crc in (False, True):
        for kind in (3, 5, 11):
            modes = (
                ("pause_before_update", "resume_before_update")
                if update_modes
                else (
                    "paused",
                    "pause_before_complete",
                    "resume_before_complete",
                    "starting",
                    "stopping",
                )
            )
            for mode in modes:
                phase = dict(starting=5, stopping=7).get(mode, 6)
                paused = mode in (
                    "paused",
                    "resume_before_complete",
                    "resume_before_update",
                )
                actions = [["Q", phase, int(paused)]]
                pid = 0
                for fid in (1, 2, 3):
                    sent = 1100000 + fid * 1000
                    data = video.payload(fid, sent, 87)
                    if kind == 11:
                        shards = encoder.encode(data)
                        pieces = []
                        for n in (0, 1, 4, 5):
                            wire = shards[n]
                            fragment, group = struct.unpack_from("<HH", wire, 5)
                            pieces.append(
                                [
                                    "W",
                                    sent + 10 + n,
                                    11,
                                    3,
                                    group,
                                    n + 1,
                                    fragment,
                                    sent + n,
                                    wire[13:].hex(),
                                ]
                            )
                    else:
                        pieces = [
                            ["W", sent + 10, kind, 3, pid, 0, 1, sent, data[:16].hex()],
                            [
                                "W",
                                sent + 20,
                                kind + 1,
                                3,
                                pid + 1,
                                0,
                                0,
                                sent,
                                data[16:].hex(),
                            ],
                        ]
                        pid += 2
                    if fid == 2 and mode in (
                        "pause_before_complete",
                        "resume_before_complete",
                    ):
                        actions += pieces[:-1]
                        actions.append(["Q", 6, int(mode == "pause_before_complete")])
                        actions += pieces[-1:]
                    else:
                        actions += pieces
                    if fid == 2 and update_modes:
                        actions.append(["Q", 6, int(mode == "pause_before_update")])
                    actions.append(["U", sent + 30, 3])
                    if fid == 2:
                        actions.append(["Q", 6, 0])
                cases.append(
                    dict(
                        name=f"admission_{kind}_{mode}_{int(crc)}",
                        crc=crc,
                        actions=actions,
                    )
                )
    return cases


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == c.SHA
    cases = []
    for inp in schedules(binary) + schedules(binary, update_modes=True):
        r = Admission(binary, inp["crc"])
        observed = []
        ids = []
        for op, *v in inp["actions"]:
            r.entries.clear()
            r.frames.clear()
            r.admitted.clear()
            r.writes.clear()
            r.wires.clear()
            if op == "Q":
                r.wi(c.CLIENT + 256, v[0])
                r.b(c.CLIENT + 19, v[1])
            elif op == "W":
                r.now, *args = v
                r.receive_packet(*args)
            else:
                assert op == "U"
                r.now, channel = v
                r.call(0x7F9C9C, r.channels[channel], r.now)
            state = r.observe()
            state.update(
                video=r.observe_collectors()["video"],
                admitted=list(r.admitted),
                wires=list(r.wires),
                client=r.i(c.CLIENT + 256),
                client_paused=bool(r.u.mem_read(c.CLIENT + 19, 1)[0]),
            )
            ids += r.admitted
            observed.append(state)
        want = (
            [1, 3]
            if "pause_before_complete" in inp["name"]
            else [2, 3]
            if "resume_before_complete" in inp["name"]
            else [3]
        )
        if "before_update" in inp["name"]:
            fec = "_11_" in inp["name"]
            want = (
                ([1, 2, 3] if fec else [1, 3])
                if "pause_before_update" in inp["name"]
                else ([3] if fec else [2, 3])
            )
        assert ids == want, (inp["name"], ids, want)
        assert not r.asserts, (inp["name"], r.asserts)
        cases.append(dict(input=inp, observed=observed))
    return cases


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    report = dict(
        binary_sha256=c.SHA, scope=__doc__, cases=audit(a.binary.read_bytes())
    )
    reference = ROOT / "scripts/fixtures/steam-media-admission-reference.json"
    if a.refresh_reference:
        if reference.exists():
            old = json.loads(reference.read_text())
            assert old["cases"] == report["cases"][: len(old["cases"])]
        reference.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert json.loads(reference.read_text()) == report
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Official media admission: {len(report['cases'])} cases")


if __name__ == "__main__":
    main()
