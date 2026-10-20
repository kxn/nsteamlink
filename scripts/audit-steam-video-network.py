#!/usr/bin/env python3
"""Execute official Socket/channel/frame/video-collector/report instructions.

The real Socket CRC/connection admission, constructors and window growth, Pop,
FEC RX/RS, OnStreamPacket, Frame::SetPacket, OnDataPacket, inline video collector
and FrameEvents/protobuf run in the pinned Android ELF. FEC video shards are
produced by its actual SendUnreliableFEC/AddPacket/RS encoder, at explicitly
controlled MTU64/percentage50; received wire IDs/clocks are controlled inputs.
Platform locks/libc, packet refcounts/destructors, final feedback transport,
CNetworkStats scoring, hardware decoder and report encryption/final admission
are adapters. Non-data FEC vector payloads stop at the recording delegate; their
header selection is compared, not unknown-message queue processing. Native
worker steps are driven explicitly; this is not full scheduling, decoder,
FEC enable policy, Steam authentication or device-display equivalence.
"""

import argparse
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "loss", ROOT / "scripts/audit-steam-network-loss.py"
)
loss = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loss)
config = loss.config


class Video(loss.Loss):
    def __init__(self, binary, crc=False):
        super().__init__(binary, crc)
        self.metadata = []
        self.wi(config.CLIENT + 256, 6)
        self.b(config.CLIENT + 625, 4)
        self.b(config.CLIENT + 626, 3)
        self.callbacks[0xC0E120] = lambda: self.ret()

    def deliver(self):
        p = self.r(2)
        raw = self.q(p + 40)
        payload = bytes(self.u.mem_read(raw + 13, self.i(p + 52) - 13))
        self.delivered.append(payload.hex())
        self.metadata.append(
            dict(
                first=self.i(p + 28),
                last=self.i(p + 32),
                sent=struct.unpack("<I", self.u.mem_read(raw + 9, 4))[0],
                fragment=struct.unpack("<H", self.u.mem_read(raw + 5, 2))[0],
            )
        )
        if payload and payload[0] == 1:
            self.u.reg_write(config.X0, config.CLIENT)
            self.jump(0x7ACFA8)
        else:
            self.ret()


class Encoder(loss.Loss):
    def __init__(self, binary):
        super().__init__(binary)
        self.encoded = []
        self.callbacks[0xC11170] = self.capture
        self.wi(0xF34D48, 64)
        self.call(0x7FBCBC, self.connection, 3, 50)

    def capture(self):
        p = self.r(2)
        self.encoded.append(bytes(self.u.mem_read(self.q(p + 40), self.i(p + 52))))
        self.ret(0)

    def encode(self, payload):
        self.encoded.clear()
        p = self.packet(3, 3, False, 12, 34, len(payload))
        self.u.mem_write(self.q(p + 40) + 13, payload)
        self.call(0x7F90E4, self.channels[3], p)
        return list(self.encoded)


def payload(fid, stamp, size=27):
    body = (struct.pack("<HBHH", 0, 0x18, 0, 0) + bytes([fid & 255]) * size)[:size]
    return b"\x01" + struct.pack("<HIHI", fid, (stamp - 1) & 0xFFFFFFFF, 0, 0) + body


def schedules(binary):
    cases, encoding = [], []
    encoder = Encoder(binary)
    encoded = {}
    for fid in range(1, 14):
        data = payload(fid, 900000 + fid * 1000, 87)
        encoded[fid] = encoder.encode(data)
        encoding.append(
            dict(payload=data.hex(), shards=[w.hex() for w in encoded[fid]])
        )
    for crc in (False, True):
        for kind in (3, 5):
            for mode in (
                "single",
                "fragment",
                "reverse",
                "partial",
                "clamp",
                "wrap",
                "zero",
                "offset",
            ):
                actions, pid = [], 0
                offset = 123 if mode == "offset" else 0
                if offset:
                    actions.append(["O", offset])
                for fid in range(1, 14):
                    sent = 900000 + fid * 1000
                    begin, end = sent + 10, sent + 20
                    if mode == "wrap":
                        sent = (0xFFFFF000 + fid * 1000) & 0xFFFFFFFF
                        begin, end = (sent + 10) & 0xFFFFFFFF, (sent + 20) & 0xFFFFFFFF
                        if fid == 4:
                            sent, begin, end = 0xFFFFFFE0, 0xFFFFFFF0, 16
                    elif mode == "zero" and fid == 1:
                        sent, begin, end = 0, 0, 2
                    elif mode == "clamp" and fid % 3 == 0:
                        begin, end = sent - 20, sent - 10
                    size = 27
                    parts = 2 if mode == "partial" else 1
                    for part in range(parts):
                        wire_sent = (sent + offset + part * 30) & 0xFFFFFFFF
                        data = payload(fid, wire_sent, size + part)
                        if mode == "single":
                            actions.append(
                                ["W", end, kind, 3, pid, 0, 0, wire_sent, data.hex()]
                            )
                            pid += 1
                        else:
                            split = 16
                            group = [
                                [
                                    "W",
                                    (begin + part * 30) & 0xFFFFFFFF,
                                    kind,
                                    3,
                                    pid,
                                    0,
                                    1,
                                    wire_sent,
                                    data[:split].hex(),
                                ],
                                [
                                    "W",
                                    (end + part * 30) & 0xFFFFFFFF,
                                    kind + 1,
                                    3,
                                    pid + 1,
                                    0,
                                    0,
                                    wire_sent,
                                    data[split:].hex(),
                                ],
                            ]
                            if mode == "reverse":
                                group[0][1], group[1][1] = end, begin
                                group.reverse()
                            actions += group
                            pid += 2
                        actions.append(["U", (end + part * 30 + 1) & 0xFFFFFFFF, 3])
                cases.append(
                    dict(
                        name=f"video_{kind}_{mode}_{int(crc)}", crc=crc, actions=actions
                    )
                )
        # Each tiny payload gets a fresh client. Decoder state is outside
        # this collector test; a zero codec payload can terminate the native
        # decoder path after sampling and must not poison later input cases.
        for kind in (3, 5):
            for size in range(8):
                data = payload(1, 900000, size)
                cases.append(
                    dict(
                        name=f"tiny_{kind}_{size}_{int(crc)}",
                        crc=crc,
                        actions=[
                            ["W", 900020, kind, 3, 0, 0, 0, 900000, data.hex()],
                            ["U", 900021, 3],
                        ],
                    )
                )
        for full in (False, True):
            actions = []
            for fid in range(1, 14):
                sent = 900000 + fid * 1000 + (80000 if fid > 11 else 0)
                data = payload(fid, sent)
                actions += [
                    ["W", sent + 10, 3, 3, (fid - 1) * 2, 2, 1, sent, data[:16].hex()],
                    [
                        "W",
                        sent + 20,
                        4,
                        3,
                        (fid - 1) * 2 + 1,
                        1,
                        0,
                        sent,
                        data[16:].hex(),
                    ],
                    ["U", sent + 21, 3],
                    ["C", fid, sent + 25],
                ]
                if fid in (11, 13):
                    actions.append(["S", sent + 30])
            cases.append(
                dict(
                    name=f"video_report_{int(crc)}_{int(full)}",
                    crc=crc,
                    full=full,
                    actions=actions,
                )
            )
        for pattern in ((0, 1, 2, 3), (3, 2, 1, 0), (0, 1, 4, 5), (5, 1, 4, 0)):
            actions = []
            for fid in range(1, 14):
                sent = 900000 + fid * 1000
                for n, index in enumerate(pattern):
                    w = encoded[fid][index]
                    fragment, group = struct.unpack_from("<HH", w, 5)
                    actions.append(
                        [
                            "W",
                            sent + 10 + n,
                            11,
                            3,
                            group,
                            index + 1,
                            fragment,
                            sent + index,
                            w[13:].hex(),
                        ]
                    )
            cases.append(
                dict(name=f"video_fec_{pattern}_{int(crc)}", crc=crc, actions=actions)
            )
    # Independently replay every surviving distinct-shard order of §26's fixed
    # k3/m2 vector, correcting the old checker which assumed first-arrival header.
    fixed = json.loads((ROOT / "scripts/fixtures/steam-fec-reference.json").read_text())
    assert fixed["binary_sha256"] == config.SHA
    wires = [bytes.fromhex(w) for w in fixed["vector"]["wires"]]
    for chosen in itertools.combinations(range(5), 3):
        for order in itertools.permutations(chosen):
            actions = [
                [
                    "W",
                    1000000 + n,
                    11,
                    3,
                    1,
                    index + 1,
                    index,
                    900000 + index,
                    wires[index][13:].hex(),
                ]
                for n, index in enumerate(order)
            ]
            cases.append(dict(name=f"fec_header_{order}", crc=False, actions=actions))
    for crc in (False, True):
        for label, times in (
            ("zero", (0, 0, 2)),
            ("wrap", (0xFFFFFFF0, 0, 16)),
            ("backwards", (20, 10, 5)),
            ("zero_then_back", (0, 2, 1)),
        ):
            actions = [
                [
                    "W",
                    tick,
                    11,
                    3,
                    1,
                    index + 1,
                    index,
                    900000 + index,
                    wires[index][13:].hex(),
                ]
                for tick, index in zip(times, (3, 0, 4))
            ]
            cases.append(
                dict(name=f"fec_times_{label}_{int(crc)}", crc=crc, actions=actions)
            )
    actions = []
    for n, fid in enumerate((65534, 65535, 0, 1, 2)):
        sent = 900000 + n * 1000
        data = payload(fid, sent)
        actions += [
            ["W", sent + 10, 3, 3, n * 2, 0, 1, sent, data[:16].hex()],
            ["W", sent + 20, 4, 3, n * 2 + 1, 0, 0, sent, data[16:].hex()],
            ["U", sent + 21, 3],
        ]
    cases.append(dict(name="video_frame_id_wrap", crc=False, actions=actions))
    actions = [
        list(a)
        for a in next(c for c in cases if c["name"] == "video_3_fragment_0")["actions"]
    ]
    for fid in (14, 15):
        sent = 1300000 + fid * 1000
        data = payload(fid, sent)
        actions += [
            ["W", sent + 10, 3, 3, (fid - 1) * 2, 0, 1, sent, data[:16].hex()],
            ["W", sent + 20, 4, 3, (fid - 1) * 2 + 1, 0, 0, sent, data[16:].hex()],
            ["U", sent + 21, 3],
        ]
    cases.append(dict(name="video_stale_derived", crc=False, actions=actions))
    return encoding, cases


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == config.SHA
    encoding, schedules_ = schedules(binary)
    cases = []
    for i in schedules_:
        r = Video(binary, i["crc"])
        r.b(config.CLIENT + 636, int(i.get("full", False)))
        observed = []
        for op, *v in i["actions"]:
            r.entries.clear()
            r.frames.clear()
            r.delivered.clear()
            r.metadata.clear()
            if op == "W":
                r.now, *args = v
                r.receive_packet(*args)
            elif op == "U":
                r.now, ch = v
                r.call(0x7F9C9C, r.channels[ch], r.now)
            elif op == "O":
                r.wi(r.connection + 848, v[0])
            elif op == "C":
                fid, r.now = v
                r.call(0x7AC3F8, config.CLIENT, 1, fid, 1)
            else:
                assert op == "S"
                r.now = v[0]
                r.call(0x7A7140, config.CLIENT)
            state = r.observe()
            state.update(
                video=r.observe_collectors()["video"],
                delivered=list(r.delivered),
                metadata=list(r.metadata),
            )
            if "full" in i:
                state.update(
                    frames=list(r.frames),
                    frame_events_time=r.i(config.CLIENT + 0x1C678),
                    keepalive_time=r.i(config.CLIENT + 0x1F6F0),
                    sequence=r.q(config.CLIENT + 128),
                    reported=r.i(r.ring(1) + 8) >> 16,
                )
            observed.append(state)
        assert not r.asserts, (i["name"], r.asserts)
        cases.append(dict(input=i, observed=observed))
    return dict(encoding_vectors=encoding, cases=cases)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    report = dict(
        binary_sha256=config.SHA, scope=__doc__, **audit(a.binary.read_bytes())
    )
    ref = ROOT / "scripts/fixtures/steam-video-network-reference.json"
    if a.refresh_reference:
        if ref.exists():
            assert (
                json.loads(ref.read_text())["cases"]
                == report["cases"][: len(json.loads(ref.read_text())["cases"])]
            )
        ref.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert json.loads(ref.read_text()) == report
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Official video network: {len(report['cases'])} cases passed")


if __name__ == "__main__":
    main()
