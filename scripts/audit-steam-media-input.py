#!/usr/bin/env python3
"""Execute official shared input-mark consumption by audio and video RX.

Original CreateInputMark, OnStreamPacket/Frame construction/OnDataPacket,
RecordFrameReceived, CFastFrameStats and video completion/report/protobuf execute.
Initial phase/paused, channels, mark counter, clocks and frames are controlled.
Socket/windows/RS, decoder workers, input producers, CNetworkStats/bitrate sample
sinks, libc/refcounts and final send remain explicit boundaries.
No claim that a physical host/producer supplies every controlled input mark.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "stats", ROOT / "scripts/audit-steam-frame-stats.py"
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Media(m.Stats):
    def __init__(self, binary, full, offset):
        self.pcs = {}
        super().__init__(binary, full, offset)
        self.watch = set()
        self.wi(m.config.CLIENT + 256, 6)
        self.callbacks[0xC0E770] = lambda: self.jump(0x7AD148)
        self.callbacks[0xC0E120] = (
            lambda: self.ret()
        )  # Packet refcount/retirement adapter.

    def hook(self, uc, address, size, data):
        labels = {
            0x7AC0A0: "new_slot",
            0x7AC08C: "same_id",
            0x7AC160: "bind_mark",
            0x7AC198: "consume_mark",
            0x7ABF94: "video_network_sample",
            0x7AD220: "rx_prepared",
        }
        if address in labels:
            key = labels[address]
            self.pcs[key] = self.pcs.get(key, 0) + 1
        super().hook(uc, address, size, data)

    def packet(self, typ, fid, start, sent, received, size, mark, input_received):
        wire = struct.pack("<BBBBBHHI", 5, 0, 34, 12, 3 + typ, 0, 0, sent)
        wire += (
            b"\x01"
            + struct.pack("<HIHI", fid, start, mark, input_received)
            + bytes(size)
        )
        p, raw = self.alloc(4096), self.alloc(max(4096, len(wire) + 64))
        self.wq(p + 40, raw)
        self.wq(p + 56, raw)
        self.wi(p + 52, len(wire))
        self.wi(p + 28, received)
        self.wi(p + 32, received)
        self.u.mem_write(raw, wire)
        self.call(0x7ACFA8, m.config.CLIENT, self.connection, p)

    def mark(self, previous, begin, sent):
        self.now = sent
        self.u.mem_write(m.config.CLIENT + 0x1F67C, struct.pack("<H", previous))
        value = self.call(0x7A9240, m.config.CLIENT, begin)
        assert value == (previous + 1 if previous != 65535 else 1)
        self.watch.add(value & 1023)
        return value

    def snapshot(self, ids):
        audio, video = self.observe(ids, 0), self.observe(ids, 1)
        frames = audio.pop("frames") + video.pop("frames")
        assertions = audio.pop("asserts") + video.pop("asserts")
        marks = []
        for index in sorted(self.watch):
            raw = bytes(self.u.mem_read(m.config.CLIENT + 0x1C67C + index * 12, 12))
            mark, begin, sent = struct.unpack("<H2xII", raw)
            marks.append([index, mark, begin, sent])
        result = dict(
            audio_slots=audio["slots"],
            video=video,
            marks=marks,
            frames=frames,
            assertions=assertions,
            pcs=self.pcs,
        )
        self.pcs = {}
        return result


def schedules():
    # RX fields: type,id,frame-start,send,receive,size,input-mark,input-received.
    def rx(
        typ,
        fid=1,
        mark=17,
        tick=0,
        frame=None,
        send=None,
        receive=None,
        size=32,
        input_received=None,
    ):
        return [
            "R",
            typ,
            fid,
            900000 + tick if frame is None else frame,
            901000 + tick if send is None else send,
            902000 + tick if receive is None else receive,
            size,
            mark,
            892000 + tick if input_received is None else input_received,
        ]

    mark = ["M", 16, 890000, 891000]
    end = [["C", 1, 1, 905000], ["S"], ["S"]]
    plans = {
        "audio_first": [mark, rx(0), rx(1)] + end,
        "video_first": [mark, rx(1), rx(0)] + end,
        "video_only": [mark, rx(1)] + end,
        "audio_only": [mark, rx(0), ["S"]],
        "same_audio_id": [rx(0, mark=0), mark, rx(0, tick=1000), rx(1)] + end,
        "same_video_id": [rx(1, mark=0), mark, rx(1, tick=1000), rx(0)] + end,
        "same_audio_new_mark": [
            mark,
            rx(0),
            ["M", 17, 893000, 894000],
            rx(0, mark=18, tick=2000),
            rx(1, mark=18),
        ]
        + end,
        "audio_alias": [
            mark,
            rx(0),
            ["M", 17, 893000, 894000],
            rx(0, 241, 18),
            rx(1, mark=18),
        ]
        + end,
        "cross_media_alias": [mark, rx(0, 241), rx(1)] + end,
        "zero_frame": [mark, rx(0, 0), rx(1)] + end,
        "zero_video_frame": [mark, rx(1, 0), rx(0)] + end,
        "zero_mark": [mark, rx(0, mark=0), rx(1)] + end,
        "future_mark": [mark, rx(0, mark=18), rx(1)] + end,
        "older_mark": [mark, ["M", 17, 893000, 894000], rx(0, mark=17), rx(1, mark=18)]
        + end,
        "mark_wrap": [["M", 65535, 890000, 891000], rx(0, mark=1), rx(1, mark=1)] + end,
        "old_after_wrap": [
            ["M", 65535, 890000, 891000],
            rx(0, mark=65535),
            rx(1, mark=1),
        ]
        + end,
        "zero_input_time": [mark, rx(0, input_received=0), rx(1)] + end,
        "receive_before_send": [mark, rx(0, receive=900500), rx(1)] + end,
        "zero_times": [
            ["M", 16, 0, 1],
            rx(0, frame=0, send=0, receive=0, input_received=0),
            rx(1),
        ]
        + end,
        "frame_wrap": [
            mark,
            rx(0, 65535),
            ["M", 17, 893000, 894000],
            rx(0, 0, 18),
            rx(1, mark=18),
        ]
        + end,
        "audio_overwrite_rebind": [
            mark,
            rx(0),
            rx(0, 241, 0),
            ["M", 17, 893000, 894000],
            rx(0, mark=18),
            rx(1, mark=18),
        ]
        + end,
    }
    for phase, paused in ((0, 0), (5, 0), (6, 1), (7, 0)):
        plans[f"blocked_audio_{phase}_{paused}"] = [
            mark,
            ["Q", phase, paused],
            rx(0),
            ["Q", 6, 0],
            rx(1),
        ] + end
    return plans


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == m.config.SHA
    cases = []
    for offset in (0, 100, -100):
        for full in (False, True):
            for name, actions in schedules().items():
                r = Media(binary, full, offset)
                ids = sorted({a[2] for a in actions if a[0] == "R"} | {1})
                states = []
                for a in actions:
                    if a[0] == "M":
                        r.mark(*a[1:])
                    elif a[0] == "R":
                        (
                            _,
                            typ,
                            fid,
                            start,
                            sent,
                            received,
                            size,
                            mark,
                            input_received,
                        ) = a
                        r.packet(
                            typ, fid, start, sent, received, size, mark, input_received
                        )
                    elif a[0] == "Q":
                        r.wi(m.config.CLIENT + 256, a[1])
                        r.b(m.config.CLIENT + 19, a[2])
                    elif a[0] == "C":
                        _, fid, result, r.now = a
                        r.call(0x7AC3F8, m.config.CLIENT, 1, fid, result)
                    else:
                        assert a == ["S"]
                        r.call(0x7A82E8, m.config.CLIENT, 1)
                    states.append(r.snapshot(ids))
                cases.append(
                    dict(
                        name=f"{name}_{offset}_{int(full)}",
                        offset=offset,
                        full=full,
                        ids=ids,
                        actions=actions,
                        observed=states,
                    )
                )
    return dict(binary_sha256=m.config.SHA, boundary=__doc__, cases=cases)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--write", type=Path)
    p.add_argument("--check", type=Path)
    a = p.parse_args()
    result = audit(a.binary.read_bytes())
    if a.write:
        a.write.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    if a.check:
        assert result == json.loads(a.check.read_text()), (
            "official shared media mark evidence drift"
        )
    print(
        f"Official media input: {len(result['cases'])} cases / "
        f"{sum(len(c['actions']) for c in result['cases'])} states"
    )


if __name__ == "__main__":
    main()
