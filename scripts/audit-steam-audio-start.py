#!/usr/bin/env python3
"""Execute original audio start/stop dispatch, factory and pending replay.

Original protobuf/Frame parsing, handlers, codec selection, decoder constructors,
Start/Stop/SetUseThreads and pending replay execute. Player-device start result,
OS thread scheduling/locks, packet refs, PCM storage and final IO are adapters.
This is not a real Steam session, physical SDL audio device or OS worker proof.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

from unicorn.arm64_const import UC_ARM64_REG_X29

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "early", ROOT / "scripts/audit-steam-early-media.py"
)
e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e)
c = e.c


class Audio(e.Early):
    def __init__(self, binary, threads=False):
        self.audio_events, self.assertions, self.audio_frames = [], [], {}
        self.ready, self.player_ok, self.thread_ok = False, True, True
        self.deliveries = []
        super().__init__(binary, False)
        self.player, self.player_vt = self.alloc(4096), self.alloc(4096)
        self.wq(self.player, self.player_vt)
        self.wq(self.player_vt + 16, 0x7BEBE0)
        self.wq(self.player_vt + 24, c.STOP + 0x610)
        self.wq(self.player_vt + 48, c.STOP + 0x620)
        self.wq(c.CLIENT + 48, self.player)
        self.b(c.CLIENT + 17, int(threads))
        self.callbacks.update(
            {
                c.STOP + 0x610: self.set_format,
                c.STOP + 0x620: self.submit,
                0xC0F690: self.device_open,
                0xC0E290: lambda: self.ret(),
                0xC0E2B0: lambda: self.ret(),
                0xC0B930: self.decoder_receive,
                0xC0BA20: self.create_audio,
                0xC0BA50: self.audio_area,
                0xC0BA60: self.audio_resize,
            }
        )
        self.ready = True
        self.audio_events.clear()

    def call(self, entry, *params):
        self.u.reg_write(c.SP, 0x300FF000)
        self.u.reg_write(c.LR, c.STOP)
        for i, value in enumerate(params):
            self.u.reg_write(c.X0 + i, value)
        self.u.emu_start(entry, c.STOP + 4, count=10000000)
        assert self.u.reg_read(c.BASE["UC_ARM64_REG_PC"]) == c.STOP, hex(
            self.u.reg_read(c.BASE["UC_ARM64_REG_PC"])
        )
        return self.r(0)

    def device_open(self):
        self.audio_events.append(
            ["device_open", self.r(1), self.r(2), self.r(3), self.player_ok]
        )
        self.ret(int(self.player_ok))

    def set_format(self):
        self.audio_events.append(["format", self.r(1), self.r(2), self.r(3)])
        self.jump(0x76799C)

    def decoder_receive(self):
        f = self.r(1)
        p = self.q(f + 8)
        raw = self.q(p + 56)
        fid = struct.unpack("<H", self.u.mem_read(f + 26, 2))[0]
        self.audio_events.append(["receive", fid])
        self.deliveries.append(
            dict(
                id=fid,
                timestamp=self.i(f + 28),
                body=bytes(self.u.mem_read(raw + 26, self.i(p + 52) - 26)).hex(),
            )
        )
        self.jump(0x76727C)

    def create_audio(self):
        p = self.alloc(4096)
        self.audio_frames[p] = dict(id=self.r(1), timestamp=self.r(2), size=0)
        self.active_audio = p
        self.ret(p)

    def audio_area(self):
        f = self.audio_frames[self.r(0) - 24]
        f["size"] = self.r(1)
        assert f["size"] <= 1024 * 1024
        f["data"] = self.alloc(f["size"] + 64)
        self.ret(f["data"])

    def audio_resize(self):
        self.audio_frames[self.r(0) - 24]["size"] = self.r(1)
        self.ret()

    def submit(self):
        f = self.audio_frames[self.r(1)]
        self.audio_events.append(["pcm", f["id"], f["timestamp"], f["size"]])
        self.ret()

    def hook(self, uc, address, size, data):
        if self.ready:
            labels = {
                0x7ADDD0: "start_lock",
                0x7ADF14: "pending",
                0x7A7EF8: "factory",
                0x7B12D0: "opus_ctor",
                0x7B1734: "raw_ctor",
                0x7670B4: "decoder_start",
                0x767160: "decoder_stop",
                0x7B16FC: "opus_stop",
                0x7B1838: "raw_decode",
                0x7B1414: "opus_decode",
                0x7ADFE0: "stop_lock",
                0x7B178C: "raw_start",
                0x7B134C: "opus_start",
                0x7C0E00: "close_audio",
            }
            if address in labels:
                entry = [labels[address]]
                if address == 0x7A7EF8:
                    entry += [self.r(1), self.r(2), self.r(3)]
                self.audio_events.append(entry)
            if address == 0x7ADE80:
                # Observe the original parsed object before the device call.
                # Codec selection itself is independently witnessed at factory.
                msg = self.u.reg_read(UC_ARM64_REG_X29) - 56
                bits = self.i(msg + 16)
                data = b""
                if bits & 1:
                    string = self.q(msg + 24)
                    tag = self.u.mem_read(string, 1)[0]
                    length = self.q(string + 8) if tag & 1 else tag >> 1
                    pointer = self.q(string + 16) if tag & 1 else string + 1
                    data = bytes(self.u.mem_read(pointer, length))
                self.audio_events.append(
                    [
                        "request",
                        self.i(msg + 32),
                        bool(bits & 4),
                        self.i(msg + 36),
                        self.i(c.CLIENT + 336),
                        self.i(msg + 40),
                        self.i(msg + 44),
                        data.hex(),
                    ]
                )
            if address == 0x7BEBE0:
                self.audio_events.append(["player_start", self.r(1), self.r(2)])
            if address == 0x7FBC98:
                self.audio_events.append(["delay", self.r(1), self.r(2)])
        name = self.plts.get(address, "")
        if name == "_ZN10CUtlBufferC1Ev":
            self.jump(self.symbols[name])
        elif name == "calloc":
            self.ret(self.alloc(self.r(0) * self.r(1)))
        elif name == "realloc":
            # Existing libc storage boundary: caller's old capacity is not
            # inferred here; libc/containers are audited separately as needed.
            raise AssertionError(f"Need realloc storage contract {self.r(1)}")
        elif name in (
            "pthread_condattr_init",
            "pthread_condattr_setclock",
            "pthread_condattr_destroy",
            "pthread_cond_init",
            "pthread_cond_destroy",
            "pthread_cond_signal",
            "pthread_cond_broadcast",
            "pthread_mutex_init",
            "pthread_mutex_destroy",
            "pthread_mutexattr_init",
            "pthread_mutexattr_settype",
            "pthread_mutexattr_destroy",
        ):
            self.ret(0)
        elif name == "pthread_self":
            self.ret(123)
        elif name in (
            "_ZN16SteamThreadTools7CThread5StartEm",
            "_ZN16SteamThreadTools7CThread4JoinEj",
        ):
            self.audio_events.append(
                ["thread_start" if "5Start" in name else "thread_join"]
            )
            self.ret(int(self.thread_ok) if "5Start" in name else 1)
        elif name.startswith("_ZN15AssertMsgHelper"):
            self.assertions.append(self.r(1))
            self.ret(1)
        elif name == "opus_multistream_decoder_create":
            self.audio_events.append(["opus_create", self.r(0), self.r(1)])
            self.jump(self.symbols[name])
        elif name == "__memset_chk":
            assert self.r(2) <= self.r(3)
            self.u.mem_write(self.r(0), bytes([self.r(1) & 255]) * self.r(2))
            self.ret(self.r(0))
        else:
            super().hook(uc, address, size, data)

    def control(self, kind, payload):
        raw = (
            struct.pack("<BBBBBHHI", 5, 0, 34, 12, 1, 0, 0, 900000)
            + bytes([kind])
            + payload
        )
        p, queue = self.alloc(max(4096, len(raw) + 64)), self.alloc(64)
        self.wq(p + 40, p + 64)
        self.wq(p + 56, p + 64)
        self.wi(p + 52, len(raw))
        self.u.mem_write(p + 64, raw)
        self.wq(c.CLIENT + 736, queue)
        self.wq(queue, p)
        self.wi(c.CLIENT + 720, 0)
        self.wi(c.CLIENT + 724, 0)
        self.wi(c.CLIENT + 728, 0)
        self.callbacks[0xC0A380] = lambda: self.ret(2)
        self.callbacks[0xC0A390] = lambda: self.ret(1)
        self.call(0x7A6368, c.CLIENT)

    def media(self, channel, fid, timestamp, sent, received, payload):
        raw = struct.pack("<BBBBBHHI", 5, 0, 34, 12, channel, 0, 0, sent)
        raw += (
            b"\x01"
            + struct.pack("<HIHI", fid, timestamp, 0, 0)
            + bytes.fromhex(payload)
        )
        p, body = self.alloc(4096), self.alloc(max(4096, len(raw) + 64))
        self.wq(p + 40, body)
        self.wq(p + 56, body)
        self.wi(p + 52, len(raw))
        self.wi(p + 28, received)
        self.wi(p + 32, received)
        self.u.mem_write(body, raw)
        self.call(0x7ACFA8, c.CLIENT, self.connection, p)

    def snapshot(self):
        decoder = self.q(c.CLIENT + 32)
        kind = None
        if decoder:
            vt = self.q(decoder)
            kind = (
                "opus" if vt == self.symbols["_ZTV18CStreamDecoderOpus"] + 16 else "raw"
            )
        details = None
        if decoder:
            first, last = self.i(decoder + 364), self.i(decoder + 368)
            count = 0 if first & 0x80000000 else ((last - first) & 0x7FFFFFFF) + 1
            details = dict(
                kind=kind,
                active=bool(self.u.mem_read(decoder + 24, 1)[0]),
                threads=bool(self.u.mem_read(decoder + 100, 1)[0]),
                queue=count,
                queue_bytes=self.i(decoder + 384),
            )
            if kind == "opus":
                details.update(
                    codec=bool(self.q(decoder + 400)),
                    rate=self.i(decoder + 392),
                    channels=self.i(decoder + 396),
                )
        queued = []
        if decoder and details["queue"]:
            mask, first = self.i(decoder + 360), self.i(decoder + 364)
            storage = self.q(decoder + 376)
            for index in range(details["queue"]):
                frame = self.q(storage + ((first + index) & mask) * 8)
                packet = self.q(frame + 8)
                body = self.q(packet + 56)
                queued.append(
                    dict(
                        id=struct.unpack("<H", self.u.mem_read(frame + 26, 2))[0],
                        timestamp=self.i(frame + 28),
                        body=bytes(
                            self.u.mem_read(body + 26, self.i(packet + 52) - 26)
                        ).hex(),
                    )
                )
        result = dict(
            phase=self.i(c.CLIENT + 256),
            paused=bool(self.u.mem_read(c.CLIENT + 19, 1)[0]),
            channel=self.u.mem_read(c.CLIENT + 625, 1)[0],
            decoder=details,
            format=[self.i(self.player + o) for o in (16, 20, 24, 28)],
            pending=self.pending(),
            delays={str(k): self.i(v + 28) for k, v in sorted(self.channels.items())},
            queued=queued,
            events=self.audio_events,
            received=self.deliveries,
            assertions=self.assertions,
        )
        self.audio_events = []
        self.deliveries = []
        self.assertions = []
        return result


def schema(binary):
    from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

    d = descriptor_pb2.FileDescriptorProto.FromString(
        binary[0x3E5474 : 0x3E5474 + 21560]
    )
    pool = descriptor_pool.DescriptorPool()
    pool.Add(d)

    def message(name, **fields):
        return message_factory.GetMessageClass(pool.FindMessageTypeByName(name))(
            **fields
        )

    return message


def schedules(message):
    raw = message(
        "CAudioFormat", format=1, frequency=48000, channels=2
    ).SerializeToString()

    def start(codec=None, channel=3, rate=48000, channels=2, data=None):
        fields = dict(channel=channel, frequency=rate, channels=channels)
        if codec is not None:
            fields["codec"] = codec
        if data is not None:
            fields["codec_data"] = data
        return [
            "C",
            50,
            message("CStartAudioDataMsg", **fields).SerializeToString().hex(),
        ]

    def media(channel=3, fid=1, codec=3):
        return [
            "M",
            channel,
            fid,
            1100000 + fid,
            1100010 + fid,
            1100020 + fid,
            "00000000" if codec == 1 else "f0fffe",
        ]

    stop = ["C", 51, ""]
    plans = []
    for fallback in (0, 1, 3):
        for codec in (None, 0, 1, 2, 3):
            chosen = fallback if codec is None else codec
            plans.append(
                dict(
                    name=f"presence_{fallback}_{codec}",
                    fallback=fallback,
                    actions=[
                        media(codec=chosen),
                        start(codec, data=raw if chosen == 1 else None),
                        media(fid=2, codec=chosen),
                        stop,
                    ],
                )
            )
    plans += [
        dict(
            name="player_failure_then_retry",
            actions=[
                media(),
                ["P", 0],
                start(3),
                media(fid=2),
                ["P", 1],
                start(3),
                media(fid=3),
                stop,
            ],
        ),
        dict(
            name="replacement",
            actions=[
                start(3),
                media(),
                start(1, data=raw),
                media(fid=2, codec=1),
                stop,
            ],
        ),
        dict(
            name="replacement_player_failure",
            actions=[start(3), media(), ["P", 0], start(3, 4), media(4, 2), stop],
        ),
        dict(
            name="channel_change",
            actions=[
                media(3),
                media(4, 2),
                start(3, 4),
                media(3, 3),
                start(3, 3),
                stop,
            ],
        ),
        dict(
            name="malformed_start", actions=[start(3), ["C", 50, "ff"], media(), stop]
        ),
        dict(
            name="missing_required_channel",
            actions=[start(3), ["C", 50, ""], media(), stop],
        ),
        dict(name="malformed_stop", actions=[start(3), ["C", 51, "ff"], media(), stop]),
        dict(name="stop_empty", actions=[stop, stop, start(3), stop, media()]),
        dict(
            name="raw_bad_data",
            source_only="Raw parser ignores failure; unsafe/zero decoder format is not safe native PCM",
            actions=[start(1, data=b"\xff"), stop],
        ),
        dict(
            name="raw_conflicting_format",
            source_only="Device/decoder rate/channel boundaries; no actual SDL device is proved",
            actions=[start(1, rate=24000, channels=1, data=raw), stop],
        ),
        dict(
            name="codec_create_failure",
            source_only="Controlled player accepts invalid rate; actual embedded Opus fails, hardware start reachability unproved",
            actions=[start(3, rate=12345), media(), stop],
        ),
    ]
    for phase, paused in (
        (0, 0),
        (1, 0),
        (2, 0),
        (3, 0),
        (4, 0),
        (5, 0),
        (6, 0),
        (6, 1),
        (7, 0),
    ):
        plans.append(
            dict(
                name=f"phase_{phase}_{paused}",
                actions=[
                    media(),
                    ["Q", phase, paused],
                    start(3),
                    ["Q", 6, 0],
                    media(fid=2),
                    stop,
                ],
            )
        )
    # Real incoming peer config establishes the member used by missing codec.
    peer = message(
        "CNegotiationSetConfigMsg",
        config=dict(selected_audio_codec=1, selected_video_codec=4),
    ).SerializeToString()
    plans.append(
        dict(
            name="peer_config_fallback",
            actions=[
                ["Q", 4, 0],
                ["C", 4, peer.hex()],
                ["Q", 6, 0],
                start(data=raw),
                media(codec=1),
                stop,
            ],
        )
    )
    for codec in (1, 3):
        plans.append(
            dict(
                name=f"thread_start_failure_{codec}",
                worker_failure=True,
                threads_only=True,
                actions=[
                    media(codec=codec),
                    start(codec, data=raw if codec == 1 else None),
                    media(fid=2, codec=codec),
                    stop,
                ],
            )
        )
    return plans


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == c.SHA
    message = schema(binary)
    cases = []
    for threads in (False, True):
        for inp in schedules(message):
            if inp.get("threads_only") and not threads:
                continue
            r = Audio(binary, threads)
            r.thread_ok = not inp.get("worker_failure", False)
            initial = message(
                "CNegotiatedConfig",
                selected_audio_codec=inp.get("fallback", 3),
                selected_video_codec=4,
            )
            assert r.parse(
                c.CLIENT + 288, initial.SerializeToString(), "CNegotiatedConfig"
            )
            states = []
            for op, *args in inp["actions"]:
                if op == "C":
                    r.control(args[0], bytes.fromhex(args[1]))
                elif op == "M":
                    r.media(*args)
                elif op == "P":
                    r.player_ok = bool(args[0])
                elif op == "Q":
                    r.wi(c.CLIENT + 256, args[0])
                    r.b(c.CLIENT + 19, args[1])
                else:
                    raise AssertionError(op)
                observed = r.snapshot()
                if op == "C" and args[0] == 51:
                    assert not any(e[0] == "close_audio" for e in observed["events"])
                states.append(observed)
            cases.append(dict(input={**inp, "threads": threads}, observed=states))
    return dict(binary_sha256=c.SHA, boundary=__doc__, cases=cases)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--write", type=Path)
    p.add_argument("--check", type=Path)
    a = p.parse_args()
    result = audit(a.binary.read_bytes())
    if a.write:
        a.write.write_text(json.dumps(result, indent=2) + "\n")
    if a.check:
        assert result == json.loads(a.check.read_text())
    print(
        f"Official audio startup: {len(result['cases'])} cases/{sum(len(x['observed']) for x in result['cases'])} states"
    )


if __name__ == "__main__":
    main()
