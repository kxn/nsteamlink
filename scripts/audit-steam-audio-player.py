#!/usr/bin/env python3
"""Execute official audio control -> real PCM Frames -> player jitter and pull.

Original control dispatch/parsing, factory, decoder, embedded Opus, CAudioFrame
creation/storage/accessors/completion, BOpenAudio, PutAudioFrame and jitter run.
The IStreamPlayer base constructor runs; CStreamPlayer UI/device-owner fields
start at controlled zero, volume=1 and decoding-thread flag=0. SDL device IO,
OS locks/thread scheduling, packet refcounts, libc storage and host sinf remain
adapters. No real Android audio device, UI producer or Steam session is proved.
"""

from pathlib import Path
import argparse
import base64
import ctypes
import ctypes.util
import hashlib
import importlib.util
import json
import struct
import zlib
from unicorn.arm64_const import UC_ARM64_REG_S0

p = Path(__file__).with_name("audit-steam-audio-start.py")
s = importlib.util.spec_from_file_location("audio", p)
a = importlib.util.module_from_spec(s)
s.loader.exec_module(a)


class Player(a.Audio):
    def __init__(self, binary, threads=False):
        self.io = []
        self.streams = {}
        self.quit_prefix = False
        self.quit_calls = []
        self.libm = ctypes.CDLL(ctypes.util.find_library("m"))
        self.libm.sinf.argtypes = [ctypes.c_float]
        self.libm.sinf.restype = ctypes.c_float
        super().__init__(binary, threads)
        self.callbacks.pop(0xC0F690)
        for address in (0xC0BA20, 0xC0BA50, 0xC0BA60):
            self.callbacks.pop(address)
        # SetPlayer asserts Idle. Execute the actual base ctor in that state,
        # then enter the controlled streaming phase used by these schedules.
        self.wi(a.c.CLIENT + 256, 0)
        self.call(0x7676A8, self.player, a.c.CLIENT)
        self.wi(a.c.CLIENT + 256, 6)
        assert not self.assertions
        self.wq(self.player, self.player_vt)
        self.wq(self.player_vt + 384, 0x767BC4)
        self.wq(self.player_vt + 104, 0x7B76E4)
        self.pcm = []
        self.pcm_size = 0
        self.output = []
        self.wi(self.player + 1304, 0x3F800000)
        cfg = a.schema(binary)(
            "CNegotiatedConfig", selected_audio_codec=3, selected_video_codec=4
        )
        assert self.parse(
            a.c.CLIENT + 288, cfg.SerializeToString(), "CNegotiatedConfig"
        )
        self.error = self.alloc(64)
        self.u.mem_write(self.error, b"controlled SDL open failure\0")

    def hook(self, uc, address, size, data):
        if self.ready and address == 0x7BF8D4:
            self.pcm_size = self.r(0)
        if self.ready and address == 0x7BF8EC:
            frame = self.q(self.player + 40)
            assert self.pcm_size <= 1024 * 1024
            raw = bytes(self.u.mem_read(self.r(0), self.pcm_size))
            self.pcm.append(
                dict(
                    id=struct.unpack("<H", self.u.mem_read(frame + 50, 2))[0],
                    timestamp=self.i(frame + 52),
                    data=base64.b64encode(zlib.compress(raw)).decode(),
                )
            )
        name = self.plts.get(address, "")
        if self.quit_prefix and name:
            self.quit_calls.append(name)
        if self.quit_prefix and name in (
            "_ZN19CVirtualHereManager11StopSharingEv",
            "SDL_SetWindowRelativeMouseMode",
            "SDL_DestroySurface",
            "SDL_RemoveEventWatch",
            "SDL_QuitSubSystem",
            "SDL_EnableScreenSaver",
        ):
            self.ret(
                1
            )  # Non-audio UI/USB terminal boundaries, no return-dependent audio gate.
        elif name == "strlen":
            self.ret(len(self.cstring(self.r(0)).encode()))
        elif name == "sinf":
            v = struct.unpack("<f", struct.pack("<I", uc.reg_read(UC_ARM64_REG_S0)))[0]
            uc.reg_write(
                UC_ARM64_REG_S0,
                struct.unpack("<I", struct.pack("<f", self.libm.sinf(v)))[0],
            )
            self.ret()
        elif name == "SDL_SetHint":
            self.io.append([name, self.cstring(self.r(0)), self.cstring(self.r(1))])
            self.ret(1)
        elif name == "SDL_OpenAudioDeviceStream":
            stream = self.alloc(64) if self.player_ok else 0
            if stream:
                self.streams[stream] = len(self.streams) + 1
            self.io.append(
                [
                    name,
                    bytes(self.u.mem_read(self.r(1), 12)).hex(),
                    self.streams.get(stream),
                    self.r(2),
                    self.r(3) == self.player,
                ]
            )
            self.ret(stream)
        elif name in ("SDL_GetAudioStreamDevice", "SDL_ResumeAudioDevice"):
            self.io.append([name])
            self.ret(1)
        elif name == "SDL_DestroyAudioStream":
            self.io.append([name, self.streams.get(self.r(0))])
            self.ret()
        elif name == "SDL_PutAudioStreamData":
            self.output.append(bytes(self.u.mem_read(self.r(1), self.r(2))))
            self.ret(1)
        elif name == "SDL_WasInit":
            self.ret(self.r(0) & 16 if self.r(0) else 16)
        elif name == "SDL_GetError":
            self.ret(self.error)
        else:
            super().hook(uc, address, size, data)

    def submit(self):
        self.jump(0x7BF8A0)

    def observe(self, label):
        snap = self.snapshot()
        j = self.q(self.player + 1320)
        value = dict(
            label=label,
            channel=snap["channel"],
            decoder=snap["decoder"],
            logical_format=snap["format"],
            requested=[self.i(self.player + x) for x in [1124, 1128, 1132]],
            stream=self.streams.get(self.q(self.player + 1104)),
            jitter=bool(j),
            queued=(self.i(j + 68) - self.i(j + 72)) % 16384 if j else None,
            jitter_channels=self.i(j + 56) if j else None,
            events=snap["events"],
            io=self.io,
            next_frame=struct.unpack("<H", self.u.mem_read(self.player + 32, 2))[0],
            first_frame=bool(self.u.mem_read(self.player + 34, 1)[0]),
            pcm=self.pcm,
            assertions=snap["assertions"],
            pending=snap["pending"],
        )
        if j:
            value["params"] = [self.i(j + 4 * i) for i in range(10)]
            value["ring_sha256"] = hashlib.sha256(
                bytes(self.u.mem_read(self.q(j + 80), 16384 * self.i(j + 56) * 4))
            ).hexdigest()
            value["jitter_state"] = {
                str(offset): self.i(j + offset)
                for offset in (
                    56,
                    60,
                    68,
                    72,
                    108,
                    112,
                    120,
                    124,
                    128,
                    132,
                    136,
                    4236,
                    4240,
                    4244,
                    4248,
                    4252,
                    4256,
                    4260,
                    4264,
                    4268,
                    4272,
                    4276,
                    4280,
                    4284,
                    4288,
                    4292,
                    4296,
                    4300,
                )
            }
            value["jitter_state"].update(
                priming=bool(self.u.mem_read(j + 104, 1)[0]),
                overrun=bool(self.u.mem_read(j + 116, 1)[0]),
            )
        else:
            value["params"] = None
            value["ring_sha256"] = None
            value["jitter_state"] = None
        value["output"] = [
            base64.b64encode(zlib.compress(v)).decode() for v in self.output
        ]
        self.output = []
        self.pcm = []
        self.io = []
        return value

    def quit_audio_prefix(self):
        actual = self.symbols["_ZTV13CStreamPlayer"] + 16
        self.wq(self.player_vt + 392, self.q(actual + 392))
        self.quit_prefix = True
        self.quit_calls = []
        self.u.reg_write(a.c.SP, 0x300FF000)
        self.u.reg_write(a.c.LR, a.c.STOP)
        self.u.reg_write(a.c.X0, self.player)
        # A declared observation boundary after original CloseAudio. Do not
        # synthesize a Quit return or claim the later video/UI teardown ran.
        self.u.emu_start(0x7C80CC, 0x7C842C, count=10000000)
        assert self.u.reg_read(a.c.BASE["UC_ARM64_REG_PC"]) == 0x7C842C
        self.quit_prefix = False
        return self.observe("quit_audio_prefix")


def schedules(message):
    def start(codec, rate=48000, channels=2, raw_rate=None, raw_channels=None):
        fields = dict(channel=3, codec=codec, frequency=rate, channels=channels)
        if codec == 1:
            fields["codec_data"] = message(
                "CAudioFormat",
                format=1,
                frequency=raw_rate or rate,
                channels=raw_channels or channels,
            ).SerializeToString()
        return [
            "C",
            50,
            message("CStartAudioDataMsg", **fields).SerializeToString().hex(),
        ]

    def frame(codec, fid=1, samples=64, channels=2):
        payload = (
            struct.pack(
                "<" + "h" * (samples * channels),
                *(((i * 257) % 65536) - 32768 for i in range(samples * channels)),
            )
            if codec == 1
            else bytes.fromhex("f0fffe")
        )
        return ["M", 3, fid, 1100000 + fid, 1100010 + fid, 1100020 + fid, payload.hex()]

    stop = ["C", 51, ""]
    close = ["X"]
    plans = []
    for codec, rates in [
        (1, (8000, 16000, 24000, 44100, 48000)),
        (3, (8000, 12000, 16000, 24000, 48000)),
    ]:
        for rate in rates:
            for channels in (1, 2):
                plans.append(
                    dict(
                        name=f"normal_{codec}_{rate}_{channels}",
                        actions=[
                            start(codec, rate, channels),
                            frame(codec, channels=channels),
                            stop,
                            ["A", 16],
                            start(codec, rate, channels),
                            frame(codec, 2, channels=channels),
                            stop,
                            close,
                        ],
                    )
                )
    for physical, logical in ((1, 2), (2, 1)):
        plans.append(
            dict(
                name=f"raw_geometry_{physical}_{logical}",
                actions=[
                    start(1, 24000, physical, 48000, logical),
                    frame(1, channels=logical),
                    stop,
                    ["A", 16],
                    close,
                ],
            )
        )
    for codec in (0, 2, 4, 5):
        plans.append(
            dict(
                name=f"unsupported_{codec}",
                actions=[start(3), frame(3), start(codec), frame(3, 2), stop, close],
            )
        )
    plans += [
        dict(
            name="device_failure_retry",
            actions=[
                start(3),
                frame(3),
                ["P", 0],
                start(3),
                frame(3, 2),
                stop,
                ["P", 1],
                start(3),
                frame(3, 3),
                stop,
                close,
            ],
        ),
        dict(
            name="codec_create_failure",
            actions=[start(3, 44100, 2), frame(3), stop, close],
        ),
        dict(
            name="malformed_controls",
            actions=[
                start(3),
                frame(3),
                ["C", 50, "ff"],
                ["C", 51, "ff"],
                frame(3, 2),
                stop,
                ["S"],
                close,
            ],
        ),
        dict(
            name="replacement",
            actions=[
                start(3),
                frame(3),
                start(1),
                frame(1, 2),
                start(3, 24000, 1),
                frame(3, 3, channels=1),
                stop,
                close,
            ],
        ),
        dict(
            name="pending_audio", actions=[frame(3), start(3), frame(3, 2), stop, close]
        ),
        dict(name="close_twice", actions=[start(1), frame(1), stop, close, close]),
        dict(
            name="opus_gap",
            actions=[
                start(3),
                frame(3),
                frame(3, 3),
                frame(3, 2),
                frame(3, 4),
                stop,
                close,
            ],
        ),
        dict(
            name="tail_playback",
            actions=[
                start(1),
                frame(1, 1, 4000),
                stop,
                ["A", 512],
                ["A", 512],
                ["A", 512],
                close,
            ],
        ),
    ]
    stimulus = json.loads(
        (Path(__file__).parent / "fixtures/steam-opus-recovery-input.json").read_text()
    )
    for inp in stimulus["cases"]:
        actions = [start(3, 48000, inp["channels"])]
        for fid in (0, 1, 2, 6, 7):
            actions.append(
                [
                    "M",
                    3,
                    fid,
                    1100000 + fid * 655,
                    1100010 + fid * 655,
                    1100020 + fid * 655,
                    inp["packets"][fid],
                ]
            )
        actions += [stop, ["A", 512], close]
        plans.append(dict(name=f"silk_recovery_{inp['channels']}", actions=actions))
    omitted = message(
        "CStartAudioDataMsg", channel=3, frequency=48000, channels=2
    ).SerializeToString()
    plans.append(
        dict(
            name="absent_codec_full_player",
            actions=[["C", 50, omitted.hex()], frame(3), stop, close],
        )
    )
    plans.append(
        dict(
            name="pending_and_changed_clock",
            actions=[
                frame(3),
                ["K", 20000],
                start(3),
                frame(3, 3),
                ["K", -10000],
                frame(3, 4),
                stop,
                ["A", 16],
                close,
            ],
        )
    )
    return plans


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == a.c.SHA
    message = a.schema(binary)
    cases = []
    for inp in schedules(message):
        r = Player(binary)
        states = []
        for op, *args in inp["actions"]:
            if op == "C":
                r.control(args[0], bytes.fromhex(args[1]))
            elif op == "M":
                r.media(*args)
            elif op == "P":
                r.player_ok = bool(args[0])
            elif op == "K":
                r.wi(r.connection + 848, args[0])
            elif op == "X":
                r.call(0x7C0E00, r.player)
            elif op == "S":
                r.call(0x7B76E4, r.player)
            elif op == "A":
                stream = r.q(r.player + 1104)
                assert stream
                r.call(0x7BFCA4, r.player, stream, args[0] * r.i(r.player + 1132) * 4)
            else:
                raise AssertionError(op)
            observed = r.observe(op)
            assert observed["assertions"] in ([], [606]), (
                inp["name"],
                op,
                observed["assertions"],
            )
            states.append(observed)
        cases.append(dict(input=inp, observed=states))
    r = Player(binary)
    r.control(
        50,
        message(
            "CStartAudioDataMsg", channel=3, codec=3, frequency=48000, channels=2
        ).SerializeToString(),
    )
    r.media(3, 1, 1100001, 1100011, 1100021, "f0fffe")
    r.control(51, b"")
    before = r.observe("before_quit_audio_prefix")
    after = r.quit_audio_prefix()
    assert before["stream"] == 1 and before["queued"] == 480
    assert after["stream"] is None and not after["jitter"]
    return dict(
        binary_sha256=a.c.SHA,
        boundary=__doc__,
        cases=cases,
        source_only_quit_audio_prefix=dict(
            scope="Actual Quit entry through 0x7c842c after CloseAudio; UI/USB adapters, zero UI/thread-owner fields; no whole-Quit/outer owner proof",
            before=before,
            after=after,
            calls=r.quit_calls,
        ),
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--write", type=Path)
    p.add_argument("--check", type=Path)
    args = p.parse_args()
    result = audit(args.binary.read_bytes())
    if args.write:
        args.write.write_text(json.dumps(result, indent=2) + "\n")
    if args.check:
        assert result == json.loads(args.check.read_text())
    print(
        f"Official audio control/PCM/player path: {len(result['cases'])} cases/{sum(len(c['observed']) for c in result['cases'])} states"
    )


if __name__ == "__main__":
    main()
