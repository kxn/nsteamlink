#!/usr/bin/env python3
"""Execute original threaded audio Stop while a recovery DecodeFrame is paused.

CPU/register/stack contexts alternate at declared codec and Join API terminals;
original shared memory persists. OS scheduling/Join success, event signal and
empty FIFO purge are adapters. The decoder active/thread flags and actual Opus
vtable are controlled boundary inputs. Original OnStreamStopped/DecodeFrame/
StopDecoding execute; this does not prove a natural platform enables threading.
Codec decode returns480 exactly as in the policy audit; no Source DSP, PCM,
wall-clock latency, real worker, transport, device or peak is measured here.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "stop_gap", ROOT / "scripts/audit-steam-audio-gap-policy.py"
)
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
c = g.opus.c
g.FUNCTIONS += ("_ZN14IStreamDecoder15OnStreamStoppedEv",)
PAUSES = (0, 16384, 32767, 32768)


class Stop(g.Policy):
    def __init__(self, binary):
        self.pause_index = None
        self.blocked = None
        self.resume_codec = self.consumer_finished = False
        self.events = []
        super().__init__(binary)
        # Declare a threaded, active decoder at the DecodeFrame boundary. Only
        # CPU/stack switch on pause/resume; no recovery state is written here.
        self.wq(self.decoder, self.symbols["_ZTV18CStreamDecoderOpus"] + 16)
        self.b(self.decoder + 24, 1)
        self.b(self.decoder + 100, 1)

    def hook(self, u, pc, size, data):
        name = self.plts.get(pc, "")
        if (
            name == "opus_multistream_decode_float"
            and self.pause_index is not None
            and self.count == self.pause_index
            and not self.resume_codec
        ):
            self.blocked = "codec"
            u.emu_stop()
            return
        if name == "_ZN16SteamThreadTools12CThreadEvent3SetEv":
            assert self.r(0) == self.decoder + 192
            self.events.append(["signal", self.is_active(), self.codec_alive()])
            self.ret(1)
            return
        if name == "_ZN16SteamThreadTools7CThread4JoinEj":
            assert self.r(0) == self.decoder + 104 and self.r(1) == 0xFFFFFFFF
            if not self.consumer_finished:
                self.events.append(["join_enter", self.count, self.codec_alive()])
                self.blocked = "join"
                u.emu_stop()
                return
            self.events.append(["join_return", self.count, self.codec_alive()])
            self.ret(1)
            return
        if name == "_ZN17CStreamFrameQueueI22CReleasableStreamFrameE5PurgeEv":
            assert self.r(0) == self.decoder + 184 and self.consumer_finished
            self.events.append(["empty_purge", self.count, self.codec_alive()])
            self.ret()  # Explicit empty-queue API boundary, not original Purge.
            return
        if pc == 0x7B16FC:
            assert self.consumer_finished and not self.is_active()
            self.events.append(["stop_codec", self.count, self.codec_alive()])
        super().hook(u, pc, size, data)

    def is_active(self):
        return bool(self.u.mem_read(self.decoder + 24, 1)[0])

    def codec_alive(self):
        return bool(self.q(self.decoder + 400))

    def save(self):
        return self.u.context_save(), bytes(self.u.mem_read(0x30000000, 0x100000))

    def restore(self, state):
        self.u.mem_write(0x30000000, state[1])
        self.u.context_restore(state[0])

    def execute(self, entry=None, *params):
        if entry is not None:
            self.u.reg_write(c.SP, 0x300FF000)
            self.u.reg_write(c.LR, c.STOP)
            for i, value in enumerate(params):
                self.u.reg_write(c.X0 + i, value)
        self.blocked = None
        self.u.emu_start(
            self.u.reg_read(g.UC_ARM64_REG_PC) if entry is None else entry,
            c.STOP + 4,
            count=30000000,
        )
        assert self.blocked or self.u.reg_read(g.UC_ARM64_REG_PC) == c.STOP
        return self.blocked

    def run(self, pause_index):
        self.start()
        self.feed(0, 1100000, bytes.fromhex("f0fffe"))
        self.reset_observer()
        self.pause_index = pause_index
        frame, packet, raw = (self.alloc(4096) for _ in range(3))
        self.wq(frame + 8, packet)
        self.wq(packet + 56, raw)
        self.wi(packet + 52, 16)
        self.u.mem_write(raw, bytes(13) + bytes.fromhex("f0fffe"))
        self.u.mem_write(frame + 26, g.struct.pack("<HI", 32769, 1101000))
        assert self.execute(0x7B1414, self.decoder, frame) == "codec"
        consumer = self.save()
        assert self.execute(0x767160, self.decoder) == "join"
        stopping = self.save()
        assert not self.is_active() and self.codec_alive() and self.count == pause_index
        self.restore(consumer)
        self.resume_codec = True
        assert self.execute() is None
        self.consumer_finished = True
        state = self.snapshot_policy()
        assert state["steps"] == 32769 and not self.is_active() and self.codec_alive()
        self.restore(stopping)
        assert self.execute() is None
        assert not self.codec_alive() and not self.is_active() and not self.assertions
        assert self.entries == set(self.hits)
        return dict(
            pause_index=pause_index,
            recovery=state,
            events=self.events,
            active_after=False,
            codec_after=False,
            function_hits={str(k): v for k, v in self.hits.items()},
            state_write_pcs={str(k): v for k, v in self.state_writes.items()},
        )


def helpers():
    return g.helpers() | {"scripts/audit-steam-audio-stop.py": g.digest(Path(__file__))}


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == g.SHA
    initial = helpers()
    cases = []
    for pause in PAUSES:
        cases.append(Stop(binary).run(pause))
        print("stop at", pause, "completed", cases[-1]["recovery"]["steps"], flush=True)
    assert helpers() == initial
    return dict(
        binary_sha256=g.SHA,
        scope=__doc__,
        descriptor=g.stim.DESCRIPTOR,
        functions=g.identities(binary),
        helpers=initial,
        cases=cases,
    )


def main():
    if not __debug__:
        raise SystemExit("Original evidence audit requires Python assertions")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    args.output.write_text(json.dumps(audit(args.binary.read_bytes()), indent=2) + "\n")


if __name__ == "__main__":
    main()
