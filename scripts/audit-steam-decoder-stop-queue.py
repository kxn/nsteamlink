#!/usr/bin/env python3
"""Original audio queue consumption at entry, codec and idle Stop boundaries.

Actual Audio Start protobuf/control/factory/constructors, Frame/OnDataPacket,
OnReceiveFrame/FIFO/copy/Release/Purge, RunDecodeLoop, Opus and StopDecoding run.
CPU/stack interleaving preserves shared heap at codec/Wait/Join API gates.
Device open, OS threads/event/locks/Join, packet refs, storage/allocation and
PCM submit are explicit adapters; Source PCM bytes/acoustics, OS concurrency,
natural threading choice, network loss, device timing/peak/ABI are not proved.
"""
import argparse
from collections import Counter
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import types

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]


def module(name, file):
    s = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


a = module("queue_audio", "audit-steam-audio-start.py")
stim = module("queue_stimuli", "decoder-stop-stimuli.py")
c = a.c
PC = c.BASE["UC_ARM64_REG_PC"]


class Queue(a.Audio):
    def __init__(self, binary, plan):
        self.enabled = False
        self.plan = plan
        self.blocked = None
        self.gate_used = self.consumer_finished = False
        self.current_input = None
        self.consumed, self.decoded, self.outputs, self.released, self.thinks = (
            [],
            [],
            [],
            [],
            [],
        )
        self.events = []
        self.hits = Counter()
        super().__init__(binary, threads=True)
        self.decoder = 0
        self.entries = {self.symbols[name] for name in stim.FUNCTIONS}
        self.enabled = True
        self.wi(c.CLIENT + 256, 6)
        self.control(
            50,
            a.schema(binary)(
                "CStartAudioDataMsg", channel=3, codec=3, frequency=48000, channels=2
            ).SerializeToString(),
        )
        self.decoder = self.q(c.CLIENT + 32)
        assert self.decoder and self.q(self.decoder + 400)
        assert self.i(self.decoder + 392) == 48000 and self.i(self.decoder + 396) == 2

    def active(self):
        return bool(self.decoder and self.u.mem_read(self.decoder + 24, 1)[0])

    def queue(self):
        d = self.decoder
        first, last = self.i(d + 364), self.i(d + 368)
        if first & 0x80000000:
            return []
        assert 0 <= last - first < 32
        base, mask = self.q(d + 376), self.i(d + 360)
        return [
            int.from_bytes(
                self.u.mem_read(self.q(base + ((i & mask) * 8)) + 26, 2), "little"
            )
            for i in range(first, last + 1)
        ]

    def submit(self):
        f = self.audio_frames[self.r(1)]
        assert f["size"] % 8 == 0
        self.outputs.append([f["id"] & 0xFFFF, f["timestamp"], f["size"] // 8])
        super().submit()

    def pause(self, reason):
        self.gate_used = True
        self.blocked = reason
        self.u.emu_stop()

    def hook(self, u, pc, size, data):
        if self.enabled:
            if pc in self.entries:
                self.hits[pc] += 1
            name = self.plts.get(pc, "")
            if pc == self.symbols["_ZN14IStreamDecoder13RunDecodeLoopEv"]:
                if self.plan["stage"] == "entry" and not self.gate_used:
                    self.pause("gate")
                    return
            if pc == 0x7B1414:
                f = self.r(1)
                self.current_input = int.from_bytes(u.mem_read(f + 26, 2), "little")
                self.consumed.append(
                    [self.current_input, self.i(f + 28), int(self.active())]
                )
            if pc == 0x767560:
                self.thinks.append(int(self.active()))
            if pc == 0x7675A0:
                self.released.append(
                    int.from_bytes(u.mem_read(self.r(0) + 26, 2), "little")
                )
            if pc in (0x7B15B4, 0x7B168C):
                assert self.decoded
                self.decoded[-1][-1] = self.r(0) & 0xFFFFFFFF
            if name == "opus_multistream_decode_float":
                if (
                    self.plan["stage"] == "decode"
                    and not self.gate_used
                    and self.current_input == self.plan["initial"][-1]["id"]
                ):
                    self.pause("gate")
                    return
                f = self.audio_frames[self.active_audio]
                self.decoded.append(
                    [
                        f["id"] & 0xFFFF,
                        f["timestamp"],
                        self.r(4),
                        int(bool(self.r(1))),
                        self.r(5),
                        -1,
                    ]
                )
                self.jump(self.symbols[name])
                return
            if name == "_ZN16SteamThreadTools12CThreadEvent3SetEv":
                self.ret(1)
                return
            if name == "_ZN16SteamThreadTools17CThreadSyncObject4WaitEj":
                assert self.r(1) == 0xFFFFFFFF
                if self.plan["stage"] == "think" and not self.gate_used:
                    self.pause("gate")
                    return
                self.events.append("wait_return")
                self.ret(1)
                return
            if name == "_ZN16SteamThreadTools7CThread4JoinEj":
                assert self.r(1) == 0xFFFFFFFF and not self.active()
                if not self.consumer_finished:
                    self.events.append("join_enter")
                    self.blocked = "join"
                    u.emu_stop()
                    return
                self.events.append("join_return")
                self.ret(1)
                return
            if pc == 0x76743C:
                assert self.consumer_finished
                self.events.append("purge")
            if pc == 0x7B16FC:
                assert self.consumer_finished
                self.events.append("stop_codec")
            if name in ("ThreadInterlockedIncrement", "ThreadInterlockedDecrement"):
                p = self.r(0)
                value = (
                    self.i(p) + (1 if name.endswith("Increment") else -1)
                ) & 0xFFFFFFFF
                self.wi(p, value)
                self.ret(value)
                return
        super().hook(u, pc, size, data)

    def feed(self, frame):
        stamp = frame["timestamp"]
        self.media(3, frame["id"], stamp, stamp + 100, stamp + 400, frame["payload"])

    def save(self):
        return self.u.context_save(), bytes(self.u.mem_read(0x30000000, 0x100000))

    def restore(self, state):
        self.u.mem_write(0x30000000, state[1])
        self.u.context_restore(state[0])

    def execute(self, entry=None):
        if entry is not None:
            self.u.reg_write(c.SP, 0x300FF000)
            self.u.reg_write(c.LR, c.STOP)
            self.u.reg_write(c.X0, self.decoder)
        self.blocked = None
        self.u.emu_start(
            self.u.reg_read(PC) if entry is None else entry, c.STOP + 4, count=30000000
        )
        assert self.blocked or self.u.reg_read(PC) == c.STOP
        return self.blocked

    def run(self):
        for f in self.plan["initial"]:
            self.feed(f)
        assert self.execute(0x766D50) == "gate"
        worker = self.save()
        for f in self.plan["pending"]:
            self.feed(f)
        admitted = self.queue()
        assert self.execute(0x767160) == "join"
        stopping = self.save()
        self.feed(self.plan["after_stop"])
        assert self.queue() == admitted
        self.restore(worker)
        assert self.execute() is None
        self.consumer_finished = True
        self.events.append("consumer_return")
        remaining = self.queue()
        self.restore(stopping)
        assert self.execute() is None
        assert (
            not self.queue() and not self.q(self.decoder + 400) and not self.assertions
        )
        assert all(s[-1] == 480 for s in self.decoded)
        return dict(
            input=self.plan,
            admitted=admitted,
            remaining=remaining,
            consumed=self.consumed,
            decoded=self.decoded,
            outputs=self.outputs,
            released=self.released,
            thinks=self.thinks,
            events=self.events,
            codec_after=False,
            function_hits={str(k): v for k, v in self.hits.items()},
        )


def helpers():
    found = {}

    def visit(m):
        p = Path(getattr(m, "__file__", "")).resolve()
        if p in found or p.parent != ROOT / "scripts":
            return
        found[p] = hashlib.sha256(p.read_bytes()).hexdigest()
        for v in vars(m).values():
            if isinstance(v, types.ModuleType):
                visit(v)

    visit(a)
    visit(stim)
    for f in ("audit-steam-decoder-stop-queue.py", "audit-steam-client-fec-policy.py"):
        p = ROOT / "scripts" / f
        found[p] = hashlib.sha256(p.read_bytes()).hexdigest()
    return {str(p.relative_to(ROOT)): h for p, h in sorted(found.items())}


def identities(binary):
    e = ELFFile(io.BytesIO(binary))
    syms = {s.name: s for s in e.get_section_by_name(".dynsym").iter_symbols()}
    out = []
    for name in stim.FUNCTIONS:
        s = syms[name]
        at, size = s["st_value"], s["st_size"]
        seg = next(
            p
            for p in e.iter_segments()
            if p["p_type"] == "PT_LOAD"
            and p["p_vaddr"] <= at < at + size <= p["p_vaddr"] + p["p_filesz"]
        )
        code = seg.data()[at - seg["p_vaddr"] : at - seg["p_vaddr"] + size]
        out.append(
            dict(
                name=name,
                address=at,
                size=size,
                sha256=hashlib.sha256(code).hexdigest(),
            )
        )
    return out


def main():
    if not __debug__:
        raise SystemExit("Original audit requires Python assertions")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == c.SHA
    initial = helpers()
    cases = []
    for plan in stim.plans():
        r = Queue(binary, plan).run()
        cases.append(r)
        print(
            plan["name"],
            "consumed",
            [x[0] for x in r["consumed"]],
            "remaining",
            r["remaining"],
            flush=True,
        )
    assert helpers() == initial
    args.output.write_text(
        json.dumps(
            dict(
                binary_sha256=c.SHA,
                scope=__doc__,
                descriptor=stim.DESCRIPTOR,
                functions=identities(binary),
                helpers=initial,
                cases=cases,
            ),
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
