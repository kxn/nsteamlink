#!/usr/bin/env python3
"""Original video FIFO drains and calls OnThink/SDK after active is cleared.

Actual original constructors, Frame/copy/FIFO/Release, RunDecodeLoop,
DecodeFrame/OnThink/StopDecoding execute. SDK/JNI, NAL metadata, OS locks/events/
Join and storage/refcount primitives inherit the queue audit's explicit adapters.
Two controlled complete key frames use the same fixture bytes. CPU/stack
switching preserves shared heap at DecodeFrame and Join gates; no real OS
concurrency, codec pixels, natural transport/roles, performance or device proof.
"""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import types

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
s = importlib.util.spec_from_file_location(
    "video_queue", ROOT / "scripts/audit-steam-decoder-queue.py"
)
q = importlib.util.module_from_spec(s)
s.loader.exec_module(q)
c = q.r.c
PC = c.BASE["UC_ARM64_REG_PC"]


class Drain(q.Queue):
    def __init__(self, binary):
        self.final_ids = []
        self.enabled = False
        self.blocked = None
        self.finished = self.resumed = False
        self.consumed, self.events, self.sdk_payloads, self.complete = [], [], [], []
        super().__init__(binary)
        self.enabled = True
        self.action = 0

    def active_flag(self):
        return self.u.mem_read(self.video + 24, 1)[0]

    def hook(self, u, pc, size, data):
        if self.enabled:
            name = self.plts.get(pc, "")
            if pc == 0x7B2000:
                if not self.resumed:
                    self.blocked = "decode"
                    u.emu_stop()
                    return
                fid = int.from_bytes(u.mem_read(self.r(1) + 26, 2), "little")
                self.consumed.append(fid)
                self.events.append(["decode", fid, self.active_flag()])
            if pc == 0x7B24DC:
                self.events.append(["think", self.active_flag()])
            if pc == 0x7B103C:
                assert self.finished
                self.events.append(["stop_codec", self.active_flag()])
            if pc == 0x7B1088:
                self.final_ids.append(self.r(1) & 0xFFFF)
            if pc == 0xC0BAA0:
                self.complete.append([self.r(2) & 0xFFFF, self.r(3)])
            if name == "AMediaCodec_queueInputBuffer":
                body = bytes(u.mem_read(self.input + self.r(2), self.r(3)))
                self.sdk_payloads.append(
                    dict(
                        size=len(body),
                        sha256=hashlib.sha256(body).hexdigest(),
                        active=self.active_flag(),
                    )
                )
            if name == "_ZN16SteamThreadTools12CThreadEvent3SetEv":
                self.ret(1)
                return
            if name == "_ZN16SteamThreadTools7CThread4JoinEj":
                assert not self.active_flag() and self.r(1) == 0xFFFFFFFF
                if not self.finished:
                    self.events.append(["join_enter", 0])
                    self.blocked = "join"
                    u.emu_stop()
                    return
                self.events.append(["join_return", 0])
                self.ret(1)
                return
            if name == "_ZN16SteamThreadTools17CThreadSyncObject4WaitEj":
                self.events.append(["wait", self.r(1), self.active_flag()])
                self.ret(1)
                return
        super().hook(u, pc, size, data)

    def save(self):
        return self.u.context_save(), bytes(self.u.mem_read(0x30000000, 0x100000))

    def restore(self, state):
        self.u.mem_write(0x30000000, state[1])
        self.u.context_restore(state[0])

    def execute(self, entry=None):
        if entry is not None:
            self.u.reg_write(c.SP, 0x300FF000)
            self.u.reg_write(c.LR, c.STOP)
            self.u.reg_write(c.X0, self.video)
        self.blocked = None
        self.u.emu_start(
            self.u.reg_read(PC) if entry is None else entry, c.STOP + 4, count=30000000
        )
        assert self.blocked or self.u.reg_read(PC) == c.STOP
        return self.blocked

    def run(self, payload):
        self.b(self.video + 24, 1)
        self.b(self.video + 100, 1)
        for fid in (1, 2):
            self.queue(fid, fid, 24, payload)
        assert self.snapshot()["input_queue"]["ids"] == [1, 2]
        assert self.execute(0x766D50) == "decode"
        consumer = self.save()
        assert self.execute(0x767160) == "join"
        stopping = self.save()
        assert self.snapshot()["input_queue"]["ids"] == [2]
        self.restore(consumer)
        self.resumed = True
        assert self.execute() is None
        self.finished = True
        assert self.consumed == [1, 2] and not self.snapshot()["input_queue"]["ids"]
        self.restore(stopping)
        assert self.execute() is None and not self.assertions
        assert len(self.sdk_payloads) == 1 and self.sdk_payloads[0] == dict(
            size=len(payload), sha256=hashlib.sha256(payload).hexdigest(), active=0
        ), self.sdk_payloads
        assert self.final_ids == [2] and self.complete == [[1, 7]], (
            self.final_ids,
            self.complete,
        )
        return dict(
            consumed=self.consumed,
            events=self.events,
            sdk=self.sdk_payloads,
            complete=self.complete,
            final_ids=self.final_ids,
            queue_after=[],
            assertions=self.assertions,
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

    visit(q)
    for name in ("audit-steam-video-stop-drain.py", "audit-steam-client-fec-policy.py"):
        p = ROOT / "scripts" / name
        found[p] = hashlib.sha256(p.read_bytes()).hexdigest()
    return {str(p.relative_to(ROOT)): h for p, h in sorted(found.items())}


def identities(binary):
    e = ELFFile(io.BytesIO(binary))
    text = e.get_section_by_name(".text")
    code, base = text.data(), text["sh_addr"]
    return [
        dict(
            name=name,
            address=at,
            size=size,
            sha256=hashlib.sha256(code[at - base : at - base + size]).hexdigest(),
        )
        for name, at, size in [
            ("RunDecodeLoop", 0x766D50, 276),
            ("OnReceiveFrame", 0x76727C, 236),
            ("OnStreamStopped", 0x767160, 80),
            ("AddToTail", 0x767368, 212),
            ("DecodeFrame", 0x7B2000, 1244),
            ("OnThink", 0x7B24DC, 808),
            ("FinalDecode", 0x7B1088, 356),
        ]
    ]


def main():
    if not __debug__:
        raise SystemExit("Original audit requires Python assertions")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == c.SHA
    fixture = ROOT / "app/tests/fixtures/video/sequential.h264"
    payload = fixture.read_bytes()[:2204]
    initial = helpers()
    observed = Drain(binary).run(payload)
    assert helpers() == initial
    args.output.write_text(
        json.dumps(
            dict(
                binary_sha256=c.SHA,
                scope=__doc__,
                functions=identities(binary),
                helpers=initial,
                fixture=dict(
                    path=str(fixture.relative_to(ROOT)),
                    size=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                ),
                observed=observed,
            ),
            indent=2,
        )
        + "\n"
    )
    print(
        "PASS: original video drains1/2 and submits2204B for frame2 after active=false"
    )


if __name__ == "__main__":
    main()
