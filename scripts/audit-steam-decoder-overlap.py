#!/usr/bin/env python3
"""Run original decoder and persistent auto-reset event while SDK input is paused.

Original FIFO/copy, decoder, CThreadEvent Set, CThreadSyncObject Wait and Android
submission execute. A paused SDK syscall gives the driver a producer opportunity:
save all CPU registers and stack, execute original OnReceiveFrame calls, restore
only CPU/stack, then resume the same consumer. Heap/FIFO/event mutations persist.
The libc/JNI/SDK/NAL terminals are inherited; pthread mutex/condition creation and
signals are OS terminals. Timed cond wait returns ETIMEDOUT; idle cond wait is an
observation stop without changing active/event state. No physical elapsed SDK
latency, kernel concurrency, Steam producer or pixels are claimed. Port queue
bounds are explicit input projections, never an official drop policy.
"""
import importlib.util
import json
import hashlib
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_PC

root = Path(__file__).resolve().parents[1]
sp = importlib.util.spec_from_file_location(
    "ident", root / "scripts/audit-steam-decoder-identity.py"
)
m = importlib.util.module_from_spec(sp)
sp.loader.exec_module(m)
c = m.p.q.r.c


class Slow(m.Identity):
    def __init__(self, binary):
        self.thinks = 0
        self.spurious = False
        self.wake_result = 0
        self.enabled = False
        self.pass_sdk = False
        self.blocked = None
        self.os_waits = []
        self.wait_calls = []
        self.last_delay = None
        super().__init__(binary)
        self.action = 0
        self.enabled = True

    def hook(self, u, pc, size, data):
        name = self.plts.get(pc, "")
        if self.enabled:
            if pc == 0x7B24DC:
                self.thinks += 1
            if name == "AMediaCodec_queueInputBuffer":
                if not self.pass_sdk:
                    self.blocked = "sdk"
                    u.emu_stop()
                    return
                self.pass_sdk = False
            elif name == "_ZN16SteamThreadTools17CThreadSyncObject4WaitEj":
                self.last_delay = self.r(1) & 0xFFFFFFFF
                self.wait_calls.append(
                    [self.last_delay, int(self.u.mem_read(self.r(0) + 110, 1)[0])]
                )
                self.jump(0x90D124)
                return
            elif name in ("pthread_cond_wait", "pthread_cond_timedwait"):
                if self.spurious:
                    self.spurious = False
                    self.ret(self.wake_result)
                    return
                self.os_waits.append(self.last_delay)
                if name == "pthread_cond_wait":
                    self.blocked = "idle"
                    u.emu_stop()
                    return
                self.ret(110)
                return
            elif name == "clock_gettime":
                import struct

                self.u.mem_write(self.r(1), struct.pack("<qq", 15, 0))
                self.ret(0)
                return
        super().hook(u, pc, size, data)

    def paused(self, fn):
        context = self.u.context_save()
        stack = bytes(self.u.mem_read(0x30000000, 0x100000))
        try:
            return fn()
        finally:
            self.u.mem_write(0x30000000, stack)
            self.u.context_restore(context)

    def run(self, initial, injections, spurious=False, after_idle=None, wake_result=0):
        self.wake_result = wake_result
        for args in initial:
            self.queue_stamped(*args[:4], bytes.fromhex(args[4]))
        self.u.reg_write(c.SP, 0x300FF000)
        self.u.reg_write(c.LR, c.STOP)
        self.u.reg_write(c.X0, self.video)
        pc = 0x766D50
        gates = []
        idle_input_sent = False
        while True:
            self.blocked = None
            self.u.emu_start(pc, c.STOP + 4, count=30000000)
            pc = self.u.reg_read(UC_ARM64_REG_PC)
            assert self.blocked in ("sdk", "idle"), hex(pc)
            if self.blocked == "idle":
                if after_idle and not idle_input_sent:

                    def deliver_idle():
                        for args in after_idle:
                            self.queue_stamped(*args[:4], bytes.fromhex(args[4]))

                    self.paused(deliver_idle)
                    idle_input_sent = True
                    self.spurious = True  # Return from the already entered OS wait.
                    continue
                break
            n = len(gates)
            payload_digest = hashlib.sha256(
                bytes(self.u.mem_read(self.input + self.r(2), self.r(3)))
            ).hexdigest()

            def inject():
                for args in injections[n] if n < len(injections) else []:
                    self.queue_stamped(*args[:4], bytes.fromhex(args[4]))
                state = self.observe()
                return dict(
                    id=self.decode_id,
                    payload=payload_digest,
                    thinks=self.thinks,
                    queue=self.snapshot()["input_queue"]["ids"],
                    tasks=self.tasks(),
                    player=state["player"],
                    flow=m.p.flow_hashes(state["flow"]),
                    dequeued=list(self.dequeued),
                    waits=list(self.os_waits),
                )

            gates.append(self.paused(inject))
            self.pass_sdk = True
            assert len(gates) < 20
        if spurious:
            self.spurious = True
            self.blocked = None
            self.u.emu_start(pc, c.STOP + 4, count=30000000)
            assert self.blocked == "idle"

        def observe_end():
            state = self.observe()
            return dict(
                thinks=self.thinks,
                player=state["player"],
                tasks=self.tasks(),
                flow=m.p.flow_hashes(state["flow"]),
                dequeued=list(self.dequeued),
                waits=list(self.os_waits),
                strict=state["strict"],
                soft=state["soft"],
                request=state["request"],
                body=state["body"],
                queue=self.snapshot()["input_queue"]["ids"],
                closed=False,
            )

        end = self.paused(observe_end)
        assert not self.assertions
        return dict(
            gates=gates, end=end, wait_calls=self.wait_calls, os_waits=self.os_waits
        )


def cases(raw):
    def f(fid, seq, flags=8, payload=raw, stamp=None):
        return [
            fid,
            seq,
            flags,
            1000000 + fid * 100 if stamp is None else stamp,
            payload.hex(),
        ]

    rows = [
        dict(
            name="interrupted_idle_wake",
            initial=[f(1, 1, 24)],
            waves=[],
            spurious=True,
            wake_result=4,
        ),
        dict(name="initial_single_image", initial=[f(1, 1, 24)], waves=[]),
        dict(
            name="input_after_idle",
            initial=[f(1, 1, 24)],
            waves=[],
            after_idle=[f(2, 2)],
            idle_gate=1,
        ),
        dict(name="spurious_idle_wake", initial=[f(1, 1, 24)], waves=[], spurious=True),
        dict(name="initial_two_images", initial=[f(1, 1, 24), f(2, 2)], waves=[]),
        dict(
            name="initial_three_images",
            initial=[f(1, 1, 24), f(2, 2), f(3, 3)],
            waves=[],
        ),
        dict(
            name="arrive_during_submit",
            initial=[f(1, 1, 24)],
            waves=[[f(2, 2), f(3, 3)]],
        ),
        dict(
            name="new_key_replaces_queued_key",
            initial=[f(1, 1, 24)],
            waves=[[f(2, 2, 24), f(3, 3, 24)]],
        ),
        dict(
            name="split_after_submit",
            initial=[f(1, 1, 24)],
            waves=[[f(2, 2, 16, raw[:1102]), f(2, 3, 8, raw[1102:])]],
        ),
        dict(
            name="unfinished_after_submit",
            initial=[f(1, 1, 24)],
            waves=[[f(2, 2, 16, raw[:1102])]],
        ),
        dict(
            name="repeated_id_inflight",
            initial=[f(1, 1, 24)],
            waves=[[f(1, 2, 24, stamp=1000200)]],
        ),
        dict(
            name="continuous_16_submits",
            initial=[f(1, 1, 24)],
            waves=[[f(i, i)] for i in range(2, 17)],
        ),
    ]
    for pattern in ("keys", "delta"):
        rows.append(
            dict(
                name="byte_guard_" + pattern,
                initial=[f(1, 1, 24)],
                waves=[
                    [
                        f(i, i, 24 if pattern == "keys" or i == 1101 else 8)
                        for i in range(2, 1102)
                    ]
                ],
                keep=994,
            )
        )
    rows.append(
        dict(
            name="count_guard_partial_keys",
            initial=[f(1, 1, 24)],
            waves=[
                [
                    f(i, i, 24 if i == 2051 else 16, raw if i == 2051 else b"x")
                    for i in range(2, 2052)
                ]
            ],
            keep=2048,
        )
    )
    return rows


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == m.p.q.r.c.SHA
    raw = (root / "app/tests/fixtures/video/sequential.h264").read_bytes()[:2204]
    rows = []
    for case in cases(raw):
        full = Slow(binary).run(
            case["initial"],
            case["waves"],
            case.get("spurious", False),
            case.get("after_idle"),
            case.get("wake_result", 0),
        )
        projected = None
        if "keep" in case:
            assert len(case["waves"]) == 1
            projected = Slow(binary).run(
                case["initial"], [case["waves"][0][-case["keep"] :]]
            )
        rows.append(dict(**case, source=full, port_projection=projected))
    from elftools.elf.elffile import ELFFile
    import io

    section = ELFFile(io.BytesIO(binary)).get_section_by_name(".text")
    code = section.data()
    base = section["sh_addr"]
    functions = []
    for name, a, n in [
        ("EventConstructor", 0x90D390, 80),
        ("EventSet", 0x90D9EC, 180),
        ("SyncWait", 0x90D124, 400),
        ("AnonymousEvent", 0x90D3E0, 300),
        ("RunDecodeLoop", 0x766D50, 276),
        ("AddToTail", 0x767368, 212),
    ]:
        functions.append(
            dict(
                name=name,
                address=a,
                size=n,
                sha256=hashlib.sha256(code[a - base : a - base + n]).hexdigest(),
            )
        )
    return dict(
        binary_sha256=m.p.q.r.c.SHA, boundary=__doc__, functions=functions, cases=rows
    )


if __name__ == "__main__":
    import argparse
    import gzip

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--write", type=Path)
    p.add_argument("--check", type=Path)
    a = p.parse_args()
    result = audit(a.binary.read_bytes())
    if a.write:
        a.write.write_bytes(
            gzip.compress((json.dumps(result, indent=2) + "\n").encode(), mtime=0)
        )
    if a.check:
        assert result == json.loads(gzip.decompress(a.check.read_bytes()))
    print(
        "Original decoder overlap/event:",
        len(result["cases"]),
        "cases,",
        sum(len(c["source"]["gates"]) for c in result["cases"]),
        "SDK gates; 3 explicit port projections",
    )
