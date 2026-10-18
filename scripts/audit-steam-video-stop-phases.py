#!/usr/bin/env python3
"""Execute official H264 stop phases, ownership cuts and recovery clock origin.

Pinned original constructors/queues/frame refs, Stop/Reset/Flush, backend flush
and destruction, new initialization, strict state/timestamp stores and subsequent
non-key DecodeFrame execute. SDK/OS/JNI/allocator and init-result terminals are
explicit boundaries. Terminal delays advance a controlled protocol clock; they
are inputs, not measured wall-clock latency. No real GPU/codec, other factories,
all reset producers or Native platform/error-code equivalence is claimed.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

from unicorn import UC_HOOK_MEM_WRITE

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "reset", ROOT / "scripts/audit-steam-decoder-reset.py"
)
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
c = r.c


class Phases(r.Reset):
    def __init__(self, binary, inp):
        self.tick = inp.get("tick", 1000000)
        self.delays = inp.get("delays", {})
        self.ledger = []
        super().__init__(binary, inp)
        self.u.hook_add(UC_HOOK_MEM_WRITE, self.write)

    def cut(self):
        state = self.snapshot()
        return {
            k: state[k]
            for k in (
                "active",
                "request",
                "strict",
                "soft",
                "last_request",
                "backend",
                "input_queue",
                "player_queue",
                "held",
                "refs",
                "pending",
                "encoded",
                "packet_buffers",
                "buffer_fields",
            )
        }

    def event(self, name, *values):
        super().event(name, *values)
        if self.tracing and name in (
            "join",
            "input_queue_purge",
            "player_flush",
            "pending_flush",
            "accel_flush",
            "codec_flush",
            "accel_quit",
            "codec_delete",
            "init_terminal",
            "decoder_info",
            "thread_start",
            "data_lost",
            "flush_return",
            "retire_return",
        ):
            self.ledger.append(
                dict(event=name, values=list(values), tick=self.tick, state=self.cut())
            )

    def write(self, u, access, address, size, value, context):
        if self.tracing and address in (self.video + 404, self.video + 408):
            self.ledger.append(
                dict(
                    event="strict_store"
                    if address == self.video + 404
                    else "clock_store",
                    value=value,
                    size=size,
                    tick=self.tick,
                )
            )

    def hook(self, u, address, size, context):
        if address == 0x7B1FE4:
            self.event("flush_return")
        elif address == 0x7B107C:
            self.event("retire_return")
        name = self.plts.get(address, "")
        if name == "_Z18GetStreamTimestampv":
            self.ret(self.tick)
            return
        super().hook(u, address, size, context)
        phase = {
            "AMediaCodec_flush": "flush",
            "AMediaCodec_delete": "delete",
            "_ZN20CAndroidVideoDecoder14BCreateDecoderEii17EStreamVideoCodec": "init",
        }.get(name)
        if self.tracing and phase:
            self.tick = (self.tick + self.delays.get(phase, 0)) & 0xFFFFFFFF
            self.ledger.append(dict(event=phase + "_done", tick=self.tick))


def run(binary, inp):
    x = Phases(binary, inp)
    x.partial(0, 30)
    x.partial(1, 30)
    if inp.get("partial") != "linked":
        x.call(0x7B24DC, x.video)
    if inp["threads"]:
        x.queue_input(1)
        x.queue_input(2)
    # Backend-absent input models initial BInit failure: it has never produced
    # decoded pictures. Nonempty player ownership is exercised with an old codec.
    if inp["old_backend"]:
        x.queue_picture(10)
        x.queue_picture(11)
        for off, fid in zip((272, 280, 288), (20, 21, 22)):
            x.wq(x.player + off, x.picture(fid))
    x.trace.clear()
    x.tracing = True
    before = x.cut()
    if inp["mode"] == "reset":
        x.call(0x7AD394, c.CLIENT, 0)
        x.call(0x7A6198, c.CLIENT)
    else:
        x.call(0x767160, x.video)
    after = x.cut()
    phases = list(x.ledger)
    # Source's late delta path is legitimate only while the restarted decoder
    # is active. Stop suppresses admission and does not run this caller.
    lost_before = sum(e["event"] == "data_lost" for e in x.ledger)
    if inp["mode"] == "reset":
        x.partial(2, 31)
    final = x.cut()
    lost_after = sum(e["event"] == "data_lost" for e in x.ledger)
    assert not x.assertions
    stores = [e for e in phases if e["event"] == "clock_store"]
    assert len(stores) == 1 and stores[0]["value"] == stores[0]["tick"]
    expected_mark = (
        inp.get("tick", 1000000)
        + (inp.get("delays", {}).get("flush", 0) if inp["old_backend"] else 0)
    ) & 0xFFFFFFFF
    assert stores[0]["tick"] == expected_mark
    names = [e["event"] for e in phases]
    assert (
        names.index("player_flush")
        < names.index("pending_flush")
        < names.index("clock_store")
    )
    if inp["old_backend"]:
        assert (
            names.index("pending_flush")
            < names.index("flush_done")
            < names.index("clock_store")
            < names.index("codec_delete")
            < names.index("delete_done")
        )
        at_delete = next(e["state"] for e in phases if e["event"] == "codec_delete")
        assert (
            not at_delete["input_queue"]["ids"] and not at_delete["player_queue"]["ids"]
        )
        assert (
            at_delete["held"] == [None, None, None]
            and not at_delete["encoded"]
            and at_delete["packet_buffers"] == 0
        )
        assert all(v == 0 for v in at_delete["refs"].values())
        assert at_delete["strict"] == 1 and at_delete["soft"] == 0
    assert not after["input_queue"]["ids"] and not after["player_queue"]["ids"]
    assert (
        after["held"] == [None, None, None]
        and not after["encoded"]
        and after["packet_buffers"] == 0
    )
    phase_names = {
        "player_flush": "player",
        "flush_return": "decoder",
        "clock_store": "mark",
        "retire_return": "retire",
    }
    phase_order = [
        [phase_names[e["event"]], e["tick"]]
        for e in phases
        if e["event"] in phase_names
    ]
    assert [e[0] for e in phase_order] == ["player", "decoder", "mark", "retire"]
    return dict(
        phase_order=phase_order,
        input=inp,
        before=before,
        after=after,
        phases=phases,
        after_delta=final,
        lost=[lost_before, lost_after],
        tick=x.tick,
        trace=x.trace,
    )


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == c.SHA
    cases = []
    profiles = (
        {},
        {"flush": 6554},
        {"delete": 6553},
        {"delete": 6554},
        {"init": 6554},
        {"flush": 100, "delete": 6500, "init": 54},
    )
    for threads in (False, True):
        for old in (False, True):
            for ready in (False, True):
                for profile in profiles:
                    inp = dict(
                        threads=threads,
                        old_backend=old,
                        init_success=ready,
                        mode="reset",
                        partial="copy",
                        escape=True,
                        delays=profile,
                    )
                    cases.append(run(binary, inp))
    for mode in ("stop", "reset"):
        for partial in ("linked", "copy"):
            cases.append(
                run(
                    binary,
                    dict(
                        threads=True,
                        old_backend=True,
                        init_success=True,
                        mode=mode,
                        partial=partial,
                        escape=False,
                        tick=0xFFFFFFF0,
                        delays=dict(flush=100, delete=6554),
                    ),
                )
            )
    return dict(binary_sha256=c.SHA, boundary=__doc__, cases=cases)


if __name__ == "__main__":
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
    print(f"Official stop phases: {len(result['cases'])} cases")
