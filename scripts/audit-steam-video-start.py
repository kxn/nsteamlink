#!/usr/bin/env python3
"""Execute official video Start/Stop dispatch, prepare gate, factory and pending.

Original control FIFO/Frame/protobuf, handlers, standalone factory/constructors,
SetUseThreads/size/OnStreamStarted and queue/pending replay execute. Player prepare
and Android backend initialization results, OS scheduling, packet refs/libc and
final IO are adapters. No real SDL window, physical decoder, all Java/platform
factories or Steam/Native resource proof is claimed.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "reset", ROOT / "scripts/audit-steam-decoder-reset.py"
)
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
c = r.c


class Video(r.Reset):
    def __init__(
        self, binary, prepare=True, ready=True, threads=True, thread_ok=True, fallback=4
    ):
        self.steps = []
        super().__init__(
            binary, dict(threads=threads, old_backend=False, init_success=ready)
        )
        self.call(0x767160, self.video)
        self.call(self.q(self.q(self.video) + 8), self.video)
        self.wq(c.CLIENT + 40, 0)
        self.wq(self.vt + 32, c.STOP + 0xA00)
        self.callbacks[c.STOP + 0xA00] = self.prepare
        self.thread_ok = thread_ok
        self.prepare_ok = prepare
        self.wi(c.CLIENT + 340, fallback)
        self.tracing = True
        self.trace = []
        self.audio_events = []
        self.assertions = []

    def prepare(self):
        self.steps.append(["prepare", self.r(1), self.r(2), self.prepare_ok])
        self.ret(int(self.prepare_ok))

    def hook(self, u, address, size, data):
        name = self.plts.get(address, "")
        if name in ("ThreadInterlockedIncrement", "ThreadInterlockedDecrement"):
            # This combined control/pending fixture uses the existing borrowed
            # packet-reference boundary, not the owned-ref oracle in reset79.
            r.d.Decoder.hook(self, u, address, size, data)
        else:
            super().hook(u, address, size, data)

    def snapshot(self):
        ptr = self.q(c.CLIENT + 40)
        decoder = None
        if ptr:
            vt = self.q(ptr)
            assert vt == self.symbols["_ZTV28CStreamDecoderH264Standalone"] + 16, hex(
                vt
            )
            size = self.i(ptr + 52)
            assert size < 65536
            begin, end = self.i(ptr + 364), self.i(ptr + 368)
            count = 0 if begin == 0xFFFFFFFF else end - begin + 1
            assert count < 64
            queued = []
            for n in range(count):
                frame = self.q(
                    self.q(ptr + 376) + ((begin + n) & self.i(ptr + 360)) * 8
                )
                packet = self.q(frame + 8)
                queued.append(
                    dict(
                        id=int.from_bytes(self.u.mem_read(frame + 26, 2), "little"),
                        timestamp=self.i(frame + 28),
                        body=bytes(
                            self.u.mem_read(
                                self.q(packet + 56) + 26, self.i(packet + 52) - 26
                            )
                        ).hex(),
                    )
                )
            decoder = dict(
                active=bool(self.u.mem_read(ptr + 24, 1)[0]),
                backend=bool(self.q(ptr + 624)),
                threads=bool(self.u.mem_read(ptr + 100, 1)[0]),
                codec=self.i(ptr + 616),
                size=[self.i(ptr + 396), self.i(ptr + 400)],
                codec_data=bytes(self.u.mem_read(self.q(ptr + 32), size)).hex()
                if size
                else "",
                queued=queued,
            )
        result = dict(
            channel=self.u.mem_read(c.CLIENT + 626, 1)[0],
            decoder=decoder,
            phase=self.i(c.CLIENT + 256),
            paused=bool(self.u.mem_read(c.CLIENT + 19, 1)[0]),
            pending=self.pending(),
            steps=list(self.steps),
            trace=list(self.trace),
            assertions=list(self.assertions),
            events=list(self.audio_events),
            delays={str(k): self.i(v + 28) for k, v in sorted(self.channels.items())},
        )
        return result


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == c.SHA
    schema = r.d.o.audio.schema(binary)
    cases = []
    for prepare in (False, True):
        for ready in (False, True):
            for threads in (False, True):
                for explicit in (False, True):
                    x = Video(binary, prepare, ready, threads)
                    msg = schema(
                        "CStartVideoDataMsg", channel=3, width=1280, height=720
                    )
                    if explicit:
                        msg.codec = 4
                    actions = [["C", 52, msg.SerializeToString().hex()]]
                    x.control(52, msg.SerializeToString())
                    cases.append(
                        dict(
                            input=dict(prepare=prepare, ready=ready, threads=threads),
                            actions=actions,
                            states=[x.snapshot()],
                        )
                    )
    for prepare in (False, True):
        for ready in (False, True):
            x = Video(binary, prepare, ready, True)
            actions = []
            states = []

            def ctrl(kind, msg):
                raw = msg.SerializeToString()
                actions.append(["C", kind, raw.hex()])
                x.control(kind, raw)
                states.append(x.snapshot())

            def media(channel, fid):
                payload = "0000180000000011223344"
                actions.append(["M", channel, fid, 1000000, 1000010, 1000020, payload])
                x.media(channel, fid, 1000000, 1000010, 1000020, payload)
                states.append(x.snapshot())

            media(3, 1)
            ctrl(
                52,
                schema(
                    "CStartVideoDataMsg",
                    channel=3,
                    codec=4,
                    width=1280,
                    height=720,
                    codec_data=b"abcd",
                ),
            )
            media(3, 2)
            ctrl(
                52,
                schema(
                    "CStartVideoDataMsg",
                    channel=4,
                    width=1920,
                    height=1080,
                    codec_data=b"efgh",
                ),
            )
            media(4, 3)
            ctrl(53, schema("CStopVideoDataMsg"))
            ctrl(53, schema("CStopVideoDataMsg"))
            cases.append(
                dict(
                    input=dict(prepare=prepare, ready=ready, threads=True),
                    actions=actions,
                    states=states,
                )
            )
    # Run actual thread Start false as well as the successful scheduling boundary.
    for ready in (False, True):
        x = Video(binary, True, ready, True, False)
        actions, states = [], []
        for kind, raw in (
            (
                52,
                schema(
                    "CStartVideoDataMsg",
                    channel=3,
                    codec=4,
                    width=1280,
                    height=720,
                    codec_data=b"\x00\x01\xff",
                ).SerializeToString(),
            ),
            (53, schema("CStopVideoDataMsg").SerializeToString()),
        ):
            actions.append(["C", kind, raw.hex()])
            x.control(kind, raw)
            states.append(x.snapshot())
        cases.append(
            dict(
                input=dict(prepare=True, ready=ready, threads=True, thread_ok=False),
                actions=actions,
                states=states,
            )
        )
    for explicit in (4,):
        x = Video(binary, True, True, True, fallback=5)
        msg = schema("CStartVideoDataMsg", channel=3, width=1280, height=720)
        if explicit is not None:
            msg.codec = explicit
        raw = msg.SerializeToString()
        x.control(52, raw)
        cases.append(
            dict(
                input=dict(prepare=True, ready=True, threads=True, fallback=5),
                actions=[["C", 52, raw.hex()]],
                states=[x.snapshot()],
            )
        )
    for body in ("80", "", "1003"):
        x = Video(binary)
        x.control(52, bytes.fromhex(body))
        cases.append(
            dict(
                input=dict(prepare=True, ready=True, threads=True),
                actions=[["C", 52, body]],
                states=[x.snapshot()],
            )
        )
    for case in cases:
        for state in case["states"]:
            assert not state["assertions"], state["assertions"]
            if state["decoder"]:
                assert state["decoder"]["active"]
                assert state["decoder"]["backend"] == case["input"]["ready"]
    return dict(binary_sha256=c.SHA, boundary=__doc__, cases=cases)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--write", type=Path)
    p.add_argument("--check", type=Path)
    a = p.parse_args()
    out = audit(a.binary.read_bytes())
    if a.write:
        a.write.write_text(json.dumps(out, indent=2) + "\n")
    if a.check:
        assert out == json.loads(a.check.read_text())
    print("Official video Start/Stop:", len(out["cases"]), "cases")
