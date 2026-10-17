#!/usr/bin/env python3
"""Execute official video bit6 mode transitions and the pending-reset submit gate.

SHA-pinned original constructors, DecodeFrame/OnThink/FinalDecode, Android SDK
submission, packet/frame ownership, whole Client::OnThink reset and lifecycle
execute. Initial readiness and post-reset BCreateDecoder result/storage are SDK
terminals; they install a labelled codec/window/format, not a physical decoder.
SDK/JNI/NAL metadata/platform/ref primitives and network/control/OS scheduling
are declared adapters inherited from the reset/key audits. Header bits arrive
at the real decoder boundary; host-side meaning/producer of bit6 and every
platform/factory/error mapping are not proved. GetBuffer observes original
retained bytes without advancing Read or mirroring its assembly policy.
"""

import argparse
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "key", ROOT / "scripts/audit-steam-keyframe-flush.py"
)
k = importlib.util.module_from_spec(spec)
spec.loader.exec_module(k)
c = k.c
PAYLOAD = (ROOT / "app/tests/fixtures/video/sequential.h264").read_bytes()[:2204]


class Mode(k.Key):
    def __init__(self, binary, inp):
        self.flow, self.requests, self.flush_cuts = [], [], []
        self.action, self.decode_id = -1, 0
        k.r.Reset.__init__(
            self,
            binary,
            dict(
                threads=inp["threads"],
                old_backend=inp["backend"],
                init_success=inp.get("ready", True),
                video_codec=inp.get("codec", 4),
            ),
        )
        self.b(self.video + 404, 0)
        self.b(self.video + 405, 0)
        if inp["initial"] is not None:
            assert inp["backend"]
            self.feed(0, 0, 24 | (64 if inp["initial"] else 0), PAYLOAD)
            assert self.snapshot()["player_queue"]["ids"] == [0]
        assert not self.assertions
        self.trace, self.sdk, self.effects = [], [], []
        self.tracing = True

    def decoder_info(self):
        if self.tracing:
            self.flow.append(["info", self.action])
        super().decoder_info()

    def hook(self, u, address, size, ctx):
        name = self.plts.get(address, "")
        if self.tracing:
            if address == 0x7AD394:
                self.requests.append([self.action, self.r(1)])
            if address in (0x7681EC, 0x7B1074, 0x7B0E70):
                self.flow.append(
                    [
                        {0x7681EC: "player", 0x7B1074: "retire", 0x7B0E70: "start"}[
                            address
                        ],
                        self.action,
                    ]
                )
            if (
                name
                == "_ZN13CStreamClient12SendDataLostE18EStreamingDataTypeRK10CUtlVectorIt10CUtlMemoryItEE"
            ):
                self.flow.append(["lost", self.action])
        if (
            name == "_ZN20CAndroidVideoDecoder14BCreateDecoderEii17EStreamVideoCodec"
            and self.scenario["init_success"]
        ):
            # A successful initialization terminal must supply SDK storage for
            # the subsequent real BSubmitFrame; returning true alone cannot.
            decoder = self.r(0)
            codec = self.alloc(64)
            self.labels[codec] = f"reinit_codec_{self.backend_generation}"
            self.wq(decoder + 88, codec)
            self.wq(decoder + 96, 1001)
            self.wq(decoder + 104, 2001)
        super().hook(u, address, size, ctx)

    def observe(self):
        state = self.state()
        buffers = self.video + 472
        length = self.alloc(4)
        parts = []
        for n in range(self.call(0x7B2BE0, buffers)):
            ptr = self.call(0x7B2BF8, buffers, n, length)
            size = self.i(length)
            assert size < 65536
            parts.append(bytes(self.u.mem_read(ptr, size)).hex() if size else "")
        state.update(
            mode=[self.u.mem_read(self.video + n, 1)[0] for n in (393, 394)],
            body="".join(parts),
            backend=bool(self.q(self.video + 624)),
            requests=list(self.requests),
            trace=list(self.trace),
        )
        return state


def run(binary, inp, actions):
    x = Mode(binary, inp)
    initial = x.observe()
    states = []
    for index, action in enumerate(actions):
        x.action = index
        if action[0] == "F":
            x.feed(*action[1:4], bytes.fromhex(action[4]))
        elif action[0] == "R":
            x.call(0x7A5FF8, c.CLIENT)  # Real inline lifecycle before network/control.
        elif action[0] == "Q":
            x.call(0x7AD394, c.CLIENT, 0)  # Actual asynchronous request entry.
        elif action[0] == "C":
            x.call(0x7B2804, x.video, action[1])  # Source-only exported helper.
        else:
            raise ValueError(action)
        states.append(x.observe())
        assert not x.assertions, (inp, index, x.assertions)
    return dict(input=inp, initial=initial, actions=actions, states=states, sdk=x.sdk)


def actions(inp, first, last, key):
    seq = int(inp["initial"] is not None)
    result = [["Q"]] if inp.get("request") else []
    result += [
        ["F", 1, seq, (16 if key else 0) | (64 if first else 0), PAYLOAD[:1102].hex()],
        ["F", 1, seq + 1, 8 | (64 if last else 0), PAYLOAD[1102:].hex()],
        ["F", 2, seq + 2, 8 | (64 if last else 0), PAYLOAD.hex()],
        ["R"],
        ["F", 3, seq + 3, 8 | (64 if last else 0), PAYLOAD.hex()],
        ["F", 4, seq + 4, 24 | (64 if last else 0), PAYLOAD.hex()],
        ["F", 5, seq + 5, 24 | (0 if last else 64), PAYLOAD.hex()],
        ["R"],
        ["F", 6, seq + 6, 24 | (0 if last else 64), PAYLOAD.hex()],
    ]
    return result


def negative_checks(binary, baseline):
    constructor = Mode.__init__
    rejected = []
    # These original sites have already executed during priming. Always remove
    # translated blocks after patching, as established by the key-flush audit.
    mutations = (
        ("omit_mode_reset_request", [(0x7B26C0, 0xD503201F)]),
        ("ignore_finishing_bit6", [(0x7B2624, 0x52800015)]),
        (
            "ignore_all_pending_gates",
            [(pc, 0xD503201F) for pc in (0x7B26C8, 0x7B26DC, 0x7B26F8)],
        ),
        (
            "clean_retained_bytes_on_request",
            [(0x7B26E0, 0x14000000 | ((0x7B2790 - 0x7B26E0) // 4))],
        ),
    )
    try:
        for name, patches in mutations:

            def modified(self, *args, **kwargs):
                constructor(self, *args, **kwargs)
                for pc, word in patches:
                    self.u.mem_write(pc, struct.pack("<I", word))
                    self.u.ctl_remove_cache(pc, pc + 4)

            Mode.__init__ = modified
            try:
                got = run(binary, baseline["input"], baseline["actions"])
            except (AssertionError, ValueError):
                rejected.append(name)
            else:
                assert got != baseline, ("undetected official mutation", name)
                rejected.append(name)
    finally:
        Mode.__init__ = constructor
    return rejected


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == c.SHA
    cases = []
    for backend, initial in ((False, None), (True, None), (True, 0), (True, 1)):
        for threads in (False, True):
            for request in (False, True):
                for first in (0, 1):
                    for last in (0, 1):
                        for key in (False, True):
                            inp = dict(
                                backend=backend,
                                initial=initial,
                                threads=threads,
                                request=request,
                                first=first,
                                last=last,
                                key=key,
                            )
                            cases.append(
                                run(binary, inp, actions(inp, first, last, key))
                            )
    for initial in (0, 1):
        for threads in (False, True):
            inp = dict(
                backend=True,
                initial=initial,
                threads=threads,
                ready=False,
                first=initial,
                last=1 - initial,
                key=True,
                request=False,
            )
            cases.append(run(binary, inp, actions(inp, initial, 1 - initial, True)))
    # Key purge before the actor, including reusing the same pending ticket.
    for initial in (0, 1):
        for threads in (False, True):
            for same_id in (False, True):
                for switch_back in (False, True):
                    mode = 1 - initial
                    after_key = initial if switch_back else mode
                    inp = dict(
                        backend=True,
                        initial=initial,
                        threads=threads,
                        same_id=same_id,
                        switch_back=switch_back,
                        shape="key_before_reset",
                    )
                    ops = [
                        ["F", 1, 1, 24 | (64 if mode else 0), PAYLOAD.hex()],
                        [
                            "F",
                            1 if same_id else 2,
                            2,
                            8 | (64 if mode else 0),
                            PAYLOAD.hex(),
                        ],
                        [
                            "F",
                            1 if same_id else 3,
                            3,
                            24 | (64 if after_key else 0),
                            PAYLOAD.hex(),
                        ],
                        ["R"],
                        ["F", 4, 4, 24 | (64 if after_key else 0), PAYLOAD.hex()],
                    ]
                    cases.append(run(binary, inp, ops))
    helpers = []
    for initial in (None, 0, 1):
        for request in (False, True):
            for first in (0, 1):
                for second in (0, 1):
                    inp = dict(
                        backend=True, initial=initial, threads=True, request=request
                    )
                    ops = ([["Q"]] if request else []) + [
                        ["C", first],
                        ["C", second],
                        ["R"],
                    ]
                    helpers.append(run(binary, inp, ops))
    sp = importlib.util.spec_from_file_location(
        "entry", ROOT / "scripts/audit-steam-client-fec-entry.py"
    )
    entry = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(entry)
    entry.TARGETS = ("_ZN19CStreamDecoderVideo16CheckContentModeEb",)
    return dict(
        binary_sha256=c.SHA,
        boundary=__doc__,
        payload_sha256=hashlib.sha256(PAYLOAD).hexdigest(),
        cases=cases,
        helper_cases=helpers,
        static=entry.static(binary),
        mutation_checks=negative_checks(
            binary,
            next(
                item
                for item in cases
                if item["input"]
                == dict(
                    backend=True,
                    initial=0,
                    threads=True,
                    request=False,
                    first=0,
                    last=1,
                    key=True,
                )
            ),
        ),
    )


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
    print(
        "Official video content mode:",
        len(result["cases"]),
        "cases/",
        sum(len(c["states"]) for c in result["cases"]),
        "states;",
        len(result["helper_cases"]),
        "source-only helper cases",
    )
