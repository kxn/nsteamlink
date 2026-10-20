#!/usr/bin/env python3
"""Run original decoder FIFO/SDK input under retained-frame and input pressure.

Media observer bounds and the declared OS Wait terminal increase beyond §143.
Original allocation/container/frame/decode/flush/OnThink instructions are intact;
libc allocation/free, SDK/JNI/OS/NAL metadata remain the inherited terminals.
Batches bound consumer scheduling, not natural wall-clock slow SDK behavior.
Two cases intentionally exceed the port's separate 256-partial guard: preserve
Source output and label the Native policy difference rather than call it equal.
Separate original statistics cases execute receive/event/complete/report and C++
serialization, with an array allocator terminal for large frame bodies.
"""

import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "queue_audit", ROOT / "scripts/audit-steam-decoder-queue.py"
)
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)


class Pressure(q.Queue):
    def queue_ids(self, head, tail, mask, storage, offset):
        if head == 0xFFFFFFFF:
            return []
        assert head <= tail and tail - head < 4096
        return [
            struct.unpack(
                "<H", self.u.mem_read(self.q(storage + ((n & mask) * 8)) + offset, 2)
            )[0]
            for n in range(head, tail + 1)
        ]

    def hook(self, u, pc, size, data):
        if self.plts.get(pc) == "_ZN16SteamThreadTools17CThreadSyncObject4WaitEj":
            delay = self.r(1) & 0xFFFFFFFF
            self.waits.append([self.action, delay])
            assert len(self.waits) < 4096
            if delay in (0, 0xFFFFFFFF):
                self.b(self.video + 24, 0)
            self.ret(1)
            return
        super().hook(u, pc, size, data)


def workload(payload):
    cases = []
    for count in (254, 255, 256, 257, 300):
        cases.append(
            dict(
                name=f"partial_prefix_{count}_then_key",
                native_guard=count > 256,
                batches=[
                    [[i, i, 0, "78"] for i in range(1, count + 1)]
                    + [[count + 1, count + 1, 24, payload.hex()]]
                ],
            )
        )
    cases.append(
        dict(
            name="300_key_inputs",
            native_guard=False,
            batches=[[[i, i, 24, payload.hex()] for i in range(1, 301)]],
        )
    )
    cases.append(
        dict(
            name="300_retained_outputs",
            native_guard=False,
            batches=[
                [[i, i, 8, payload.hex()] for i in range(first, first + 10)]
                for first in range(1, 301, 10)
            ],
        )
    )
    return cases


def flow_hashes(flow):
    return [
        (
            event[:3] + [hashlib.sha256(bytes.fromhex(event[3])).hexdigest()]
            if event[0] == "decode"
            else event
        )
        for event in flow
    ]


def stats_cases(binary):
    spec = importlib.util.spec_from_file_location(
        "stats_pressure_audit", ROOT / "scripts/audit-steam-frame-stats.py"
    )
    stats = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stats)
    cases = []
    for full in (False, True):
        x = stats.Stats(binary, full=full, offset=0)
        # Large full reports cross the original inline frame buffer and request
        # C++ array storage. Supply only that libc-equivalent allocation/free.
        for address, name in x.plts.items():
            if name == "_Znam":
                x.callbacks[address] = lambda x=x: x.ret(x.alloc(x.r(0)))
            elif name in ("_ZdaPv", "_ZdaPvm"):
                x.callbacks[address] = lambda x=x: x.ret()

        ids = [1, 60, 61, 250, 256, 300]
        actions = []
        for fid in range(1, 301):
            base = 900000 + fid * 100
            actions.append(["R", fid, base, base + 17, base + 211, 100, 0, 0])
        actions += [
            ["E", 300, 14, 940001],
            ["E", 300, 15, 940101],
            ["C", 300, 1, 941001],
            ["C", 250, 1, 942001],
            ["S"],
            ["S"],
        ]
        observed = []
        for index, action in enumerate(actions):
            if action[0] == "R":
                keys = (
                    "fid",
                    "frame_start",
                    "sent",
                    "received",
                    "size",
                    "input_mark",
                    "input_received",
                )
                x.receive(**dict(zip(keys, action[1:])))
            elif action[0] == "E":
                x.call(0x7AC35C, stats.config.CLIENT, 1, *action[1:])
            elif action[0] == "C":
                _, fid, result, x.now = action
                x.call(0x7AC3F8, stats.config.CLIENT, 1, fid, result)
            else:
                x.call(0x7A82E8, stats.config.CLIENT, 1)
                state = x.observe(ids)
                assert not state["asserts"]
                observed.append(dict(index=index, state=state))
        cases.append(dict(full=full, ids=ids, actions=actions, observed=observed))
    return cases


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == q.r.c.SHA
    baseline = q.audit(binary)
    assert baseline == json.loads(
        (ROOT / "scripts/fixtures/steam-decoder-queue-reference.json").read_text()
    )
    payload = (ROOT / "app/tests/fixtures/video/sequential.h264").read_bytes()[:2204]
    results = []
    for case in workload(payload):
        x = Pressure(binary)
        states = []
        for index, batch in enumerate(case["batches"]):
            x.action = index
            x.b(x.video + 24, 1)
            for fid, seq, flags, raw in batch:
                x.queue(fid, seq, flags, bytes.fromhex(raw))
            assert x.snapshot()["input_queue"]["ids"] == [f[0] for f in batch]
            x.call(0x766D50, x.video)
            state = x.observe()
            states.append(
                dict(
                    strict=state["strict"],
                    soft=state["soft"],
                    request=state["request"],
                    flow=flow_hashes(state["flow"]),
                    player=state["player"],
                    body=state["body"],
                    waits=list(x.waits),
                    dequeued=list(x.dequeued),
                    closed=x.i(q.r.c.CLIENT + 256) in (0, 7),
                )
            )
            assert not x.assertions, (case["name"], index, x.assertions)
            assert not x.snapshot()["input_queue"]["ids"]
        results.append(dict(**case, states=states))
    return dict(
        binary_sha256=q.r.c.SHA,
        boundary=__doc__,
        functions=baseline["functions"],
        statistics_boundary="Original Stats receive/event/complete/report and C++ serialization; explicit array allocator terminal for large reports; no decoder/GPU/Socket proof.",
        stats_cases=stats_cases(binary),
        stats_helper_sha256=hashlib.sha256(
            (ROOT / "scripts/audit-steam-frame-stats.py").read_bytes()
        ).hexdigest(),
        cases=results,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--write", type=Path)
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    result = audit(args.binary.read_bytes())
    if args.write:
        args.write.write_bytes(
            gzip.compress((json.dumps(result, indent=2) + "\n").encode(), mtime=0)
        )
    if args.check:
        assert result == json.loads(gzip.decompress(args.check.read_bytes()))
    print(
        "Official decoder pressure:",
        len(result["cases"]),
        "cases/",
        sum(len(c["states"]) for c in result["cases"]),
        "states",
    )
