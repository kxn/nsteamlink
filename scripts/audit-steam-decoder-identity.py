#!/usr/bin/env python3
"""Execute original video FIFO/SDK tasks across repeated and discontinuous IDs.

Input IDs, sequences, flags and timestamps enter original OnReceiveFrame/copy,
RunDecodeLoop, DecodeFrame, OnThink and Android submission. Task labels identify
actual retained CAndroidFrame pointers, not wire IDs; properties are read from
original SetFrameProperties storage. RecordFrameComplete/Event calls are observed
at their original client endpoints, with the inherited completion terminal.
An explicit C action supplies a completion at that declared endpoint while the
old task stays retained; this is not a real Android output/render operation.
Inherited allocator/JNI/SDK/NAL metadata and bounded Wait terminals remain.
This proves decoder-boundary handling, not that Steam naturally emits each jump,
physical pixels, scheduler timing or the reported player's stall cause.
"""

import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "pressure_identity", ROOT / "scripts/audit-steam-decoder-pressure.py"
)
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class Identity(p.Pressure):
    def __init__(self, binary):
        self.completes, self.stages, self.task_labels = [], [], {}
        super().__init__(binary)

    def queue_stamped(self, fid, seq, flags, stamp, payload):
        body = (
            b"\1"
            + struct.pack("<HIHI", fid, stamp, 0, 0)
            + struct.pack("<HBHH", seq, flags, 0, 0)
            + payload
        )
        packet = self.packet(5, 3, False, 12, 34, len(body))
        label = f"identity_{self.action}_{len(self.refs)}"
        self.labels[packet] = label
        self.u.mem_write(self.q(packet + 40) + 13, body)
        frame = self.alloc(64)
        self.call(self.symbols["_ZN12CStreamFrameC1EP13CStreamPacket"], frame, packet)
        self.call(0x76727C, self.video, frame)
        self.call(self.symbols["_ZN12CStreamFrameD1Ev"], frame)
        self.refs[label] = packet

    def hook(self, u, pc, size, data):
        if getattr(self, "tracing", False):
            if pc == 0xC0BAA0:
                fid, result = self.r(2) & 65535, self.r(3)
                if (
                    self.completes
                    and self.completes[-1][2] == result
                    and (self.completes[-1][0] + self.completes[-1][1]) & 65535 == fid
                ):
                    self.completes[-1][1] += 1
                else:
                    self.completes.append([fid, 1, result])
            if pc == 0x7AC35C:
                self.stages.append([self.r(2), self.r(3)])
        super().hook(u, pc, size, data)

    def tasks(self):
        head, tail = self.i(self.player + 244), self.i(self.player + 248)
        if head == 0xFFFFFFFF:
            return []
        storage, mask = self.q(self.player + 256), self.i(self.player + 240)
        rows = []
        for index in range(head, tail + 1):
            obj = self.q(storage + (index & mask) * 8)
            label = self.task_labels.setdefault(obj, len(self.task_labels))
            rows.append([label, self.h(obj + 28), self.i(obj + 32)])
        return rows


def cases(payload):
    def frame(fid, seq, flags=24, stamp=1000100, raw=payload):
        return ["F", fid, seq, flags, stamp, raw.hex()]

    rows = []
    for fid in (0, 1, 255, 256, 32767, 32768, 32769, 40000, 65280, 65281, 65535):
        rows.append(dict(name=f"key_from_zero_to_{fid}", batches=[[frame(fid, 1)]]))
    rows += [
        dict(
            name="duplicate_keys_separate",
            batches=[[frame(1, 1)], [frame(1, 2, stamp=1000200)]],
        ),
        dict(
            name="duplicate_delta_same_batch",
            batches=[[frame(1, 1, 8), frame(1, 2, 8, 1000200)]],
        ),
        dict(
            name="duplicate_delta_separate",
            batches=[[frame(1, 1, 8)], [frame(1, 2, 8, 1000200)]],
        ),
        dict(
            name="duplicate_keys_same_batch",
            batches=[[frame(1, 1), frame(1, 2, stamp=1000200)]],
        ),
        dict(
            name="completed_duplicate_key",
            batches=[[frame(1, 1)], [["C", 1], frame(1, 2, stamp=1000200)]],
        ),
        dict(
            name="replace_unfinished_same_id",
            batches=[
                [frame(1, 1, 16, raw=payload[:1102])],
                [frame(1, 2, stamp=1000200)],
            ],
        ),
        dict(
            name="split_same_id",
            batches=[
                [frame(1, 1, 16, raw=payload[:1102])],
                [frame(1, 2, 8, 1000200, payload[1102:])],
            ],
        ),
        dict(
            name="split_across_ids_then_reuse",
            batches=[
                [
                    frame(1, 1, 16, raw=payload[:1102]),
                    frame(2, 2, 8, 1000200, payload[1102:]),
                ],
                [frame(1, 3, 8, 1000300)],
            ],
        ),
        dict(
            name="wrap_then_old_id",
            batches=[
                [frame(65535, 1)],
                [frame(0, 2, stamp=1000200)],
                [frame(65535, 3, stamp=1000300)],
            ],
        ),
        dict(
            name="half_jump_then_return",
            batches=[[frame(32768, 1)], [frame(0, 2, stamp=1000200)]],
        ),
        dict(
            name="gap_drop_then_same_id_key",
            batches=[[frame(1, 2, 8)], [frame(1, 3, stamp=1000200)]],
        ),
    ]
    return rows


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == p.q.r.c.SHA
    payload = (ROOT / "app/tests/fixtures/video/sequential.h264").read_bytes()[:2204]
    results = []
    for case in cases(payload):
        x, states = Identity(binary), []
        assert x.tasks() == [[0, 0, 1000000]]
        for index, batch in enumerate(case["batches"]):
            x.action = index
            x.b(x.video + 24, 1)
            for action in batch:
                if action[0] == "C":
                    x.call(0xC0BAA0, p.q.r.c.CLIENT, 1, x.tasks()[action[1]][1], 7)
                else:
                    x.queue_stamped(*action[1:5], bytes.fromhex(action[5]))
            x.call(0x766D50, x.video)
            value = x.observe()
            state = {
                key: value[key]
                for key in ("strict", "soft", "request", "body", "player")
            }
            state.update(
                flow=p.flow_hashes(value["flow"]),
                waits=list(x.waits),
                dequeued=list(x.dequeued),
                tasks=x.tasks(),
                completes=[list(row) for row in x.completes],
                stages=list(x.stages),
                closed=False,
            )
            assert not x.assertions and not x.snapshot()["input_queue"]["ids"]
            assert len({row[0] for row in state["tasks"]}) == len(state["tasks"])
            states.append(state)
        results.append({**case, "states": states})
    elf = ELFFile(io.BytesIO(binary))
    section = elf.get_section_by_name(".text")
    code, base = section.data(), section["sh_addr"]
    functions = []
    for name, address, size in [
        ("RunDecodeLoop", 0x766D50, 276),
        ("DecodeFrame", 0x7B2000, 1244),
        ("OnThink", 0x7B24DC, 808),
        ("FlushPendingData", 0x7B2A68, 376),
        ("VideoConstructor", 0x7B1C08, 220),
        ("SetFrameProperties", 0x76769C, 12),
    ]:
        functions.append(
            dict(
                name=name,
                address=address,
                size=size,
                sha256=hashlib.sha256(
                    code[address - base : address - base + size]
                ).hexdigest(),
            )
        )
    return dict(
        binary_sha256=p.q.r.c.SHA,
        boundary=__doc__,
        functions=functions,
        cases=results,
        stats_cases=stats_projection(binary, results),
    )


def stats_projection(binary, media):
    """Project observed cancellation calls through original stats/report code.

    Receive rows and eventual Displayed completion are explicit boundary inputs;
    this is compositional evidence, not a physical player/rendered outcome.
    """
    spec = importlib.util.spec_from_file_location(
        "identity_stats", ROOT / "scripts/audit-steam-frame-stats.py"
    )
    stats = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stats)
    results = []
    for key in (255, 256):
        media_case = next(c for c in media if c["name"] == f"key_from_zero_to_{key}")
        state = media_case["states"][0]
        for full in (False, True):
            x = stats.Stats(binary, full=full)
            # Original full reports allocate beyond the inline buffer. Only
            # supply array allocation/free; serialization still executes.
            for address, name in x.plts.items():
                if name == "_Znam":
                    x.callbacks[address] = lambda x=x: x.ret(x.alloc(x.r(0)))
                elif name in ("_ZdaPv", "_ZdaPvm"):
                    x.callbacks[address] = lambda x=x: x.ret()
            ids = [1, 2, 239, 240, 254, 255, 256]
            actions = [
                [
                    "R",
                    fid,
                    900000 + fid * 100,
                    901000 + fid * 100,
                    902000 + fid * 100,
                    100,
                    0,
                    0,
                ]
                for fid in range(1, key + 1)
            ]
            for first, count, result in state["completes"]:
                actions.extend(
                    ["C", (first + index) & 65535, result, 1000000]
                    for index in range(count)
                )
            actions.extend(["E", fid, event, 1000000] for fid, event in state["stages"])
            actions += [["C", key, 1, 1000100], ["S"], ["S"]]
            observed = []
            for index, action in enumerate(actions):
                if action[0] == "R":
                    _, fid, start, sent, received, size, mark, input_received = action
                    x.receive(
                        fid,
                        start,
                        sent,
                        received,
                        size,
                        input_mark=mark,
                        input_received=input_received,
                    )
                elif action[0] == "C":
                    _, fid, result, x.now = action
                    x.call(0x7AC3F8, stats.config.CLIENT, 1, fid, result)
                elif action[0] == "E":
                    x.call(0x7AC35C, stats.config.CLIENT, 1, *action[1:])
                else:
                    x.call(0x7A82E8, stats.config.CLIENT, 1)
                    value = x.observe(ids)
                    assert not value["asserts"]
                    observed.append(dict(index=index, state=value))
            results.append(
                dict(
                    media_case=media_case["name"],
                    full=full,
                    ids=ids,
                    actions=actions,
                    observed=observed,
                )
            )
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--write", type=Path)
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    result = audit(args.binary.read_bytes())
    if args.write:
        args.write.write_text(json.dumps(result, indent=2) + "\n")
    if args.check:
        assert result == json.loads(args.check.read_text())
    print(
        "Official decoder identity:",
        len(result["cases"]),
        "cases,",
        sum(len(c["states"]) for c in result["cases"]),
        "batch states",
    )
