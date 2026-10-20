#!/usr/bin/env python3
"""Official CNetworkStats lifecycle/scoring and actual ordinary/FEC receive paths.

Pinned Android core instructions run constructors, Start/Record/fold/Stop and
both score overloads. Component Frame fields and direct-score floats are explicit
inputs. Pipeline cases additionally run original Socket/channel/windows/FEC RS,
OnStreamPacket/OnDataPacket and frame/report paths, with NetworkStats active.
Clock/OS/locks/libc/refcounts, decoder and final feedback/report admission are
adapters. This does not prove natural global scheduling, optional full recording,
statistics files, host FEC activation or a Steam/Switch/GPU session.
"""

import argparse
import gzip
import hashlib
import importlib.util
import io
import itertools
import json
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_S0

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "video", ROOT / "scripts/audit-steam-video-network.py"
)
video = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(video)
c = video.config
REFERENCE = ROOT / "scripts/fixtures/steam-media-network-stats-reference.json.gz"


class Quality(video.Video):
    def __init__(self, binary, crc=False):
        super().__init__(binary, crc)
        self.stats = c.CLIENT + 968
        self.call(0x77A0F8, self.stats)
        self.callbacks[0xC0C250] = lambda: self.jump(0x77A228)

    def snapshot(self):
        q = self.stats
        count, windows = self.i(q + 48), self.i(q + 72)
        assert count <= 600 and windows <= 10000
        self.call(0x77A994, q)
        loss = self.u.reg_read(UC_ARM64_REG_S0)
        self.call(0x77A9CC, q)
        mean = self.u.reg_read(UC_ARM64_REG_S0)
        self.call(0x77AAF8, q)
        deviation = self.u.reg_read(UC_ARM64_REG_S0)
        return dict(
            expected=int.from_bytes(self.u.mem_read(q + 16, 2), "little"),
            total=self.i(q + 20),
            batch=self.i(q + 24),
            latencies=[self.i(self.q(q + 32) + 4 * i) for i in range(count)],
            samples=[
                bytes(self.u.mem_read(self.q(q + 56) + 12 * i, 12)).hex()
                for i in range(windows)
            ],
            average=bytes(self.u.mem_read(q + 112, 12)).hex(),
            result=self.call(0x77A908, q),
            current=struct.pack("<III", loss, mean, deviation).hex(),
        )

    def direct(self, fid, sent, received):
        frame = self.alloc(64)
        self.u.mem_write(frame + 26, struct.pack("<H", fid))
        self.wi(frame + 32, sent)
        self.wi(frame + 40, received)
        self.call(0x77A228, self.stats, frame)

    def score(self, mean, deviation, loss):
        for i, value in enumerate((mean, deviation, loss)):
            self.u.reg_write(UC_ARM64_REG_S0 + i, value)
        return self.call(0x77A954, self.stats)


def component_schedules():
    yield dict(
        name="empty_repeated_stop_restart", actions=[["Q"], ["E"], ["E"], ["Z"], ["Q"]]
    )
    for count in (1, 2, 7, 8, 9, 599, 600, 601, 1200):
        yield dict(
            name=f"count_{count}",
            actions=[["Z"], ["N", 0, count, 0], ["E"], ["E"], ["Z"]],
        )
    for pattern in range(4):
        yield dict(
            name=f"float_rounding_{pattern}",
            actions=[
                ["Z"],
                ["N", 0, 599, pattern],
                ["Q"],
                ["N", 599, 1, pattern],
                ["N", 600, 9, pattern],
                ["E"],
            ],
        )
    for ids in (
        (0, 1, 3, 3, 2, 4),
        (23, 24, 29),
        (65534, 65535, 0, 1, 2),
        (32768, 32769, 0),
        (32769, 0, 32768),
    ):
        yield dict(
            name="ids_" + str(ids),
            actions=[["Z"]] + [["R", i, 1000000, 1000065] for i in ids] + [["E"]],
        )
    for gap in (598, 599, 600, 1199, 32768):
        yield dict(
            name=f"gap_{gap}",
            actions=[
                ["Z"],
                ["R", gap, 1000000, 1000017],
                ["R", (gap + 1) & 65535, 1001000, 1001067],
                ["E"],
            ],
        )
    yield dict(
        name="clock_edges",
        actions=[["Z"]]
        + [
            ["R", n, sent, received]
            for n, (sent, received) in enumerate(
                (
                    (0, 0),
                    (0xFFFFFFF0, 16),
                    (20, 5),
                    (1, 0x80000000),
                    (0, 0x80000000),
                    (0xFFFFFFFF, 0),
                )
            )
        ]
        + [["E"]],
    )
    yield dict(
        name="unequal_batches",
        actions=[["Z"], ["N", 0, 599, 0], ["F"], ["R", 1000, 1000000, 1001000], ["E"]],
    )


def generated(index, pattern):
    ticks = (
        (65, 200, 300, 1, 2147483647, 0, 65535, 65536, 1234567)[index % 9]
        if pattern
        else 65
    )
    sent = (1000000 + index * 1000) & 0xFFFFFFFF
    received = (sent + ticks) & 0xFFFFFFFF
    if pattern == 2 and index % 3 == 0:
        received = (sent - 10) & 0xFFFFFFFF
    if pattern == 3:
        ticks = (index * 1103515245 + 12345) & 0x7FFFFFFF
        received = (sent + ticks) & 0xFFFFFFFF
    return sent, received


def components(binary):
    result = []
    for inp in component_schedules():
        r = Quality(binary)
        observed = []
        for op, *a in inp["actions"]:
            if op == "Z":
                r.call(0x77A15C, r.stats)
            elif op == "E":
                r.call(0x77A844, r.stats)
            elif op == "F":
                r.call(0x77A494, r.stats)
            elif op == "R":
                r.direct(*a)
            elif op == "N":
                start, count, pattern = a
                for i in range(start, start + count):
                    r.direct(i & 65535, *generated(i, pattern))
            else:
                assert op == "Q"
            observed.append(r.snapshot())
        assert not r.asserts, (inp["name"], r.asserts)
        result.append(dict(input=inp, observed=observed))
    return result


def pipelines(binary):
    encoding, schedules = video.schedules(binary)
    result = []
    for old in schedules:
        if not old["name"].startswith("video_"):
            continue
        inp = dict(old)
        inp["actions"] = [["Z"]] + old["actions"] + [["E"]]
        r = Quality(binary, inp["crc"])
        r.b(c.CLIENT + 636, int(inp.get("full", False)))
        observed = []
        for op, *a in inp["actions"]:
            r.entries.clear()
            r.frames.clear()
            r.delivered.clear()
            r.metadata.clear()
            if op == "W":
                r.now, *args = a
                r.receive_packet(*args)
            elif op == "U":
                r.now, ch = a
                r.call(0x7F9C9C, r.channels[ch], r.now)
            elif op == "O":
                r.wi(r.connection + 848, a[0])
            elif op == "C":
                fid, r.now = a
                r.call(0x7AC3F8, c.CLIENT, 1, fid, 1)
            elif op == "S":
                r.now = a[0]
                r.call(0x7A7140, c.CLIENT)
            elif op == "Z":
                r.call(0x77A15C, r.stats)
            else:
                assert op == "E"
                r.call(0x77A844, r.stats)
            state = r.observe()
            state.update(
                video=r.observe_collectors()["video"],
                delivered=list(r.delivered),
                metadata=list(r.metadata),
            )
            if "full" in inp:
                state.update(
                    frames=list(r.frames),
                    frame_events_time=r.i(c.CLIENT + 0x1C678),
                    keepalive_time=r.i(c.CLIENT + 0x1F6F0),
                    sequence=r.q(c.CLIENT + 128),
                    reported=r.i(r.ring(1) + 8) >> 16,
                )
            state["quality"] = r.snapshot()
            observed.append(state)
        assert not r.asserts, (inp["name"], r.asserts)
        result.append(dict(input=inp, observed=observed))
    return encoding, result


def scores(binary):
    r = Quality(binary)
    values = (
        0,
        0x80000000,
        0x3F800000,
        0x40FFFFFF,
        0x41000000,
        0x417FFFFF,
        0x41800000,
        0x3E7FFFFF,
        0x3E800000,
        0x3F7FFFFF,
        0x7F800000,
        0xFF800000,
        0x7FC00001,
    )
    cases = []
    for mean, deviation, loss in itertools.product(
        (0, 0x3F800000, 0x7FC00001), values, values
    ):
        cases.append(
            dict(input=[mean, deviation, loss], observed=r.score(mean, deviation, loss))
        )
    return cases


def stop_counterfactual(binary):
    """Patch actual loaded BL-to-fold into NOP; require clean real returns."""
    observations = []
    for mutant in (False, True):
        r = Quality(binary)
        pc, hits = 0x77A854, []
        original = bytes(r.u.mem_read(pc, 4)).hex()
        if mutant:
            r.u.mem_write(pc, struct.pack("<I", 0xD503201F))
        r.u.hook_add(
            UC_HOOK_CODE,
            lambda u, address, size, data: hits.append(address)
            if address == pc
            else None,
        )
        r.call(0x77A15C, r.stats)
        for i in range(600):
            r.direct(i, *generated(i, 0))
        before = r.snapshot()
        r.call(0x77A844, r.stats)
        after = r.snapshot()
        assert not r.asserts and len(hits) == 1
        observations.append(
            dict(
                mutant=mutant,
                address=pc,
                original=original,
                patched=bytes(r.u.mem_read(pc, 4)).hex(),
                hits=len(hits),
                asserts=r.asserts,
                before=before,
                after=after,
            )
        )
    assert observations[0]["before"] == observations[1]["before"]
    assert observations[0]["after"] != observations[1]["after"]
    return observations


def inventory(binary):
    e = ELFFile(io.BytesIO(binary))
    text = e.get_section_by_name(".text")
    result = {}
    for s in e.get_section_by_name(".dynsym").iter_symbols():
        if s["st_value"] and (
            s.name.startswith("_ZN13CNetworkStats")
            or s.name.startswith("_ZNK13CNetworkStats")
        ):
            start = s["st_value"] - text["sh_addr"]
            code = text.data()[start : start + s["st_size"]]
            assert code
            result[s.name] = dict(
                address=s["st_value"],
                size=len(code),
                sha256=hashlib.sha256(code).hexdigest(),
            )
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    binary = a.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == c.SHA
    encoding, network = pipelines(binary)
    report = dict(
        binary_sha256=c.SHA,
        scope=__doc__,
        functions=inventory(binary),
        stop_counterfactual=stop_counterfactual(binary),
        component_cases=components(binary),
        pipeline_cases=network,
        score_cases=scores(binary),
        encoding_vectors=encoding,
    )
    if a.refresh_reference:
        if REFERENCE.exists():
            assert json.loads(gzip.decompress(REFERENCE.read_bytes())) == report
        REFERENCE.write_bytes(
            gzip.compress((json.dumps(report, indent=2) + "\n").encode(), mtime=0)
        )
    else:
        assert json.loads(gzip.decompress(REFERENCE.read_bytes())) == report
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        "Official media network stats:",
        len(report["component_cases"]),
        "component cases,",
        len(network),
        "packet pipelines,",
        len(report["score_cases"]),
        "score inputs",
    )


if __name__ == "__main__":
    main()
