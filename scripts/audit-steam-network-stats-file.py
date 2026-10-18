#!/usr/bin/env python3
"""Official streaming_stats.bin format and automatic network-test trigger.

Pinned shell executes full Panel ctor/connecting producer, original stats
Load/Save, CRC32/grouping/f32 arithmetic, generated protobuf parsing/serialization,
and completion action3 -> a new ordinary connecting request. File endpoints,
Qt/base objects/settings/display inputs, allocation/string storage, printf,
thread start/join, credential lookup and final discovery sends are adapters.
Completed stats are explicit inputs to completion cases; no real host/test
thread, natural Qt loop, filesystem durability, decoder or device is proved.
"""
import argparse
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import zlib

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "discovery", ROOT / "scripts/audit-steam-network-test-discovery.py"
)
discovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(discovery)
PANEL, APP, CONFIG = discovery.PANEL, discovery.APP, discovery.CONFIG
REFERENCE = ROOT / "scripts/fixtures/steam-network-stats-file-reference.json.gz"
INITIAL = struct.pack("<fff", 11.5, 22.5, 33.5)


class StatsFile(discovery.Discovery):
    def __init__(self, binary, patch=None):
        self.file = None
        self.read_ok = self.write_ok = True
        self.reads, self.writes, self.formats = [], [], []
        self.warning_count = 0
        self.file_tail = b"\0" * 32
        self.test_starts = []
        super().__init__(binary, patch=patch)
        for name, address in self.symbols.items():
            if address and (
                "NetworkStats" in name
                or "CStreamingSessionStats" in name
                or name.startswith("_Z10CRC32")
                or name.startswith("_Z11CRC32")
                or name.startswith("_Z19CRC32")
            ):
                self.function_entries.setdefault(address, []).append(name)
        self.wq(APP + 0x18, self.manager)
        self.wi(APP + 0x38, 1280)
        self.wi(APP + 0x3C, 720)
        self.wi(self.manager + 0x1BC, 4)

    def format(self, fmt, ap):
        stack, gr, vr, go, vo = struct.unpack("<QQQii", self.u.mem_read(ap, 32))

        def gp():
            nonlocal stack, go
            if go < 0:
                p = gr + go
                go += 8
            else:
                p = stack
                stack += 8
            return self.q(p)

        if fmt == "%u=%s":
            value = f"{gp() & 0xffffffff}={self.cstring(gp())}"
        elif fmt == "%d:":
            value = gp() & 0xFFFFFFFF
            value = value - 0x100000000 if value & 0x80000000 else value
            value = f"{value}:"
        elif fmt == "%.2f":
            p = vr + vo if vo < 0 else stack
            value = "%.2f" % struct.unpack("<d", self.u.mem_read(p, 8))[0]
        else:
            raise AssertionError(("unimplemented file format", fmt))
        self.formats.append(dict(format=fmt, value=value))
        return value.encode()

    def hook(self, u, pc, size, data):
        name = self.plts.get(pc, "")
        if name in (
            "_ZN17CShellApplication16LoadNetworkStatsEP13CNetworkStats",
            "_ZN17CShellApplication16SaveNetworkStatsEPK13CNetworkStats",
            "_ZN13CPanelConnect23SetPanelStateConnectingEv",
        ):
            self.jump(self.symbols[name])
        elif name == "_ZN14CServerManager14StartStreamingEyPKc":
            self.test_starts.append(bool(self.u.mem_read(self.r(0) + 0x1E5, 1)[0]))
            super().hook(u, pc, size, data)
        elif name == "_Z9BLoadFilePKcS0_R10CUtlBuffer":
            self.reads.append(
                dict(
                    directory=self.cstring(self.r(0)),
                    name=self.cstring(self.r(1)),
                    available=self.file is not None and self.read_ok,
                )
            )
            if self.file is None or not self.read_ok:
                self.ret(0)
            else:
                value = self.file + self.file_tail
                p, buf = self.alloc(len(value) + 1), self.r(2)
                self.u.mem_write(p, value + b"\0")
                self.wq(buf, p)
                self.wi(buf + 8, len(value) + 1)
                self.wi(buf + 20, len(self.file))
                self.ret(1)
        elif name == "_Z9BSaveFilePKcS0_RK10CUtlBuffer":
            buf = self.r(2)
            self.writes.append(
                dict(
                    directory=self.cstring(self.r(0)),
                    name=self.cstring(self.r(1)),
                    body=bytes(u.mem_read(self.q(buf), self.i(buf + 20))).hex(),
                    success=self.write_ok,
                )
            )
            self.ret(int(self.write_ok))
        elif name == "vasprintf":
            value = self.format(self.cstring(self.r(1)), self.r(2))
            p = self.alloc(len(value) + 1)
            u.mem_write(p, value + b"\0")
            self.wq(self.r(0), p)
            self.ret(len(value))
        elif name == "vsnprintf":
            value = self.format(self.cstring(self.r(2)), self.r(3))
            if self.r(1):
                u.mem_write(self.r(0), value[: self.r(1) - 1] + b"\0")
            self.ret(len(value))
        elif "basic_string" in name and "6resizeEmc" in name:
            dest, length = self.r(0), self.r(1)
            tag = u.mem_read(dest, 1)[0]
            old_size = self.q(dest + 8) if tag & 1 else tag >> 1
            old_ptr = self.q(dest + 16) if tag & 1 else dest + 1
            value = bytes(u.mem_read(old_ptr, min(old_size, length))) + bytes(
                [self.r(2) & 255]
            ) * max(0, length - old_size)
            p = self.alloc(length + 1)
            u.mem_write(p, value + b"\0")
            self.wq(dest, (length + 1) | 1)
            self.wq(dest + 8, length)
            self.wq(dest + 16, p)
            self.ret(dest)
        elif "basic_string" in name and "6__initEPKcm" in name:
            dest, length = self.r(0), self.r(2)
            p = self.alloc(length + 1)
            u.mem_write(p, bytes(u.mem_read(self.r(1), length)) + b"\0")
            self.wq(dest, (length + 1) | 1)
            self.wq(dest + 8, length)
            self.wq(dest + 16, p)
            self.ret(dest)
        elif "basic_string" in name and "D1Ev" in name:
            self.ret()
        elif name == "__memmove_chk":
            assert self.r(2) <= self.r(3)
            if self.r(2):
                u.mem_write(self.r(0), bytes(u.mem_read(self.r(1), self.r(2))))
            self.ret(self.r(0))
        elif name == "_ZN10CPanelBaseC2EP17CShellApplication":
            self.wq(self.r(0) + 0x30, self.r(1))
            self.ret()
        elif name in (
            "_ZN8QVariantC1Ey",
            "_ZN8QVariantC1ERK7QString",
            "_ZN6QTimerC1EP7QObject",
            "_ZN6QTimer5startEi",
            "_ZN14CServerManager11AddDelegateEP22IServerManagerDelegate",
        ):
            self.ret()
        elif name == "_ZNK8QVariant11toULongLongEPb":
            self.ret(123)
        elif name == "_ZNK8QVariant8toStringEv":
            self.wq(self.r(8), self.empty)
            self.ret()
        elif name == "_ZN7QString15fromUtf8_helperEPKci":
            # Warning text only; QString storage/printing is an OS/Qt adapter.
            self.wq(self.r(8), self.qstring("warning"))
            self.ret()
        elif name == "_ZN10QArrayData10deallocateEPS_mm":
            self.ret()
        elif name == "_ZNK14QMessageLogger7warningEv":
            self.warning_count += 1
            self.wq(self.r(8), self.alloc(64))
            self.ret()
        elif name in (
            "_ZN11QTextStreamlsERK7QString",
            "_ZN11QTextStreamlsEc",
            "_ZN6QDebugD1Ev",
        ):
            self.ret(self.r(0))
        else:
            super().hook(u, pc, size, data)

    def stats(self, average, samples):
        q = self.alloc(512)
        self.call(self.symbols["_ZN13CNetworkStatsC1Ev"], q)
        self.u.mem_write(q + 112, bytes.fromhex(average))
        if samples:
            p = self.alloc(len(samples) * 8)
            self.u.mem_write(p, b"".join(struct.pack("<II", *row) for row in samples))
            self.wq(q + 88, p)
            self.wi(q + 104, len(samples))
        return q


def loads(binary, name, body, output=True, tail=0):
    r = StatsFile(binary)
    r.file = bytes.fromhex(body) if body is not None else None
    r.file_tail = bytes([tail]) * 32
    q = r.stats(INITIAL.hex(), [])
    status = r.call(
        r.symbols["_ZN17CShellApplication16LoadNetworkStatsEP13CNetworkStats"],
        APP,
        q if output else 0,
    )
    assert not r.assertions
    return dict(
        name=name,
        body=body,
        output=output,
        tail=tail,
        readable=bool(status),
        average=bytes(r.u.mem_read(q + 112, 12)).hex(),
        reads=r.reads,
        source_assertions=r.assertions,
        executed=sorted(r.executed),
    )


def save(binary, name, average, samples, success=True):
    r = StatsFile(binary)
    r.write_ok = success
    q = r.stats(average, samples)
    r.call(
        r.symbols["_ZN17CShellApplication16SaveNetworkStatsEPK13CNetworkStats"], APP, q
    )
    assert len(r.writes) == 1 and not r.assertions
    result = r.writes[0]
    raw = b"".join(struct.pack("<II", *row) for row in samples)
    text = next(value["value"] for value in r.formats if value["format"] == "%u=%s")
    assert text.startswith(str(zlib.crc32(raw)) + "=")
    return dict(
        name=name,
        average=average,
        samples=samples,
        write=result,
        warning_count=r.warning_count,
        test_data=text,
        source_assertions=r.assertions,
        executed=sorted(r.executed),
    )


def trigger(binary, action, video, body, patch=None):
    r = StatsFile(binary, patch)
    r.file = bytes.fromhex(body) if body is not None else None
    r.wi(CONFIG + 16, r.i(CONFIG + 16) | (1 << 29))
    r.b(CONFIG + 157, int(video))
    r.call(
        r.symbols["_ZN13CPanelConnectC1EP17CShellApplicationNS_14EConnectActionE"],
        PANEL,
        APP,
        action,
    )
    assert not r.assertions
    r.call(r.symbols["_ZN14CServerManager25SendStartStreamingRequestEv"], r.manager)
    wires = r.message_wires()
    flags = discovery.fields(bytes.fromhex(wires[-1]["body"]))["12"]
    return dict(
        input=dict(action=action, video=video, body=body),
        action=r.i(PANEL + 0xD0),
        test=bool(r.u.mem_read(PANEL + 0xD4, 1)[0]),
        panel_state=r.i(PANEL + 0xD8),
        reads=r.reads,
        test_starts=r.test_starts,
        network_flag=flags[0],
        source_assertions=r.assertions,
        executed=sorted(r.executed),
        patch_hits=r.patch_hits,
    )


def completion(binary, accepted, write_ok, patch=None):
    r = StatsFile(binary, patch)
    r.write_ok = write_ok
    r.call(
        r.symbols["_ZN13CPanelConnectC1EP17CShellApplicationNS_14EConnectActionE"],
        PANEL,
        APP,
        0,
    )
    r.call(r.symbols["_ZN14CServerManager25SendStartStreamingRequestEv"], r.manager)
    # Authorized endpoint/token are explicit inputs, as in §116/119. Execute
    # the real Panel OnUpdate -> SetPanelStateNetworkTest before completion;
    # completing directly from connecting state4 would hit its idempotent guard.
    token = r.alloc(32)
    r.u.mem_write(token, discovery.PLAIN)
    r.call(r.symbols["_ZN10CUtlBuffer3PutEPKvi"], r.manager + 0x398, token, 32)
    r.wi(r.manager + 8, 6)
    r.call(r.symbols["_ZN13CPanelConnect8OnUpdateEv"], PANEL)
    before_state = r.i(PANEL + 0xD8)
    assert before_state == 5 and r.auth_tokens == [discovery.PLAIN.hex()]
    # Explicit completed statistics and no-recommendation input. Full Run/
    # media/score coverage is separate (§118–120), not fabricated here.
    q = discovery.lifecycle.media.TEST + 16
    r.u.mem_write(q + 112, struct.pack("<fff", 99.91667, 1.0, 0.0))
    r.wi(PANEL + 704, 0)
    r.call(
        r.symbols["_ZN13CPanelConnect21OnNetworkTestCompleteEi"], PANEL, int(accepted)
    )
    r.call(r.symbols["_ZN14CServerManager25SendStartStreamingRequestEv"], r.manager)
    assert not r.assertions
    if not patch:
        assert r.test_starts == [True, False]
    return dict(
        input=dict(accepted=accepted, write_ok=write_ok),
        before_state=before_state,
        action=r.i(PANEL + 0xD0),
        test=bool(r.u.mem_read(PANEL + 0xD4, 1)[0]),
        panel_state=r.i(PANEL + 0xD8),
        test_starts=r.test_starts,
        messages=r.message_wires(),
        writes=r.writes,
        warning_count=r.warning_count,
        source_assertions=r.assertions,
        executed=sorted(r.executed),
        patch_hits=r.patch_hits,
    )


def inventory(binary, cases):
    names = {n for c in cases for n in c["executed"]}
    e = ELFFile(io.BytesIO(binary))
    t = e.get_section_by_name(".text")
    out = {}
    for s in e.get_section_by_name(".dynsym").iter_symbols():
        if s.name in names and s["st_size"]:
            at = s["st_value"] - t["sh_addr"]
            code = t.data()[at : at + s["st_size"]]
            out[s.name] = dict(
                address=s["st_value"],
                size=len(code),
                sha256=hashlib.sha256(code).hexdigest(),
            )
    assert names == set(out)
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    binary = a.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == discovery.lifecycle.media.flow.SHA
    average = struct.pack("<fff", 0.5, 2.5, 3.5).hex()
    saves = []
    for name, samples in [
        ("empty", []),
        ("zeros", [[0, 65], [0, 65536]]),
        (
            "groups",
            [
                [15000, 1],
                [15000, 327],
                [0, 65],
                [15000, 65536],
                [10000, 65537],
                [10000, 0],
                [0, 0],
                [15000, 65535],
            ],
        ),
        (
            "signed",
            [[0xFFFFFFFF, 0xFFFFFFFF], [0x80000000, 0x80000000], [42, 0x7FFFFFFF]],
        ),
        ("long", [[(0 if i % 7 == 0 else 10000 + i % 3), i * 657] for i in range(640)]),
    ]:
        saves.append(save(binary, name, average, samples))
        print("save", name, flush=True)
    saves.append(save(binary, "raw_float_bits", "000000804523c17f0000807f", []))
    saves.append(save(binary, "write_failure", average, [], False))
    bodies = [
        ("missing", None),
        ("empty", ""),
        ("three_floats", saves[0]["write"]["body"]),
        ("partial", "0d0000803e80"),
        ("duplicate_partial", "0d0000803e0d0000803f1501"),
        ("short_float", "0d0102"),
        ("wrong_wire", "0807150000803f"),
        ("unknown_group", "4b0d0000803f4c1500000040"),
        ("raw_float_bits", saves[-2]["write"]["body"]),
        ("bad_tag", "80"),
    ]
    bodies += [
        ("float_zero_bytes", "0d"),
        ("float_three_bytes", "1d010203"),
        ("zero_tag", "0d0000803f001500000040"),
        ("unknown_varint", "48071500000040"),
        ("bad_unknown_varint", "4880"),
        ("unknown_fixed64", "4901020304050607081500000040"),
        ("short_unknown_fixed64", "490102"),
        ("short_unknown_fixed32", "4d0102"),
        ("unknown_string", "4a01781500000040"),
        ("short_unknown_string", "4a0478"),
        ("end_group", "4c1500000040"),
        ("mismatched_group", "4b541500000040"),
        ("bad_wire", "4e1500000040"),
        ("duplicate", "0d0000803e0d0000803f"),
        ("test_data_string", "220278781500000040"),
        ("short_test_data", "220478"),
    ]
    loaded = [
        loads(binary, name, body, output, tail)
        for name, body in bodies
        for output in [False, True]
        for tail in [0, 0xA5]
    ]
    triggers = [
        trigger(binary, action, video, body)
        for action in range(4)
        for video in [False, True]
        for body in [None, "", saves[0]["write"]["body"], "80"]
    ]
    completed = [
        completion(binary, accepted, write_ok)
        for accepted in [False, True]
        for write_ok in [False, True]
    ]
    all_cases = saves + loaded + triggers + completed
    mutations = []
    for name, pc, before, after, original, mutant in [
        (
            "readable_branch",
            0xC6DEAC,
            0x37000180,
            0x36000180,
            trigger(binary, 0, True, ""),
            trigger(binary, 0, True, "", (0xC6DEAC, 0x37000180, 0x36000180)),
        ),
        (
            "clear_test_flag",
            0xC72248,
            0x3903527F,
            0xD503201F,
            completion(binary, False, False),
            completion(binary, False, False, (0xC72248, 0x3903527F, 0xD503201F)),
        ),
    ]:
        assert mutant["patch_hits"] == [pc] and not mutant["source_assertions"]
        assert original["test_starts"] != mutant["test_starts"]
        mutations.append(
            dict(
                name=name,
                pc=pc,
                before=before,
                after=after,
                original=original,
                mutant=mutant,
            )
        )
    report = dict(
        binary_sha256=discovery.lifecycle.media.flow.SHA,
        scope=__doc__,
        functions=inventory(binary, all_cases),
        saves=saves,
        loads=loaded,
        triggers=triggers,
        completions=completed,
        mutations=mutations,
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
        "Stats file original:", len(saves), len(loaded), len(triggers), len(completed)
    )


if __name__ == "__main__":
    main()
