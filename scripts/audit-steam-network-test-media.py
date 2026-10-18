#!/usr/bin/env python3
"""Official network-test media ingress, completion, score and FEC recommendation.

Pinned Android shell instructions execute UI/Start, an explicit established and
auth-requested boundary, response/parser/request8, actual Socket/CRC/channel/
windows/FEC RS, media Frame/parser/normalization, full CNetworkStats, completion
and result/confirmation/complete-config serializer. OS, clocks, connection table
and address comparison, Qt graph callback/presentation, packet refcounts, identity
crypto, final sends/close and file endpoints are explicit adapters. FEC encoding
uses the original channel encoder at controlled MTU64/percentage50; source/dest,
send/receive timestamps and CRC at transport emission are controlled, bypassing the
outgoing enable gate on purpose; this does NOT prove network-test FEC activation.
Native comparisons execute raw ingress/window/FEC/preparation and the default
collector on these same controlled wires, plus the original scoring inputs;
they do not prove an implemented Native network-test session or UI.
"""

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile
from unicorn.arm64_const import UC_ARM64_REG_S0, UC_ARM64_REG_X30

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "flow", ROOT / "scripts/audit-steam-network-test-fec-flow.py"
)
flow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flow)
TEST, PANEL, APP, CONFIG = flow.TEST, flow.PANEL, flow.APP, flow.CONFIG
REFERENCE = ROOT / "scripts/fixtures/steam-network-test-media-reference.json.gz"


class Media(flow.Flow):
    def __init__(self, binary, patch=None):
        self.accepted, self.graph, self.scores, self.encoded, self.feedback = (
            [],
            [],
            [],
            [],
            [],
        )
        self.producing = False
        self.wire_count = 0
        self.transport_update = 0
        self.produced = []
        self.encoder_connection = None
        self.completed_scores = []
        super().__init__(binary, patch)
        self.record_pc = self.symbols[
            "_ZN12CNetworkTest19RecordFrameReceivedEP12CStreamFrame"
        ]
        self.score_pc = self.symbols["_ZNK13CNetworkStats9GetResultEfff"]
        self.function_entries = {}
        for name, address in self.symbols.items():
            if address and any(
                name.startswith(prefix)
                for prefix in (
                    "_ZN12CNetworkTest",
                    "_ZN13CNetworkStats",
                    "_ZNK13CNetworkStats",
                    "_ZN13CStreamSocket",
                    "_ZN17CStreamConnection",
                    "_ZN14CStreamChannel",
                    "_ZN12CStreamFrame",
                    "_ZN15CPacketsWindow",
                    "_ZN12CFECDecoder",
                )
            ):
                self.function_entries.setdefault(address, []).append(name)
        self.executed = set()

    def hook(self, u, pc, size, data):
        if pc in getattr(self, "function_entries", {}):
            self.executed.update(self.function_entries[pc])
        if pc == getattr(self, "record_pc", 0):
            f = self.r(1)
            self.accepted.append(
                [
                    int.from_bytes(u.mem_read(f + 26, 2), "little"),
                    self.i(f + 32),
                    self.i(f + 40),
                ]
            )
        if pc == getattr(self, "score_pc", 0):
            self.scores.append(
                dict(
                    input=[u.reg_read(UC_ARM64_REG_S0 + i) for i in range(3)],
                    caller=u.reg_read(UC_ARM64_REG_X30),
                    observed=None,
                )
            )
        if pc in (0xCA932C, 0xCA9348):
            self.scores[-1]["observed"] = self.r(0)
        if pc == 0xCAA358:  # after original Complete's GetResult return
            self.completed_scores.append(self.r(0))
        name = self.plts.get(pc, "")
        if name in ("_ZN6QMutex4lockEv", "_ZN6QMutex6unlockEv", "__cxa_atexit"):
            self.ret()
        elif name == "__cxa_guard_acquire":
            self.ret(1)
        elif name == "__cxa_guard_release":
            self.b(self.r(0), 1)
            self.ret()
        elif name == "calloc":
            self.ret(self.alloc(self.r(0) * self.r(1)))
        elif name in ("_ZnwmRKSt9nothrow_t", "_ZnamRKSt9nothrow_t"):
            self.ret(self.alloc(self.r(0)))
        elif name == "_ZNK10CIPAndPort10CompareAdrERKS_b":
            self.ret(1)
        elif name == "ThreadInterlockedIncrement":
            self.ret(2)
        elif name == "ThreadInterlockedDecrement":
            self.ret(1)
        elif name == "_ZNK10CIPAndPort8ToStringEPcjb":
            self.ret()
        elif name == "_ZN13CStreamSocket4SendEP17CStreamConnectionP13CStreamPacket":
            p = self.r(2)
            wire = bytes(u.mem_read(self.q(p + 40), self.i(p + 52)))
            (self.encoded if self.producing else self.feedback).append(wire.hex())
            self.ret(0)
        else:
            super().hook(u, pc, size, data)

    def graph_callback(self):
        self.graph.append([self.r(1), self.r(2), self.u.reg_read(UC_ARM64_REG_S0)])
        self.ret()

    def initialize(self, values):
        self.config(CONFIG, values.get("before", False), values.get("quality", 2))
        self.wi(CONFIG + 16, self.i(CONFIG + 16) | 0x18000000)
        self.wi(CONFIG + 152, values["bitrate"])
        self.b(CONFIG + 156, 0)
        self.loaded = CONFIG
        initial = self.serialize(CONFIG).hex()
        self.wq(PANEL + 728, self.empty)
        self.wq(PANEL + 200, APP + 0x2000)
        self.wi(APP + 0x2000 + 8, 6)
        self.call(0xC7029C, PANEL)
        self.connection, self.sock = self.alloc(4096), self.alloc(4096)
        self.call(
            self.symbols["_ZN17CStreamConnectionC1EP13CStreamSocket"],
            self.connection,
            self.sock,
        )
        self.wi(self.connection + 16, 1)
        self.wq(TEST + 0x128, self.connection)
        self.call(
            self.symbols["_ZN12CNetworkTest17OnStreamConnectedEP17CStreamConnection"],
            TEST,
            self.connection,
        )
        self.wi(TEST + 0x114, 3)  # explicit auth-request boundary, as §116
        self.receive(2, bytes.fromhex("1001"))
        # Table/address and OS transport are controlled; packet admission and
        # subsequent channel/window/RS/Frame/NetworkTest methods are original.
        table, shaper, transport, vt = (self.alloc(4096) for _ in range(4))
        self.wq(self.sock, transport)
        self.wq(transport, vt)
        self.wq(vt + 72, flow.config.STOP + 0x500)
        self.callbacks[flow.config.STOP + 0x500] = lambda: self.ret(0)
        self.wq(self.sock + 8, table)
        self.wi(self.sock + 24, 1)
        self.wq(table, self.connection)
        self.wq(self.sock + 64, shaper)
        self.b(self.connection + 12, 12)
        self.b(self.connection + 13, 34)
        self.b(self.connection + 10, int(values.get("crc", False)))
        self.wq(self.connection + 368, TEST)
        self.call(
            self.symbols["_ZN17CStreamConnection22SetChannelMaxRecvDelayEhi"],
            self.connection,
            3,
            6553,
        )
        graph = self.q(TEST + 16)
        assert graph == 0xC70678
        self.callbacks[graph] = self.graph_callback
        return initial

    def packet(self, wire, received):
        p = self.alloc(len(wire) + 128)
        raw = p + 64
        self.u.mem_write(raw, bytes(wire))
        self.wq(p + 40, raw)
        self.wq(p + 56, raw)
        self.wi(p + 48, len(wire) + 64)
        self.wi(p + 52, len(wire))
        self.wi(p + 28, received)
        self.wi(p + 32, received)
        return p

    def rx(self, wire, now, corrupt=False):
        self.now = now & 0xFFFFFFFF
        wire = bytearray(wire)
        wire[2:4] = bytes([34, 12])
        if self.u.mem_read(self.connection + 10, 1)[0]:
            wire[0] |= 128
            wire += b"\0" * 4
            packet = self.packet(wire, self.now)
            crc = self.call(
                self.symbols["_Z30CRC32PolyC_ProcessSingleBufferPKvi"],
                self.q(packet + 40),
                len(wire) - 4,
            )
            self.wi(self.q(packet + 40) + len(wire) - 4, crc ^ int(corrupt))
        else:
            assert not corrupt
            packet = self.packet(wire, self.now)
        actual_wire = bytes(self.u.mem_read(self.q(packet + 40), len(wire)))
        self.wire_count += 1
        self.call(
            self.symbols["_ZN13CStreamSocket12HandlePacketEP13CStreamPacketj"],
            self.sock,
            packet,
            self.now,
        )
        ch = wire[4]
        channel = self.q(self.connection + 112 + 8 * ch)
        if channel:
            self.transport_update = self.now + 1
            self.call(
                self.symbols["_ZN14CStreamChannel6UpdateEj"], channel, self.now + 1
            )

        return actual_wire

    def encode(self, fid, sent):
        payload = data(fid, sent)
        wire = struct.pack("<BBBBBHHI", 3, 0, 12, 34, 3, 0, 0, sent) + payload
        p = self.packet(wire, sent)
        self.wi(self.symbols["_ZN13CStreamPacket6s_nMTUE"], 64)
        if self.encoder_connection is None:
            self.encoder_connection = self.alloc(4096)
            self.call(
                self.symbols["_ZN17CStreamConnectionC1EP13CStreamSocket"],
                self.encoder_connection,
                self.sock,
            )
        self.call(
            self.symbols["_ZN17CStreamConnection23SetChannelFECPercentageEhi"],
            self.encoder_connection,
            3,
            50,
        )
        self.encoded.clear()
        self.producing = True
        self.now = sent
        self.call(
            self.symbols["_ZN14CStreamChannel17SendUnreliableFECEP13CStreamPacket"],
            self.q(self.encoder_connection + 136),
            p,
        )
        self.producing = False
        assert len(self.encoded) == 6
        self.produced.append(dict(payload=payload.hex(), shards=list(self.encoded)))
        return list(self.encoded)

    def quality(self):
        q = TEST + 16
        current = []
        for method in (
            "_ZN13CNetworkStats28CalculateFrameLossPercentageEv",
            "_ZN13CNetworkStats29CalculateAverageNetworkTimeMSEv",
            "_ZN13CNetworkStats28CalculateStdDevNetworkTimeMSEf",
        ):
            self.call(self.symbols[method], q)
            current.append(self.u.reg_read(UC_ARM64_REG_S0))
        return dict(
            current=struct.pack("<III", *current).hex(),
            expected=int.from_bytes(self.u.mem_read(q + 16, 2), "little"),
            total=self.i(q + 20),
            batch=self.i(q + 24),
            latencies=[self.i(self.q(q + 32) + 4 * i) for i in range(self.i(q + 48))],
            samples=[
                bytes(self.u.mem_read(self.q(q + 56) + 12 * i, 12)).hex()
                for i in range(self.i(q + 72))
            ],
            average=bytes(self.u.mem_read(q + 112, 12)).hex(),
            result=self.call(self.symbols["_ZNK13CNetworkStats9GetResultEv"], q),
        )

    def state(self, label):
        result = self.observe(label)
        self.call(self.symbols["_ZN12CNetworkTest21GetProgressPercentageEv"], TEST)
        progress = self.u.reg_read(UC_ARM64_REG_S0)
        result.update(
            quality=self.quality(),
            full=[
                list(
                    struct.unpack("<II", self.u.mem_read(self.q(TEST + 104) + 8 * i, 8))
                )
                for i in range(self.i(TEST + 120))
            ],
            progress_bits=progress,
            wire_count=self.wire_count,
            transport_update=self.transport_update,
            accepted=len(self.accepted),
            graph=len(self.graph),
        )
        return result


def data(fid, sent):
    return (
        b"\x01"
        + struct.pack("<HIHI", fid & 65535, (sent - 1) & 0xFFFFFFFF, 0, 0)
        + struct.pack("<HBHH", 0, 0x18, 0, 0)
        + bytes([fid & 255]) * 80
    )


def schedules():
    for bitrate in (20000, -1):
        for count in (0, 1, 2, 7, 8, 9, 599, 600, 601, 1200):
            yield dict(
                name=f"count_{bitrate}_{count}",
                bitrate=bitrate,
                actions=[["N", 0, count, 0]],
            )
    for ids in ((599,), (0, 1, 599), (0, 1, 3, 599), (0, 1, 1, 0, 599), (1, 2, 599)):
        yield dict(
            name="gaps_" + str(ids),
            bitrate=20000,
            actions=[
                ["R", fid, 1000065 + i * 1000, 1000000 + i * 1000]
                for i, fid in enumerate(ids)
            ],
        )
    for bitrate in (20000, -1):
        for offset in (123, -123):
            yield dict(
                name=f"offset_{bitrate}_{offset}",
                bitrate=bitrate,
                offset=offset,
                actions=[["N", 0, 9, 1]],
            )
    for bitrate in (20000, -1):
        yield dict(
            name=f"old_refresh_{bitrate}",
            bitrate=bitrate,
            actions=[["R", 0, 1000065, 1000000], ["R", 0, 1200065, 1200000]],
        )
    for quality in (1, 2, 3):
        for before in (False, True):
            for accepted in (0, 1):
                yield dict(
                    name=f"bad_media_recommend_{quality}_{int(before)}_{accepted}",
                    bitrate=-1,
                    quality=quality,
                    before=before,
                    accepted=accepted,
                    actions=[["T", 100000], ["N", 0, 9, 1]],
                )
    for crc in (False, True):
        for shards in ((0, 1, 4, 5), (5, 4, 1, 0), (0, 1, 2, 3, 4, 5)):
            yield dict(
                name=f"fec_{crc}_{shards}",
                bitrate=20000,
                crc=crc,
                actions=[["F", i, list(shards)] for i in (0, 1, 599)],
            )
        yield dict(
            name=f"fec_incomplete_{crc}",
            bitrate=20000,
            crc=crc,
            actions=[["F", 0, [0, 1, 4]], ["F", 599, [0, 1, 4, 5]]],
        )
        yield dict(
            name=f"fec_targets_{crc}",
            bitrate=-1,
            crc=crc,
            accepted=1,
            actions=[
                ["T", 100000],
                ["F", 0, [0, 1, 4, 5]],
                ["T", 99999],
                ["F", 1, [0, 1, 4, 5]],
            ],
        )
    for bitrate in (20000, -1):
        yield dict(
            name=f"wire_gap_{bitrate}",
            bitrate=bitrate,
            actions=[
                ["G", 599, 599],
                ["U", 1000065 + 6553],
                ["U", 1000065 + 6554],
                ["G", 600, 600, 1007065, 1007000],
            ],
        )
    yield dict(
        name="corrupt_crc_then_good",
        bitrate=20000,
        crc=True,
        actions=[["B", 0], ["N", 0, 2, 0]],
    )


def run(binary, inp, patch=None):
    r = Media(binary, patch)
    initial = r.initialize(inp)
    if inp.get("offset"):
        r.wi(r.connection + 848, inp["offset"])
    states, wires = [r.state("started")], []
    pid = 0
    for op, *a in inp["actions"]:
        if op == "T":
            r.receive(94, b"\x08" + flow.varint(a[0]))
        elif op == "G":
            fid, packet_id, *timing = a
            received, sent = timing or (1000065, 1000000)
            wire = struct.pack("<BBBBBHHI", 3, 0, 34, 12, 3, 0, packet_id, sent) + data(
                fid, sent
            )
            actual_wire = r.rx(wire, received)
            wires.append([received, actual_wire.hex(), False])
        elif op == "U":
            r.now = a[0]
            r.transport_update = r.now
            r.call(
                r.symbols["_ZN14CStreamChannel6UpdateEj"],
                r.q(r.connection + 136),
                r.now,
            )
        elif op in ("N", "R", "B"):
            if op == "N":
                start, count, pattern = a
                frames = [
                    (
                        i,
                        1000000
                        + i * 1000
                        + (65 if not pattern or i % 2 == 0 else 3000),
                        1000000 + i * 1000,
                    )
                    for i in range(start, start + count)
                ]
            elif op == "B":
                frames = [(a[0], 1000065, 1000000)]
            else:
                frames = [tuple(a)]
            for fid, received, sent in frames:
                wire = struct.pack("<BBBBBHHI", 3, 0, 34, 12, 3, 0, pid, sent) + data(
                    fid, sent
                )
                actual_wire = r.rx(wire, received, corrupt=(op == "B"))
                wires.append([received, actual_wire.hex(), op == "B"])
                if op != "B":
                    pid += 1
        else:
            assert op == "F"
            fid, shards = a
            sent = 1000000 + len(wires) * 1000
            encoded = r.encode(fid, sent)
            for i, shard in enumerate(shards):
                # Encoder stops before Socket::Send's transport metadata.
                # As in §56, timestamps are explicit replay inputs.
                wire = bytearray.fromhex(encoded[shard])
                wire[9:13] = struct.pack("<I", sent)
                wire = bytes(wire)
                actual_wire = r.rx(wire, sent + 65 + i)
                wires.append([sent + 65 + i, actual_wire.hex(), False])
        states.append(r.state(op))
    if r.i(TEST + 0x114) != 5:
        r.now = (r.i(TEST + 0x150) + 196608) & 0xFFFFFFFF
        r.call(r.symbols["_ZN12CNetworkTest17HandleNetworkTestEv"], TEST)
        states.append(r.state("timeout_equal"))
        r.now = (r.now + 1) & 0xFFFFFFFF
        r.call(r.symbols["_ZN12CNetworkTest17HandleNetworkTestEv"], TEST)
        states.append(r.state("timeout_after"))
    r.call(r.symbols["_ZN12CNetworkTest19CompleteNetworkTestEv"], TEST)
    states.append(r.state("complete"))
    r.call(0xC707C4, PANEL)
    states.append(r.state("result_page"))
    r.wi(PANEL + 208, 3)
    r.b(PANEL + 212, 1)
    r.call(0xC72164, PANEL, inp.get("accepted", 0))
    states.append(r.state("user_result"))
    assert not r.assertions, (inp["name"], r.assertions)
    saved = [r.serialize(p).hex() for p in r.saves]
    return dict(
        input=inp,
        initial=initial,
        states=states,
        wires=wires,
        accepted=r.accepted,
        graph=r.graph,
        scores=r.scores,
        completed_scores=r.completed_scores,
        control_frames=r.frames,
        feedback=r.feedback,
        produced=r.produced,
        saved=saved,
        final=saved[-1] if saved else initial,
        source_assertions=r.assertions,
        executed=sorted(r.executed),
    ), r.patch_hits


def mutations(binary):
    case = dict(
        name="single_frame_599", bitrate=20000, actions=[["R", 599, 1000065, 1000000]]
    )
    original, _ = run(binary, case)
    # Both patches apply to actual loaded instructions, with identity checked
    # by Flow.__init__; both paths must return normally with no assertions.
    probe = Media(binary)
    changes = (
        ("count_received_instead_of_span", 0xCAB7D8, 0xB9407A68),
        ("score_with_internal_batch_loss", 0xCAA34C, 0xBD408262),
    )
    report = []
    for name, pc, replacement in changes:
        before = int.from_bytes(probe.u.mem_read(pc, 4), "little")
        changed, hits = run(binary, case, (pc, before, replacement))
        assert hits == [pc] and not changed["source_assertions"]
        assert changed["states"][1]["quality"] == original["states"][1]["quality"]
        if name.startswith("count"):
            assert (
                original["states"][1]["state"] == 5
                and changed["states"][1]["state"] == 4
            )
        else:
            assert original["completed_scores"] == [2] and changed[
                "completed_scores"
            ] == [0]
        report.append(
            dict(
                name=name,
                pc=pc,
                before=before,
                after=replacement,
                hits=hits,
                original=original,
                mutant=changed,
            )
        )
    return report


def inventory(binary, cases):
    names = {n for c in cases for n in c["executed"]}
    elf = ELFFile(io.BytesIO(binary))
    text = elf.get_section_by_name(".text")
    out = {}
    for s in elf.get_section_by_name(".dynsym").iter_symbols():
        if s.name in names and s["st_size"]:
            at = s["st_value"] - text["sh_addr"]
            code = text.data()[at : at + s["st_size"]]
            out[s.name] = dict(
                address=s["st_value"],
                size=len(code),
                sha256=hashlib.sha256(code).hexdigest(),
            )
    assert names == set(out), names - set(out)
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    binary = a.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == flow.SHA
    cases = [run(binary, inp)[0] for inp in schedules()]
    report = dict(
        binary_sha256=flow.SHA,
        scope=__doc__,
        cases=cases,
        functions=inventory(binary, cases),
        mutations=mutations(binary),
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
        "Official network-test media:",
        len(cases),
        "cases,",
        sum(len(c["states"]) for c in cases),
        "states,",
        sum(len(c["accepted"]) for c in cases),
        "accepted frames",
    )


if __name__ == "__main__":
    main()
