#!/usr/bin/env python3
"""Official network-test authentication and original RunNetworkTest loop.

The original token buffer constructor/setter and CCrypto HMAC, Frame/protobuf,
Socket/channel admission, NetworkTest dispatcher, real run-loop stage selection,
Handle/Complete/Cancel and disconnected callback execute in pinned Android shell.
An established Connection/transport and BConnect's bool are explicit boundaries.
Global network processing is a controlled event driver; OS/clock/locks, address
comparison, packet refcounts, final I/O/Close, Qt and identity frame cipher remain
adapters. The original CUtlBuffer constructor runs, including overflow setup.
The test receive delay is read from a real generic Channel constructor, unlike
§118's explicit 6553 input. This is not a real Steam/Qt/background-thread run.
"""

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import hmac

from elftools.elf.elffile import ELFFile
from unicorn.arm64_const import (
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X30,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_PC,
)

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "media", ROOT / "scripts/audit-steam-network-test-media.py"
)
media = importlib.util.module_from_spec(spec)
spec.loader.exec_module(media)
TEST = media.TEST
REFERENCE = ROOT / "scripts/fixtures/steam-network-test-lifecycle-reference.json.gz"
RETURN = media.flow.config.STOP + 0x850


class Lifecycle(media.Media):
    def __init__(self, binary, inp, patch=None):
        self.running = False
        self.trace = []
        self.hmac_calls = []
        self.closes = []
        self.inputs = inp
        self.event_index = 0
        self.control_pid = self.data_pid = 0
        self.saved_context = None
        self.calls = []
        super().__init__(binary, patch)
        for name, address in self.symbols.items():
            if address and (
                "CUtlBufferC" in name
                or name == "_ZN7CCrypto15GenerateHMAC256EPKvmS1_mPA32_h"
            ):
                self.function_entries.setdefault(address, []).append(name)
        # Original static connection globals: default receive delay=65,
        # retry/RTO and connected/suspended receive leases.
        self.call(0xCCEC98)
        self.now = self.inputs.get("start", 1000000)
        self.callbacks[RETURN] = self.return_to_driver
        self.callbacks[RETURN + 4] = self.after_socket
        self.callbacks[RETURN + 8] = lambda: self.ret()

    def call(self, entry, *args):
        self.u.reg_write(UC_ARM64_REG_SP, 0x300FF000)
        self.u.reg_write(UC_ARM64_REG_X30, media.flow.config.STOP)
        for i, v in enumerate(args):
            self.u.reg_write(UC_ARM64_REG_X0 + i, v)
        self.u.emu_start(entry, media.flow.config.STOP + 4, count=10000000)
        assert self.u.reg_read(UC_ARM64_REG_PC) == media.flow.config.STOP, (
            "instruction budget exceeded"
        )
        return self.r(0)

    def receive(self, tag, payload):
        # §118's setup auth response is deliberately withheld. Original
        # ServerHandshake now produces the real authentication request.
        if tag != 2:
            return super().receive(tag, payload)

    def hook(self, u, pc, size, data):
        if pc in getattr(self, "function_entries", {}):
            self.executed.update(self.function_entries[pc])
        name = self.plts.get(pc, "")
        if name == "SDL_LogMessageV":
            self.ret()
        elif "CUtlBufferC" in name or name.startswith(
            "_ZN12CNetworkTest12SetAuthToken"
        ):
            self.jump(self.symbols[name])
        elif name == "_ZN7CCrypto15GenerateHMAC256EPKvmS1_mPA32_h":
            self.hmac_calls.append(
                dict(
                    plain=bytes(u.mem_read(self.r(0), self.r(1))).hex(),
                    key=bytes(u.mem_read(self.r(2), self.r(3))).hex(),
                )
            )
            self.jump(self.symbols[name])
        elif name == "_ZN12CNetworkTest8BConnectEv" and self.running:
            self.calls.append("BConnect_boundary")
            self.ret(int(self.inputs.get("connect", True)))
        elif name == "_Z20StreamProcessNetworkv" and self.running:
            self.drive()
        elif name == "_ZN22CStreamTransportClient6UpdateEv" and self.running:
            self.calls.append("transport_update_boundary")
            self.ret()
        elif name in (
            "_ZN17CStreamConnection10DisconnectEv",
            "_ZN17CStreamConnection5CloseEv",
        ):
            self.closes.append(name)
            self.ret()
        else:
            super().hook(u, pc, size, data)

    def snapshot(self, label):
        state = self.observe(label)
        q = TEST + 16
        state.update(
            total=self.i(q + 20),
            batch=self.i(q + 24),
            latencies=[self.i(self.q(q + 32) + 4 * i) for i in range(self.i(q + 48))],
            samples=[
                bytes(self.u.mem_read(self.q(q + 56) + 12 * i, 12)).hex()
                for i in range(self.i(q + 72))
            ],
            average=bytes(self.u.mem_read(q + 112, 12)).hex(),
            full_count=self.i(q + 104),
            full=[
                list(struct.unpack("<II", self.u.mem_read(self.q(q + 88) + 8 * i, 8)))
                for i in range(self.i(q + 104))
            ],
            receive_delay=getattr(self, "constructor_delay", None),
            frame_count=len(self.frames),
            accepted=len(self.accepted),
            tick=self.now,
        )
        self.trace.append(state)

    def initialize(self):
        super().initialize(dict(bitrate=self.inputs.get("bitrate", 20000)))
        # Re-enter the original post-connect handshake boundary. No auth
        # request/response is injected by the old setup's direct-state shortcut.
        self.call(
            self.symbols["_ZN12CNetworkTest15SetSessionStateENS_13ESessionStateE"],
            TEST,
            2,
        )
        self.now = self.inputs.get("start", 1000000)
        self.wi(TEST + 0x130, self.now)
        channel31 = self.call(
            self.symbols["_ZN17CStreamConnection10GetChannelEh"], self.connection, 31
        )
        self.constructor_delay = self.i(channel31 + 28)
        assert self.constructor_delay == 65
        self.call(
            self.symbols["_ZN17CStreamConnection22SetChannelMaxRecvDelayEhi"],
            self.connection,
            3,
            self.constructor_delay,
        )
        token = bytes(range(self.inputs.get("key_length", 32)))
        ptr = self.alloc(len(token) + 1)
        if token:
            self.u.mem_write(ptr, token)
        self.call(
            self.symbols["_ZN12CNetworkTest12SetAuthTokenEPKvi"], TEST, ptr, len(token)
        )
        transport, vt = self.alloc(512), self.alloc(512)
        self.wq(transport, vt)
        self.wq(vt + 56, RETURN + 8)
        self.wq(TEST + 0x120, transport)
        self.snapshot("started")

    def drive(self):
        self.snapshot("before_global_" + str(self.event_index))
        if self.i(TEST + 0x114) == 0:
            self.ret()
            return
        if self.event_index == len(self.inputs["events"]) and self.i(TEST + 0x114) == 5:
            self.calls.append("empty_finishing_network_cycle")
            self.ret()
            return
        assert self.event_index < len(self.inputs["events"]), (
            "event driver exhausted",
            self.inputs,
            self.trace[-1],
        )
        event = self.inputs["events"][self.event_index]
        self.event_index += 1
        self.now = (self.inputs.get("start", 1000000) + event[0]) & 0xFFFFFFFF
        self.saved_context = self.u.context_save()
        op, *args = event[1:]
        if op == "C":
            tag, body = args
            wire = (
                struct.pack(
                    "<BBBBBHHI",
                    5,
                    0,
                    34,
                    12,
                    1,
                    0,
                    self.control_pid,
                    (self.now - 65) & 0xFFFFFFFF,
                )
                + bytes([tag])
                + bytes.fromhex(body)
            )
            self.control_pid += 1
            p = self.packet(wire, self.now)
            self.u.reg_write(UC_ARM64_REG_X0, self.sock)
            self.u.reg_write(UC_ARM64_REG_X0 + 1, p)
            self.u.reg_write(UC_ARM64_REG_X0 + 2, self.now)
            self.u.reg_write(UC_ARM64_REG_X30, RETURN + 4)
            self.jump(
                self.symbols["_ZN13CStreamSocket12HandlePacketEP13CStreamPacketj"]
            )
        elif op == "D":
            fid = args[0]
            wire = struct.pack(
                "<BBBBBHHI",
                3,
                0,
                34,
                12,
                3,
                0,
                self.data_pid,
                (self.now - 65) & 0xFFFFFFFF,
            ) + media.data(fid, (self.now - 65) & 0xFFFFFFFF)
            self.data_pid += 1
            p = self.packet(wire, self.now)
            self.u.reg_write(UC_ARM64_REG_X0, self.sock)
            self.u.reg_write(UC_ARM64_REG_X0 + 1, p)
            self.u.reg_write(UC_ARM64_REG_X0 + 2, self.now)
            self.u.reg_write(UC_ARM64_REG_X30, RETURN + 4)
            self.jump(
                self.symbols["_ZN13CStreamSocket12HandlePacketEP13CStreamPacketj"]
            )
        elif op in ("K", "X"):
            self.u.reg_write(UC_ARM64_REG_X0, TEST)
            self.u.reg_write(UC_ARM64_REG_X0 + 1, self.connection)
            self.u.reg_write(UC_ARM64_REG_X30, RETURN + 4)
            name = (
                "_ZN12CNetworkTest6CancelEv"
                if op == "K"
                else "_ZN12CNetworkTest20OnStreamDisconnectedEP17CStreamConnection"
            )
            self.jump(self.symbols[name])
        else:
            assert op == "T"
            self.after_socket()

    def after_socket(self):
        self.u.reg_write(UC_ARM64_REG_X0, self.connection)
        self.u.reg_write(UC_ARM64_REG_X0 + 1, self.now)
        self.u.reg_write(UC_ARM64_REG_X30, RETURN)
        self.jump(self.symbols["_ZN17CStreamConnection6UpdateEj"])

    def return_to_driver(self):
        context = self.saved_context
        assert context is not None
        self.saved_context = None
        self.u.context_restore(context)
        self.snapshot("after_network_" + str(self.event_index))
        self.ret()


def schedules():
    server = [0, "C", 7, "0a0308c00b"]
    good = [1, "C", 2, "1001"]
    for bitrate in (20000, -1):
        yield dict(
            name=f"success_{bitrate}",
            bitrate=bitrate,
            events=[server, good, [2, "D", 599]]
            + ([] if bitrate > 0 else [[196610, "T"], [196611, "T"]]),
        )
    for key_length in (16, 32):
        yield dict(
            name=f"hmac_{key_length}",
            key_length=key_length,
            events=[server, good, [2, "D", 599]],
        )
    for name, body, ok in (
        ("absent_version", "", False),
        ("version0", "1000", False),
        ("unknown_version", "1002", False),
        ("failed", "08011001", False),
        ("unknown_result", "08021001", True),
        ("known_then_unknown_version", "10011002", True),
        ("last_result_success", "080108001001", True),
    ):
        yield dict(
            name=name,
            events=[server, [1, "C", 2, body]] + ([[2, "D", 599]] if ok else []),
        )
    for state, prefix in ((2, []), (3, [server]), (4, [server, good])):
        for op in ("K", "X"):
            yield dict(name=f"{op}_phase{state}", events=prefix + [[2, op]])
    for name, payload in (
        ("empty_info", "0a00"),
        ("small_mtu", "0a03088002"),
        ("large_mtu", "0a0308d00f"),
    ):
        yield dict(name=name, events=[[0, "C", 7, payload], good, [2, "D", 599]])
    yield dict(
        name="missing_info_timeout",
        events=[[0, "C", 7, ""], [655360, "T"], [655361, "T"]],
    )
    yield dict(name="handshake_timeout", events=[[655360, "T"], [655361, "T"]])
    yield dict(
        name="handshake_timeout_wrap",
        start=0xFFFF0000,
        events=[[655360, "T"], [655361, "T"]],
    )
    yield dict(
        name="malformed_auth_then_disconnect",
        events=[server, [1, "C", 2, "10"], [2, "X"]],
    )
    yield dict(name="connect_failure_boundary", connect=False, events=[])
    yield dict(name="media_before_handshake", events=[[0, "D", 599]])
    for bitrate in (20000, -1):
        yield dict(
            name=f"timeout_then_late_media_{bitrate}",
            bitrate=bitrate,
            events=[server, good, [2, "D", 0], [196611, "T"], [196612, "D", 599]],
        )
    yield dict(
        name="bandwidth_targets_and_full_samples",
        bitrate=-1,
        events=[server, good, [2, "C", 94, "08a08d06"], [3, "D", 0],
                [4, "C", 94, "089f8d06"], [5, "D", 1], [196614, "T"]],
    )


def run(binary, inp, patch=None):
    r = Lifecycle(binary, inp, patch)
    r.initialize()
    r.running = True
    r.call(r.symbols["_ZN12CNetworkTest14RunNetworkTestEv"], TEST)
    r.running = False
    r.snapshot("returned")
    assert not r.assertions, (inp, r.assertions)
    for q in r.hmac_calls:
        assert bytes.fromhex(q["plain"]) == b"Steam In-Home Streaming"
    expected = hmac.new(
        bytes(range(inp.get("key_length", 32))),
        b"Steam In-Home Streaming",
        hashlib.sha256,
    ).digest()
    for frame in r.frames:
        body = bytes.fromhex(frame["body"])
        if frame["channel"] == 1 and body[:1] == b"\x01":
            assert body == b"\x01\x0a\x20" + expected + b"\x10\x01", body.hex()
    return dict(
        input=inp,
        trace=r.trace,
        frames=r.frames,
        hmac=r.hmac_calls,
        closes=r.closes,
        loop_calls=r.calls,
        executed=sorted(r.executed),
        accepted=r.accepted,
        completed_scores=r.completed_scores,
        source_assertions=r.assertions,
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
    assert hashlib.sha256(binary).hexdigest() == media.flow.SHA
    cases = []
    for inp in schedules():
        cases.append(run(binary, inp))
        print(inp["name"], cases[-1]["trace"][-1]["status"], flush=True)
    report = dict(
        binary_sha256=media.flow.SHA,
        scope=__doc__,
        functions=inventory(binary, cases),
        cases=cases,
    )
    original = next(c for c in cases if c["input"]["name"] == "handshake_timeout")
    r = Lifecycle(binary, {})
    pc = 0xCA9E5C
    before = r.i(pc)
    assert before & 0xFF00001F == 0x54000005  # B.PL (signed >=0)
    after = (before & ~15) | 12  # B.GT: wrongly expire at equality.
    mutant = run(binary, original["input"], (pc, before, after))
    assert mutant["patch_hits"] == [pc]
    assert len(mutant["trace"]) < len(original["trace"])
    assert mutant["trace"][-1]["status"] == original["trace"][-1]["status"] == 4
    report["mutation"] = dict(pc=pc, before=before, after=after, original=original, mutant=mutant)
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
        "Official network-test lifecycle:",
        len(cases),
        "cases,",
        sum(len(c["trace"]) for c in cases),
        "checkpoints",
    )


if __name__ == "__main__":
    main()
