#!/usr/bin/env python3
"""Replay official Linux player config delegates, nested config and reset actor.

The pinned CLIENT executes full CStreamPlayer/base constructors, its real vtable
config delegate, overlay/fullscreen/microphone helpers, real API/peer99 control
dispatcher, codec reset request and actor. Original AVCodec send EIO also runs.
Player startup's hardware-cache copy is a labelled original instruction span;
it is not full SDL/player Init. Fullscreen/overlay active state, post-auth and
configured decoder are declared boundaries. No Qt startup/physical UI or SDK
natural-error mapping is claimed. The selected microphone input is unavailable.

SDK status/context/memory, SDL IO/window/OS/math/strings, file save, encryption,
connection completion and final Channel sends remain declared terminals from
the existing client audits. Statistics enum-name lookup is a diagnostic terminal;
enum validation still executes original instructions. The real config delegate is observed, never replaced.
Source snapshots retain original protobuf serialization; no original binary or
invented pixels are distributed. Original CPU bootstrap assert is separate;
all measured actions and instruction mutants must return without source asserts.
"""

import argparse
from collections import Counter
import ctypes as ct
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

from unicorn.x86_const import UC_X86_REG_RBX, UC_X86_REG_XMM0, UC_X86_REG_XMM1

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "fec", ROOT / "scripts/audit-steam-client-linux-fec.py"
)
fec = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fec)
codec = fec.codec
FUNCTIONS = {
    0x337610: "player_constructor",
    0x2EE0F0: "player_base_constructor",
    0x32A250: "player_config_delegate",
    0x329C10: "toggle_overlay",
    0x329BE0: "update_overlay",
    0x329810: "can_toggle_fullscreen",
    0x3298B0: "toggle_fullscreen",
    0x32A200: "toggle_microphone",
    0x32A000: "close_microphone",
    0x32A060: "open_microphone",
    0x32A050: "can_open_microphone",
    0x2FC260: "microphone_encoder_constructor",
    0x2FC410: "microphone_encoder_shutdown",
    0x31BD50: "stop_microphone_stream",
    0x319360: "request_decoder_reset",
    0x1A9B40: "atomic_flag_set",
    0x31F9D0: "pending_reset_actor",
    0x2EDC50: "decoder_restart",
    0x2EDBF0: "decoder_stop",
    0x2ED980: "decoder_start",
    0x324610: "avcodec_constructor",
    0x3246D0: "avcodec_start",
    0x324840: "avcodec_stop",
    0x2EEAC0: "player_flush",
    0x325BD0: "video_stop",
    0x324190: "avcodec_final_decode",
    0x321F80: "set_client_config",
    0x322B90: "control_dispatcher",
    0x322060: "peer_client_config",
    0x48FCA0: "config_copy",
    0x45A330: "config_constructor",
    0x44BD20: "config_byte_size",
    0x7C9920: "protobuf_parse_array",
    0x7C9A90: "protobuf_serialize_array",
    0x1947A0: "frame_send",
}
INIT_SPAN = (0x33E59C, 0x33E5B7)


class Player(fec.Client):
    def __init__(self, binary, case, patch=None):
        self.config_visits = Counter()
        self.driver = case.get("driver", "dummy")
        self.saved = []
        super().__init__(binary, bytes.fromhex(case["initial_config"]), patch=patch)
        self.action("connect")
        self.action("connected")
        self.player = self.alloc(0x10000)
        self.call(0x337610, self.player, self.client, 0, 0)
        assert not self.assertions and self.q(self.player) == 0x11001A0
        assert self.q(self.client + 48) == self.player
        assert self.q(self.player + 8) == self.client
        assert self.q(0x11001A0 + 128) == 0x32A250
        assert self.q(self.player + 0x470) == self.client
        self.constructor_hardware = self.u.mem_read(self.player + 0x6F3, 1)[0]
        self.hooks[INIT_SPAN[1]] = lambda: self.ret()
        self.u.reg_write(UC_X86_REG_RBX, self.player)
        self.call(INIT_SPAN[0])
        self.window = self.alloc(64)
        self.wq(self.player + 0x598, self.window)
        # Explicit active-window/player boundary; not full SDL Init.
        self.u.mem_write(
            self.player + 0x5F3, bytes([not self.u.mem_read(self.config + 115, 1)[0]])
        )
        self.u.mem_write(
            self.player + 0xDA4, bytes(self.u.mem_read(self.config + 104, 1))
        )
        self.u.mem_write(
            self.player + 0x468, bytes(self.u.mem_read(self.config + 106, 1))
        )
        self.wi(self.client + 256, 6)
        self.u.mem_write(self.client + 16, b"\1")
        self.calls, self.step = [], 0
        self.sdk_format, self.sdk_size, self.sdk_pts = 0, (128, 72), 123456
        self.input_size, self.parsed_size = 2204, None
        self.call(0x324610, self.dec, self.client, self.player, 4)
        self.bootstrap_assertions = list(self.assertions)
        assert self.bootstrap_assertions == [[2919, 0x8C88D0]]
        self.assertions = []
        self.wq(self.client + 40, self.dec)
        self.u.mem_write(self.client + 0x272, b"\3")
        self.wi(self.dec + 0x184, 128)
        self.wi(self.dec + 0x188, 72)
        self.call(0x3246D0, self.dec, self.alloc(64))
        self.u.mem_write(self.dec + 100, b"\0")  # Declared single-thread scheduling.
        self.call(0x2EDBF0, self.dec)
        self.call(0x2ED980, self.dec, self.dec + 32)
        assert self.u.mem_read(self.dec + 24, 1) == b"\1"
        self.ctx = self.q(self.dec + 0x268)
        self.raw = self.alloc(65536)
        self.payload = (ROOT / "app/tests/fixtures/video/sequential.h264").read_bytes()[
            :2204
        ]
        self.u.mem_write(self.raw, self.payload)
        self.events, self.writes = [], []
        self.enum_descriptor = self.alloc(32)
        self.hooks[0x44B110] = lambda: self.ret(self.enum_descriptor)
        self.hooks[0x845860] = self.enum_name

    def enum_name(self):
        assert self.arg(0) == self.enum_descriptor
        result = self.alloc(32)
        self.wq(result, result + 16)
        self.events.append(["diagnostic_enum_name_terminal", self.arg(1)])
        self.ret(result)

    def freeze(self, config):
        copy = self.alloc(256)
        self.u.mem_write(copy, bytes(self.u.mem_read(config, 256)))
        return copy

    def save(self):
        self.events.append(["save_snapshot", self.freeze(self.config)])
        self.ret()

    def hook(self, u, pc, size, data):
        if pc in FUNCTIONS:
            self.config_visits[pc] += 1
        if pc == 0x32A250:
            self.events.append(
                ["notify_snapshot", self.freeze(self.arg(1)), self.arg(2)]
            )
        elif pc == 0x319360:
            self.events.append(["reset_request", self.arg(1)])
        elif pc == 0x2EDC50:
            self.events.append(["decoder_restart"])
        elif pc == 0x1780C0:
            # Recovery observer also records this; keep its original entry.
            pass
        if pc in (0x1A8E50, 0x1AA0A0, 0x1A92F0):
            self.ret()  # OS event/thread-object construction/wake; no OS workers.
            return
        name = self.names.get(pc, "")
        if name in ("SDL_strcmp", "strcmp"):
            a, b = self.cstring(self.arg(0)), self.cstring(self.arg(1))
            self.ret((a > b) - (a < b))
        elif name == "SDL_GetPrefPath":
            self.ret(self.string(b"/tmp/official-client-fixture/"))
        elif name == "SDL_GetCurrentVideoDriver":
            self.ret(self.string(self.driver.encode()))
        elif name == "SDL_GetDisplays":
            self.wi(self.arg(0), 1)
            pointer = self.alloc(16)
            self.wi(pointer, 1)
            self.ret(pointer)
        elif name in (
            "SDL_RestoreWindow",
            "SDL_SetWindowMouseGrab",
            "SDL_SetWindowFullscreen",
        ):
            assert self.arg(0) == self.window
            self.events.append(
                ["window_terminal", name]
                + ([] if name == "SDL_RestoreWindow" else [self.arg(1)])
            )
            self.ret(1)
        elif name == "SDL_IOFromFile":
            self.ret(0)
        elif name == "SDL_GetError":
            self.ret(self.string(b"fixture IO unavailable"))
        elif name == "SDL_free":
            self.ret()
        elif name == "powf":
            function = ct.CDLL("libm.so.6").powf
            function.argtypes, function.restype = [ct.c_float, ct.c_float], ct.c_float
            values = [
                struct.unpack(
                    "<f", struct.pack("<I", self.u.reg_read(reg) & 0xFFFFFFFF)
                )[0]
                for reg in (UC_X86_REG_XMM0, UC_X86_REG_XMM1)
            ]
            self.u.reg_write(
                UC_X86_REG_XMM0,
                struct.unpack("<I", struct.pack("<f", function(*values)))[0],
            )
            self.ret()
        else:
            super().hook(u, pc, size, data)

    def string(self, value):
        pointer = self.alloc(len(value) + 1)
        self.u.mem_write(pointer, value + b"\0")
        return pointer

    def serialize_at(self, pointer):
        old = self.config
        self.config = pointer
        try:
            return self.serialize_config()
        finally:
            self.config = old

    def state(self):
        if not hasattr(self, "constructor_hardware"):
            return super().state()
        assert not self.assertions, self.assertions
        events = []
        for event in self.events:
            if event[0] == "notify_snapshot":
                events.append(["notify", self.serialize_at(event[1]), event[2]])
            elif event[0] == "save_snapshot":
                events.append(["save", self.serialize_at(event[1])])
            else:
                events.append(event)
        return dict(
            config=self.serialize_config(),
            cache_hardware=bool(self.u.mem_read(self.player + 0x6F3, 1)[0]),
            cache_microphone=bool(self.u.mem_read(self.player + 0x468, 1)[0]),
            fullscreen=bool(self.u.mem_read(self.player + 0x5F3, 1)[0]),
            overlay=bool(self.u.mem_read(self.player + 0xDA4, 1)[0]),
            reset=self.i(self.dec + 96),
            gate=self.u.mem_read(self.conn + 11, 1)[0],
            events=events,
            writes=list(self.writes),
        )

    def action(self, op, value=None):
        self.events, self.writes, self.stage = [], [], op
        if op == "actor":
            self.call(0x31F9D0, self.client)
        elif op == "eio":
            self.feed(dict(send=-5, receive=-11, id=23))
        else:
            return super().action(op, value)
        return self.state()


def scenarios():
    cases = []
    for initial in ("3800", "3801"):
        for hardware in ("", "3800", "3801"):
            wire = hardware + "c80101d00f09"
            for entry in ("api0", "api1", "peer99"):
                action = (
                    ["api", [wire, int(entry[-1])]]
                    if entry.startswith("api")
                    else [
                        "peer99",
                        (
                            bytes([10, len(bytes.fromhex(wire))]) + bytes.fromhex(wire)
                        ).hex(),
                    ]
                )
                cases.append(
                    dict(
                        name=f"hardware_{initial}_{hardware or 'absent'}_{entry}",
                        initial_config=initial,
                        actions=[action, ["actor", None], action, ["actor", None]],
                        native_hardware_projection=True,
                    )
                )
    for driver in ("dummy", "kmsdrm"):
        for flags in range(8):
            wire = (
                "3800"
                + ("4001" if flags & 1 else "")
                + ("7801" if flags & 2 else "")
                + "c80101"
                + ("d80101" if flags & 4 else "")
            )
            for local in (0, 1):
                cases.append(
                    dict(
                        name=f"delegate_{driver}_{flags}_local{local}",
                        driver=driver,
                        initial_config="3801c80101",
                        actions=[["api", [wire, local]], ["actor", None]],
                        native_hardware_projection=False,
                    )
                )
    cases.append(
        dict(
            name="eio_keeps_player_cache",
            initial_config="3801",
            actions=[
                ["eio", None],
                ["actor", None],
                ["api", ["3800", 1]],
                ["actor", None],
                ["api", ["3800", 1]],
                ["actor", None],
                ["peer99", "0a03c80101"],
                ["actor", None],
                ["peer99", "0a023801"],
                ["actor", None],
            ],
            native_hardware_projection=True,
        )
    )
    for hardware in ("", "3800", "3801"):
        wire = hardware + "c80101d00f09"
        for entry in ("api0", "api1", "peer99"):
            action = (
                ["api", [wire, int(entry[-1])]]
                if entry.startswith("api")
                else [
                    "peer99",
                    (bytes([10, len(bytes.fromhex(wire))]) + bytes.fromhex(wire)).hex(),
                ]
            )
            cases.append(
                dict(
                    name=f"hardware_default_{hardware or 'absent'}_{entry}",
                    initial_config="",
                    actions=[action, ["actor", None], action, ["actor", None]],
                    native_hardware_projection=True,
                )
            )
    for case in list(cases):
        if case["name"].startswith("delegate_") and case["name"].endswith("_local1"):
            wire = case["actions"][0][1][0]
            case = dict(
                case,
                name=case["name"].replace("_local1", "_peer99"),
                actions=[
                    [
                        "peer99",
                        (
                            bytes([10, len(bytes.fromhex(wire))]) + bytes.fromhex(wire)
                        ).hex(),
                    ],
                    ["actor", None],
                ],
            )
            cases.append(case)
    return cases


def run(binary, case, patch=None):
    r = Player(binary, case, patch)
    result = dict(case, constructor_hardware=r.constructor_hardware, initial=r.state())
    result["states"] = [r.action(*action) for action in case["actions"]]
    result["entries"] = {FUNCTIONS[pc]: n for pc, n in sorted(r.config_visits.items())}
    result["bootstrap_assertions"] = r.bootstrap_assertions
    result["patch_hits"] = r.patch_hits
    return result


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == codec.SHA
    cases = [run(binary, case) for case in scenarios()]
    for case in cases:
        assert case["constructor_hardware"] == 0
        assert case["initial"]["cache_hardware"] == (
            not case["initial_config"].startswith("3800")
        )
        if case["name"].startswith("delegate_"):
            parts = case["name"].split("_")
            flags, driver = int(parts[2]), parts[1]
            state = case["states"][0]
            count = sum(
                e[0] == "channel_send_terminal" and e[2] == 1 and e[3].startswith("63")
                for e in state["events"]
            )
            assert count == int(parts[3] == "local0") + bool(flags & 2) + bool(
                flags & 4 and driver != "kmsdrm"
            )
            assert state["overlay"] == bool(flags & 1)
            assert state["cache_microphone"] == bool(flags & 2)
            assert state["fullscreen"] == (not (flags & 4 and driver != "kmsdrm"))
    eio = next(c for c in cases if c["name"] == "eio_keeps_player_cache")
    assert [s["cache_hardware"] for s in eio["states"]] == [
        True,
        True,
        False,
        False,
        False,
        False,
        False,
        False,
        True,
        True,
    ]
    assert [s["reset"] for s in eio["states"]] == [1, 0, 1, 0, 0, 0, 0, 0, 1, 0]
    assert all(any(name in c["entries"] for c in cases) for name in FUNCTIONS.values())
    assert all(s["gate"] == 0 for c in cases for s in c["states"])
    checks = []
    for name, case_name, pc, before, after in (
        (
            "omit_hardware_presence",
            "hardware_3800_absent_api1",
            0x32A273,
            "740f",
            "9090",
        ),
        (
            "omit_hardware_reset",
            "hardware_3801_3800_api1",
            0x32A2BA,
            "e8a1f0feff",
            "9090909090",
        ),
        (
            "omit_hardware_cache_update",
            "hardware_3801_3800_api1",
            0x32A2C4,
            "8883f3060000",
            "909090909090",
        ),
        (
            "microphone_suppresses_nested_99",
            "delegate_dummy_2_local1",
            0x32A214,
            "31d2",
            "b201",
        ),
        ("ignore_kmsdrm_guard", "delegate_kmsdrm_4_local1", 0x329864, "7522", "eb22"),
    ):
        case = next(c for c in cases if c["name"] == case_name)
        mutated = run(
            binary,
            next(c for c in scenarios() if c["name"] == case_name),
            (pc, bytes.fromhex(before), bytes.fromhex(after)),
        )
        assert mutated["patch_hits"] and mutated["states"] != case["states"], name
        checks.append(name)
    previous = codec.FUNCTIONS
    try:
        codec.FUNCTIONS = FUNCTIONS
        inventory = codec.inventory(binary)
    finally:
        codec.FUNCTIONS = previous
    return dict(
        binary_sha256=codec.SHA,
        archive_sha256=codec.ARCHIVE_SHA,
        scope=__doc__,
        functions=inventory,
        init_span=dict(
            start=INIT_SPAN[0],
            end=INIT_SPAN[1],
            sha256=hashlib.sha256(binary[INIT_SPAN[0] : INIT_SPAN[1]]).hexdigest(),
        ),
        cases=cases,
        mutation_checks=checks,
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    report = audit(a.binary.read_bytes())
    encoded = (json.dumps(report, indent=2) + "\n").encode()
    path = ROOT / "scripts/fixtures/steam-client-player-config-reference.json.gz"
    if a.refresh_reference:
        if path.exists():
            previous = json.loads(gzip.decompress(path.read_bytes()))
            assert previous["cases"] == report["cases"][: len(previous["cases"])]
            assert {k: v for k, v in previous.items() if k != "cases"} == {
                k: v for k, v in report.items() if k != "cases"
            }
        path.write_bytes(gzip.compress(encoded, mtime=0))
    else:
        assert json.loads(gzip.decompress(path.read_bytes())) == report
    a.output.write_bytes(encoded)
    print(
        "Official player config:",
        len(report["cases"]),
        "cases,",
        sum(len(c["states"]) for c in report["cases"]),
        "states,",
        len(FUNCTIONS),
        "functions,",
        len(report["mutation_checks"]),
        "mutations",
    )


if __name__ == "__main__":
    main()
