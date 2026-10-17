#!/usr/bin/env python3
"""Replay official Linux AVCodec EIO config mutation, reset actor and format choice.

The pinned official CLIENT runs its config constructor/parser/serializer,
FinalDecode, complete Client::OnThink/HandlePendingResets, original decoder
stop/restart/start, format callback/selector and decoder-info/control serializer.
The configured decoder and original base player are instantiated independently
of Qt/startup. Single-thread decoder mode is an explicit scheduling input.

SDK results/capabilities/contexts, allocator/C++ string storage, libc formatting,
OS locks/guards and absent environment/dynamic graphics libraries are terminals.
Client network/control-drain/Streaming/Stats pumps, control encryption and config save/notify are
labelled terminals; no full network/producer/UI, real HW success, NVTEGRA status
mapping, physical pixels or SDK ABI/startup equivalence is claimed. The real
Linux hardware constructors/availability failures execute; none is replaced by
an internal success result. Packet send terminates at the original connection
handoff after the encryption terminal, retaining full plaintext bodies (not
encrypted wire). A configured window handle is an external SDL input.
Source releases are observed in
an emulated heap, not a physical resource/lifecycle proof.
"""

import argparse
from collections import Counter
import ctypes as ct
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "avcodec_source", ROOT / "scripts/audit-steam-client-avcodec.py"
)
codec = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(codec)
SDK_CODEC_SHA = "c53a7e3d32a986323ec6bedd28df73a6e5842c4753b67b1d2aa0d6e4f524472f"
FUNCTIONS = dict(codec.FUNCTIONS)
FUNCTIONS.update(
    {
        0x45A330: "client_config_constructor",
        0x7C9920: "protobuf_parse_array",
        0x468240: "client_config_parse",
        0x44BD20: "client_config_byte_size",
        0x44C9C0: "client_config_serialize",
        0x7C9A90: "protobuf_serialize_array",
        0x3230A0: "client_on_think",
        0x31F9D0: "handle_pending_resets",
        0x2EDC50: "decoder_restart",
        0x2EDBF0: "decoder_stop",
        0x2ED980: "decoder_start",
        0x324840: "avcodec_stop",
        0x325BD0: "video_stop",
        0x2EE0F0: "player_base_constructor",
        0x2EEAC0: "player_flush",
        0x2EDF70: "player_put",
        0x324D00: "sdk_format_callback",
        0x324C90: "format_thread_dispatch",
        0x324990: "select_format",
        0x31DD40: "send_decoder_info",
        0x31AF60: "send_control",
        0x458010: "decoder_info_constructor",
        0x2DBC60: "hardware_base_constructor",
        0x2E6600: "gamescope_vaapi_constructor",
        0x2E60F0: "gamescope_vaapi_available",
        0x2DC3C0: "drm_vaapi_constructor",
        0x2DC2A0: "drm_vaapi_available",
        0x2DBDD0: "vaapi_load_library",
        0x2E6EB0: "x11_vaapi_constructor",
        0x2E7A60: "x11_vaapi_available",
        0x1780A0: "supported_hw_format",
    }
)


class Recovery(codec.Client):
    def __init__(self, binary, wire):
        self.entered = Counter()
        super().__init__(binary)
        self.bootstrap_assertions = list(self.assertions)
        assert self.bootstrap_assertions == [[2919, 0x8C88D0]]
        self.assertions = []
        self.config = self.client + 456
        self.call(0x45A330, self.config)
        data = self.alloc(len(wire) + 64)
        if wire:
            self.u.mem_write(data, wire)
        assert self.call(0x7C9920, self.config, data, len(wire)) == 1
        assert self.q(self.config) == 0x110BFA0
        self.wi(self.client + 256, 0)
        self.call(0x2EE0F0, self.player, self.client)
        self.wi(self.client + 256, 6)
        self.u.mem_write(self.dec + 100, b"\0")  # Declared single-thread mode.
        self.wq(self.client + 264, self.alloc(64))
        self.u.mem_write(self.client + 16, b"\1")
        self.wq(0x13C5470, self.alloc(64))  # Configured external SDL window.
        self.hooks[0x194B60] = self.control_encryption_terminal
        for pc, name in (
            (0x191F90, "network"),
            (0x322B90, "control_drain"),
            (0x31FFC0, "streaming"),
            (0x31BB10, "stats_pump"),
            (0x31A010, "save_config"),
        ):
            self.hooks[pc] = lambda name=name: (
                self.events.append(["terminal", name]),
                self.ret(),
            )
        # Constructed base player has no actual UI consumer for config notices.
        self.hooks[codec.STOP + 0xF100] = lambda: (
            self.events.append(["notify"]),
            self.ret(),
        )
        self.call(0x2EDBF0, self.dec)
        self.call(0x2ED980, self.dec, self.dec + 32)
        assert self.u.mem_read(self.dec + 24, 1) == b"\1"
        self.events = []

    def cstring(self, p):
        data = bytearray()
        while self.u.mem_read(p + len(data), 1)[0]:
            data += self.u.mem_read(p + len(data), 1)
            assert len(data) < 65536
        return bytes(data)

    def control_encryption_terminal(self):
        frame = self.arg(0)
        packet = self.q(frame + 8)
        start = self.q(packet + 56) + 13
        self.events.append(
            [
                "control_plaintext",
                bytes(self.u.mem_read(start, self.i(packet + 52) - 13)).hex(),
            ]
        )
        self.ret(1)

    def format_string(self):
        # Translate the SysV va_list's GP arguments for the real host snprintf.
        # Only the observed integer/string format family is admitted; no %n,
        # floats, raw emulated pointers or unbounded C output enter host libc.
        fmt, va = self.cstring(self.arg(1)), self.arg(2)
        specs = re.findall(rb"%[-0-9.]*(?:ll|l|z)?[sdiuxX]", fmt)
        assert fmt.count(b"%") == len(specs)
        gp, overflow, save = self.i(va), self.q(va + 8), self.q(va + 16)
        args = []
        for spec in specs:
            if gp < 48:
                value, gp = self.q(save + gp), gp + 8
            else:
                value, overflow = self.q(overflow), overflow + 8
            if spec.endswith(b"s"):
                args.append(ct.c_char_p(self.cstring(value)))
            elif any(x in spec for x in (b"l", b"z")):
                args.append(ct.c_uint64(value))
            else:
                args.append(ct.c_int(value & 0xFFFFFFFF))
        buf = ct.create_string_buffer(4096)
        libc = ct.CDLL(None)
        libc.snprintf.restype = ct.c_int
        count = libc.snprintf(buf, 4096, ct.c_char_p(fmt), *args)
        assert 0 <= count < 4096
        dest = self.alloc(count + 1)
        self.u.mem_write(dest, buf.raw[: count + 1])
        self.wq(self.arg(0), dest)
        self.ret(count)

    def hook(self, u, pc, size, data):
        if pc in FUNCTIONS and pc not in codec.FUNCTIONS:
            self.entered[pc] += 1
        if pc == 0x1780C0:
            self.events.append(["codec_preference", self.arg(1)])
        elif pc == 0x2EDF70:
            self.events.append(["player_put", self.i(self.arg(1) + 40) & 65535])
        elif pc in (0x2EDC50, 0x324840, 0x2ED980):
            self.events.append(["actor", FUNCTIONS[pc]])
        name = self.names.get(pc, "")
        if name == "avcodec_get_hw_config":
            # H264 metadata independently read from the pinned bundled SDK.
            # Enumeration keeps one codec; other capabilities remain terminals.
            configs = ((44, 11, 3), (98, 11, 1))
            index = self.arg(1)
            if index < len(configs):
                p = self.alloc(16)
                self.u.mem_write(p, struct.pack("<iii", *configs[index]))
                self.ret(p)
            else:
                self.ret(0)
        elif name in ("__cxa_atexit", "SDL_UnloadObject"):
            self.ret()
        elif name == "__cxa_guard_acquire":
            self.ret(not self.u.mem_read(self.arg(0), 1)[0])
        elif name == "__cxa_guard_release":
            self.u.mem_write(self.arg(0), b"\1")
            self.ret()
        elif name == "pthread_self":
            self.ret(1)
        elif name in ("getenv", "SDL_LoadObject"):
            self.events.append(
                ["platform_absent", name, self.cstring(self.arg(0)).decode()]
            )
            self.ret(0)
        elif name == "strlen":
            self.ret(len(self.cstring(self.arg(0))))
        elif name == "vasprintf":
            self.format_string()
        elif name == "malloc":
            self.ret(self.alloc(self.arg(0)))
        elif "_M_createERmm" in name:
            self.ret(self.alloc(self.q(self.arg(1)) + 1))
        elif name in ("memset", "memmove"):
            dest, length = self.arg(0), self.arg(2)
            if length:
                content = (
                    bytes([self.arg(1) & 255]) * length
                    if name == "memset"
                    else bytes(self.u.mem_read(self.arg(1), length))
                )
                self.u.mem_write(dest, content)
            self.ret(dest)
        elif name in ("avcodec_free_context", "av_frame_free"):
            self.events.append(["sdk_free", name])
            self.wq(self.arg(0), 0)
            self.ret()
        elif name == "av_parser_close":
            self.events.append(["sdk_close_parser"])
            self.ret()
        elif name == "avcodec_open2":
            self.wi(self.arg(0) + 0x290, 1)  # Declared SDK thread metadata.
            super().hook(u, pc, size, data)
        else:
            super().hook(u, pc, size, data)

    def serialize_config(self):
        size = self.call(0x44BD20, self.config)
        dest = self.alloc(size + 64)
        assert self.call(0x7C9A90, self.config, dest) == dest + size
        return bytes(self.u.mem_read(dest, size)).hex()

    def state(self):
        assert not self.assertions, self.assertions
        return dict(
            events=list(self.events),
            config=self.serialize_config(),
            hardware=bool(self.u.mem_read(self.config + 156, 1)[0]),
            has_hardware=bool(self.i(self.config + 16) & 0x10000000),
            reset=self.i(self.dec + 96),
            active=bool(self.u.mem_read(self.dec + 24, 1)[0]),
            selected_format=struct.unpack("<i", self.u.mem_read(self.dec + 0x2C8, 4))[
                0
            ],
        )

    def action(self, op, value):
        self.events, self.assertions = [], []
        if op == "submit":
            self.feed(value)
        elif op == "actor":
            self.call(0x3230A0, self.client)
        elif op == "format":
            formats = self.alloc(4 * (len(value) + 1))
            self.u.mem_write(
                formats, struct.pack("<" + "i" * (len(value) + 1), *value, -1)
            )
            result = self.call(0x324D00, self.q(self.dec + 0x268), formats)
            self.events.append(["format_return", result & 0xFFFFFFFF])
        else:
            raise AssertionError(op)
        return self.state()


def scenarios():
    cases = []
    for label, wire in (
        ("default", ""),
        ("true", "3801"),
        ("false", "3800"),
        ("mixed_unknown", "08013801c80101d00f09"),
    ):
        for status in (-5, -11, -12, 0):
            actions = [
                ["format", [44, 0]],
                ["submit", dict(send=status, receive=-11, id=23)],
                ["actor", None],
                ["format", [44, 0]],
                ["actor", None],
            ]
            cases.append(
                dict(name=f"{label}_send_{status}", config=wire, actions=actions)
            )
    for label, wire in (("true", "3801"), ("false", "3800")):
        cases.append(
            dict(
                name=f"{label}_eio_output",
                config=wire,
                actions=[
                    ["submit", dict(send=-5, receive=0, id=23)],
                    ["actor", None],
                    ["format", [44, 12]],
                ],
            )
        )
    cases.extend(
        [
            dict(
                name="receive_eio_preserves_preference",
                config="3801",
                actions=[
                    ["submit", dict(send=0, receive=-5, id=23)],
                    ["actor", None],
                    ["format", [44, 0]],
                ],
            ),
            dict(
                name="eio_recovery_next_input",
                config="08013801c80101d00f09",
                actions=[
                    ["format", [44, 0]],
                    ["submit", dict(send=-5, receive=-11, id=23)],
                    ["actor", None],
                    ["format", [44, 0]],
                    ["submit", dict(send=0, receive=0, id=24, native_key=True)],
                    ["actor", None],
                ],
            ),
            dict(
                name="disabled_without_software_format",
                config="3800",
                actions=[
                    ["format", [44]],
                    ["actor", None],
                ],
            ),
        ]
    )
    return cases


def run(binary, case, patch=None):
    r = Recovery(binary, bytes.fromhex(case["config"]))
    if patch:
        pc, expected, changed = patch
        assert bytes(r.u.mem_read(pc, len(expected))) == expected
        r.u.mem_write(pc, changed)
        r.u.ctl_remove_cache(pc, pc + len(changed))
    result = dict(case, initial=r.state())
    result["states"] = [r.action(*action) for action in case["actions"]]
    result["entries"] = {
        FUNCTIONS[pc]: count for pc, count in sorted(r.entered.items())
    }
    result["bootstrap_assertions"] = r.bootstrap_assertions
    return result


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == codec.SHA
    cases = [run(binary, case) for case in scenarios()]
    for case in cases:
        for (op, value), state in zip(case["actions"], case["states"], strict=True):
            assert not any(
                row[0] == "notify"
                or row[:2] == ["terminal", "save_config"]
                or (row[0] == "control_plaintext" and row[1].startswith("63"))
                for row in state["events"]
            )
            if op == "submit" and value["send"] == -5:
                assert state["has_hardware"] and not state["hardware"]
    assert all(
        any(name in case["entries"] for case in cases) for name in FUNCTIONS.values()
    )
    checks = []
    shape = next(case for case in cases if case["name"] == "default_send_-5")
    for label, pc, changed in (
        ("omit_eio_presence", 0x3245DA, bytes(10)),
        ("omit_eio_value", 0x3245E4, bytes(7)),
        ("omit_pending_reset_actor", 0x3230B9, bytes(5)),
        ("ignore_hardware_preference", 0x324A3C, bytes(6)),
    ):
        changed = b"\x90" * len(changed)
        before = binary[pc : pc + len(changed)]
        mutant = run(
            binary,
            {k: shape[k] for k in ("name", "config", "actions")},
            (pc, before, changed),
        )
        assert mutant["states"] != shape["states"], label
        checks.append(label)
    previous = codec.FUNCTIONS
    try:
        codec.FUNCTIONS = FUNCTIONS
        functions = codec.inventory(binary)
    finally:
        codec.FUNCTIONS = previous
    return dict(
        binary_sha256=codec.SHA,
        archive_sha256=codec.ARCHIVE_SHA,
        scope=__doc__,
        functions=functions,
        cases=cases,
        mutation_checks=checks,
    )


def check_sdk_metadata(path):
    assert hashlib.sha256(path.read_bytes()).hexdigest() == SDK_CODEC_SHA
    util = path.parent / "libavutil.so.59"
    assert hashlib.sha256(util.read_bytes()).hexdigest() == codec.SDK_SHA
    ct.CDLL(str(util.resolve()), mode=ct.RTLD_GLOBAL)
    sdk = ct.CDLL(str(path.resolve()))
    sdk.avcodec_find_decoder_by_name.argtypes = [ct.c_char_p]
    sdk.avcodec_find_decoder_by_name.restype = ct.c_void_p
    sdk.avcodec_get_hw_config.argtypes = [ct.c_void_p, ct.c_int]
    sdk.avcodec_get_hw_config.restype = ct.c_void_p
    h264 = sdk.avcodec_find_decoder_by_name(b"h264")
    assert h264
    values = []
    for index in range(16):
        p = sdk.avcodec_get_hw_config(h264, index)
        if not p:
            break
        values.append([ct.c_int.from_address(p + n).value for n in (0, 4, 8)])
    assert values == [[44, 11, 3], [98, 11, 1]]
    print("Bundled H264 HW metadata (no decoder open/gate alteration):", values)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--refresh-reference", action="store_true")
    parser.add_argument("--sdk-library", type=Path)
    args = parser.parse_args()
    report = audit(args.binary.read_bytes())
    if args.sdk_library:
        check_sdk_metadata(args.sdk_library)
    encoded = (json.dumps(report, indent=2) + "\n").encode()
    path = ROOT / "scripts/fixtures/steam-client-avcodec-recovery-reference.json.gz"
    if args.refresh_reference:
        if path.exists():
            old = json.loads(gzip.decompress(path.read_bytes()))
            assert old["cases"] == report["cases"][: len(old["cases"])]
            assert {k: v for k, v in old.items() if k != "cases"} == {
                k: v for k, v in report.items() if k != "cases"
            }
        path.write_bytes(gzip.compress(encoded, mtime=0))
    else:
        assert json.loads(gzip.decompress(path.read_bytes())) == report
    args.output.write_bytes(encoded)
    print(
        "Official AVCodec recovery:",
        len(report["cases"]),
        "cases,",
        sum(len(case["states"]) for case in report["cases"]),
        "states,",
        len(report["functions"]),
        "functions,",
        len(report["mutation_checks"]),
        "mutations",
    )


if __name__ == "__main__":
    main()
