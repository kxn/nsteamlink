#!/usr/bin/env python3
"""Replay official Android client config replacement, API and player delegate.

Original frame envelope, dispatcher, C++ protobuf parser/CopyFrom/serializer and
client branches execute; dedicated player cases execute the real player delegate.
Core-only cases use a recording delegate. File/final network/codec actions, libc
allocation/string storage and packet refcounts are doubles. Initialization-error
text formatting is excluded. No actual network, codec or display runs.
"""

import argparse
import hashlib
import json
import runpy
import struct
from pathlib import Path

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

ROOT = Path(__file__).resolve().parents[1]
BASE = runpy.run_path(str(Path(__file__).with_name("audit-steam-client-fec-policy.py")))
Shell, STOP = BASE["Shell"], BASE["STOP"]
SP, LR, X0 = BASE["UC_ARM64_REG_SP"], BASE["UC_ARM64_REG_X30"], BASE["UC_ARM64_REG_X0"]
SHA = "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"
CLIENT, INPUT, PLAYER = 0x20010000, 0x20020000, 0x20030000
DELEGATE, VTABLE = 0x20040000, 0x20050000


class Core(Shell):
    def __init__(self, binary):
        super().__init__(binary)
        self.actions = []
        self.callbacks.update(
            {
                0x974564: lambda: self.ret(),  # Diagnostic formatting only; required checks execute.
                0xC0A7A0: self.save_config,
                0xC0E110: self.send_control,
                STOP + 0x100: self.notify,
            }
        )
        self.call(self.symbols["_ZN22CStreamingClientConfigC1Ev"], CLIENT + 456)
        self.wq(CLIENT + 48, DELEGATE)
        self.wq(DELEGATE, VTABLE)
        self.wq(VTABLE + 128, STOP + 0x100)

    def freeze(self, address, size=208):
        copy = self.alloc(size)
        self.u.mem_write(copy, bytes(self.u.mem_read(address, size)))
        return copy

    def notify(self):
        self.actions.append(
            {"notify": self.freeze(self.r(1)), "local_only": bool(self.r(2))}
        )
        self.ret()

    def save_config(self):
        self.actions.append({"save": self.freeze(self.r(0) + 456)})
        self.ret()

    def send_control(self):
        assert self.r(1) == 99
        self.actions.append({"send": self.freeze(self.r(2), 40)})
        self.ret()

    def serialize(self, address, message="CStreamingClientConfig"):
        symbol = f"_ZNK{len(message)}{message}12ByteSizeLongEv"
        size = self.call(self.symbols[symbol], address)
        dest = self.alloc(size + 64)
        assert self.call(
            self.symbols["_ZNK6google8protobuf11MessageLite16SerializeToArrayEPvi"],
            address,
            dest,
            size,
        )
        return bytes(self.u.mem_read(dest, size))

    def parse(self, address, data, message="CStreamingClientConfig"):
        self.call(self.symbols[f"_ZN{len(message)}{message}C1Ev"], address)
        source = self.alloc(len(data) + 64)
        if data:
            self.u.mem_write(source, data)
        return bool(
            self.call(
                self.symbols["_ZN6google8protobuf11MessageLite14ParseFromArrayEPKvi"],
                address,
                source,
                len(data),
            )
        )

    def result(self):
        events = []
        for action in self.actions:
            if "send" in action:
                events.append(
                    {
                        "send": 99,
                        "payload": self.serialize(
                            action["send"], "CSetStreamingClientConfig"
                        ).hex(),
                    }
                )
            elif "notify" in action:
                events.append(
                    {
                        "notify": self.serialize(action["notify"]).hex(),
                        "local_only": action["local_only"],
                    }
                )
            elif "save" in action:
                events.append({"save": self.serialize(action["save"]).hex()})
            else:
                events.append(action)
        return {"config": self.serialize(CLIENT + 456).hex(), "events": events}

    def receive(self, payload, state=6, channel=1):
        data = (
            struct.pack("<BBBBBHHI", 5, 0, 34, 12, channel, 0, 0, 900000)
            + bytes([99])
            + payload
        )
        packet, queue = self.alloc(max(4096, len(data) + 64)), self.alloc(64)
        self.wq(packet + 40, packet + 64)
        self.wq(packet + 56, packet + 64)
        self.wi(packet + 52, len(data))
        self.u.mem_write(packet + 64, data)
        self.wq(CLIENT + 736, queue)
        self.wq(queue, packet)
        self.wi(CLIENT + 256, state)
        self.callbacks.update(
            {
                0xC0A380: lambda: self.ret(2),
                0xC0A390: lambda: self.ret(1),
                0xC0E120: lambda: self.ret(),
            }
        )
        self.call(0x7A6368, CLIENT)

    def hook(self, uc, address, size, data):
        if address == 0x7C5504:
            self.actions.append(
                {"notify": self.freeze(self.r(1)), "local_only": bool(self.r(2))}
            )
        name = self.plts.get(address, "")
        if name in ("memcpy", "memmove", "__memcpy_chk"):
            if name == "__memcpy_chk":
                assert self.r(2) <= self.r(3)
            if self.r(2):
                self.u.mem_write(
                    self.r(0), bytes(self.u.mem_read(self.r(1), self.r(2)))
                )
            self.ret(self.r(0))
        elif name == "memset":
            if self.r(2):
                self.u.mem_write(self.r(0), bytes([self.r(1) & 255]) * self.r(2))
            self.ret(self.r(0))
        elif "basic_string" in name and any(
            op in name for op in ("6assignEPKc", "6appendEPKc")
        ):
            # libc++ string storage adapter; protobuf parsing/copying is original.
            dest = self.r(0)
            length = (
                self.r(2) if "EPKcm" in name else len(self.cstring(self.r(1)).encode())
            )
            value = bytes(self.u.mem_read(self.r(1), length))
            if "6append" in name:
                tag = self.u.mem_read(dest, 1)[0]
                old_length = self.q(dest + 8) if tag & 1 else tag >> 1
                old_ptr = self.q(dest + 16) if tag & 1 else dest + 1
                value = bytes(self.u.mem_read(old_ptr, old_length)) + value
            length = len(value)
            pointer = self.alloc(length + 1)
            self.u.mem_write(pointer, value + b"\0")
            self.wq(dest, (length + 1) | 1)
            self.wq(dest + 8, length)
            self.wq(dest + 16, pointer)
            self.ret(dest)
        elif "LogInitializationErrorMessage" in name:
            self.ret()
        elif name in ("pthread_mutex_lock", "pthread_mutex_unlock", "Error", "Log"):
            self.ret()
        elif "GetMessageName" in name:
            self.ret(self.alloc(32))
        elif "CSetStreamingClientConfigD" in name:
            self.ret()  # Preserve callback payloads after the stack message retires.
        elif "RepeatedPtrFieldBase" in name and self.symbols.get(name):
            self.jump(self.symbols[name])
        else:
            super().hook(uc, address, size, data)


def audit(binary):
    schema = descriptor_pb2.FileDescriptorProto.FromString(
        binary[0x3E5474 : 0x3E5474 + 21560]
    )
    pool = descriptor_pool.DescriptorPool()
    pool.Add(schema)
    Config = message_factory.GetMessageClass(
        pool.FindMessageTypeByName("CStreamingClientConfig")
    )
    Message = message_factory.GetMessageClass(
        pool.FindMessageTypeByName("CSetStreamingClientConfig")
    )
    initial = Config(
        enable_input_streaming=False,
        enable_audio_streaming=False,
        enable_video_streaming=False,
        enable_unreliable_fec=True,
        enable_video_hevc=True,
        desired_resolution_x=640,
        desired_resolution_y=360,
        desired_bitrate_kbps=12000,
    ).SerializeToString()
    cases = []

    def seed(core):
        assert core.parse(INPUT, initial)
        core.call(0x7B01C4, CLIENT, INPUT, 1)
        core.actions.clear()

    for state in (2, 3, 4, 6):
        for local in (0, 1, 2, 3):
            for present in (False, True):
                core = Core(binary)
                seed(core)
                updated = Config(desired_resolution_x=1280, desired_resolution_y=720)
                if present:
                    updated.enable_unreliable_fec = True
                wire = updated.SerializeToString()
                assert core.parse(INPUT, wire)
                core.wi(CLIENT + 256, state)
                core.call(0x7B01C4, CLIENT, INPUT, local)
                observed = core.result()
                assert bytes.fromhex(observed["config"]) == wire
                assert [next(iter(event)) for event in observed["events"]] == [
                    "notify",
                    "save",
                ] + (["send"] if state == 6 and not local & 1 else [])
                cases.append(
                    {
                        "case": f"setter_s{state}_b{local}_fec{int(present)}",
                        "entry": "setter",
                        "input": {
                            "initial": initial.hex(),
                            "config": wire.hex(),
                            "state": state,
                            "local_only": local,
                        },
                        "observed": observed,
                    }
                )

    for state in (2, 6):
        for local in (0, 1):
            core = Core(binary)
            seed(core)
            wire = Config(
                controller_overlay_hotkey="x" * 4096, enable_unreliable_fec=True
            ).SerializeToString()
            assert core.parse(INPUT, wire)
            core.wi(CLIENT + 256, state)
            core.call(0x7B01C4, CLIENT, INPUT, local)
            cases.append(
                {
                    "case": f"setter_large_s{state}_b{local}",
                    "entry": "setter",
                    "input": {
                        "initial": initial.hex(),
                        "config": wire.hex(),
                        "state": state,
                        "local_only": local,
                    },
                    "observed": core.result(),
                }
            )

    rich = Config(
        enable_unreliable_fec=True,
        controller_overlay_hotkey="config-test",
        display_limit={"mode": {"width": 1280, "height": 720}},
        decoder_limit=[
            {"codec": 2, "bitrate_kbps": 15000},
            {"codec": 1, "mode": {"width": 1920, "height": 1080}},
        ],
    )
    # Unknown tag 150, varint 7, retained by original C++ copy/serialization.
    rich_wire = rich.SerializeToString() + b"\xb0\x09\x07"
    incoming = [
        ("empty_config", Message(config=Config()).SerializeToString()),
        (
            "fec_only",
            Message(config=Config(enable_unreliable_fec=True)).SerializeToString(),
        ),
        (
            "disable_input",
            Message(config=Config(enable_input_streaming=False)).SerializeToString(),
        ),
        ("rich", b"\x0a" + bytes([len(rich_wire)]) + rich_wire),
        (
            "large_string",
            Message(
                config=Config(
                    controller_overlay_hotkey="x" * 4096, enable_unreliable_fec=True
                )
            ).SerializeToString(),
        ),
        ("missing_required", b""),
        ("truncated", b"\x0a\x08\x08"),
        ("missing_nested_required", b"\x0a\x06\xaa\x01\x03\x12\x01\x00"),
    ]
    for state in (2, 3, 4, 6):
        for name, wire in incoming:
            core = Core(binary)
            seed(core)
            try:
                core.receive(wire, state)
            except Exception as error:
                raise AssertionError((name, state, hex(core.u.reg_read(LR)))) from error
            observed = core.result()
            valid = name not in (
                "missing_required",
                "truncated",
                "missing_nested_required",
            )
            assert bool(observed["events"]) == (state == 6 and valid), (
                name,
                state,
                observed,
            )
            if state == 6 and valid:
                assert [next(iter(event)) for event in observed["events"]] == [
                    "notify",
                    "save",
                ]
                expected = Message.FromString(wire).config
                assert Config.FromString(bytes.fromhex(observed["config"])) == expected
            else:
                assert observed["config"] == initial.hex()
            cases.append(
                {
                    "case": f"incoming_s{state}_{name}",
                    "entry": "queued_control",
                    "input": {
                        "initial": initial.hex(),
                        "message": wire.hex(),
                        "state": state,
                    },
                    "observed": observed,
                }
            )
    # Every schema field passes through original nested/string/repeated copying.
    for field in Config.DESCRIPTOR.fields:
        item = Config()
        if field.message_type:
            value = {
                "codec": 2,
                "mode": {"width": 1280, "height": 720},
                "bitrate_kbps": 15000,
            }
            if field.is_repeated:
                getattr(item, field.name).add(**value)
                getattr(item, field.name).add(codec=1, bitrate_kbps=30000)
            else:
                getattr(item, field.name).CopyFrom(
                    message_factory.GetMessageClass(field.message_type)(**value)
                )
        elif field.type == field.TYPE_STRING:
            setattr(item, field.name, "config-字段")
        elif field.type == field.TYPE_BOOL:
            setattr(item, field.name, not field.default_value)
        elif field.type == field.TYPE_ENUM:
            setattr(item, field.name, list(field.enum_type.values)[-1].number)
        elif field.type == field.TYPE_FLOAT:
            setattr(item, field.name, 1.5)
        else:
            setattr(item, field.name, 123)
        wire = Message(config=item).SerializeToString()
        core = Core(binary)
        seed(core)
        assert core.parse(INPUT, b"")
        before = bytes(core.u.mem_read(INPUT, 208))
        assert core.parse(INPUT, item.SerializeToString())
        after = bytes(core.u.mem_read(INPUT, 208))
        core.receive(wire)
        observed = core.result()
        observed["storage_delta"] = [
            [offset, old, new]
            for offset, (old, new) in enumerate(zip(before, after))
            if old != new
        ]
        assert Config.FromString(bytes.fromhex(observed["config"])) == item, field.name
        cases.append(
            {
                "case": "field_" + field.name,
                "entry": "queued_control",
                "input": {"initial": initial.hex(), "message": wire.hex(), "state": 6},
                "observed": observed,
            }
        )

    # Real player delegate, including its nested local setter on mic changes.
    for name, values, overlay, hardware, mic in (
        ("fec_only", {"enable_unreliable_fec": True}, False, False, False),
        ("hardware_absent", {}, False, False, False),
        ("hardware_changed", {"enable_hardware_decoding": False}, False, True, False),
        ("hardware_same", {"enable_hardware_decoding": True}, False, True, False),
        ("overlay_default_off", {}, True, False, False),
        ("overlay_on", {"enable_performance_overlay": True}, False, False, False),
        ("mic_default_off", {}, False, False, True),
        ("mic_on", {"enable_microphone_streaming": True}, False, False, False),
        (
            "combined",
            {
                "enable_hardware_decoding": False,
                "enable_microphone_streaming": True,
                "enable_performance_overlay": True,
                "enable_unreliable_fec": True,
            },
            False,
            True,
            False,
        ),
    ):
        core = Core(binary)
        seed(core)
        core.wq(VTABLE + 128, 0x7C5504)
        core.wq(DELEGATE + 8, CLIENT)
        core.b(DELEGATE + 3524, int(overlay))
        core.b(DELEGATE + 1787, int(hardware))
        core.b(DELEGATE + 1136, int(mic))
        core.b(CLIENT + 636, int(overlay))
        core.wq(DELEGATE + 1096, 0x20060000 if mic else 0)
        core.callbacks[0xC0E7B0] = lambda: (
            core.actions.append({"reset_decoder": bool(core.r(1))}),
            core.ret(),
        )
        core.callbacks[0xC0BDD0] = lambda: (
            core.actions.append({"microphone_shutdown": True}),
            core.ret(),
        )
        core.callbacks[0xC0EFA0] = lambda: (
            core.actions.append({"microphone_open": True}),
            core.ret(1),
        )
        core.callbacks[0xC0F020] = lambda: (
            core.actions.append({"audio_stream_destroy": True}),
            core.ret(),
        )
        wire = Message(config=Config(**values)).SerializeToString()
        core.receive(wire)
        observed = core.result()
        observed["player"] = {
            "overlay": bool(core.u.mem_read(DELEGATE + 3524, 1)[0]),
            "hardware": bool(core.u.mem_read(DELEGATE + 1787, 1)[0]),
            "microphone": bool(core.u.mem_read(DELEGATE + 1136, 1)[0]),
        }
        assert any("reset_decoder" in x for x in observed["events"]) == (
            "enable_hardware_decoding" in values
            and bool(values["enable_hardware_decoding"]) != hardware
        ), (name, observed)
        assert observed["player"]["overlay"] == bool(
            values.get("enable_performance_overlay", False)
        ), name
        assert observed["player"]["microphone"] == bool(
            values.get("enable_microphone_streaming", False)
        ), name
        cases.append(
            {
                "case": "player_" + name,
                "entry": "player_delegate",
                "input": {
                    "initial": initial.hex(),
                    "message": wire.hex(),
                    "state": 6,
                    "overlay": overlay,
                    "hardware": hardware,
                    "microphone": mic,
                },
                "observed": observed,
            }
        )
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--refresh-reference", action="store_true")
    args = parser.parse_args()
    binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == SHA
    cases = audit(binary)
    report = {"binary_sha256": SHA, "scope": __doc__, "cases": cases}
    reference = ROOT / "scripts/fixtures/steam-client-config-reference.json"
    if args.refresh_reference:
        if reference.exists():
            previous = {
                case["case"]: case
                for case in json.loads(reference.read_text())["cases"]
            }
            for case in cases:
                if case["case"] in previous:
                    assert (
                        case == previous[case["case"]]
                    ), "existing official observation changed"
        reference.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert report == json.loads(
            reference.read_text()
        ), "official config reference changed"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"Official Android client config: {len(cases)} original-instruction cases passed"
    )


if __name__ == "__main__":
    main()
