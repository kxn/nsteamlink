#!/usr/bin/env python3
"""Replay plaintext config messages into the pinned x64 host and mode selector.

Reuses the declared allocation/OS/control-delivery terminals of the host64 FEC
audit. The original dispatcher, protobuf parser/copy/apply, actual configuration
getters, mode selector and estimator reset/start/stop execute in one emulator.
Thread start/join and floating clock are explicit terminals. No authenticated
transport, running Steam, thread scheduling or encoder hardware is exercised.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

import pefile
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from unicorn.x86_const import UC_X86_REG_XMM0

source = Path(__file__).resolve().parents[1] / "scripts/audit-steam-host64-fec.py"
spec = importlib.util.spec_from_file_location("host64_fec", source)
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)
host.NODES.update(
    {
        0x13A18B340: "adaptive_mode_selector",
        0x13A18C8E0: "adaptive_request_getter",
        0x13A18C920: "quality_getter",
        0x13A171EF0: "estimator_start",
        0x13A171F40: "estimator_stop",
        0x13A171B40: "estimator_reset",
    }
)


class AdaptiveHost(host.Host64):
    def __init__(self, pe, image, mutation):
        super().__init__(pe, image)
        self.mode_actions = []
        if mutation:
            address = 0x13A1F6192
            assert bytes(self.u.mem_read(address, 7)) == bytes.fromhex("4489a65c020000")
            self.u.mem_write(address, b"\x90" * 7)
        self.qw(self.server, 0x13AC8F830)
        self.qw(self.server + 0x4538, 0x13AC8FA20)
        self.w(self.server + 0x4618, -1)
        self.w(self.server + 0x461C, -1)
        self.w(self.server + 0x45D0, 1280)
        self.w(self.server + 0x45D4, 720)
        self.w(self.server + 0x45E8, 60)
        self.w(self.server + 0x45EC, 1)
        self.estimator = self.server + 0x4928
        # Valid preallocated storage is fixture input, not a full constructor.
        for off, size in [(0x18, 120), (0x20, 240), (0x58, 2000), (0xF8, 3040)]:
            self.qw(self.estimator + off, self.alloc(size))
        self.u.mem_write(self.estimator + 9, b"\x01")
        for off, value in [(0x98, 10), (0x9C, 10), (0xA0, 1), (0xAC, 1), (0xB0, 100)]:
            self.u.mem_write(self.estimator + off, struct.pack("<f", value))
        for iat, terminal, action in [
            (0x13AC4B450, 0x4000E000, "start"),
            (0x13AC4B460, 0x4000E010, "join"),
        ]:
            self.qw(iat, terminal)
            self.hooks[terminal] = lambda action=action: self.thread_effect(action)
        self.qw(0x13AC4B528, 0x4000E020)
        self.hooks[0x4000E020] = self.clock

    def thread_effect(self, action):
        assert self.arg(0) == self.estimator + 0x100
        self.mode_actions.append(
            {"action": action, "parameter": self.arg(1) & 0xFFFFFFFF}
        )
        self.ret(1)

    def clock(self):
        self.u.reg_write(
            UC_X86_REG_XMM0, int.from_bytes(struct.pack("<d", 2), "little")
        )
        self.ret()

    def observe_mode(self):
        selected = self.call(0x13A18B340, self.server) & 0xFFFFFFFF
        signed = lambda value: value - 0x100000000 if value & 0x80000000 else value
        return {
            "copied_request": signed(self.rd(self.server + 0x230)),
            "applied_request": signed(self.rd(self.server + 0x25C)),
            "applied_cap_kbps": self.rd(self.server + 0x260),
            "selected_ceiling_kbps": selected,
            "estimator_enabled": bool(self.u.mem_read(self.estimator + 8, 1)[0]),
            "active_thread_word": self.rd(self.estimator + 0xC),
            "thread_actions": list(self.mode_actions),
            "visited": sorted(self.visited),
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument(
        "--mutation", action="store_true", help="Negative: remove applied-request store"
    )
    args = parser.parse_args()
    raw = args.binary.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == host.SHA256
    pe = pefile.PE(data=raw)
    image = pe.get_memory_mapped_image()
    schema = descriptor_pb2.FileDescriptorProto.FromString(
        raw[0xD55800 : 0xD55800 + 21827]
    )
    assert schema.name == "steammessages_remoteplay.proto"
    pool = descriptor_pool.DescriptorPool()
    pool.Add(schema)
    config_type = pool.FindMessageTypeByName("CStreamingClientConfig")
    field = config_type.fields_by_name["desired_bitrate_kbps"]
    assert field.number == 6 and field.default_value == -1

    def message(name, **values):
        return message_factory.GetMessageClass(pool.FindMessageTypeByName(name))(
            **values
        )

    def config(desired):
        return message(
            "CStreamingClientConfig",
            quality=2,
            **({} if desired is None else {"desired_bitrate_kbps": desired}),
        )

    def update(desired):
        return message(
            "CSetStreamingClientConfig", config=config(desired)
        ).SerializeToString()

    cases = []

    def check(h, name, payloads, expected, initial=False, states=None):
        observed = h.observe_mode()
        assert observed["copied_request"] == expected, (name, "copied", observed)
        assert observed["applied_request"] == expected, (name, "applied", observed)
        assert observed["selected_ceiling_kbps"] == (
            250000 if expected == 0 else 10000 if expected == -1 else expected
        ), (name, observed)
        assert observed["estimator_enabled"] == (expected == 0), (name, observed)
        assert observed["active_thread_word"] == int(expected == 0)
        assert {"adaptive_mode_selector", "adaptive_request_getter"} <= h.visited
        if initial:
            assert "initial_config_handler" in h.visited
        cases.append(
            {
                "name": name,
                "plaintext_payloads": payloads,
                "message_types": [4] if initial else [99] * len(payloads),
                "server_states": (
                    states
                    if states is not None
                    else [6 if initial else 7] * len(payloads)
                ),
                "observed": observed,
            }
        )

    for initial in (False, True):
        for desired in (None, -1, 0, 6000):
            h = AdaptiveHost(pe, image, args.mutation)
            if initial:
                payload = message(
                    "CNegotiationSetConfigMsg",
                    config=message("CNegotiatedConfig"),
                    streaming_client_config=config(desired),
                ).SerializeToString()
                h.control(payload, kind=4, state=6)
                h.video()
            else:
                h.video()
                h.visited.clear()
                payload = update(desired)
                h.control(payload)
            assert {
                "client_config_wire_parser",
                "config_copy",
                "apply_config",
            } <= h.visited
            check(
                h,
                f"{'initial4' if initial else 'runtime99'}-{desired}",
                [payload.hex()],
                -1 if desired is None else desired,
                initial,
            )

    h = AdaptiveHost(pe, image, args.mutation)
    h.video()
    h.control(update(0))
    h.observe_mode()
    h.visited.clear()
    h.control(update(None))
    check(h, "omitted-after-zero-clears", [update(0).hex(), update(None).hex()], -1)
    assert [a["action"] for a in h.mode_actions] == ["start", "join"]

    h = AdaptiveHost(pe, image, args.mutation)
    h.video()
    payload = update(0)
    h.visited.clear()
    h.control(payload, state=8)
    assert {"config_copy", "apply_config"} <= h.visited
    check(h, "runtime99-accepted-state8", [payload.hex()], 0, states=[8])

    for state in (6, 9):
        h = AdaptiveHost(pe, image, args.mutation)
        h.video()
        h.control(update(6000))
        h.observe_mode()
        h.visited.clear()
        h.control(update(0), state=state)
        assert "apply_config" not in h.visited and "config_copy" not in h.visited
        check(
            h,
            f"runtime99-ignored-state{state}",
            [update(6000).hex(), update(0).hex()],
            6000,
            states=[7, state],
        )

    h = AdaptiveHost(pe, image, args.mutation)
    h.video()
    h.control(update(0))
    h.observe_mode()
    h.visited.clear()
    bad = b"\x0a\x02\x30"  # Embedded config declares two bytes but is truncated.
    h.control(bad)
    assert "config_copy" not in h.visited and "apply_config" not in h.visited
    check(h, "runtime99-truncated-preserves", [update(0).hex(), bad.hex()], 0)
    assert [a["action"] for a in h.mode_actions] == ["start"]
    print(
        json.dumps(
            {
                "sha256": host.SHA256,
                "reused_terminal_harness": str(source.relative_to(source.parents[1])),
                "harness_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "boundary": "Plaintext frames with explicit server states enter original dispatch/parser/copy/apply, then actual mode selection/reset/start/stop in the same emulator. Fixtures supply session vtables/overrides/dimensions/FPS and preallocated estimator buffers. Inherited allocation/free/locks/log/platform-ID/control/socket terminals plus floating clock and OS thread start/join apply. No authenticated transport, real workers, actual host or encoder device evidence.",
                "cases": cases,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
