#!/usr/bin/env python3
"""Replay plaintext overflow feedback through the pinned original host.

Original control dispatch, C++ protobuf parsing, RTTI callback, estimator and
encoder-stage min/store run in one emulator. Reuse the config audit's declared
allocation/locks/logging/OS-thread terminals. Fixture-provided delegate binding,
clock, buffers and encoder callback list are not a complete session constructor.
The next encoder stage is a delivery terminal, not an encoder device. Optional
Native client output is compared with original Linux vectors before replay;
no authentication, encrypted transport, actual network or hardware is exercised.
"""
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import struct
import subprocess

import pefile
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RSP, UC_X86_REG_XMM0

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/steam-adaptive-config64-audit.py"
spec = importlib.util.spec_from_file_location("adaptive_config", SOURCE)
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)
config.host.NODES.update(
    {
        0x13A1ED49B: "overflow_dispatch",
        0x13A122410: "overflow_field_parser",
        0x13A1907F0: "overflow_callback",
        0x13A171A10: "overflow_event",
        0x13A170E80: "sender_rate_query",
        0x13A172500: "recompute",
        0x13A18C4C0: "encoder_rate_getter",
        0x13A1A2FE0: "encoder_bitrate_stage",
        0x13A1A4510: "next_stage_forward",
    }
)
PATCHES = {
    "delegate": (0x13A1ED4D4, "ff5048"),
    "parse-gate": (0x13A1ED4C6, "740f"),
    "enable-gate": (0x13A1907F7, "740c"),
    "parser-last-field": (0x13A122512, "4189561c"),
    "encoder-store": (0x13A1A3038, "87be68010000"),
}


class FeedbackHost(config.AdaptiveHost):
    def __init__(self, pe, image, mutation):
        self.now = 2.0
        self.parsed = []
        super().__init__(pe, image, False)
        if mutation:
            address, signature = PATCHES[mutation]
            original = bytes.fromhex(signature)
            assert bytes(self.u.mem_read(address, len(original))) == original
            self.u.mem_write(address, b"\x90" * len(original))
        # Same logging terminal as the existing estimator audit.
        self.hooks[0x13A1A0560] = lambda: self.ret()

    def clock(self):
        self.u.reg_write(
            UC_X86_REG_XMM0, int.from_bytes(struct.pack("<d", self.now), "little")
        )
        self.ret()

    def hook(self, u, pc, size, context):
        if pc == 0x13A1ED4C4:
            # Observe only, after the ORIGINAL Frame::Get/C++ protobuf parser.
            message = self.r(UC_X86_REG_RSP) + 0x30
            self.parsed.append(
                dict(
                    ok=bool(self.r(UC_X86_REG_RAX) & 255),
                    presence=self.rd(message + 0x10),
                    first=self.rd(message + 0x18),
                    last=self.rd(message + 0x1C),
                )
            )
        super().hook(u, pc, size, context)

    def prepare(self, desired, update, *, delegate=True, other_limit=0):
        self.video()
        self.control(update)
        ceiling = self.observe_mode()["selected_ceiling_kbps"]
        # Bind the actual RTTI callback AFTER config delivery, whose delegate is
        # absent in the inherited config fixture. This does not claim to execute
        # a full constructor or the config-notification/target-update chain.
        self.qw(self.server + 0x4528, 0x13AC8F8B0)
        self.qw(self.server + 0x38, self.server + 0x4528 if delegate else 0)
        # Disabled getter's saved target is a declared fixture input, not a
        # claim to execute CGameStreamSession's target-notification producer.
        self.w(self.server + 0x4648, ceiling)
        if desired == 0:
            # Execute one original recompute at a declared clock after reset;
            # this replaces neither its algorithm nor any real thread schedule.
            self.now = 3.0
            self.call(0x13A172500, self.estimator)
        self.stage = self.alloc(0x50)
        self.encoder = self.alloc(0x200)
        vector = self.alloc(16)
        self.frame = self.alloc(0x60)
        downstream, vt = self.alloc(16), self.alloc(0x40)
        self.qw(self.stage, 0x13AC92060)
        self.qw(self.stage + 0x30, self.encoder)
        self.qw(self.stage + 0x10, downstream)
        self.qw(downstream, vt)
        self.qw(vt + 0x38, 0x4000E030)
        self.hooks[0x4000E030] = lambda: self.ret()
        self.qw(self.encoder + 0x68, vector)
        self.w(self.encoder + 0x78, 2 if other_limit else 1)
        self.qw(vector, self.server + 0x4538)
        if other_limit:
            other, other_vt = self.alloc(16), self.alloc(0x30)
            self.qw(vector + 8, other)
            self.qw(other, other_vt)
            self.qw(other_vt + 0x28, 0x4000E040)
            self.hooks[0x4000E040] = lambda: self.ret(other_limit)
        self.visited.clear()

    def estimator_state(self):
        def floating(offset, fmt):
            return struct.unpack(
                fmt, self.u.mem_read(self.estimator + offset, struct.calcsize(fmt))
            )[0]

        return dict(
            enabled=bool(self.u.mem_read(self.estimator + 8, 1)[0]),
            started_at=floating(0x10, "<d"),
            last_event=floating(0x90, "<d"),
            initialized_link_mbps=floating(0x98, "<f"),
            coefficient=floating(0xA0, "<f"),
            ramp=floating(0xA4, "<f"),
            estimate_mbps=floating(0xA8, "<f"),
            lower_mbps=floating(0xAC, "<f"),
            upper_mbps=floating(0xB0, "<f"),
            decoder_mbps=floating(0xB4, "<f"),
            history_mbps=floating(0xB8, "<f"),
        )

    def encode_stage(self):
        self.w(self.encoder + 0x168, 0xA5A5A5A5)
        self.call(0x13A1A2FE0, self.stage, self.frame)
        return self.rd(self.encoder + 0x168)


def native_client(receiver, case):
    lines = []
    for action in case["input"]:
        values = [
            action.get("phase", 6),
            action.get("waiting_key", 0),
            action.get("syncing", 0),
            action.get("count", 2),
            action.get("first", 100),
            action.get("last", 102),
            action.get("ticks", 5000),
            action.get("previous_span", 0),
            int("previous_span" in action),
            action.get("phase_after_feedback", 0xFFFFFFFF),
        ]
        lines.append(" ".join(map(str, values)))
    result = subprocess.run(
        [str(receiver.resolve())],
        input="\n".join(lines) + "\n",
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, (case["name"], result.stderr)
    states = [json.loads(line) for line in result.stdout.splitlines()]
    expected = [
        {key: value for key, value in state.items() if key != "assertions"}
        for state in case["states"]
    ]
    assert states == expected, (case["name"], states, expected)
    return states


def audit(args):
    raw = args.binary.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == config.host.SHA256
    pe = pefile.PE(data=raw)
    image = pe.get_memory_mapped_image()
    schema = descriptor_pb2.FileDescriptorProto.FromString(raw[0xD55800:0xD5AD43])
    assert schema.name == "steammessages_remoteplay.proto"
    pool = descriptor_pool.DescriptorPool()
    pool.Add(schema)

    def message(name, **values):
        return message_factory.GetMessageClass(pool.FindMessageTypeByName(name))(
            **values
        )

    def update(desired):
        fields = {} if desired is None else {"desired_bitrate_kbps": desired}
        return message(
            "CSetStreamingClientConfig",
            config=message("CStreamingClientConfig", quality=2, **fields),
        ).SerializeToString()

    fields = pool.FindMessageTypeByName("CStreamVideoOverflowMsg").fields_by_name
    assert fields["first_frame_id"].number == 1
    assert fields["last_frame_id"].number == 2
    cases = []

    def run(
        name,
        payloads,
        *,
        desired=0,
        now=8,
        state=7,
        valid=True,
        delegate=True,
        other_limit=0,
        client=None
    ):
        h = FeedbackHost(pe, image, args.mutation)
        config_payload = update(desired)
        h.prepare(desired, config_payload, delegate=delegate, other_limit=other_limit)
        before = h.estimator_state()
        baseline = h.encode_stage()
        expected_baseline = (
            15000
            if desired == 0
            else 10000 if desired is None or desired == -1 else desired
        )
        if other_limit:
            expected_baseline = min(expected_baseline, other_limit)
        assert baseline == expected_baseline, (name, "baseline encoder", baseline)
        h.visited.clear()
        h.now = now
        states = []
        accepted_state = state in (7, 8)
        feedback = accepted_state and valid and delegate
        effective = feedback and desired == 0 and now - 2.0 >= 5.0
        for payload in payloads:
            h.parsed.clear()
            h.visited.clear()
            h.control(payload, kind=148, state=state)
            after = h.estimator_state()
            assert bool(h.parsed) == accepted_state, (name, "dispatch gate", h.parsed)
            if accepted_state:
                assert h.parsed[0]["ok"] == valid, (name, "parse result", h.parsed)
                if valid:
                    decoded = message("CStreamVideoOverflowMsg")
                    decoded.ParseFromString(payload)
                    expected = dict(
                        ok=True,
                        presence=int(decoded.HasField("first_frame_id"))
                        | (int(decoded.HasField("last_frame_id")) << 1),
                        first=decoded.first_frame_id,
                        last=decoded.last_frame_id,
                    )
                    assert h.parsed == [expected], (
                        name,
                        "decoded fields",
                        h.parsed,
                        expected,
                    )
                    assert {
                        "overflow_dispatch",
                        "protobuf_parse",
                        "overflow_field_parser",
                    } <= h.visited
            assert ("overflow_callback" in h.visited) == feedback, (
                name,
                "callback gate",
                sorted(h.visited),
            )
            assert ("overflow_event" in h.visited) == (feedback and desired == 0), (
                name,
                "enable gate",
                sorted(h.visited),
            )
            assert ("recompute" in h.visited) == effective, (
                name,
                "time gate",
                sorted(h.visited),
            )
            if effective:
                assert after["last_event"] == now
                assert math.isclose(after["estimate_mbps"], 2.5, rel_tol=1e-6), (
                    name,
                    after,
                )
            else:
                assert after == before, (name, "unchanged estimator", after, before)
            target = h.encode_stage()
            expected_target = 2500 if effective else expected_baseline
            if other_limit:
                expected_target = min(expected_target, other_limit)
            assert target == expected_target, (
                name,
                "encoder store",
                target,
                expected_target,
            )
            assert {
                "encoder_rate_getter",
                "encoder_bitrate_stage",
                "next_stage_forward",
            } <= h.visited
            states.append(
                dict(
                    payload=payload.hex(),
                    parsed=list(h.parsed),
                    estimator=after,
                    encoder_kbps=target,
                    visited=sorted(h.visited),
                )
            )
        cases.append(
            dict(
                name=name,
                config_plaintext=config_payload.hex(),
                desired=desired,
                now=now,
                server_state=state,
                delegate=delegate,
                other_limit=other_limit,
                before=before,
                initial_encoder_kbps=baseline,
                states=states,
                client=client,
            )
        )
        return h

    normal = bytes.fromhex("08641066")
    for name, payload in [
        ("normal", normal),
        ("explicit-zero", bytes.fromhex("08001000")),
        ("omitted", b""),
        ("first-only", bytes.fromhex("0864")),
        ("last-only", bytes.fromhex("1066")),
        ("frame-ids-uint32", bytes.fromhex("08ffffffff0f1000")),
        ("duplicate-last", bytes.fromhex("086410651066")),
        ("unknown-varint", normal + bytes.fromhex("1809")),
        ("wrong-wire-type-unknown", bytes.fromhex("0a01ff")),
    ]:
        run("plaintext148-" + name, [payload])
    for state in (6, 8, 9):
        run("plaintext148-state" + str(state), [normal], state=state)
    for desired in (None, -1, 6000):
        run("plaintext148-mode" + str(desired), [normal], desired=desired)
    for now in (6.999, 7.0):
        run("plaintext148-early-" + str(now), [normal], now=now)
    for payload in (b"\x08\x80", b"\x1a\x03a"):
        run("plaintext148-malformed-" + payload.hex(), [payload], valid=False)
    run("plaintext148-no-delegate", [normal], delegate=False)
    run("plaintext148-independent-encoder-limit", [normal], other_limit=2000)
    run("plaintext148-repeated-not-loss-latched", [normal, normal])

    h = run("plaintext148-recovery-to-encoder", [normal])
    recovery = []
    for elapsed, estimate, bitrate in [
        (0.125, 3.75, 3750),
        (0.25, 7.5, 7500),
        (0.5, 15.0, 15000),
    ]:
        h.visited.clear()
        h.now = 8 + elapsed
        h.call(0x13A172500, h.estimator)
        after = h.estimator_state()
        assert after["last_event"] == 8
        assert math.isclose(after["estimate_mbps"], estimate, rel_tol=1e-6), (
            "recovery estimate",
            elapsed,
            after,
        )
        actual = h.encode_stage()
        assert actual == bitrate, ("recovery encoder", elapsed, actual, bitrate)
        recovery.append(
            dict(
                elapsed=elapsed,
                estimator=after,
                encoder_kbps=actual,
                visited=sorted(h.visited),
            )
        )
    cases[-1]["recovery_steps"] = recovery

    reference_path = ROOT / "scripts/fixtures/steam-video-overflow-reference.json"
    reference = json.loads(reference_path.read_text())
    assert (
        reference["binary_sha256"]
        == "95482ca6120f90bb90798b27206b7946ab732e079f008d7fc90ea58a8b0074e1"
    )
    client_count = client_states = 0
    for case in reference["cases"]:
        states = (
            native_client(args.client_receiver, case)
            if args.client_receiver
            else case["states"]
        )
        client_count += 1
        client_states += len(states)
        payloads = []
        for result in states:
            for channel, payload in result["feedback"]:
                if channel == 1:
                    data = bytes.fromhex(payload)
                    assert data[0] == 148
                    payloads.append(data[1:])
        if payloads:
            run(
                "client-consumer-" + case["name"],
                payloads,
                client=dict(
                    input=case["input"],
                    states=states,
                    producer=(
                        "Native"
                        if args.client_receiver
                        else "saved original Linux vectors"
                    ),
                ),
            )

    ranges = [
        (0x13A1ED49B, 0x13A1ED4E3),
        (0x13A122410, 0x13A1225FC),
        (0x13A1907F0, 0x13A190806),
        (0x13A171A10, 0x13A171B3C),
        (0x13A172500, 0x13A1725B9),
        (0x13A1ECA00, 0x13A1ED72C),
        (0x13A1ED72C, 0x13A1ED74C),
        (0x13A18C4C0, 0x13A18C4E6),
        (0x13A1A2FE0, 0x13A1A3058),
    ]
    return dict(
        sha256=config.host.SHA256,
        original_ranges=[
            dict(
                start=hex(a),
                end=hex(b),
                sha256=hashlib.sha256(
                    image[
                        a
                        - pe.OPTIONAL_HEADER.ImageBase : b
                        - pe.OPTIONAL_HEADER.ImageBase
                    ]
                ).hexdigest(),
            )
            for a, b in ranges
        ],
        reused_config_harness_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        reused_host_harness_sha256=hashlib.sha256(
            config.source.read_bytes()
        ).hexdigest(),
        client_reference_sha256=hashlib.sha256(reference_path.read_bytes()).hexdigest(),
        native_receiver_sha256=(
            hashlib.sha256(args.client_receiver.read_bytes()).hexdigest()
            if args.client_receiver
            else None
        ),
        client_cases=client_count,
        client_states=client_states,
        boundary="Explicit plaintext control frames and server states run original dispatch/C++ parser/RTTI callback/estimator/encoder-stage min/store. Config is applied with no delegate; actual RTTI delegate binding and saved disabled-mode target are subsequent fixture inputs. An original recompute at t=3 after reset(t=2) establishes the controlled baseline without a real worker. Next-stage delivery, inherited allocation/locks/logging/OS-thread services and floating clock are terminals. The estimate's 15Mbps initial link is reset state, not observed throughput. Optional production Native consumer output first matches original Linux vectors; its control payload enters the host, but DataLost/video-channel feedback is not forwarded here. No transport authentication/encryption/ACK, actual encoder, concurrent scheduling or live host/Switch is claimed.",
        cases=cases,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--client-receiver", type=Path)
    parser.add_argument("--mutation", choices=PATCHES)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    text = json.dumps(audit(args), indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
