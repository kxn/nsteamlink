#!/usr/bin/env python3
"""Replay Native discovery-channel PingResponse bytes into the original host.

The inherited fixture supplies a configured session, preallocated estimator,
request ledger, platform receive timestamp and encoder delivery terminal. The
original Frame copy/Get, C++ protobuf parser, ledger matcher, RTTI callback,
estimator and encoding stage execute. CRC/authentication/socket receive are NOT
executed; the entry is the already-admitted plaintext packet boundary. Native
body bytes first match five saved original ARM64 client vectors. Packet text
formatting, inherited allocation/locks/logging/OS threads and floating clock
are explicit terminals. Synthetic invalid/boundary packets are labelled
separately, never product output.
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
from unicorn.x86_const import (
    UC_X86_REG_R8,
    UC_X86_REG_RAX,
    UC_X86_REG_RDX,
    UC_X86_REG_RSP,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/steam-adaptive-feedback64-audit.py"
spec = importlib.util.spec_from_file_location("feedback64", SOURCE)
feedback = importlib.util.module_from_spec(spec)
spec.loader.exec_module(feedback)
feedback.config.host.NODES.update(
    {
        0x13A1F04D0: "ping_response_entry",
        0x13A1E26D0: "packet_frame_copy",
        0x13A1E1420: "length_prefixed_frame_get",
        0x13A18E8F0: "ping_session_callback",
        0x13A171820: "ping_estimator_sample",
    }
)
PATCHES = {
    "parse-gate": (0x13A1F0532, "0f84ac000000", "909090909090"),
    "size-gate": (0x13A1F058C, "7411", "eb11"),
    "receive-clock": (0x13A1E27DE, "894328", "909090"),
    "delegate": (0x13A1F05D4, "ff5050", "909090"),
    "recovery": (0x13AC8B6A4, "0ad7233d", "00000000"),
    "encoder-store": (0x13A1A3038, "87be68010000", "909090909090"),
}


class PingHost(feedback.FeedbackHost):
    def __init__(self, pe, image, mutation):
        self.callbacks = []
        self.ping_parsed = []
        super().__init__(pe, image, None)
        # Wrong-channel/type diagnostics format a packet description; this
        # platform formatting terminal does not decide acceptance or parse.
        self.hooks[0x13A86F410] = self.packet_description
        if mutation:
            address, expected, changed = PATCHES[mutation]
            expected = bytes.fromhex(expected)
            assert bytes(self.u.mem_read(address, len(expected))) == expected
            self.u.mem_write(address, bytes.fromhex(changed))

    def packet_description(self):
        self.u.mem_write(self.arg(1), b"\x00")
        self.ret(0)

    def hook(self, u, pc, size, context):
        if pc == 0x13A18E8F0:
            self.callbacks.append(
                dict(
                    sequence=self.r(UC_X86_REG_RDX) & 0xFFFFFFFF,
                    elapsed_ticks=self.r(UC_X86_REG_R8) & 0xFFFFFFFF,
                )
            )
        if pc == 0x13A1F0530:
            # Observation AFTER the original Get/C++ parser; no input injection.
            msg = self.r(UC_X86_REG_RSP) + 0x20
            self.ping_parsed.append(
                dict(
                    ok=bool(self.r(UC_X86_REG_RAX) & 255),
                    presence=self.rd(msg + 0x10),
                    sequence=self.rd(msg + 0x18),
                packet_size_received=self.rd(msg + 0x1C),
                )
            )
        super().hook(u, pc, size, context)


def native_reply(oracle, presence, requested):
    result = subprocess.run(
        [str(oracle.resolve()), "0", "1472", "4", str(presence), "0", str(requested)],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    value = json.loads(result.stdout)
    assert value["admitted"] and value["attempts"] == 1
    assert len(value["wire"]) == 1
    data = bytes.fromhex(value["wire"][0])
    assert data[4] == 0 and data[13] == 2
    return data


def audit(args):
    raw = args.binary.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == feedback.config.host.SHA256
    pe = pefile.PE(data=raw)
    image = pe.get_memory_mapped_image()
    reference_path = ROOT / "scripts/fixtures/steam-discovery-protobuf-reference.json"
    reference = json.loads(reference_path.read_text())
    assert reference["binary_sha256"] == (
        "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"
    )
    vectors = []
    wires = {}
    for case in reference["cases"]:
        source = case["input"]
        presence, requested = source["presence"], source["requested"]
        wire = native_reply(args.client_oracle, presence, requested)
        # The original client vector excludes header/CRC and message byte;
        # compare length prefix, encoded fields AND all original padding bytes.
        body = wire[14:].hex()
        assert body == case["observed"]["frame_body"], (source, body)
        wires[presence, requested] = wire
        vectors.append(dict(input=source, wire=wire.hex(), body_matches_original=True))
    normal = wires[3, 64]
    cases = []

    def run(
        name,
        wire=normal,
        *,
        presence=3,
        sequence=7,
        echoed_size=64,
        requested=64,
        ledger_sequence=7,
        sent=65536,
        received=67174,
        desired=0,
        delegate=True,
        valid=True,
        dispatched=True,
        repeats=1,
        other_limit=0,
        synthetic=False,
        pressure=False,
    ):
        assert desired in (0, 6000), (name, "unsupported config fixture", desired)
        h = PingHost(pe, image, args.mutation)
        config = bytes.fromhex("0a023000" if desired == 0 else "0a0330f02e")
        h.prepare(desired, config, delegate=delegate, other_limit=other_limit)
        # Explicit stable window/rate fixture, not measured network history.
        h.u.mem_write(h.q(h.estimator + 0x58), struct.pack("<500f", *([10.0] * 500)))
        h.u.mem_write(h.estimator + 0xA0, struct.pack("<f", 0.5))
        h.call(0x13A172500, h.estimator)
        before = h.estimator_state()
        initial_target = h.encode_stage()
        expected_initial = min(7500 if desired == 0 else desired, other_limit or 0xFFFFFFFF)
        assert initial_target == expected_initial, (name, "initial target", initial_target)
        ledger = h.alloc(48)
        h.qw(h.server + 0x280, ledger)
        h.w(h.server + 0x294, 0)
        h.w(h.server + 0x29C, 1)
        h.u.mem_write(
            ledger,
            struct.pack("<6I", ledger_sequence, requested, sent, 0, 0xFFFFFFFF, 0xFFFFFFFF),
        )
        match = dispatched and valid and sequence == ledger_sequence and (
            requested == 0 or echoed_size == requested
        )
        callback = match and delegate
        estimator = callback and desired == 0 and sequence < 500
        # Official signed modular difference, NOT max(received, sent).
        elapsed = (received - sent) & 0xFFFFFFFF
        if elapsed & 0x80000000:
            elapsed = 0
        expected_stamp = (sent + elapsed) & 0xFFFFFFFF if match else 0
        states = []
        for index in range(repeats):
            h.callbacks.clear()
            h.ping_parsed.clear()
            h.visited.clear()
            packet = h.packet(wire)
            h.w(packet + 0x20, received)
            h.call(0x13A1F04D0, h.server, 0, packet)
            assert "packet_frame_copy" in h.visited, (name, "original frame copy")
            assert bool(h.ping_parsed) == dispatched, (name, "dispatch", h.ping_parsed)
            if dispatched:
                assert "length_prefixed_frame_get" in h.visited, (name, "original Get")
                assert h.ping_parsed[0]["ok"] == valid, (name, "parser", h.ping_parsed)
                if valid:
                    assert h.ping_parsed == [dict(
                        ok=True, presence=presence, sequence=sequence, packet_size_received=echoed_size
                    )], (name, "parsed fields", h.ping_parsed)
                    assert "protobuf_parse" in h.visited, (name, "original protobuf parse")
            expected_callbacks = [dict(sequence=sequence, elapsed_ticks=elapsed)] if callback else []
            assert h.callbacks == expected_callbacks, (name, "callback", h.callbacks, expected_callbacks)
            assert h.rd(ledger + 12) == expected_stamp, (name, "ledger timestamp", h.rd(ledger + 12), expected_stamp)
            after = h.estimator_state()
            if estimator:
                coefficient = 0.08 if pressure else min(0.5 + 0.04 * (index + 1), 1)
                # Ordinary mode0's original reset/config sets a 2.5Mbps floor.
                estimate = max(2.5, 15.0 * coefficient)
                assert math.isclose(after["coefficient"], coefficient, rel_tol=1e-6), (name, after)
                assert math.isclose(after["estimate_mbps"], estimate, rel_tol=1e-6), (name, after)
                assert {"ping_estimator_sample", "recompute"} <= h.visited, (name, h.visited)
                target = round(estimate * 1000)
                if other_limit:
                    target = min(target, other_limit)
            else:
                assert after == before, (name, "unchanged estimator", before, after)
                target = expected_initial
            actual_target = h.encode_stage()
            assert actual_target == target, (name, "encoder target", actual_target, target)
            states.append(dict(
                parsed=list(h.ping_parsed), callbacks=list(h.callbacks),
                ledger_received=h.rd(ledger + 12), estimator=after,
                encoder_kbps=actual_target, visited=sorted(h.visited),
            ))
        cases.append(dict(
            name=name, source="synthetic boundary input" if synthetic else "Native production response",
            wire=wire.hex(), requested=requested, ledger_sequence=ledger_sequence,
            sent=sent, received=received, desired=desired, delegate=delegate,
            before=before, initial_encoder_kbps=initial_target, states=states,
        ))

    for presence, requested in wires:
        run(
            f"original-vector-presence{presence}-requested{requested}",
            wires[presence, requested],
            presence=presence, sequence=7 if presence & 1 else 0,
            echoed_size=requested if presence & 2 else 0,
            requested=requested,
        )
    run("native-repeat-retains-ledger", repeats=2)
    run("native-no-delegate", delegate=False)
    run("native-disabled-estimator", desired=6000)
    run("native-unknown-sequence", ledger_sequence=8)
    run("native-requested-size-mismatch", requested=65)
    run("native-zero-requested-size-accepts-any-echo", requested=0)
    run("native-independent-encoder-limit", other_limit=8000)
    run("native-receive-before-sent", received=65535)
    run("native-receive-equals-sent", received=65536)
    run("native-tick-rollover", sent=0xFFFF0000, received=1638, pressure=True)
    run("native-signed-negative-boundary", sent=0, received=0x80000000)
    run("native-signed-positive-boundary", sent=0, received=0x7FFFFFFF, pressure=True)
    # The echoed field is checked, not the datagram's actual padded length.
    run("synthetic-padding-removed", normal[:22], synthetic=True)
    run("synthetic-extra-padding", normal + b"\xfe" * 32, synthetic=True)
    for stamp in (0, 0xFFFFFFFF):
        altered = bytearray(normal)
        struct.pack_into("<I", altered, 9, stamp)
        run("synthetic-wire-clock-" + str(stamp), bytes(altered), synthetic=True)
    for offset, value in [(4, 1), (13, 1)]:
        altered = bytearray(normal)
        altered[offset] = value
        run(f"synthetic-header-{offset}", bytes(altered), dispatched=False, synthetic=True)
    for name, payload, valid, presence, sequence, size in [
        ("empty", b"", True, 0, 0, 0),
        ("explicit-zero", bytes.fromhex("08001000"), True, 3, 0, 0),
        ("duplicate-size", bytes.fromhex("0807103f1040"), True, 3, 7, 64),
        ("unknown-field", bytes.fromhex("080710401809"), True, 3, 7, 64),
        ("uint32-sequence", bytes.fromhex("08ffffffff0f1040"), True, 3, 0xFFFFFFFF, 64),
        ("truncated-varint", bytes.fromhex("08071080"), False, 0, 0, 0),
        ("bad-unknown-length", bytes.fromhex("080710401a04ff"), False, 0, 0, 0),
    ]:
        wire = normal[:14] + struct.pack("<I", len(payload)) + payload
        run("synthetic-protobuf-" + name, wire, valid=valid, presence=presence,
            sequence=sequence, echoed_size=size, synthetic=True,
            ledger_sequence=sequence if name == "uint32-sequence" else 7)
    bad_length = normal[:14] + struct.pack("<I", 4096) + normal[18:]
    run("synthetic-body-length-exceeds-packet", bad_length, valid=False, synthetic=True)
    ranges = [
        (0x13A1F04D0, 0x13A1F063A), (0x13A1E26D0, 0x13A1E27EA),
        (0x13A1E1420, 0x13A1E14E0), (0x13A18E8F0, 0x13A18E97A),
        (0x13A171820, 0x13A171A10), (0x13A172500, 0x13A1725B9),
        (0x13A1A2FE0, 0x13A1A3058),
    ]
    base = pe.OPTIONAL_HEADER.ImageBase
    return dict(
        binary_sha256=feedback.config.host.SHA256,
        audit_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        inherited_harness_sha256={str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in [SOURCE, feedback.SOURCE, feedback.config.source]},
        original_ranges=[dict(start=hex(a), end=hex(b), sha256=hashlib.sha256(image[a-base:b-base]).hexdigest())
                         for a, b in ranges],
        native_oracle_sha256=hashlib.sha256(args.client_oracle.read_bytes()).hexdigest(),
        original_client_reference_sha256=hashlib.sha256(reference_path.read_bytes()).hexdigest(),
        boundary=__doc__, original_client_vectors=vectors, cases=cases,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--client-oracle", type=Path, required=True)
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
