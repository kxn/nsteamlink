#!/usr/bin/env python3
"""Replay original-client DataLost into the original Win64 host and loss latch.

Original plaintext packet receive/Frame/protobuf/channel dispatch, session loss
callback, estimator, encoder bitrate stage, pending query and output callbacks
execute. Fixture objects/clock and inherited allocation/locks/logging/threads
remain explicit inputs/terminals. Encoder begin/output dispatchers run, but their
frame descriptors/chunks are supplied, NOT produced by a GPU. New terminals are
byte-preserving memcpy/strcmp/chunk conversion, platform timestamp conversion,
stack probe, statistics and final outgoing Frame delivery. No CRC/authentication,
actual network, physical encode or natural scheduling is claimed. Chunk codec
semantics are not inferred from its low five type bits alone.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess

import pefile
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from unicorn.x86_const import UC_X86_REG_RAX

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/steam-adaptive-feedback64-audit.py"
spec = importlib.util.spec_from_file_location("feedback64", SOURCE)
feedback = importlib.util.module_from_spec(spec)
spec.loader.exec_module(feedback)
feedback.config.host.NODES.update({
    0x13A1EF890: "plaintext_packet_receive",
    0x13A1E26D0: "packet_frame_copy",
    0x13A1EF490: "loss_handler",
    0x13A11D110: "loss_field_parser",
    0x13A190740: "video_loss_callback",
    0x13A170FC0: "loss_estimator_entry",
    0x13A1A1580: "encoder_pending_query",
    0x13A18B2C0: "session_pending_getter",
    0x13A1A2930: "encoder_begin_dispatch",
    0x13A18BF50: "session_frame_begin",
    0x13A1A2810: "encoder_buffer_dispatch",
    0x13A18B7A0: "session_buffer_output",
    0x13A1A2860: "encoder_chunk_dispatch",
    0x13A18BD00: "session_chunk_output",
})
PATCHES = {
    "parse-gate": (0x13A1EF4CD, "0f8478030000", "909090909090"),
    "video-delegate": (0x13A1EF7E6, "ff90e8000000", "909090909090"),
    # The enable comparison below reuses AL from the latch snapshot. Removing
    # only JNE leaves AL=1 and accidentally skips enabled=1 too. Zero the whole
    # snapshot instead, so this negative genuinely bypasses duplicate merging.
    "loss-latch": (0x13A19074F, "85c0", "31c0"),
    "buffer-clear": (0x13A18B87A, "8787940c0000", "909090909090"),
    "chunk-first": (0x13A18BD40, "751f", "9090"),
    "chunk-type6": (0x13A18BD54, "740b", "9090"),
    "chunk-clear": (0x13A18BD5B, "8783940c0000", "909090909090"),
    "chunk-suppress": (0x13A18BD70, "0f85c5010000", "909090909090"),
}


class LossHost(feedback.FeedbackHost):
    def __init__(self, pe, image, mutation):
        self.loss_parsed = []
        self.callbacks = []
        self.output_frames = []
        self.statistics_calls = []
        super().__init__(pe, image, None)
        self.hooks.update({
            0x13AC31090: self.memcpy,
            0x13AC31C60: self.strcmp,
            0x13A1E9FF0: self.timestamp,
            0x13AAB3380: lambda: self.ret(),  # CRT stack page probe.
            0x13A1F0D00: self.statistics,
            0x13A18A8A0: self.statistics,
            0x13A192B90: self.output_delivery,
            0x4000E090: self.convert_chunk,
            0x4000E0A0: lambda: self.ret(),  # Profiling/logging label.
        })
        self.qw(0x13AC4B510, 0x4000E0A0)
        if mutation:
            address, expected, changed = PATCHES[mutation]
            expected = bytes.fromhex(expected)
            assert bytes(self.u.mem_read(address, len(expected))) == expected
            self.u.mem_write(address, bytes.fromhex(changed))

    def memcpy(self):
        destination, source, size = [self.arg(i) for i in range(3)]
        self.u.mem_write(destination, bytes(self.u.mem_read(source, size)))
        self.ret(destination)

    def convert_chunk(self):
        destination, source, size = [self.arg(i) for i in range(3)]
        self.u.mem_write(destination, bytes(self.u.mem_read(source, size)))
        self.ret(destination + size)

    def strcmp(self):
        def string(address):
            value = bytearray()
            for _ in range(1024):
                byte = self.u.mem_read(address, 1)[0]
                if not byte:
                    return bytes(value)
                value.append(byte)
                address += 1
            raise AssertionError("unterminated fixture string")
        left, right = [string(self.arg(i)) for i in range(2)]
        self.ret(0 if left == right else 1 if left > right else 0xFFFFFFFFFFFFFFFF)

    def timestamp(self):
        # The Windows TLS/frequency helper is a platform boundary. All supplied
        # frame timestamps are zero; no timestamp/latency algorithm is tested.
        assert self.arg(0) == 0
        self.ret(0)

    def statistics(self):
        self.statistics_calls.append([self.arg(i) for i in range(3)])
        self.ret()

    def output_delivery(self):
        assert self.arg(0) == self.server
        frame = self.arg(1)
        packet = self.q(frame + 8)
        # Frame's optional message byte and 12-byte video header precede body.
        offset = (13 + bool(self.u.mem_read(frame + 0x10, 1)[0])
                  + 12 * bool(self.u.mem_read(frame + 0x11, 1)[0])
                  + self.rd(frame + 0x14))
        size = self.rd(packet + 0x34) - offset
        assert size >= 7
        body = bytes(self.u.mem_read(self.q(packet + 0x38) + offset, size))
        self.output_frames.append(dict(body=body.hex(), flags=body[2]))
        self.ret()

    def hook(self, u, pc, size, context):
        if pc == 0x13A1EF4CB:
            self.loss_parsed.append(bool(self.r(UC_X86_REG_RAX) & 255))
        if pc in (0x13A1EF7CA, 0x13A1EF7E6):
            vector = self.arg(1)
            count = self.rd(vector + 0x10)
            assert count <= 1024
            values = list(struct.unpack("<" + "H" * count,
                                       self.u.mem_read(self.q(vector), count * 2))) if count else []
            self.callbacks.append(dict(role="audio" if pc == 0x13A1EF7CA else "video",
                                       packets=values))
        super().hook(u, pc, size, context)

    def pending(self):
        return self.rd(self.server + 0x51CC)

    def query(self):
        value = self.call(0x13A1A1580, self.encoder, self.frame) & 255
        assert {"encoder_pending_query", "session_pending_getter"} <= self.visited
        return bool(value)

    def receive_loss(self, payload, *, channel=3, state=7):
        self.loss_parsed.clear()
        self.callbacks.clear()
        self.visited.clear()
        self.w(self.server + 0x94, state)
        # Header/packet admission is fixture-provided. Payload includes the
        # real client's message byte; no host dispatcher/parse is bypassed.
        wire = struct.pack("<BBBBBHHI", 3, 0, 34, 12, channel, 0, 0, 900000) + payload
        self.call(0x13A1EF890, self.server, 0, self.packet(wire))
        return wire.hex()

    def output_fixture(self):
        frame = self.alloc(0x200)
        self.w(frame + 0x40, 0x200000)
        self.w(frame + 0x44, 0x100)
        self.w(frame + 0x48, 4)
        self.w(frame + 0x4C, 1280)
        self.w(frame + 0x50, 720)
        self.payload = self.alloc(4)
        self.u.mem_write(self.payload, b"\0\0\0\x01")
        self.qw(frame + 0xC0, self.payload)
        callback = self.server + 0x4538
        # Already configured codec/size/description are declared fixture input;
        # original frame-begin still executes its comparison and marker writes.
        for offset, value in (
            (0xC78, self.call(0x13A1A2B50, 0x200000)),
            (0xC7C, self.call(0x13A1A2B90, 0x100)),
            (0x98, 1280), (0x9C, 720), (0xA0, 0x100),
        ):
            self.w(callback + offset, value)
        self.w(self.server + 0x11C, 4)  # Original chunk support getter input.
        self.qw(callback + 0xCC8, 0x4000E090)
        self.completed_frame = frame

    def begin(self):
        self.call(0x13A1A2930, self.encoder, self.completed_frame)
        assert self.rd(self.server + 0x51C4) == 1
        assert self.rd(self.server + 0x51C8) == 0
        assert {"encoder_begin_dispatch", "session_frame_begin"} <= self.visited

    def chunk(self, kind):
        self.call(0x13A1A2860, self.encoder, kind, 0, 0, 0, self.payload, 4)
        assert {"encoder_chunk_dispatch", "session_chunk_output"} <= self.visited


def audit(args):
    raw = args.binary.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == feedback.config.host.SHA256
    pe = pefile.PE(data=raw)
    image = pe.get_memory_mapped_image()
    base = pe.OPTIONAL_HEADER.ImageBase
    pointer = lambda address: struct.unpack_from("<Q", image, address - base)[0]
    for vtable, offset, target in (
        (0x13AC8F8B0, 0xE8, 0x13A190740),
        (0x13AD5D030, 0x50, 0x13A11D110),
        (0x13AC8FA20, 8, 0x13A18B2C0),
        (0x13AC8FA20, 0xA8, 0x13A18BF50),
        (0x13AC8FA20, 0xB8, 0x13A18BD00),
        (0x13AC8FA20, 0xC0, 0x13A18B7A0),
    ):
        assert pointer(vtable + offset) == target
    # Fresh official client execution plus the Native production consumer's
    # queue assertions (including one-byte02). We replay the ORIGINAL client
    # bytes, not a claimed native packet capture or a saved hand-written vector.
    client_tool = ROOT / "tools/steam-client-loss-phase-audit.py"
    command = [args.python, str(client_tool), "--binary", str(args.client_binary),
               "--receiver", str(args.client_oracle)]
    result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=120)
    client = json.loads(result.stdout)
    channel, body = client["cases"][6]["feedback"][0]
    assert channel == 3 and body == "02"
    normal = bytes.fromhex(body)
    schema = descriptor_pb2.FileDescriptorProto.FromString(raw[0xD55800:0xD5AD43])
    pool = descriptor_pool.DescriptorPool()
    pool.Add(schema)
    cls = message_factory.GetMessageClass(pool.FindMessageTypeByName("CStreamDataLostMsg"))
    assert cls.DESCRIPTOR.fields_by_name["packets"].number == 1
    cases = []

    def new(desired=0, delegate=True):
        h = LossHost(pe, image, args.mutation)
        h.prepare(desired, bytes.fromhex("0a023000" if desired == 0 else "0a0330f02e"),
                  delegate=delegate)
        assert h.encode_stage() == (15000 if desired == 0 else 6000)
        assert not h.query() and h.pending() == 0
        h.now = 8.0
        return h

    def run(name, payload=normal, *, desired=0, now=8.0, channel=3,
            delegate=True, state=7, valid=True, packets=(), role="video"):
        h = new(desired, delegate)
        if role == "audio":
            channel = h.audio()
        h.now = now
        before = h.estimator_state()
        wire = h.receive_loss(payload, channel=channel, state=state)
        assert {"plaintext_packet_receive", "packet_frame_copy", "loss_handler",
                "protobuf_parse", "loss_field_parser"} <= h.visited, (name, h.visited)
        assert h.loss_parsed == [valid], (name, "parse", h.loss_parsed)
        delivered = valid and delegate and role in ("audio", "video")
        expected = [dict(role=role, packets=[p & 65535 for p in packets])] if delivered else []
        assert h.callbacks == expected, (name, "role/ids", h.callbacks, expected)
        video = delivered and role == "video"
        assert ("video_loss_callback" in h.visited) == video, (name, h.visited)
        assert ("loss_estimator_entry" in h.visited) == (video and desired == 0)
        effective = video and desired == 0 and now >= 7.0
        after = h.estimator_state()
        if effective:
            assert after["last_event"] == now and after["estimate_mbps"] == 2.5
        else:
            assert after == before, (name, "estimator changed", before, after)
        assert h.pending() == int(video) and h.query() == video, (name, "latch")
        assert h.pending() == int(video), (name, "query must not consume")
        target = h.encode_stage()
        assert target == (2500 if effective else 15000 if desired == 0 else 6000)
        cases.append(dict(name=name, source="original-client body" if payload == normal
                          else "synthetic protobuf boundary", wire=wire, state=state,
                          desired=desired, now=now, parsed=list(h.loss_parsed),
                          callbacks=list(h.callbacks), pending=h.pending(), estimator=after,
                          encoder_kbps=target, visited=sorted(h.visited)))
        return h

    run("original-client-empty-list")
    for count in (1, 2, 16, 17, 33):
        values = [0, 1, 65535, 65536, 0xFFFFFFFF] * 7
        values = values[:count]
        run("packet-id-count-" + str(count), b"\x02" + cls(packets=values).SerializeToString(),
            packets=values)
    run("packed-list", b"\x02\x0a\x03\x01\x80\x01", packets=[1, 128])
    run("unknown-field", b"\x02\x10\x05")
    for payload in (b"\x02\x08\x80", b"\x02\x0a\x03a"):
        run("malformed-" + payload.hex(), payload, valid=False)
    run("no-delegate", delegate=False)
    run("wrong-channel", channel=5, role="unknown")
    run("audio-role", role="audio")
    for state in (0, 6, 8, 9):
        run("already-admitted-state-" + str(state), state=state)
    run("fixed-bitrate-still-requests-key", desired=6000)
    run("early-loss-still-requests-key", now=6.999)
    run("loss-time-boundary", now=7.0)

    # Suppression is a latch, not a debounce timer. Even an early ignored
    # estimator event sets it; advancing time alone does not consume it.
    for early in (False, True):
        h = run("repeat-basis-early-" + str(early), now=6.999 if early else 8.0)
        before = h.estimator_state()
        h.now = 30.0
        h.receive_loss(normal)
        assert h.callbacks == [dict(role="video", packets=[])]
        assert "loss_estimator_entry" not in h.visited, "repeated loss bypassed latch"
        assert h.estimator_state() == before and h.pending() == 1 and h.query()
        cases.append(dict(name="repeat-at-30-early-" + str(early),
                          estimator=h.estimator_state(), pending=h.pending(),
                          visited=sorted(h.visited)))

    # Exercise real encoder begin → callback marker → chunk dispatch. The
    # converter/output are terminals; type and first-chunk predicates are not.
    for kind, first in ((1, True), (5, True), (6, True), (7, True), (8, True),
                        (9, True), (0x25, True), (5, False), (7, False), (8, False)):
        h = new()
        h.receive_loss(normal)
        h.output_fixture()
        h.begin()
        if not first:
            h.chunk(1)  # Real first call consumes marker while retaining loss.
            assert h.pending() == 1 and not h.output_frames
        h.chunk(kind)
        clears = first and kind & 31 in (5, 7, 8)
        assert h.pending() == int(not clears), (kind, first, "chunk clear")
        assert h.query() == (not clears)
        after_output_pending = h.pending()
        output_visited = sorted(h.visited)
        assert len(h.output_frames) == int(clears), (kind, first, "chunk suppression")
        if clears:
            assert h.output_frames[0]["flags"] == 0x1C
            h.now = 9.0
            h.receive_loss(normal)
            assert "loss_estimator_entry" in h.visited
            assert h.estimator_state()["last_event"] == 9.0 and h.pending() == 1
        cases.append(dict(name=f"chunk-type-{kind}-first-{first}", pending=h.pending(),
                          after_output_pending=after_output_pending,
                          output_visited=output_visited,
                          output=list(h.output_frames), estimator=h.estimator_state(),
                          visited=sorted(h.visited)))

    for first_kind in (1, 5):
        h = new()
        h.output_fixture()
        h.begin()
        h.chunk(first_kind)
        assert not h.pending() and not h.query()
        assert [f["flags"] for f in h.output_frames] == [0x1C if first_kind == 5 else 0x0C]
        h.chunk(1)
        assert not h.pending() and [f["flags"] for f in h.output_frames][-1] == 0x0C
        cases.append(dict(name=f"no-loss-first-chunk-{first_kind}", pending=h.pending(),
                          output=list(h.output_frames), visited=sorted(h.visited)))

    for key, buffered, size, pointer_present in (
        (False, 0, 4, True), (True, 0, 4, True), (True, 4, 4, True),
        (True, 0, 0, True), (True, 0, 4, False),
    ):
        h = new()
        h.receive_loss(normal)
        h.output_fixture()
        h.begin()
        h.w(h.server + 0x51C8, buffered)
        h.w(h.completed_frame + 0x48, size)
        h.qw(h.completed_frame + 0xC0, h.payload if pointer_present else 0)
        h.u.mem_write(h.completed_frame + 0xBE, bytes([int(key)]))
        h.call(0x13A1A2810, h.encoder, h.completed_frame)
        admitted = buffered == 0 and size != 0 and pointer_present
        clears = key and admitted
        assert h.pending() == int(not clears) and h.query() == (not clears), (
            "buffer loss latch", key, buffered, size, pointer_present, h.pending())
        assert len(h.output_frames) == int(admitted)
        if admitted:
            assert h.output_frames[0]["flags"] == (0x5C if key else 0x4C)
        cases.append(dict(name=f"buffer-key-{key}-buffered-{buffered}-size-{size}-ptr-{pointer_present}",
                          pending=h.pending(), output=list(h.output_frames),
                          visited=sorted(h.visited)))

    dependencies = [SOURCE, feedback.config.source,
                    ROOT / "tools/steam-adaptive-config64-audit.py", client_tool]
    return dict(scope=__doc__, host_sha256=feedback.config.host.SHA256,
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                original_ranges={f"0x{address:x}": dict(size=size, sha256=hashlib.sha256(
                    image[address - base:address - base + size]).hexdigest())
                    for address, size in ((0x13A1EF490, 0x3D3), (0x13A190740, 0x38),
                                          (0x13A1A1580, 0x63), (0x13A18BF50, 0x444),
                                          (0x13A18BD00, 0x24E), (0x13A18B7A0, 0x559))},
                dependencies={str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                              for p in dependencies}, client_basis=client,
                mutation=args.mutation, cases=cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--client-binary", type=Path, required=True)
    parser.add_argument("--client-oracle", type=Path, required=True)
    parser.add_argument("--python", default="python3")
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
