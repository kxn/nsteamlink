#!/usr/bin/env python3
"""Execute SHA-pinned Steam Link ARM64 FEC queue and Reed-Solomon instructions.

Allocation, CUtl containers, packet construction, refcounts and socket I/O use
explicit test doubles. Coding and receiver decisions execute original instructions.
This is neither a native FEC implementation nor a host/device integration test.
"""
import argparse
import contextlib
import io
import itertools
import json
import runpy
import struct
import sys
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--binary", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
saved_argv = sys.argv
sys.argv = [
    str(Path(__file__).with_name("audit-steam-video-recovery.py")),
    "--binary",
    str(args.binary),
    "--output",
    str(args.output.with_name("official-branches.json")),
]
with contextlib.redirect_stdout(io.StringIO()):
    base = runpy.run_path(sys.argv[0])
sys.argv = saved_argv
Run, STOP = base["Run"], base["STOP"]


class FEC:
    def __init__(self, mtu=1500):
        self.r = r = Run()
        self.channel, self.conn = 0x20020000, 0x20030000
        self.out, self.inc = self.channel + 312, self.channel + 344
        self.slots = []
        self.coding_calls = []
        self.delivered = []
        self.attempts = []
        self.socket_result = 0
        r.wq(0xC806C8, 0xF34D48)  # ELF GLOB_DAT: CStreamPacket::s_nMTU
        if mtu is not None:
            r.w32(0xF34D48, mtu)
        r.wh(self.inc, 65535)  # constructor @0x7f86cc
        r.wq(self.channel + 8, self.conn)
        player, vt = 0x20040000, 0x20041000
        r.wq(self.conn + 368, player)
        r.wq(player, vt)
        r.wq(vt + 48, STOP + 0x300)

        def call(entry):
            r.u.reg_write(base["UC_ARM64_REG_PC"], entry)

        def grow(width):
            p, extra = r.r(0), r.r(1)
            old, count = r.q(p), r.i(p + 8)
            new = count + extra
            assert 0 <= new < 65536
            mem = r.alloc(max(1, new * width))
            if old and count:
                r.u.mem_write(mem, bytes(r.u.mem_read(old, count * width)))
            r.wq(p, mem)
            r.w32(p + 8, new)
            r.ret()

        def copy():
            n = r.r(2)
            if n:
                r.u.mem_write(r.r(0), bytes(r.u.mem_read(r.r(1), n)))
            r.ret(r.r(0))

        def fill():
            n = r.r(2)
            if n:
                r.u.mem_write(r.r(0), bytes([r.r(1) & 255]) * n)
            r.ret(r.r(0))

        def append():
            # AddPacket's queue append is abstracted; SendPackets receives the
            # resulting slots in a separately initialized real ring layout.
            slot = r.alloc(8)
            self.slots.append(slot)
            r.wq(r.r(1), 0)
            r.ret(slot)

        def prepend():
            q = r.r(0)
            head, tail = r.i(q + 4), r.i(q + 8)
            if head == 0xFFFFFFFF:
                head = tail = 0
            else:
                head = (head - 1) & r.i(q)
            r.w32(q + 4, head)
            r.w32(q + 8, tail)
            r.wq(r.r(1), 0)
            r.ret(r.q(q + 16) + head * 8)

        def coding(kind, entry):
            self.coding_calls.append(kind)
            call(entry)

        def delivered():
            p = r.r(2)
            self.delivered.append(self.wire(p))
            r.ret()

        def socket():
            self.attempts.append(self.wire(r.r(2)))
            r.ret(self.socket_result)

        r.callbacks.update(
            {
                0xC11150: lambda: grow(8),
                0xC0A430: lambda: grow(1),
                0xBFF3D0: copy,
                0xC09980: fill,
                0xC09AB0: lambda: r.ret(r.alloc(r.r(0))),
                0xC09AC0: lambda: r.ret(),
                0xC0BAE0: lambda: r.ret(r.alloc(r.r(0) * r.r(1))),
                0xC09E50: append,
                0xC09E60: lambda: r.ret(),
                0xC0FFD0: prepend,
                0xC0A380: lambda: r.ret(2),
                0xC11180: lambda: call(0x7F7EEC),
                0xC11190: lambda: call(0x7F7FCC),
                0xC111A0: lambda: call(0x7F84DC),
                0xC110B0: lambda: coding("decode", 0x7F609C),
                0xC110C0: lambda: coding("encode", 0x7F6B7C),
                STOP + 0x300: delivered,
                0xC11170: socket,
            }
        )

    def run(self, entry, *args):
        r = self.r
        r.u.reg_write(base["UC_ARM64_REG_SP"], 0x300FF000)
        r.u.reg_write(base["UC_ARM64_REG_X30"], STOP)
        r.run(entry, *args)
        return r.r(0)

    def wire(self, p):
        r = self.r
        return bytes(r.u.mem_read(r.q(p + 56), r.i(p + 52)))

    def packet(self, wire, receive=1000000):
        r = self.r
        p = r.alloc(max(4096, len(wire) + 64))
        r.packet(p, received=receive)
        r.w32(p + 48, max(2200, len(wire)))
        r.w32(p + 52, len(wire))
        r.u.mem_write(p + 64, wire)
        return p

    def encode(self, payload, percent=20, previous=0):
        r = self.r
        r.wh(self.out, previous)
        header = struct.pack("<BBBBBHHI", 11, 0, 12, 34, 3, 0, 0, 123456)
        p = self.packet(header + payload)
        self.run(0x7F7904, self.out, p, percent)
        return [self.wire(r.q(slot)) for slot in self.slots]

    def prepare_send(self):
        r, q = self.r, self.out + 8
        buf = r.alloc(4096)
        r.w32(q, 511)
        r.w32(q + 4, 0 if self.slots else 0xFFFFFFFF)
        r.w32(q + 8, len(self.slots) - 1)
        r.wq(q + 16, buf)
        for i, slot in enumerate(self.slots):
            r.wq(buf + i * 8, r.q(slot))

    def send(self):
        return self.run(0x7F7D40, self.out, self.conn, 0x20060000)

    def add(self, wire, receive=1000000):
        r = self.r
        result = 0x20050000
        r.wq(result, 0)
        ok = self.run(0x7F7FCC, self.inc, self.packet(wire, receive), result)
        return self.wire(r.q(result)) if ok else None

    def handle(self, wire):
        # Real channel handler routes directly to OnDataPacket; no normal
        # unreliable receive window or type-10 feedback helper is invoked.
        return self.run(0x7F9940, self.channel, self.packet(wire))


def payload(n):
    return bytes((i * 37 + 11) & 255 for i in range(n))


def describe(wire):
    size, shard, parity = struct.unpack_from("<IHH", wire, 13)
    return dict(
        group=struct.unpack_from("<H", wire, 7)[0],
        index=struct.unpack_from("<H", wire, 5)[0],
        size=size,
        shard=shard,
        parity=parity,
        data=(size + shard - 1) // shard,
        wire_bytes=len(wire),
    )


results = []

# Protobuf descriptor is read from the same hash-checked ELF, not the local .proto.
from google.protobuf import descriptor_pb2

schema = descriptor_pb2.FileDescriptorProto.FromString(
    base["BINARY"][0x3E5474 : 0x3E5474 + 21560]
)
field = next(
    f
    for m in schema.message_type
    if m.name == "CStreamingClientConfig"
    for f in m.field
    if f.name == "enable_unreliable_fec"
)
assert field.number == 25 and field.type == 8 and field.default_value == "false"


def record(name, **values):
    results.append({"case": name, **values})


record(
    "embedded_fec_configuration_descriptor",
    field=field.name,
    number=field.number,
    type="bool",
    default=field.default_value,
)

# Verify the original lookup tables against field arithmetic, not a library name.
f = FEC()
mult = bytes(f.r.u.mem_read(0x4641E8, 65536))
inverse = bytes(f.r.u.mem_read(0x4640E8, 256))


def gf_mul(a, b):
    value = 0
    while b:
        if b & 1:
            value ^= a
        a <<= 1
        if a & 256:
            a ^= 0x11D
        b >>= 1
    return value


assert all(mult[a * 256 + b] == gf_mul(a, b) for a in range(256) for b in range(256))
assert all(gf_mul(a, inverse[a]) == 1 for a in range(1, 256))
record(
    "original_GF256_tables_match_polynomial_0x11d",
    multiplication_entries=65536,
    inverse_entries=255,
)

# Preserve the ELF's data initializer for this case; other tests inject MTU.
f = FEC(mtu=None)
initial_mtu = f.r.i(0xF34D48)
assert initial_mtu == 1024
wires = f.encode(payload(4000), 20)
outputs = [value for w in wires[1:] if (value := f.add(w))]
assert len(outputs) == 1 and outputs[0][13:] == payload(4000)
record(
    "ELF_initial_mtu_not_runtime_negotiated_mtu",
    mtu=initial_mtu,
    **describe(wires[0]),
    dropped=[0],
    recovered=True,
)

# Sender routing is conditional on a connection flag, not on packet type
# availability or the percentage setter alone. Downstream send calls are stubs.
for flag in (0, 1):
    f = FEC()
    f.r.w32(f.conn + 16, 1)
    f.r.b(f.conn + 11, flag)
    selected = []
    f.r.callbacks[0xC0E390] = lambda: f.r.ret(f.channel)

    def route(name):
        selected.append(name)
        f.r.ret(0)

    f.r.callbacks[0xC11210] = lambda: route("ordinary")
    f.r.callbacks[0xC11230] = lambda: route("fec")
    assert f.run(0x7FBB58, f.conn, f.packet(b"\x03" + bytes(12)), 3) == 0
    assert selected == ["fec" if flag else "ordinary"]
    record("send_route_flag_" + str(flag), selected=selected)
    f.run(0x7FBCBC, f.conn, 3, 50)
    assert f.r.i(f.channel + 32) == 50 and f.r.u.mem_read(f.conn + 11, 1)[0] == flag
    record("percentage_does_not_enable_flag_" + str(flag), percentage=50, flag=flag)

# Byte vectors can be used by a future independent implementation. These are
# generated by original AddPacket + encode, not by the arithmetic checker above.
f = FEC(mtu=64)
data = payload(80)
wires = f.encode(data, 50)
assert describe(wires[0])["data"] == 3 and describe(wires[0])["parity"] == 2
record(
    "reference_vector_k3_m2_shard32",
    payload=data.hex(),
    mtu=64,
    percent=50,
    wires=[w.hex() for w in wires],
)

# Deterministic round trips execute the actual encoder AND decoder. No modeled
# parity bytes or RS substitute is used; known source bytes are the oracle.
for size, percent in (
    (1, 20),
    (16, 20),
    (17, 20),
    (1472, 20),
    (1473, 20),
    (4000, 0),
    (4000, 1),
    (4000, 20),
    (4000, 50),
    (8000, 50),
):
    f = FEC()
    original_payload = payload(size)
    wires = f.encode(original_payload, percent)
    meta = describe(wires[0])
    k, m = meta["data"], meta["parity"]
    assert len(wires) == k + m
    assert all(describe(w)["index"] == i for i, w in enumerate(wires))
    assert m == (k * percent + 99) // 100
    assert all(
        w[21:]
        == (
            original_payload[i * meta["shard"] : (i + 1) * meta["shard"]].ljust(
                meta["shard"], b"\0"
            )
        )
        for i, w in enumerate(wires[:k])
    )
    for drop_count in sorted(set((0, min(1, m), m, m + 1))):
        # Erase data before parity; remain within valid shard indices.
        drop = set(range(min(drop_count, len(wires))))
        receiver = FEC()
        output = []
        for wire in (w for i, w in enumerate(wires) if i not in drop):
            value = receiver.add(wire)
            if value:
                output.append(value)
        expected = len(wires) - len(drop) >= k
        assert bool(output) == expected
        if output:
            assert len(output) == 1 and output[0][13:] == original_payload
        record(
            f"roundtrip_{size}_{percent}_drop{len(drop)}",
            **meta,
            dropped=sorted(drop),
            recovered=bool(output),
            rs_calls=receiver.coding_calls,
        )

# Permutations include parity-first arrival and a missing middle data shard.
wires = FEC().encode(payload(4000), 50)  # k=3, m=2
for lost in itertools.combinations(range(5), 2):
    keep = [i for i in range(5) if i not in lost]
    for order in (keep, list(reversed(keep))):
        f = FEC()
        outputs = [value for i in order if (value := f.add(wires[i]))]
        assert len(outputs) == 1 and outputs[0][13:] == payload(4000)
        record(
            "erasures_"
            + "_".join(map(str, lost))
            + "_order"
            + "".join(map(str, order)),
            lost=lost,
            order=order,
            recovered=True,
            rs_calls=f.coding_calls,
        )

# The current-group receiver discards incomplete data on a different group.
f = FEC()
a = FEC().encode(payload(4000), 20, previous=0)
b = FEC().encode(payload(4001), 20, previous=1)
assert f.add(a[0]) is None
assert f.add(b[0]) is None
assert f.r.h(f.r.q(f.inc + 8) + 64 + 7) == 2
assert f.add(a[1]) is None
assert f.r.h(f.r.q(f.inc + 8) + 64 + 7) == 1
record("unfinished_group_replaced_even_by_older_uncompleted_group", active_group=1)

# Completed group IDs use signed 16-bit deltas, including wrap.
f = FEC()
f.r.wh(f.inc, 65534)
wires = FEC().encode(payload(2000), 20, previous=65535)
outputs = [value for w in wires if (value := f.add(w))]
assert len(outputs) == 1 and outputs[0][13:] == payload(2000)
assert f.add(wires[0]) is None
record("completed_group_wrap_and_late_duplicates", group=0, delivered=1)

# Raw duplicate handling is observed, not endorsed as a safe receiver design.
f = FEC()
wires = FEC().encode(payload(4000), 20)
assert f.add(wires[0]) is None and f.add(wires[0]) is None
value = f.add(wires[0])
assert value is not None and value[13:] != payload(4000)
record(
    "duplicate_count_triggers_insufficient_unique_reconstruction",
    received_datagrams=3,
    unique_shards=1,
    delivered=True,
    payload_matches=False,
)

# At k+m > 255 the sender disables parity rather than truncating it.
f = FEC(mtu=64)
wires = f.encode(payload(32 * 128), 100)
meta = describe(wires[0])
assert meta["data"] == 128 and meta["parity"] == 0 and len(wires) == 128
assert f.coding_calls == []
record("parity_disabled_above_255_total_shards", **meta)

# Malformed single datagrams must fail these observed entry guards. This is
# not exhaustive fuzzing or a proof of upstream memory safety.
wires = FEC().encode(payload(4000), 20)
for name, change in (
    ("short", lambda w: w[:21]),
    ("negative_size", lambda w: w[:13] + struct.pack("<I", 0x80000000) + w[17:]),
    ("zero_shard", lambda w: w[:17] + b"\0\0" + w[19:]),
    ("bad_index", lambda w: w[:5] + struct.pack("<H", 4) + w[7:]),
    ("bad_length", lambda w: w[:-1]),
):
    f = FEC()
    assert f.add(change(wires[0])) is None
    record("guard_" + name, delivered=False)

# The actual handler bypasses the normal unreliable receive window.
f = FEC()
for w in wires[1:]:
    f.handle(w)
assert len(f.delivered) == 1 and f.delivered[0][13:] == payload(4000)
assert f.r.q(f.channel + 296) == 0 and f.r.h(f.channel + 288) == 0
record(
    "fec_handler_direct_delivery_without_normal_window",
    delivered=1,
    normal_window_untouched=True,
)

# Reconstructed type-11 packets are parsed as the same media frame envelope;
# group sequence is not the application video frame ID.
f = FEC()
body = b"\x01" + struct.pack("<HIHI", 123, 87654, 45, 9988) + b"coded-data"
wires = f.encode(body, 20)
values = [value for w in wires[1:] if (value := f.add(w))]
assert len(values) == 1 and values[0][0] == 11
frame = 0x20070000
f.run(0x7F2BAC, frame, f.packet(values[0]))
assert (
    f.r.h(frame + 26) == 123 and f.r.i(frame + 28) == 87654 and f.r.h(frame + 44) == 45
)
assert f.r.u.mem_read(frame + 24, 2) == bytes([3, 1])
record(
    "reconstructed_type11_uses_media_envelope",
    group=1,
    frame_id=123,
    frame_timestamp=87654,
    input_mark=45,
)

# No ACK/NACK cache after successful FEC sends. Socket result 1 is a local
# retry: put the single failed send back at the head, then return.
f = FEC()
wires = f.encode(payload(4000), 20)
f.prepare_send()
f.socket_result = 1
f.send()
assert len(f.attempts) == 1
f.socket_result = 0
f.send()
assert len(f.attempts) == len(wires) + 1 and f.attempts[1:] == wires
f.send()
assert len(f.attempts) == len(wires) + 1
record(
    "send_backpressure_retry_then_no_retained_resend",
    attempts=len(f.attempts),
    shard_count=len(wires),
)

# The committed byte fixture must continue to match the original instructions;
# this script never overwrites it from current native implementation output.
fixture_path = Path(__file__).with_name("fixtures") / "steam-fec-reference.json"
fixture = json.loads(fixture_path.read_text())
assert (
    fixture["binary_sha256"]
    == "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"
)
assert fixture["vector"] == next(
    c for c in results if c["case"] == "reference_vector_k3_m2_shard32"
)

args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(
    json.dumps(
        {
            "scope": __doc__,
            "binary_sha256": "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e",
            "cases": results,
        },
        indent=2,
    )
    + "\n"
)
print(
    json.dumps({"cases": len(results), "result": "passed", "output": str(args.output)})
)
