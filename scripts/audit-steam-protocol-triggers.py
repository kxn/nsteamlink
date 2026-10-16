#!/usr/bin/env python3
"""Execute original protocol branches from wire/event/API triggers.

Fixed Android ELF, no host or device I/O. Real socket/connection CRC, guards,
frame-envelope extraction, client dispatch and pause/resume execute unchanged.
Protobuf parsing uses the original embedded schema through Python; allocation,
address comparison, delegates and final transport sends are explicit doubles.
"""
import argparse
import contextlib
import io
import json
import runpy
import struct
import sys
from pathlib import Path
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from google.protobuf.message import DecodeError

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
schema = descriptor_pb2.FileDescriptorProto.FromString(
    base["BINARY"][0x3E5474 : 0x3E5474 + 21560]
)
pool = descriptor_pool.DescriptorPool()
pool.Add(schema)


def message(name, **fields):
    return message_factory.GetMessageClass(pool.FindMessageTypeByName(name))(**fields)


def crc32c(data):
    crc = 0xFFFFFFFF
    for value in data:
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


assert crc32c(b"123456789") == 0xE3069283


def wire(
    kind,
    body=b"",
    *,
    crc=False,
    source=34,
    dest=12,
    channel=0,
    sequence=0,
    stamp=900000,
):
    data = (
        struct.pack(
            "<BBBBBHHI",
            kind | (128 if crc else 0),
            0,
            source,
            dest,
            channel,
            0,
            sequence,
            stamp,
        )
        + body
    )
    return data + struct.pack("<I", crc32c(data)) if crc else data


class Harness(Run):
    def __init__(self):
        super().__init__()
        self.callbacks.update(
            {
                0xC09E30: lambda: self.ret(),
                0xBFF1A0: lambda: self.ret(),
                0xC0A380: lambda: self.ret(2),
            }
        )
        self.call(0x7FE284)

    def jump(self, address):
        self.u.reg_write(base["UC_ARM64_REG_PC"], address)

    def call(self, address, *params):
        self.u.reg_write(base["UC_ARM64_REG_SP"], 0x300FF000)
        self.u.reg_write(base["UC_ARM64_REG_X30"], STOP)
        self.run(address, *params)
        return self.r(0)

    def packet_bytes(self, data):
        p = self.alloc(max(4096, len(data) + 64))
        self.packet(p)
        self.w32(p + 52, len(data))
        self.u.mem_write(p + 64, data)
        return p

    def raw(self, p):
        return bytes(self.u.mem_read(self.q(p + 56), self.i(p + 52)))


cases = []


def record(name, group, inputs, observed):
    cases.append(dict(case=name, group=group, input=inputs, observed=observed))


# Full socket -> HandleMessage -> connection -> Connected. CRC code is original;
# fixture CRCs come from an independent bitwise implementation above.
def transport_fixture():
    r = Harness()
    sock, conn, ch, delegate, vt, array, transport, tvt = (
        0x20000000 + i * 4096 for i in range(8)
    )
    r.wq(sock + 8, array)
    r.w32(sock + 24, 1)
    r.wq(array, conn)
    r.b(conn + 12, 12)
    r.w32(conn + 1212, 0xFFFFFFFF)
    r.wq(conn + 368, delegate)
    r.wq(delegate, vt)
    r.wq(vt + 40, STOP + 0x100)
    r.wq(sock, transport)
    r.wq(transport, tvt)
    r.wq(tvt + 72, STOP + 0x200)
    r.actions = []

    def action(name):
        r.actions.append(name)
        r.ret()

    r.callbacks.update(
        {
            0xC11450: lambda: r.jump(0x8E1610),
            0xC110D0: lambda: r.jump(0x7F6DD0),
            0xC115A0: lambda: r.jump(0x7FF640),
            0xC11350: lambda: r.jump(0x7FACFC),
            0xC11390: lambda: r.jump(0x7FBEF4),
            0xC0DC80: lambda: r.ret(1),
            0xC0DA00: lambda: r.ret(),
            0xC11360: lambda: r.ret(),
            0xC11370: lambda: r.ret(),
            0xC112A0: lambda: action("timestamp"),
            STOP + 0x100: lambda: action("connected"),
            STOP + 0x200: lambda: action("transport_send"),
            0xC0E390: lambda: r.ret(ch),
            0xC11250: lambda: action("channel"),
            0xC0E030: lambda: action("disconnect"),
        }
    )
    return r, sock, conn


for crc in (False, True):
    for size in (3, 4, 5):
        r, sock, conn = transport_fixture()
        data = wire(2, bytes(size), crc=crc)
        p = r.packet_bytes(data)
        r.call(0x7FF3E0, sock, p, r.now)
        accepted = size == 4
        assert ("connected" in r.actions) == accepted
        assert bool(r.u.mem_read(conn + 10, 1)[0]) == (crc and accepted)
        record(
            f"connected_crc{int(crc)}_body{size}",
            "connected",
            dict(datagram=data.hex(), state=0, local_id=12, peer_address_matches=True),
            dict(
                actions=list(r.actions),
                state=r.i(conn + 16),
                crc_required=bool(r.u.mem_read(conn + 10, 1)[0]),
                stripped_length=r.i(p + 52),
            ),
        )

# Handshake followed by a second datagram, in the SAME connection state.
for mode in (
    "none",
    "valid",
    "bad_crc",
    "short_crc",
    "bad_source",
    "bad_destination",
    "bad_address",
):
    r, sock, conn = transport_fixture()
    handshake = wire(2, bytes(4), crc=True)
    r.call(0x7FF3E0, sock, r.packet_bytes(handshake), r.now)
    assert r.i(conn + 16) == 1 and r.u.mem_read(conn + 10, 1) == b"\x01"
    r.actions.clear()
    data = wire(
        3,
        b"\x01payload",
        crc=mode != "none",
        channel=3,
        source=35 if mode == "bad_source" else 34,
        dest=13 if mode == "bad_destination" else 12,
    )
    if mode == "bad_crc":
        data = data[:-1] + bytes([data[-1] ^ 1])
    if mode == "short_crc":
        data = data[:16]
    if mode == "bad_address":
        r.callbacks[0xC0DC80] = lambda: r.ret(0)
    r.call(0x7FF3E0, sock, r.packet_bytes(data), r.now + 100)
    assert ("channel" in r.actions) == (mode == "valid"), (mode, r.actions)
    record(
        "negotiated_crc_" + mode,
        "crc_requirement",
        dict(
            datagrams=[handshake.hex(), data.hex()],
            peer_address_matches=mode != "bad_address",
        ),
        dict(actions=list(r.actions), crc_required=True, last_receive=r.i(conn + 52)),
    )

# CRC-required enforcement is on ordinary data; connection type 9 has its own
# earlier ID/address path. Verify both instead of globally rejecting every plain
# packet after a CRC-enabled handshake.
for required in (False, True):
    for kind in (3, 9):
        for mode in ("none", "valid", "bad_crc"):
            r, sock, conn = transport_fixture()
            handshake = wire(2, bytes(4), crc=required)
            r.call(0x7FF3E0, sock, r.packet_bytes(handshake), r.now)
            r.actions.clear()
            data = wire(
                kind,
                b"payload" if kind == 3 else b"",
                crc=mode != "none",
                channel=3 if kind == 3 else 0,
            )
            if mode == "bad_crc":
                data = data[:-1] + bytes([data[-1] ^ 1])
            r.call(0x7FF3E0, sock, r.packet_bytes(data), r.now + 100)
            accepted = mode != "bad_crc" and (
                kind == 9 or not required or mode == "valid"
            )
            assert r.actions == (
                ["disconnect" if kind == 9 else "channel"] if accepted else []
            )
            record(
                f"crc_policy_required{required}_type{kind}_{mode}",
                "crc_policy",
                dict(
                    datagrams=[handshake.hex(), data.hex()], peer_address_matches=True
                ),
                dict(actions=list(r.actions), last_receive=r.i(conn + 52)),
            )

# Plaintext control envelope after reliable reassembly; execute actual packet
# frame constructor and queued dispatcher. Only protobuf parse/layout is doubled.
for name, state, channel, kind, body, expected in (
    (
        "mtu_low",
        2,
        1,
        7,
        message("CServerHandshakeMsg", info={"mtu": 0}).SerializeToString(),
        512,
    ),
    (
        "mtu_high",
        2,
        1,
        7,
        message("CServerHandshakeMsg", info={"mtu": 9000}).SerializeToString(),
        1472,
    ),
    (
        "mtu_absent",
        2,
        1,
        7,
        message("CServerHandshakeMsg", info={}).SerializeToString(),
        512,
    ),
    ("mtu_missing_info", 2, 1, 7, b"", 1024),
    ("mtu_bad_proto", 2, 1, 7, b"\x0a\x08\x08", 1024),
    (
        "mtu_wrong_state",
        3,
        1,
        7,
        message("CServerHandshakeMsg", info={"mtu": 9000}).SerializeToString(),
        1024,
    ),
    (
        "mtu_wrong_channel",
        2,
        2,
        7,
        message("CServerHandshakeMsg", info={"mtu": 9000}).SerializeToString(),
        1024,
    ),
    ("mtu_wrong_message", 2, 1, 9, b"", 1024),
):
    r = Harness()
    client, queue, info = 0x20000000, 0x20010000, 0x20020000
    data = wire(5, bytes([kind]) + body, channel=channel)
    p = r.packet_bytes(data)
    r.wq(client + 736, queue)
    r.wq(queue, p)
    r.w32(client + 256, state)
    r.wq(0xC806C8, 0xF34D48)
    r.w32(0xF34D48, 1024)
    r.wq(0xC7E308, info)
    actions = []

    def parse():
        frame, msgptr = r.r(0), r.r(1)
        packet = r.q(frame + 8)
        payload = r.raw(packet)[14:]
        msg = message("CServerHandshakeMsg")
        try:
            msg.ParseFromString(payload)
            valid = msg.IsInitialized()
        except DecodeError:
            valid = False
        actions.append("parse_ok" if valid else "parse_failed")
        if valid:
            r.wq(msgptr + 24, info)
            r.w32(info + 24, msg.info.mtu)
        r.ret(int(valid))

    def auth():
        actions.append("start_authentication")
        r.ret()

    r.callbacks.update(
        {
            0xC0E130: lambda: r.jump(0x7F2B98),
            0xC10FC0: lambda: r.jump(0x7F2BAC),
            0xC0A380: lambda: r.ret(2),
            0xC0A390: lambda: r.ret(1),
            0xC0E120: lambda: r.ret(),
            0xC03E40: lambda: r.ret(),
            0xC0E160: parse,
            0xC043B0: lambda: r.ret(),
            0xC0E170: auth,
            0xC0E1A0: lambda: r.ret(0),
        }
    )
    r.call(0x7A6368, client)
    assert r.i(0xF34D48) == expected, (name, r.i(0xF34D48))
    assert ("start_authentication" in actions) == (
        name in ("mtu_low", "mtu_high", "mtu_absent")
    )
    record(
        name,
        "mtu",
        dict(
            reassembled_plaintext_packet=data.hex(),
            client_state=state,
            initial_mtu=1024,
        ),
        dict(mtu=r.i(0xF34D48), actions=actions),
    )


# Pause/Resume are local lifecycle actions, not incoming host control messages.
def pause_fixture(paused=False, connection_state=1, client_state=6):
    r = Harness()
    client, conn = 0x20000000, 0x20010000
    r.b(client + 19, int(paused))
    r.w32(client + 256, client_state)
    r.wq(client + 280, conn if connection_state is not None else 0)
    r.w32(conn + 16, connection_state or 0)
    r.b(conn + 8, int(paused))
    r.w32(conn + 48, 123456)
    r.w32(conn + 52, 100)
    r.w32(conn + 56, 200)
    r.actions = []

    def control():
        r.actions.append(dict(control=r.r(1)))
        r.ret()

    def loss():
        r.actions.append(dict(data_lost=r.r(1), frame_ids_count=r.i(r.r(2) + 16)))
        r.ret()

    r.callbacks.update(
        {
            0xC03DA0: lambda: r.ret(),
            0xC04F90: lambda: r.ret(),
            0xC03E20: lambda: r.ret(),
            0xC04FB0: lambda: r.ret(),
            0xC0E110: control,
            0xC0E810: lambda: r.jump(0x7FB990),
            0xC0E830: lambda: r.jump(0x7FB99C),
            0xC0E090: loss,
        }
    )
    return r, client, conn


for action, entry in (("pause", 0x7B02BC), ("resume", 0x7B0384)):
    for paused in (False, True):
        for conn_state in (None, 0, 1, 3):
            for client_state in (2, 6):
                r, client, conn = pause_fixture(paused, conn_state, client_state)
                r.call(entry, client)
                eligible = (
                    not paused if action == "pause" else paused
                ) and conn_state == 1
                expected = []
                if eligible and client_state == 6:
                    expected = (
                        [dict(control=122)]
                        if action == "pause"
                        else [
                            dict(control=123),
                            dict(data_lost=0, frame_ids_count=0),
                            dict(data_lost=1, frame_ids_count=0),
                        ]
                    )
                assert r.actions == expected, (
                    action,
                    paused,
                    conn_state,
                    client_state,
                    r.actions,
                )
                assert r.u.mem_read(client + 19, 1) == bytes([action == "pause"])
                if eligible:
                    assert r.u.mem_read(conn + 8, 1) == bytes([action == "pause"])
                    if action == "resume":
                        assert r.i(conn + 52) == 123456 and r.i(conn + 56) == 123456
                record(
                    f"{action}_p{int(paused)}_conn{conn_state}_client{client_state}",
                    "pause_resume",
                    dict(
                        action=action,
                        client_paused=paused,
                        connection_state=conn_state,
                        client_state=client_state,
                    ),
                    dict(
                        actions=r.actions,
                        client_paused=bool(r.u.mem_read(client + 19, 1)[0]),
                        connection_paused=bool(r.u.mem_read(conn + 8, 1)[0]),
                        last_receive=r.i(conn + 52),
                        last_echo=r.i(conn + 56),
                    ),
                )

for event, expected in (
    (0x103, [dict(control=122)]),
    (0x104, []),
    (0x105, []),
    (
        0x106,
        [
            dict(control=123),
            dict(data_lost=0, frame_ids_count=0),
            dict(data_lost=1, frame_ids_count=0),
        ],
    ),
):
    r, client, conn = pause_fixture(paused=event == 0x106)
    player, ev = 0x20020000, 0x20030000
    r.wq(player + 8, client)
    r.w32(ev, event)
    r.callbacks.update(
        {0xC0E800: lambda: r.jump(0x7B02BC), 0xC0E820: lambda: r.jump(0x7B0384)}
    )
    r.call(0x7B8110, player, ev)
    assert r.actions == expected, (event, r.actions)
    record(
        f"sdl_event_{event:x}",
        "lifecycle",
        dict(sdl_event=event, connection_state=1, client_state=6),
        dict(actions=r.actions),
    )


# Socket::Send trigger: quota rejection occurs BEFORE transport I/O; transport
# failure is a separate return with no budget consumption. ACK/NACK/FEC bypass
# this particular two-class shaper, as in the original inlined admission path.
for kind in (3, 5, 7, 10, 11):
    for offset in (-1, 0, 1):
        for transport_result in (0, 1, 2):
            r = Harness()
            sock, conn, shaper, transport, vt = (
                0x20000000,
                0x20010000,
                0x20020000,
                0x20030000,
                0x20040000,
            )
            r.now = 1000
            r.wq(sock, transport)
            r.wq(transport, vt)
            r.wq(vt + 72, STOP + 0x200)
            r.wq(sock + 64, shaper)
            r.w32(shaper, 65536)
            r.w32(shaper + 4, 65536)
            r.w32(shaper + 8, 1000 + offset)
            r.w32(shaper + 12, 1000 + offset)
            r.b(conn + 10, 1)
            sent = []

            def send():
                packet = r.r(1)
                sent.append(
                    bytes(r.u.mem_read(r.q(packet + 56), r.i(packet + 52) + 4)).hex()
                )
                r.ret(transport_result)

            r.callbacks.update(
                {
                    STOP + 0x200: send,
                    0xC10FE0: lambda: r.ret(),
                    0xC11450: lambda: r.jump(0x8E1610),
                    0xC11370: lambda: r.ret(),
                }
            )
            data = wire(kind, b"payload", channel=3)
            packet = r.packet_bytes(data)
            result = r.call(0x7FF1DC, sock, conn, packet)
            blocked = kind in (3, 5) and offset == 1
            assert bool(sent) == (not blocked)
            assert result == (1 if blocked else transport_result)
            assert bool(r.u.mem_read(sock + 57, 1)[0]) == blocked
            if sent:
                actual = bytes.fromhex(sent[0])
                assert struct.unpack_from("<I", actual, len(actual) - 4)[0] == crc32c(
                    actual[:-4]
                )
                assert struct.unpack_from("<I", actual, 9)[0] == 1000
            for slot in (8, 12):
                charged = (
                    not blocked
                    and transport_result == 0
                    and slot == (8 if kind == 3 else 12)
                    and kind in (3, 5)
                )
                assert r.i(shaper + slot) == 1000 + offset + (
                    len(data) if charged else 0
                )
            record(
                f"send_type{kind}_deadline{offset:+}_transport{transport_result}",
                "send_budget",
                dict(
                    packet=data.hex(),
                    now=1000,
                    deadline=1000 + offset,
                    rate=65536,
                    crc_required=True,
                    transport_result=transport_result,
                ),
                dict(
                    result=result,
                    sent=sent,
                    shaper_blocked=blocked,
                    unreliable_deadline=r.i(shaper + 8),
                    reliable_deadline=r.i(shaper + 12),
                ),
            )

# Raw type-11 ingress is independent of the outgoing enable byte. The selected
# shards here are the previously committed original-code byte vector, not newly
# encoded host defaults. Both layers route into the actual FEC receiver/RS code.
sys.argv = [
    str(Path(__file__).with_name("audit-steam-fec.py")),
    "--binary",
    str(args.binary),
    "--output",
    str(args.output.with_name("fec-audit.json")),
]
with contextlib.redirect_stdout(io.StringIO()):
    fec_module = runpy.run_path(sys.argv[0])
sys.argv = saved_argv
vector = json.loads(
    (Path(__file__).with_name("fixtures") / "steam-fec-reference.json").read_text()
)["vector"]
for label, indices, delivered, correct in (
    ("all_data", [0, 1, 2], 1, True),
    ("one_missing", [1, 2, 3], 1, True),
    ("two_missing", [2, 3, 4], 1, True),
    ("too_few", [3, 4], 0, False),
    ("duplicate_counts_as_received_in_original", [1, 1, 1], 1, False),
):
    f = fec_module["FEC"]()
    r = f.r
    sock, array = 0x20080000, 0x20090000
    r.wq(sock + 8, array)
    r.w32(sock + 24, 1)
    r.wq(array, f.conn)
    r.w32(f.conn + 16, 1)
    r.b(f.conn + 12, 34)
    r.b(f.conn + 13, 12)
    r.w32(f.conn + 1212, 0xFFFFFFFF)
    r.b(f.conn + 11, 0)

    def jump(address):
        r.u.reg_write(base["UC_ARM64_REG_PC"], address)

    r.callbacks.update(
        {
            0xC115A0: lambda: jump(0x7FF640),
            0xC11350: lambda: jump(0x7FACFC),
            0xC0DC80: lambda: r.ret(1),
            0xC11360: lambda: r.ret(),
            0xC11370: lambda: r.ret(),
            0xC0E390: lambda: r.ret(f.channel),
            0xC11250: lambda: jump(0x7F9250),
            0xC11260: lambda: jump(0x7F9940),
        }
    )
    datagrams = [vector["wires"][index] for index in indices]
    for datagram in datagrams:
        f.run(0x7FF3E0, sock, f.packet(bytes.fromhex(datagram)), r.now)
    assert len(f.delivered) == delivered
    assert (
        bool(f.delivered and f.delivered[0][13:].hex() == vector["payload"]) == correct
    )
    record(
        "fec_" + label,
        "fec_ingress",
        dict(datagrams=datagrams, outgoing_fec_enabled=False, local_id=34, peer_id=12),
        dict(delivered=[value.hex() for value in f.delivered], payload_correct=correct),
    )


# Previously described only as "RTO": exercise the actual retry condition,
# including the strict boundary and the counter==0 / timestamp==0 shortcuts.
for srtt in (0, 65, 1000, 3276, 5000):
    clamped = max(65, min(srtt, 3276))
    threshold = clamped + clamped // 4
    for age in (threshold - 1, threshold, threshold + 1):
        for counter in (1, 255):
            r = Harness()
            ch, conn, slots = 0x20000000, 0x20010000, 0x20020000
            r.wq(ch + 8, conn)
            r.w32(conn + 744, srtt)
            r.w32(ch + 116, 7)
            r.wh(ch + 120, 100)
            r.wh(ch + 122, 101)
            r.wq(ch + 128, slots)
            p = r.packet_bytes(
                wire(5, b"payload", channel=1, sequence=100, stamp=r.now - age)
            )
            r.b(p + 65, counter)
            r.wq(slots + (100 & 7) * 8, p)
            sent = []

            def send_reliable():
                sent.append(100)
                r.w32(p + 73, r.now)
                r.ret(0)

            r.callbacks[0xC11170] = send_reliable
            r.call(0x7F8AC4, ch, r.now)
            assert bool(sent) == (age > threshold), (srtt, age, counter, sent)
            expected_counter = min(255, counter + int(bool(sent)))
            assert r.u.mem_read(p + 65, 1)[0] == expected_counter
            record(
                f"reliable_srtt{srtt}_age{age}_counter{counter}",
                "reliable_retry",
                dict(srtt_ticks=srtt, age_ticks=age, wire_counter=counter),
                dict(
                    sent=bool(sent),
                    wire_counter=expected_counter,
                    head=r.h(ch + 120),
                    tail=r.h(ch + 122),
                ),
            )
for counter, stamp in ((0, 1000000), (1, 0), (255, 0)):
    r = Harness()
    ch, conn, slots = 0x20000000, 0x20010000, 0x20020000
    r.wq(ch + 8, conn)
    r.w32(ch + 116, 7)
    r.wh(ch + 120, 100)
    r.wh(ch + 122, 101)
    r.wq(ch + 128, slots)
    p = r.packet_bytes(wire(5, b"payload", channel=1, sequence=100, stamp=stamp))
    r.b(p + 65, counter)
    r.wq(slots + (100 & 7) * 8, p)
    sent = []

    def shortcut_send():
        sent.append(100)
        r.ret(0)

    r.callbacks[0xC11170] = shortcut_send
    r.call(0x7F8AC4, ch, r.now)
    assert sent == [100]
    record(
        f"reliable_shortcut_counter{counter}_stamp{stamp}",
        "reliable_retry",
        dict(srtt_ticks=0, wire_counter=counter, last_send=stamp),
        dict(sent=True, wire_counter=r.u.mem_read(p + 65, 1)[0]),
    )

# ACK ingress: use real channel dispatch, cumulative ACK and window Advance.
# Retained object lifetime/refcounts and ProcessTimestamp are doubles.
for label, head, tail, ack, missing, expected in (
    ("old", 100, 104, 99, [], 100),
    ("one", 100, 104, 100, [], 101),
    ("three", 100, 104, 102, [], 103),
    ("beyond_tail_capped", 100, 104, 200, [], 104),
    ("old_ack_skips_existing_empty_head", 100, 104, 99, [100], 101),
    ("wrap", 65534, 2, 65535, [], 0),
    ("half_range_rejected", 100, 104, 32867, [], 100),
    ("below_half_range_capped", 100, 104, 32866, [], 104),
):
    r = Harness()
    ch, conn, slots, times = 0x20000000, 0x20010000, 0x20020000, 0x20030000
    r.wq(ch + 8, conn)
    window = ch + 112
    r.w32(window + 4, 7)
    r.wh(window + 8, head)
    r.wh(window + 10, tail)
    r.wq(window + 16, slots)
    r.wq(window + 24, times)
    count = 0
    for step in range((tail - head) & 65535):
        ident = (head + step) & 65535
        if ident in missing:
            continue
        packet = r.packet_bytes(wire(5, b"payload", channel=1, sequence=ident))
        r.wq(slots + (ident & 7) * 8, packet)
        count += 1
    r.w32(window, count)
    data = wire(7, struct.pack("<I", 899000), channel=1, sequence=ack)
    callbacks = []

    def timestamp():
        callbacks.append([r.r(1), r.r(2), r.r(3)])
        r.ret()

    r.callbacks.update(
        {
            0xC11280: lambda: r.jump(0x7F94B8),
            0xC11130: lambda: r.jump(0x7F76F4),
            0xC112A0: timestamp,
        }
    )
    r.call(0x7F9250, ch, r.packet_bytes(data), r.now)
    assert r.h(window + 8) == expected, (label, r.h(window + 8))
    record(
        "reliable_ack_" + label,
        "reliable_ack",
        dict(packet=data.hex(), head=head, tail=tail, missing_slots=missing),
        dict(
            head=r.h(window + 8),
            tail=r.h(window + 10),
            occupied=r.i(window),
            timestamp_calls=callbacks,
        ),
    )

# Timestamp acceptance gate, min RTT and smoothing: stats callbacks capture
# samples, but do NOT pretend to emulate the entire sample-queue eviction model.
for label, last, echo, peer_stamp, now, minimum, previous_smooth, next_min_update in (
    ("too_old", 5000, 4869, 6000, 10000, 0, 0, 20000),
    ("old_boundary", 5000, 4870, 6000, 10000, 0, 0, 20000),
    ("equal_echo", 5000, 5000, 6000, 10000, 0, 0, 20000),
    ("new_echo", 5000, 5001, 6000, 10000, 0, 0, 20000),
    ("future_echo", 5000, 11000, 12000, 10000, 0, 0, 20000),
    ("smooth_and_offset_rejected", 5000, 5001, 6000, 10000, 100, 1000, 20000),
    ("offset_boundary", 5000, 9000, 9500, 10000, 935, 1000, 20000),
    ("offset_above_boundary", 5000, 8999, 9500, 10000, 935, 1000, 20000),
    ("min_increase_due", 5000, 9000, 9500, 10000, 935, 1000, 9999),
):
    r = Harness()
    conn = 0x20000000
    r.callbacks.update({0xC09E30: lambda: r.ret(), 0xBFF1A0: lambda: r.ret()})
    r.call(0x7FE284)
    r.w32(conn + 56, last)
    r.w32(conn + 740, minimum)
    r.w32(conn + 744, previous_smooth)
    r.w32(conn + 736, next_min_update)
    samples = []

    def sample(kind):
        samples.append(dict(kind=kind, value=r.i(r.r(1)), at=r.r(2)))
        r.ret()

    def release_guard():
        r.b(0xF479E8, 1)
        r.ret()

    r.callbacks.update(
        {
            0xC112C0: lambda: sample("rtt"),
            0xC112D0: lambda: sample("offset"),
            0xC017F0: lambda: r.ret(1),
            0xC01810: release_guard,
        }
    )
    r.call(0x7F9A2C, conn, echo, peer_stamp, now)
    accepted = echo - last >= -130
    assert bool(samples) == accepted
    if accepted:
        rtt = max(0, now - echo)
        expected_min = (
            rtt
            if rtt > 0 and (minimum == 0 or rtt < minimum)
            else minimum + (65 if minimum and next_min_update < now else 0)
        )
        assert r.i(conn + 740) == expected_min
        assert r.i(conn + 744) == (
            (previous_smooth + rtt) // 2 if previous_smooth else rtt
        )
        assert any(v["kind"] == "offset" for v in samples) == (rtt <= expected_min + 65)
    record(
        "timestamp_" + label,
        "timestamp",
        dict(
            last_echo=last,
            echo=echo,
            peer_send=peer_stamp,
            now=now,
            min_rtt=minimum,
            smooth=previous_smooth,
            next_min_update=next_min_update,
        ),
        dict(
            samples=samples,
            last_echo=r.i(conn + 56),
            min_rtt=r.i(conn + 740),
            smooth=r.i(conn + 744),
            next_min_update=r.i(conn + 736),
        ),
    )


# QoS and bitrate have different triggers/actions; do not wire bitrate control
# directly to both shaper classes merely because the units look related.
for schema_name, kind, entry, ctor, dtor, field in (
    ("CSetQoSMsg", 87, 0x7ADCD0, 0xC03F10, 0xC05220, "use_qos"),
    ("CSetTargetBitrateMsg", 94, 0x7AEBB4, 0xC03F50, 0xC05260, "bitrate"),
):
    for value, udp_present, conn_present, delegate_present in (
        (0, True, True, True),
        (1, True, True, True),
        (None, True, True, True),
        (1, False, True, True),
        (1, True, False, True),
        (1, True, True, False),
    ):
        r = Harness()
        client, conn, udp, delegate, vt, frame = (
            0x20000000,
            0x20010000,
            0x20020000,
            0x20030000,
            0x20040000,
            0x20050000,
        )
        r.wq(client + 280, conn if conn_present else 0)
        r.wq(client + 272, udp if udp_present else 0)
        r.wq(client + 48, delegate if delegate_present else 0)
        r.wq(delegate, vt)
        r.wq(vt + 144, STOP + 0x300)
        payload = (
            message(schema_name, **{field: value}).SerializeToString()
            if value is not None
            else b""
        )
        data = wire(5, bytes([kind]) + payload, channel=1)
        packet = r.packet_bytes(data)
        r.call(0x7F2BAC, frame, packet)
        actions = []

        def parsed_control():
            obj = r.r(1)
            msg = message(schema_name)
            msg.ParseFromString(r.raw(r.q(r.r(0) + 8))[14:])
            valid = msg.IsInitialized()
            if valid:
                if kind == 87:
                    r.b(obj + 24, int(msg.use_qos))
                else:
                    r.w32(obj + 24, msg.bitrate)
            r.ret(int(valid))

        def qos():
            actions.append(
                dict(qos_type=r.r(1), peer_address_is_connection=r.r(2) == conn + 20)
            )
            r.ret()

        def bitrate():
            actions.append(dict(target_bitrate=r.r(1)))
            r.ret()

        r.callbacks.update(
            {
                ctor: lambda: r.ret(),
                dtor: lambda: r.ret(),
                0xC0E160: parsed_control,
                0xC0E250: qos,
                STOP + 0x300: bitrate,
            }
        )
        r.call(entry, client, frame)
        expected = []
        if value is not None:
            if kind == 87 and udp_present and conn_present:
                expected = [dict(qos_type=value * 2, peer_address_is_connection=True)]
            if kind == 94 and delegate_present:
                expected = [dict(target_bitrate=value)]
        assert actions == expected, (kind, value, actions)
        if kind == 94 and value is not None:
            assert r.i(client + 664) == value
        record(
            f"control_{kind}_v{value}_udp{udp_present}_conn{conn_present}_delegate{delegate_present}",
            "control_actions",
            dict(
                reassembled_plaintext_packet=data.hex(),
                udp_present=udp_present,
                connection_present=conn_present,
                delegate_present=delegate_present,
            ),
            dict(actions=actions, stored_bitrate=r.i(client + 664)),
        )

args.output.parent.mkdir(parents=True, exist_ok=True)
report = dict(
    scope=__doc__,
    binary_sha256="50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e",
    cases=cases,
)
reference_path = (
    Path(__file__).with_name("fixtures") / "steam-protocol-trigger-reference.json"
)
reference = json.loads(reference_path.read_text())
assert report["binary_sha256"] == reference["binary_sha256"]
assert cases == reference["cases"], "original trigger reference changed"
args.output.write_text(json.dumps(report, indent=2) + "\n")
print(
    json.dumps(
        dict(
            cases=len(cases),
            groups={
                g: sum(c["group"] == g for c in cases)
                for g in sorted({c["group"] for c in cases})
            },
            result="passed",
        )
    )
)
