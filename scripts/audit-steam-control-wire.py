#!/usr/bin/env python3
"""Execute official client control/Frame/Connection/Channel/window/Socket sends.

Original ARM64 instructions construct the frame, copy the serializer output,
assign header/IDs, fragment, insert into the reliable window, select packets,
stamp, shape and append CRC. Protobuf bytes/ByteSize/serialization, allocation,
channel constructor, mutex/refcount/stats/destructors and final transport are
explicit adapters. Factory selection itself executes original GetChannel.
Discovery additionally adapts protobuf parsing; its response fields, padding,
Frame/Connection SendUnconnected and Socket execute original instructions.
No encryption, real UDP, Steam session or decoder is exercised.
"""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "outgoing", ROOT / "scripts/audit-steam-outgoing.py"
)
outgoing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(outgoing)


def varint(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def audit(base):
    outgoing.audit(base)
    STOP = base["STOP"]

    class Sender(outgoing.audit.Sender):
        def __init__(self, crc, mtu, payload, result=0):
            super().__init__(rate=0, transport=result)
            self.payload = payload
            self.frame, self.message, self.client, self.msgvt = (
                self.alloc(4096) for _ in range(4)
            )
            self.created = []
            self.packet_ptr = None
            self.frame_result = None
            self.wq(self.client + 280, self.conn)
            self.w32(self.client + 256, 2)
            self.b(self.conn + 10, crc)
            self.b(self.conn + 12, 12)
            self.b(self.conn + 13, 34)
            self.wq(0xC806C8, 0xF34D48)  # ELF GLOB_DAT, CStreamPacket::s_nMTU
            self.w32(0xF34D48, mtu)
            self.wq(self.message, self.msgvt)
            self.wq(self.msgvt + 88, STOP + 0x300)
            self.callbacks.update(
                {
                    0xC0E2D0: lambda: self.jump(0x7F2AF4),
                    0xC0E2E0: lambda: self.jump(0x7F321C),
                    0xC0BA60: lambda: self.jump(0x7F2EF8),
                    0xC0BE20: self.serialize,
                    0xC0E2F0: lambda: self.jump(0x7F3078),
                    0xC10FF0: lambda: self.jump(0x7FB9B4),
                    0xC0E390: lambda: self.jump(0x7FBA34),
                    0xC11470: self.construct_channel,
                    0xC111F0: lambda: self.jump(0x7F89DC),
                    0xC110F0: lambda: self.jump(0x7F6F94),
                    0xC11100: lambda: self.jump(0x7F7230),
                    0xC0A380: lambda: self.ret(2),
                    0xC10FD0: self.construct_packet,
                    0xC0E120: lambda: self.ret(),
                    0xBFF3D0: self.memcpy,
                    STOP + 0x300: lambda: self.ret(len(self.payload)),
                    0x7A7E08: self.capture_result,
                }
            )

        def capture_result(self):
            self.frame_result = self.r(0) & 0xFFFFFFFF

        def construct_packet(self):
            self.packet(self.r(0), typ=0, stamp=0, received=0, retry=0, id=0)
            self.w32(self.r(0) + 48, 4000)
            self.ret()

        def serialize(self):
            if self.payload:
                self.u.mem_write(self.r(1), self.payload)
            self.ret(self.r(1) + len(self.payload))

        def memcpy(self):
            if self.r(2):
                self.u.mem_write(
                    self.r(0), bytes(self.u.mem_read(self.r(1), self.r(2)))
                )
            self.ret(self.r(0))

        def construct_channel(self):
            p, sock, conn, ident = (self.r(i) for i in range(4))
            self.wq(p, sock)
            self.wq(p + 8, conn)
            self.b(p + 16, ident)
            self.channels[ident] = p
            self.created.append(ident)
            for offset in (112, 248):
                window = p + offset
                self.w32(window + 4, 15)
                self.wq(window + 16, self.alloc(4096))
                self.wq(window + 24, self.alloc(4096))
            self.ret()

        def send(self):
            p = self.r(1)
            ptr = self.q(p + 56)
            size = self.i(p + 52) + (4 if self.u.mem_read(ptr, 1)[0] & 128 else 0)
            self.sent.append(bytes(self.u.mem_read(ptr, size)).hex())
            self.ret(self.transport_result)

        def snapshot(self, ident=1):
            channel = self.channels.get(ident)
            window = channel + 112 if channel else 0
            return dict(
                wire=self.sent,
                channels=self.created,
                result=self.frame_result,
                next_id=self.h(window + 10) if window else 0,
            )

        def control(self, typ):
            self.call(0x7A7D90, self.client, typ, self.message)

        def frame_send(self):
            self.call(0x7F2AF4, self.frame, 1, 6)
            self.call(0x7F321C, self.frame, self.message, 0)
            self.frame_result = self.call(0x7F3078, self.frame, self.conn, 1)

    def discovery_case(
        crc, requested, result, sequence_present=True, requested_present=True
    ):
        request = b"\x08\x07" if sequence_present else b""
        request += b"\x10" + varint(requested) if requested_present else b""
        r = Sender(crc, 1024, request, result)
        r.call(0x7F2AF4, r.frame, 0, 1)
        r.call(0x7F321C, r.frame, r.message, 1)
        request_packet = r.q(r.frame + 8)
        address = r.alloc(4096)

        request_obj, response_obj = [], []
        serialized_objects = []

        def ctor(objects):
            objects.append(r.r(0))
            r.wq(r.r(0), r.msgvt)
            r.ret()

        def parse():
            dest = r.r(1)
            r.w32(dest + 16, int(sequence_present) | (int(requested_present) << 1))
            r.w32(dest + 24, 7 if sequence_present else 0)
            r.w32(dest + 28, requested if requested_present else 0)
            r.ret(1)

        def response_size():
            msg = r.r(0)
            serialized_objects.append("request" if msg in request_obj else "response")
            mask = r.i(msg + 16)
            r.payload = b"\x08" + varint(r.i(msg + 24)) if mask & 1 else b""
            if mask & 2:
                r.payload += b"\x10" + varint(r.i(msg + 28))
            r.ret(len(r.payload))

        def memset():
            if r.r(2):
                r.u.mem_write(r.r(0), bytes([r.r(1) & 255]) * r.r(2))
            r.ret(r.r(0))

        r.callbacks.update(
            {
                0xC03BB0: lambda: ctor(request_obj),
                0xC03BC0: lambda: ctor(response_obj),
                0xC0E160: parse,
                STOP + 0x300: response_size,
                0xC0BA50: lambda: r.jump(0x7F2FD0),
                0xC09980: memset,
                0xC0E760: lambda: r.jump(0x7F3160),
                0xC11010: lambda: r.jump(0x7FBC04),
                0xC042C0: lambda: r.ret(),
                0xC042A0: lambda: r.ret(),
                0x7ACD9C: r.capture_result,
            }
        )
        assert r.call(0x7ACC20, r.client, r.frame, address) == 1
        observed = r.snapshot(0)
        assert observed["result"] == result
        assert observed["channels"] == []
        assert serialized_objects == ["request"]
        assert r.payload == request
        assert r.i(response_obj[0] + 24) == (7 if sequence_present else 0)
        assert r.i(response_obj[0] + 28) == r.i(request_packet + 52)
        observed["serialized"] = serialized_objects[0]
        observed["computed_received"] = r.i(response_obj[0] + 28)
        return dict(
            group="discovery",
            input=dict(crc=crc, mtu=1024, requested=requested, socket_result=result),
            observed=observed,
        )

    cases = []
    for crc in (0, 1):
        for mtu in (512, 1024, 1472):
            limit = mtu - 17
            for body_size in (1, limit - 1, limit, limit + 1, 2 * limit, 2 * limit + 1):
                payload = bytes(i % 251 for i in range(body_size - 1))
                r = Sender(crc, mtu, payload)
                r.frame_send()
                observed = r.snapshot()
                assert observed["result"] == 0
                assert observed["channels"] == [0, 1]
                assert observed["next_id"] == len(observed["wire"])
                cases.append(
                    dict(
                        group="frame",
                        input=dict(crc=crc, mtu=mtu, payload=payload.hex()),
                        observed=observed,
                    )
                )
        # Real client control caller, with exact empty protobuf wire inputs;
        # handshake messages have their required empty nested info present.
        for typ, payload in ((1, b""), (2, b""), (6, b"\x0a\x00"), (7, b"\x0a\x00")):
            for result in range(5):
                r = Sender(crc, 1024, payload, result)
                r.control(typ)
                observed = r.snapshot()
                # Real reliable sender maps Socket's would-block result 1 to
                # accepted 0, retaining the packet; 2/3/4 propagate unchanged.
                assert observed["result"] == (0 if result == 1 else result), (
                    typ,
                    crc,
                    result,
                    observed,
                )
                assert observed["channels"] == [0, 1]
                cases.append(
                    dict(
                        group="control",
                        input=dict(crc=crc, mtu=1024, type=typ, socket_result=result),
                        observed=observed,
                    )
                )
        r = Sender(crc, 1024, b"\x0a\x00")

        def message_ctor():
            r.wq(r.r(0), r.msgvt)
            r.ret()

        for address in (0xC03B10, 0xC04080, 0xC04310, 0xC042E0, 0xC04330):
            r.callbacks[address] = message_ctor
        r.callbacks[0xC04350] = lambda: r.ret(r.message)
        r.call(0x7ACE2C, r.client, r.conn)
        observed = r.snapshot()
        observed["result"] = 0  # OnStreamConnected has no Frame result contract.
        assert observed["channels"] == [0, 1]
        cases.append(
            dict(group="connected", input=dict(crc=crc, mtu=1024), observed=observed)
        )
    # Append, preserving every original control vector unchanged.
    for crc in (0, 1):
        for mtu in (512, 1024):
            for length in (0, 491, 492, 493, 1004, 1005, 1006, 2048):
                payload = b"\x12" + varint(length) + b"x" * length
                r = Sender(crc, mtu, payload)
                r.callbacks[0x7A8C14] = r.capture_result
                r.call(0x7A8BBC, r.client, 3, r.message)
                observed = r.snapshot(2)
                assert observed["channels"] == [0, 1, 2]
                assert observed["next_id"] == len(observed["wire"])
                cases.append(
                    dict(
                        group="stats",
                        input=dict(
                            crc=crc, mtu=mtu, text_length=length, socket_result=0
                        ),
                        observed=observed,
                    )
                )
        for result in range(1, 5):
            r = Sender(crc, 1024, b"\x12\x00", result)
            r.callbacks[0x7A8C14] = r.capture_result
            r.call(0x7A8BBC, r.client, 3, r.message)
            observed = r.snapshot(2)
            assert observed["result"] == (0 if result == 1 else result)
            cases.append(
                dict(
                    group="stats",
                    input=dict(crc=crc, mtu=1024, text_length=0, socket_result=result),
                    observed=observed,
                )
            )
        for requested in (0, 64, 1024, 1472):
            for result in (0, 1):
                cases.append(discovery_case(crc, requested, result))
    for crc in (0, 1):
        for presence in (0, 1, 2):
            case = discovery_case(
                crc,
                64 if presence == 2 else 0,
                0,
                bool(presence & 1),
                bool(presence & 2),
            )
            case["input"]["presence"] = presence
            cases.append(case)
    audit.Sender = Sender
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--refresh-reference", action="store_true")
    args = parser.parse_args()
    base = outgoing.load(args.binary, args.output.with_name("wire-base.json"))
    report = dict(binary_sha256=outgoing.SHA, scope=__doc__, cases=audit(base))
    reference = ROOT / "scripts/fixtures/steam-control-wire-reference.json"
    if args.refresh_reference:
        if reference.exists():
            previous = json.loads(reference.read_text())
            assert previous["binary_sha256"] == report["binary_sha256"]
            assert previous["cases"] == report["cases"][: len(previous["cases"])]
        reference.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert report == json.loads(reference.read_text())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Official Android control wire: {len(report['cases'])} cases passed")


if __name__ == "__main__":
    main()
