#!/usr/bin/env python3
"""Execute original client control delivery/decrypt/queue/drain boundaries.

Original OnStreamPacket, Frame ctor/BDecrypt/Resize, CStreamQueue PushItem and
CUtlQueue growth/dequeue, HandleIncomingPackets state selection, and peer
SetConfig parser/copy execute. AES-CBC/HMAC primitives use cryptography/hashlib
adapters; cipher inputs are retained verbatim. Mutex/refcount/destruction and
terminal handlers other than peer SetConfig/config99 are adapters. Input is an assembled
control frame, not a real Socket, authentication, decoder or OS-thread test.
Two separate empty-carrier cases execute Socket/Connection/reliable Pop with the
client delegate adapted; they do not claim one end-to-end authenticated session.
"""

import argparse
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "stats", ROOT / "scripts/audit-steam-frame-stats.py"
)
stats = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stats)
config = stats.config
KEY = bytes([8, 1, 0, 11, 45, 14, 19, 19] * 4)
HANDLERS = {
    "OnServerHandshake": 7,
    "OnAuthenticationResponse": 2,
    "OnNegotiationInit": 3,
    "OnNegotiationSetConfig": 4,
    "OnSetTitle": 81,
    "OnSetStreamingClientConfig": 99,
}


class Handoff(stats.Stats):
    def __init__(self, binary, state):
        super().__init__(binary)
        self.init_handoff(state)

    def init_handoff(self, state):
        """Initialize real client queues/crypto on an existing network runner."""
        self.events, self.phase = [], "receive"
        self.wi(config.CLIENT + 256, state)
        self.call(self.symbols["_ZN17CNegotiatedConfigC1Ev"], config.CLIENT + 288)
        self.call(self.symbols["_ZN17CUtlQueueBaseImplC2Ej"], config.CLIENT + 720, 8)
        key = self.alloc(64)
        self.u.mem_write(key, KEY)
        self.wq(config.CLIENT + 64, key)
        self.wi(config.CLIENT + 84, len(KEY))
        self.wq(config.VTABLE + 80, config.STOP + 0x600)
        self.wq(config.VTABLE + 160, config.STOP + 0x604)
        self.callbacks.update(
            {
                0xC099D0: self.decrypt,
                0xC0E130: self.construct_frame,
                0xC0E170: lambda: self.handler(7),
                0xC09AB0: lambda: self.ret(self.alloc(self.r(0))),
                0xC09AC0: lambda: self.ret(),
                0xC09A70: self.mac,
                0xC0A390: lambda: self.ret(1),
                0xC0E120: lambda: self.ret(),
                0xC0E1A0: lambda: self.ret(self.empty),
                0xC09F90: lambda: self.ret(),
                config.STOP + 0x600: lambda: self.handler(106),
                config.STOP + 0x604: lambda: self.handler(81),
            }
        )
        for address, name in self.plts.items():
            for part, tag in HANDLERS.items():
                if name.startswith("_ZN13CStreamClient") and part in name:
                    self.callbacks[address] = lambda tag=tag, name=name: self.handler(
                        tag, name
                    )

    def decrypt(self):
        cipher = bytes(self.u.mem_read(self.r(0), self.r(1)))
        iv = bytes(self.u.mem_read(self.r(2), self.r(3)))
        key = bytes(self.u.mem_read(self.r(6), self.r(7)))
        try:
            d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
            plain = d.update(cipher) + d.finalize()
            pad = plain[-1]
            assert 1 <= pad <= 16 and plain[-pad:] == bytes([pad]) * pad
            plain = plain[:-pad]
            assert len(plain) <= self.i(self.r(5))
        except (ValueError, IndexError, AssertionError):
            self.ret(0)
            return
        self.u.mem_write(self.r(4), plain)
        self.wi(self.r(5), len(plain))
        self.ret(1)

    def mac(self):
        plain = bytes(self.u.mem_read(self.r(0), self.r(1)))
        key = bytes(self.u.mem_read(self.r(2), self.r(3)))
        self.u.mem_write(self.r(4), hmac.new(key, plain, hashlib.md5).digest())
        self.ret(1)

    def packet_value(self, p):
        raw = bytes(self.u.mem_read(self.q(p + 56), self.i(p + 52)))
        return dict(
            type=raw[13],
            body=raw[14:].hex(),
            sent=struct.unpack_from("<I", raw, 9)[0],
            receive=self.i(p + 32),
        )

    def construct_frame(self):
        self.current_frame = self.r(0)
        self.jump(0x7F2B98)

    def handler(self, tag, name=None):
        value = self.packet_value(self.q(self.current_frame + 8))
        assert value["type"] == tag
        self.events.append(dict(value, phase=self.phase))
        if tag in (4, 99):
            self.jump(self.symbols[name])
        else:
            self.ret()

    def receive(self, sent, received, raw):
        body = bytes.fromhex(raw)
        packet = self.alloc(len(body) + 4096)
        data = packet + 64
        wire = struct.pack("<BBBBBHHI", 5, 0, 34, 12, 1, 0, 0, sent) + body
        self.u.mem_write(data, wire)
        self.wq(packet + 40, data)
        self.wq(packet + 56, data)
        self.wi(packet + 52, len(wire))
        self.wi(packet + 28, received)
        self.wi(packet + 32, received)
        self.call(0x7ACFA8, config.CLIENT, self.connection, packet)

    def observe_handoff(self):
        first, last = self.i(config.CLIENT + 724), self.i(config.CLIENT + 728)
        count = 0 if first == 0xFFFFFFFF else ((last - first) & 0x7FFFFFFF) + 1
        assert count < 1024
        data, mask = self.q(config.CLIENT + 736), self.i(config.CLIENT + 720)
        queued = [
            self.packet_value(self.q(data + ((first + i) & mask) * 8))
            for i in range(count)
        ]
        result = dict(
            state=self.i(config.CLIENT + 256),
            receive_sequence=self.q(config.CLIENT + 136),
            queue=queued,
            events=list(self.events),
            negotiated=self.serialize(config.CLIENT + 288, "CNegotiatedConfig").hex(),
            client_config=self.serialize(config.CLIENT + 456).hex(),
        )
        self.events.clear()
        return result


def ciphertext(tag, body=b"", sequence=0, mode="valid"):
    if tag in (1, 2, 6, 7):
        return (bytes([tag]) + body).hex()
    plain = struct.pack("<Q", sequence) + body
    iv = hmac.new(KEY, plain, hashlib.md5).digest()
    pad = 16 - len(plain) % 16
    e = Cipher(algorithms.AES(KEY), modes.CBC(iv)).encryptor()
    result = bytearray(
        bytes([tag]) + iv + e.update(plain + bytes([pad]) * pad) + e.finalize()
    )
    if mode == "bad_mac":
        result[1] ^= 1
    if mode == "short":
        result = result[:17]
    return result.hex()


def schedules(binary):
    schema = config.descriptor_pb2.FileDescriptorProto.FromString(
        binary[0x3E5474 : 0x3E5474 + 21560]
    )
    pool = config.descriptor_pool.DescriptorPool()
    pool.Add(schema)
    message = config.message_factory.GetMessageClass(
        pool.FindMessageTypeByName("CNegotiationSetConfigMsg")
    )
    valid = message(
        config=dict(reliable_data=False, selected_audio_codec=3, selected_video_codec=4)
    ).SerializeToString()
    other = message(
        config=dict(reliable_data=True, selected_audio_codec=1, selected_video_codec=5)
    ).SerializeToString()
    config_message = config.message_factory.GetMessageClass(
        pool.FindMessageTypeByName("CSetStreamingClientConfig")
    )
    fec_config = config_message(
        config=dict(enable_unreliable_fec=True, desired_bitrate_kbps=12000)
    ).SerializeToString()
    cases = []
    for state in range(8):
        rows, seq = [], 0
        for n, tag in enumerate((7, 2, 6, 1, 3, 4, 8, 9, 106, 81, 99, 255)):
            body = (
                valid
                if tag == 4
                else fec_config
                if tag == 99
                else b"\x0a\x00"
                if tag == 7
                else b"\x0a\x03abc"
            )
            rows.append(["R", 900000 + n, 1000000 + n, ciphertext(tag, body, seq)])
            if tag not in (1, 2, 6, 7):
                seq += 1
        cases.append(dict(name=f"routes_s{state}", state=state, actions=rows + [["D"]]))
    for state in (2, 3, 4, 5, 6):
        for tag in (7, 2, 4, 81, 106):
            body = valid if tag == 4 else b"\x0a\x00" if tag == 7 else b"\x0a\x03abc"
            cases.append(
                dict(
                    name=f"single_{state}_{tag}",
                    state=state,
                    actions=[["R", 900000, 1000000, ciphertext(tag, body)], ["D"]],
                )
            )
    for name, payloads in (
        ("valid_other", (valid, other)),
        ("bad_valid", (b"\xff", valid)),
    ):
        cases.append(
            dict(
                name=name,
                state=4,
                actions=[
                    ["R", 900000 + n, 1000000 + n, ciphertext(4, p, n)]
                    for n, p in enumerate(payloads)
                ]
                + [["D"]],
            )
        )
    for mode in ("bad_mac", "short", "sequence_future", "sequence_old"):
        seq = 99 if mode == "sequence_future" else 0
        cases.append(
            dict(
                name=mode,
                state=6,
                actions=[
                    ["R", 900000, 1000000, ciphertext(81, b"\x0a\x03one", 0)],
                    ["R", 900001, 1000001, ciphertext(81, b"\x0a\x03bad", seq, mode)],
                    ["R", 900002, 1000002, ciphertext(81, b"\x0a\x03two", 2)],
                    ["D"],
                ],
            )
        )
    for new_state in (0, 2, 3, 4, 5, 6, 7):
        cases.append(
            dict(
                name=f"consume_state_{new_state}",
                state=6,
                actions=[
                    ["R", 900000, 1000000, ciphertext(81, b"\x0a\x03abc")],
                    ["S", new_state],
                    ["D"],
                ],
            )
        )
    for count in (17, 129, 257):
        cases.append(
            dict(
                name=f"grow_{count}",
                state=6,
                actions=[
                    ["R", 900000 + n, 1000000 + n, ciphertext(81, b"\x0a\x03abc", n)]
                    for n in range(count)
                ]
                + [["D"]],
            )
        )
    cases.append(
        dict(
            name="starting_config99",
            state=4,
            actions=[
                ["R", 900000, 1000000, ciphertext(4, valid, 0)],
                ["R", 900001, 1000001, ciphertext(99, fec_config, 1)],
                ["D"],
            ],
        )
    )
    cases.append(
        dict(name="empty_control", state=6, actions=[["R", 900000, 1000000, ""], ["D"]])
    )
    cases.append(
        dict(
            name="destroy_queued",
            state=6,
            actions=[
                ["R", 900000, 1000000, ciphertext(81, b"\x0a\x03abc", 0)],
                ["R", 900001, 1000001, ciphertext(99, fec_config, 1)],
            ],
        )
    )
    cases.append(
        dict(
            name="two_rounds",
            state=6,
            actions=[
                ["R", 900000, 1000000, ciphertext(81, b"\x0a\x03one", 0)],
                ["D"],
                ["R", 900001, 1000001, ciphertext(99, fec_config, 1)],
                ["D"],
                ["R", 900002, 1000002, ciphertext(9, b"", 2)],
                ["D"],
                ["R", 900003, 1000003, ciphertext(81, b"\x0a\x03two", 3)],
                ["D"],
            ],
        )
    )
    for transport in (2, 3):
        cases.append(
            dict(
                name=f"transport_{transport}_frame_boundary",
                state=6,
                actions=[
                    ["T", transport],
                    ["R", 900000, 1000000, ciphertext(99, fec_config, 0)],
                    ["D"],
                ],
            )
        )
    return cases


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == config.SHA
    cases = []
    for inp in schedules(binary):
        r = Handoff(binary, inp["state"])
        observed = []
        for action in inp["actions"]:
            r.phase = "receive" if action[0] == "R" else "drain"
            if action[0] == "R":
                r.receive(*action[1:])
            elif action[0] == "S":
                r.wi(config.CLIENT + 256, action[1])
            elif action[0] == "T":
                r.wi(r.connection + 16, action[1])
            else:
                try:
                    r.call(0x7A6368, config.CLIENT)
                except Exception:
                    print(
                        "source drain failed",
                        inp["name"],
                        "PC",
                        hex(r.u.reg_read(config.BASE["UC_ARM64_REG_PC"])),
                    )
                    raise
            observed.append(r.observe_handoff())
        assert all(line in (2683, 2684) for line in r.asserts), (inp["name"], r.asserts)
        cases.append(
            dict(input=inp, observed=observed, source_assertions=list(r.asserts))
        )
    return cases


def empty_carriers(binary):
    spec = importlib.util.spec_from_file_location(
        "cycle", ROOT / "scripts/audit-steam-receive-cycle.py"
    )
    cycle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cycle)
    cases = []
    for crc in (False, True):
        r = cycle.Cycle(binary, crc)
        r.prepare([cycle.packet(0, kind=5, channel=1, payload="")], crc)
        r.now, r.ready = 1000000, True
        r.call(0x7FEB90, r.sock, 2)
        r.call(0x7FECD4, r.sock)
        assert r.delivered == [""] and r.entries == [13] and not r.asserts
        cases.append(
            dict(crc=crc, delivered=r.delivered, metadata=r.metadata, entries=r.entries)
        )
    return cases


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    binary = a.binary.read_bytes()
    report = dict(
        binary_sha256=config.SHA,
        scope=__doc__,
        cases=audit(binary),
        empty_carriers=empty_carriers(binary),
    )
    ref = ROOT / "scripts/fixtures/steam-control-handoff-reference.json"
    if a.refresh_reference:
        assert (
            not ref.exists()
            or json.loads(ref.read_text())["cases"]
            == report["cases"][: len(json.loads(ref.read_text())["cases"])]
        )
        ref.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert json.loads(ref.read_text()) == report
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Official control handoff: {len(report['cases'])} cases passed")


if __name__ == "__main__":
    main()
