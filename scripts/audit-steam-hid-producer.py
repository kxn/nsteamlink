#!/usr/bin/env python3
"""Execute original HID gates, protobuf, control lock, crypto frame and factory.

The fixed Android client executes SendRemoteHIDMessage, SendControlMessage,
BEncrypt/Frame Send, Connection Send/GetChannel and the channel constructor.
Channel::Send is a recording terminal (no window, UDP or host). Crypto primitives
are hashlib/cryptography adapters, not execution of the bundled crypto library.
The batch entry also executes UpdateHIDDeviceReports; one synthetic generator's
collect terminal copies a parsed report with the original C++ CopyFrom. It is
not a real HID device, generator reset implementation or OS-thread schedule.
Input-enable is applied through the original local-only config setter; its
delegate/save are Core adapters. Recording is disabled. Allocator, mutex and
refcount/OS remain adapters.
"""

import argparse
import gzip
import hashlib
import hmac
import importlib.util
import io
import json
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "lifecycle", ROOT / "scripts/audit-steam-client-fec-lifecycle.py"
)
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)
c = source.c
KEY = bytes([8, 1, 0, 11, 45, 14, 19, 19] * 4)
BATCH = "1a0b0a09080112050a03010203"
REFERENCE = ROOT / "scripts/fixtures/steam-hid-producer-reference.json.gz"
HELPERS = [
    "audit-steam-hid-producer.py",
    "audit-steam-client-fec-lifecycle.py",
    "audit-steam-client-config.py",
    "audit-steam-client-fec-policy.py",
]


class HID(source.Client):
    def __init__(self, binary):
        self.locks, self.depth, self.crypto, self.collects = [], {}, [], 0
        self.collecting = False
        super().__init__(binary)
        self.wi(source.CONN + 16, 1)
        self.wi(c.CLIENT + 0x1F6B0, 0)  # Recording flag: ADD #0x1f000 then +0x6b0.
        self.wq(c.CLIENT + 128, 0)
        key = self.alloc(64)
        self.u.mem_write(key, KEY)
        self.wq(c.CLIENT + 64, key)
        self.wi(c.CLIENT + 84, len(KEY))
        self.callbacks.update(
            {
                0xC0E3A0: lambda: self.jump(0x7F342C),
                0xC09A70: self.mac,
                0xC099A0: self.encrypt,
                0xC0E640: lambda: self.jump(0x7AB374),
                c.STOP + 0x700: self.collect,
            }
        )

    def hook(self, u, pc, size, data):
        name = self.plts.get(pc, "")
        if name in ("pthread_mutex_lock", "pthread_mutex_unlock"):
            pointer = self.r(0)
            depth = self.depth.get(pointer, 0)
            lock = name == "pthread_mutex_lock"
            assert depth == (0 if lock else 1), (name, hex(pointer), depth)
            self.depth[pointer] = int(lock)
            self.locks.append(
                {"operation": "lock" if lock else "unlock", "mutex": pointer}
            )
            self.ret(0)
        else:
            if pc == 0x7BD91C and self.collecting:
                self.u.reg_write(c.X0, 1)  # The device collect terminal succeeds.
                self.collecting = False
            super().hook(u, pc, size, data)

    def mac(self):
        plain = bytes(self.u.mem_read(self.r(0), self.r(1)))
        key = bytes(self.u.mem_read(self.r(2), self.r(3)))
        self.crypto.append(
            {
                "plain": plain.hex(),
                "locks": sorted(p for p, n in self.depth.items() if n),
            }
        )
        self.u.mem_write(self.r(4), hmac.new(key, plain, hashlib.md5).digest())
        self.ret(1)

    def encrypt(self):
        plain = bytes(self.u.mem_read(self.r(0), self.r(1)))
        iv = bytes(self.u.mem_read(self.r(2), self.r(3)))
        key = bytes(self.u.mem_read(self.r(6), self.r(7)))
        pad = 16 - len(plain) % 16
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(plain + bytes([pad]) * pad) + encryptor.finalize()
        assert len(ciphertext) <= self.i(self.r(5))
        self.u.mem_write(self.r(4), ciphertext)
        self.wi(self.r(5), len(ciphertext))
        self.ret(1)

    def collect(self):
        assert self.depth.get(c.PLAYER + 2040) == 1
        self.collects += 1
        destination, active = self.r(1), self.r(2)
        self.b(active, self.active)
        self.u.reg_write(c.X0, destination)
        self.u.reg_write(c.X0 + 1, self.reports)
        self.collecting = True
        self.jump(
            self.symbols["_ZN40CHIDMessageFromRemote_DeviceInputReports8CopyFromERKS_"]
        )

    def prepare_batch(self, message, active):
        self.active = active
        self.reports = self.q(message + 24)  # Parsed reports oneof object.
        self.wq(c.PLAYER + 8, c.CLIENT)
        generator, vtable, array = (self.alloc(256) for _ in range(3))
        self.wq(generator, vtable)
        self.wq(vtable + 16, c.STOP + 0x700)
        self.wq(array, generator)
        self.wq(c.PLAYER + 2088, array)
        self.wi(c.PLAYER + 2104, 1)

    def snapshot(self):
        assert not any(self.depth.values())
        emitted = [v for v in self.observed if v.get("event") == "channel_send"]
        for item in emitted:
            assert item["kind"] == "reliable" and item["channel"] == 1
        return {
            "bodies": [v["body"] for v in emitted],
            "sequence": self.q(c.CLIENT + 128),
            "locks": self.locks,
            "crypto": self.crypto,
            "collects": self.collects,
        }


def scenarios():
    for mode in ("generic", "report", "batch"):
        for payload in ([BATCH] if mode == "batch" else ["1a00", "2a00"]):
            for state in range(8):
                for enabled in (False, True):
                    for active in ([False] if mode == "generic" else [False, True]):
                        yield dict(
                            mode=mode,
                            payload=payload,
                            state=state,
                            enabled=enabled,
                            active=active,
                        )


def inventory(binary):
    elf = ELFFile(io.BytesIO(binary))
    names = {
        "_ZN13CStreamClient20SendRemoteHIDMessageEPK21CHIDMessageFromRemoteb",
        "_ZN13CStreamPlayer22UpdateHIDDeviceReportsEv",
        "_ZN13CStreamClient18SendControlMessageE21EStreamControlMessageRKN6google8protobuf11MessageLiteE",
        "_ZN13CStreamClient24SetStreamingClientConfigERK22CStreamingClientConfigb",
        "_ZN12CStreamFrame8BEncryptEyPKhj",
        "_ZN12CStreamFrame4SendEP17CStreamConnectionb",
        "_ZN17CStreamConnection4SendEP13CStreamPacketh",
        "_ZN17CStreamConnection10GetChannelEh",
        "_ZN14CStreamChannelC1EP13CStreamSocketP17CStreamConnectionh",
        "_ZNK21CHIDMessageFromRemote12ByteSizeLongEv",
        "_ZN40CHIDMessageFromRemote_DeviceInputReports8CopyFromERKS_",
    }
    result = {}
    text = elf.get_section_by_name(".text")
    for symbol in elf.get_section_by_name(".dynsym").iter_symbols():
        if symbol.name in names:
            offset = symbol["st_value"] - text["sh_addr"]
            data = text.data()[offset : offset + symbol["st_size"]]
            assert data and len(data) == symbol["st_size"]
            result[symbol.name] = dict(
                address=symbol["st_value"],
                size=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
            )
    assert set(result) == names, names - set(result)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    args = p.parse_args()
    binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == c.SHA
    cases = []
    for inputs in scenarios():
        r = HID(binary)
        message = r.alloc(256)
        assert r.parse(
            message, bytes.fromhex(inputs["payload"]), "CHIDMessageFromRemote"
        )
        r.wi(c.CLIENT + 256, inputs["state"])
        config = r.alloc(256)
        assert r.parse(
            config, b"\x58" + bytes([inputs["enabled"]]), "CStreamingClientConfig"
        )
        r.call(
            r.symbols[
                "_ZN13CStreamClient24SetStreamingClientConfigERK22CStreamingClientConfigb"
            ],
            c.CLIENT,
            config,
            1,
        )
        assert r.u.mem_read(c.CLIENT + 615, 1)[0] == inputs["enabled"]
        if inputs["mode"] == "batch":
            r.prepare_batch(message, inputs["active"])
            r.call(0x7BD838, c.PLAYER)
        else:
            r.call(0x7AB374, c.CLIENT, message, inputs["active"])
        value = r.snapshot()
        accepted = inputs["state"] == 6 and inputs["enabled"]
        assert len(value["bodies"]) == value["sequence"] == int(accepted)
        if accepted:
            channel = r.channels[1]
            assert value["crypto"][0]["locks"] == [channel + 56]
            assert (
                value["crypto"][0]["plain"]
                == (
                    bytes(8)
                    + b"\x0a"
                    + bytes([len(bytes.fromhex(inputs["payload"]))])
                    + bytes.fromhex(inputs["payload"])
                    + b"\x10"
                    + bytes([inputs["active"]])
                ).hex()
            )
        cases.append(dict(input=inputs, observed=value))
    report = dict(
        binary_sha256=c.SHA,
        scope=__doc__,
        functions=inventory(binary),
        helpers={
            s: hashlib.sha256((ROOT / "scripts" / s).read_bytes()).hexdigest()
            for s in HELPERS
        },
        cases=cases,
    )
    if args.refresh_reference:
        REFERENCE.write_bytes(
            gzip.compress(json.dumps(report, sort_keys=True).encode(), mtime=0)
        )
    else:
        assert report == json.loads(gzip.decompress(REFERENCE.read_bytes()))
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"Verified {len(cases)} original HID/control producer cases; explicit channel/crypto/device terminals"
    )


if __name__ == "__main__":
    main()
