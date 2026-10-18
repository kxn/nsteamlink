#!/usr/bin/env python3
"""Execute official discovery credentials -> test auth -> control AES for 16/32 keys.

Pinned Android shell: response parser/handler, credential AES, Panel OnUpdate,
test Start/SetAuthToken, connected/handshake/auth/control dispatcher and original
Frame HMAC-MD5/AES-CBC encrypt/decrypt execute. No crypto result is adapted.
Persistent identity/secret, peer response and established Connection are explicit
inputs. Qt/storage, OS/thread/clock/locks, packet ownership and final sends inherit
declared adapters from the discovery audit. This proves acceptance of these input
key sizes, not which key lengths a current Steam host naturally issues. Other
lengths, ordinary-session factories, devices and full OS scheduling are unproved.
"""

import argparse
import gzip
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "discovery", ROOT / "scripts/audit-steam-network-test-discovery.py"
)
d = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d)
TEST, PANEL = d.lifecycle.TEST, d.PANEL
REFERENCE = ROOT / "scripts/fixtures/steam-session-key-reference.json.gz"
CRYPTO = (
    "_ZN12CStreamFrame8BEncryptEyPKhj",
    "_ZN12CStreamFrame8BDecryptEyPKhj",
    "_ZN7CCrypto22SymmetricEncryptWithIVEPKhjS1_jPhPjS1_j",
    "_ZN7CCrypto22SymmetricDecryptWithIVEPKhjS1_jPhPjS1_jb",
    "_ZN7CCrypto15GenerateHMACMD5EPKvmS1_mPA16_h",
)


def encrypt(key, plain, sequence):
    body = struct.pack("<Q", sequence) + plain
    iv = hmac.new(key, body, hashlib.md5).digest()
    pad = 16 - len(body) % 16
    aes = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv + aes.update(body + bytes([pad]) * pad) + aes.finalize()


class Keys(d.Discovery):
    def __init__(self, binary):
        self.crypto_calls = {}
        self.encrypt_inputs = []
        super().__init__(binary)
        for name in CRYPTO:
            assert self.symbols.get(name), name
            self.function_entries.setdefault(self.symbols[name], []).append(name)
        # Record entered software AES implementation, not just wrappers.
        self.crypto_sites = {
            0x102F05C: "aes_decrypt_schedule",
            0x102F5D4: "aes_decrypt_block",
            0xCDC558: "cbc_decrypt",
        }

    def hook(self, u, pc, size, data):
        if pc == self.symbols.get(CRYPTO[0]):
            self.encrypt_inputs.append(
                dict(sequence=self.r(1), input=self.body(self.r(0)).hex())
            )
        if pc in getattr(self, "crypto_sites", {}):
            name = self.crypto_sites[pc]
            self.crypto_calls[name] = self.crypto_calls.get(name, 0) + 1
        name = self.plts.get(pc, "")
        if name in CRYPTO:
            self.jump(self.symbols[name])
            return
        super().hook(u, pc, size, data)

    def store(self, body):
        pointer = self.alloc(len(body) + 1)
        if body:
            self.u.mem_write(pointer, body)
        return pointer

    def frame(self, body):
        frame, packet = self.alloc(128), self.alloc(max(4096, len(body) + 128))
        self.call(self.symbols["_ZN12CStreamFrameC1Ehh"], frame, 1, 106)
        wire = bytes(13) + bytes([106]) + body
        raw = packet + 64
        self.u.mem_write(raw, wire)
        self.wq(packet + 40, raw)
        self.wq(packet + 56, raw)
        self.wi(packet + 48, max(4000, len(body) + 64))
        self.wi(packet + 52, len(wire))
        self.wq(frame + 8, packet)
        return frame

    def body(self, frame):
        packet = self.q(frame + 8)
        return bytes(
            self.u.mem_read(self.q(packet + 56) + 14, self.i(packet + 52) - 14)
        )


def chain(binary, key_length, bitrate):
    r = Keys(binary)
    key = bytes(range(key_length))
    peer = r.store(bytes(range(1, 25)))
    r.u.mem_write(peer + 22, struct.pack("<H", 27036))
    cipher = d.encrypted(key)
    body = b"\x08\x11\x10\0\x18" + d.varint(27031)
    body += b"\x22" + d.varint(len(cipher)) + cipher
    obj = r.alloc(512)
    assert r.parse(obj, body, d.RESPONSE)
    r.call(
        r.symbols[
            "_ZN14CServerManager28HandleStartStreamingResponseERK10CIPAndPortyPK33CMsgRemoteDeviceStreamingResponse"
        ],
        r.manager,
        peer,
        123,
        obj,
    )
    assert r.i(r.manager + 8) == 6 and r.i(r.manager + 0x3AC) == key_length
    r.wi(d.CONFIG + 152, bitrate)
    r.b(d.CONFIG + 156, 0)
    r.b(PANEL + 0xD4, 1)
    r.wi(PANEL + 0xD8, 4)
    r.call(r.symbols["_ZN13CPanelConnect8OnUpdateEv"], PANEL)
    assert r.auth_tokens == [key.hex()]
    # The actual OS connection is a boundary; all later auth/crypto is original.
    r.connection, sock = r.alloc(4096), r.alloc(4096)
    r.call(r.symbols["_ZN17CStreamConnectionC1EP13CStreamSocket"], r.connection, sock)
    r.wi(r.connection + 16, 1)
    r.wq(TEST + 0x128, r.connection)
    r.call(
        r.symbols["_ZN12CNetworkTest17OnStreamConnectedEP17CStreamConnection"],
        TEST,
        r.connection,
    )
    r.receive(7, bytes.fromhex("0a0308c00b"))
    assert r.i(TEST + 0x114) == 3
    request = r.frames[-1]["body"]
    token = hmac.new(key, b"Steam In-Home Streaming", hashlib.sha256).digest()
    assert request == (b"\x01\x0a\x20" + token + b"\x10\x01").hex()
    # Lifecycle.receive deliberately withholds its legacy setup response;
    # enter the original packet dispatcher through the underlying driver.
    d.lifecycle.media.flow.Flow.receive(r, 2, bytes.fromhex("1001"))
    assert r.i(TEST + 0x114) == 4
    tx = list(r.frames)
    # Independent crypto constructs ingress. Original dispatcher decrypts it.
    target = encrypt(key, b"\x08" + d.varint(100000), 0)
    r.receive(94, target)
    assert r.i(TEST + 0x140) == 100000 and r.q(TEST + 0xD8) == 1
    assert not r.assertions
    return r, dict(
        key_length=key_length,
        bitrate=bitrate,
        response=body.hex(),
        key=r.auth_tokens[0],
        authentication=request,
        transmitted=tx,
        encrypted_inputs=list(r.encrypt_inputs),
        incoming_target=target.hex(),
        target=r.i(TEST + 0x140),
        tx_sequence=r.q(TEST + 0xD0),
        rx_sequence=r.q(TEST + 0xD8),
        crypto_visits=dict(r.crypto_calls),
        source_assertions=list(r.assertions),
        executed=sorted(r.executed),
    )


def vectors(r, key_length):
    key = bytes(range(key_length))
    pointer = r.store(key)
    result = []
    for size in (0, 1, 7, 8, 15, 16, 17, 31, 32, 255):
        plain = bytes(n & 255 for n in range(size))
        for sequence in (0, 1, 0x100000001, 0xFFFFFFFFFFFFFFFF):
            frame = r.frame(plain)
            assert r.call(r.symbols[CRYPTO[0]], frame, sequence, pointer, key_length)
            cipher = r.body(frame)
            assert cipher == encrypt(key, plain, sequence)
            result.append(
                dict(op="E", sequence=sequence, input=plain.hex(), output=cipher.hex())
            )
            for kind, expected in (
                ("valid", sequence),
                ("wrong_sequence", sequence ^ 1),
            ):
                frame = r.frame(cipher)
                ok = bool(
                    r.call(r.symbols[CRYPTO[1]], frame, expected, pointer, key_length)
                )
                assert ok == (kind == "valid")
                if ok:
                    assert r.body(frame) == plain
                result.append(
                    dict(
                        op="D",
                        kind=kind,
                        sequence=expected,
                        input=cipher.hex(),
                        ok=ok,
                        output=plain.hex() if ok else None,
                    )
                )
    # Authenticate independently chosen ciphertexts; failures are not crypto adapters.
    plain = bytes(range(33))
    cipher = encrypt(key, plain, 7)
    faults = [("short", cipher[:n]) for n in (0, 1, 15)]
    bad_hash = bytearray(cipher)
    bad_hash[0] ^= 128
    faults.append(("bad_hash", bytes(bad_hash)))
    bad_padding = bytearray(cipher)
    bad_padding[-17] ^= 128
    faults.append(("bad_padding", bytes(bad_padding)))
    for kind, body in faults:
        frame = r.frame(body)
        ok = bool(r.call(r.symbols[CRYPTO[1]], frame, 7, pointer, key_length))
        assert not ok
        result.append(
            dict(op="D", kind=kind, sequence=7, input=body.hex(), ok=False, output=None)
        )
    assert not r.assertions
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    binary = a.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == d.lifecycle.media.flow.SHA
    chains, cases, functions = [], [], set()
    for length in (16, 32):
        for bitrate in (20000, -1):
            r, row = chain(binary, length, bitrate)
            chains.append(row)
            if bitrate == 20000:
                cases.append(dict(key_length=length, vectors=vectors(r, length)))
            functions.update(r.executed)
    # Counterfactual modifies the original sequence store, without assertion failure.
    r = Keys(binary)
    pc, original, mutant = 0xCC39A4, 0xF8008418, 0xF800841F
    assert bytes(r.u.mem_read(pc, 4)) == struct.pack("<I", original)
    r.u.mem_write(pc, struct.pack("<I", mutant))
    hits = []
    from unicorn import UC_HOOK_CODE

    r.u.hook_add(
        UC_HOOK_CODE,
        lambda u, address, size, data: hits.append(address),
        begin=pc,
        end=pc,
    )
    frame, key = r.frame(b"abc"), r.store(bytes(range(16)))
    assert r.call(r.symbols[CRYPTO[0]], frame, 7, key, 16)
    altered = r.body(frame)
    assert hits == [pc] and not r.assertions
    assert altered != encrypt(bytes(range(16)), b"abc", 7)
    report = dict(
        binary_sha256=d.lifecycle.media.flow.SHA,
        scope=__doc__,
        chains=chains,
        cases=cases,
        functions=sorted(functions),
        mutation=dict(
            pc=hex(pc),
            original=hex(original),
            mutant=hex(mutant),
            hits=[hex(v) for v in hits],
            output=altered.hex(),
            source_assertions=r.assertions,
        ),
    )
    if a.refresh_reference:
        REFERENCE.write_bytes(
            gzip.compress((json.dumps(report, sort_keys=True) + "\n").encode(), mtime=0)
        )
    else:
        assert report == json.loads(
            gzip.decompress(REFERENCE.read_bytes())
        ), "official key contract changed"
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"Official session keys: {len(chains)} chains, {sum(len(c['vectors']) for c in cases)} crypto vectors; original-instruction counterfactual detected"
    )


if __name__ == "__main__":
    main()
