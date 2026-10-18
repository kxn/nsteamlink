#!/usr/bin/env python3
"""Official shell authorization result admission, full crypto and cache policy.

Original StartStreaming/keypair generation, ticket/request serializers,
AuthorizationResponse parser/handler, complete key-exchange/cache/limit logic,
raw key objects, curve25519, SHA256, AES/token check, buffer replacement,
confirmation and ordinary/test request resumption execute. Random bytes, fixture
identity/peer/account/token, clock, RSA request encryption, persistence endpoint,
libc storage and final send are explicit adapters. No crypto response result is
adapted. Qt pairing display, cloud/OS dispatch, actual Steam identity, storage
reload, Switch or full client process execution are not proved.
"""
import argparse
import gzip
import importlib.util
import json
import struct
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = Path(__file__).resolve().parents[1]
s = importlib.util.spec_from_file_location(
    "producer", ROOT / "scripts/audit-steam-authorization-producer.py"
)
p = importlib.util.module_from_spec(s)
s.loader.exec_module(p)
DID = 0x1122334455667788
REFERENCE = ROOT / "scripts/fixtures/steam-authorization-exchange-reference.json.gz"


class Exchange(p.Authorization):
    def __init__(self, b, patch=None):
        self.auth_saved = []
        self.crypto_entries = []
        self.derive_count = 0
        self.response_crypto = []
        super().__init__(b, patch)
        self.wq(self.manager + 0x10, DID)
        self.call(self.symbols["_ZN10CUtlBufferC1Ev"], self.manager + 0x2D8)
        for off, n, t in [
            (0x260, "_ZTV23CECKeyExchangePublicKey", 5),
            (0x288, "_ZTV24CECKeyExchangePrivateKey", 6),
        ]:
            self.wq(self.manager + off, self.symbols[n] + 16)
            self.wi(self.manager + off + 8, t)
            self.wq(self.manager + off + 16, 0)
            self.wq(self.manager + off + 24, 0)

    def hook(self, u, pc, size, data):
        if pc == self.symbols.get(
            "_ZN7CCrypto18PerformKeyExchangeERK24CECKeyExchangePrivateKeyRK23CECKeyExchangePublicKeyPA32_h"
        ):
            self.derive_count += 1
        name = self.plts.get(pc, "")
        if name == "memcmp":
            n = self.r(2)
            left = bytes(u.mem_read(self.r(0), n)) if n else b""
            right = bytes(u.mem_read(self.r(1), n)) if n else b""
            self.ret((left > right) - (left < right))
        elif (
            name
            == "_ZN7CCrypto26GenerateKeyExchangeKeyPairEP23CECKeyExchangePublicKeyP24CECKeyExchangePrivateKey"
        ):
            self.jump(self.symbols[name])
        elif name == "_ZN14CServerManager23SavePersistentClientKeyEyyR10CUtlBuffer":
            buf = self.r(3)
            self.auth_saved.append(
                dict(
                    client=self.r(1),
                    steamid=self.r(2),
                    secret=bytes(u.mem_read(self.q(buf), self.i(buf + 20))).hex(),
                )
            )
            self.ret()
        else:
            super().hook(u, pc, size, data)

    def auth_response(self, result=0, host=123, key=None, token=None):
        v = p.m.discovery.varint
        body = b"\x08" + v(result) + b"\x11" + struct.pack("<Q", 76561198000000001)
        if key is not None:
            body += b"\x1a" + v(len(key)) + key
        if token is not None:
            body += b"\x22" + v(len(token)) + token
        obj, peer = self.alloc(512), self.alloc(24)
        assert self.parse(obj, body, "CMsgRemoteDeviceAuthorizationResponse")
        self.call(
            self.symbols[
                "_ZN14CServerManager33HandleDeviceAuthorizationResponseERK10CIPAndPortyPK37CMsgRemoteDeviceAuthorizationResponse"
            ],
            self.manager,
            peer,
            host,
            obj,
        )

    def snapshot(self, label):
        state = self.observe_auth(label)
        state.update(
            derived=self.derive_count,
            attempts=self.i(self.manager + 0x2D0),
            saved=list(self.auth_saved),
            secret=bytes(
                self.u.mem_read(
                    self.q(self.manager + 0x218), self.i(self.manager + 0x22C)
                )
            ).hex(),
            cache=bytes(
                self.u.mem_read(
                    self.q(self.manager + 0x2D8), self.i(self.manager + 0x2EC)
                )
            ).hex(),
            cached_result=self.i(self.manager + 0x318),
        )
        return state


def material(index=0, token_device=DID, pin=b"0042", plain=None):
    our = X25519PrivateKey.from_private_bytes(bytes(range(32)))
    peer = X25519PrivateKey.from_private_bytes(
        bytes((index * 17 + 32 + n) & 255 for n in range(32))
    )
    public = peer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    secret = hashlib.sha256(our.exchange(peer.public_key())).digest()
    auth = bytes(x ^ y for x, y in zip(public, hashlib.sha256(pin).digest()))
    raw = struct.pack("<Q", token_device) if plain is None else plain
    iv = bytes(range(16))
    pad = 16 - len(raw) % 16
    ecb = Cipher(algorithms.AES(secret), modes.ECB()).encryptor()
    cbc = Cipher(algorithms.AES(secret), modes.CBC(iv)).encryptor()
    token = (
        ecb.update(iv)
        + ecb.finalize()
        + cbc.update(raw + bytes([pad]) * pad)
        + cbc.finalize()
    )
    return auth, token, secret


def run(binary, inp, patch=None):
    r = Exchange(binary, patch)
    r.start(inp.get("test", False))
    r.response(1)
    steps = [r.snapshot("authorization")]
    inputs = []
    path = inp["path"]
    if path in ("wall_clock", "wall_rollback"):
        clocks = (
            [
                (1001000, 1001),
                (1002000, 1002),
                (1002999, 1002),
                (1003000, 1003),
                (1003000, 1003),
                (1006000, 1006),
            ]
            if path == "wall_clock"
            else [
                (1000020, 999),
                (1000040, 998),
                (1000060, 1002),
                (1000080, 1003),
                (1000100, 1300),
            ]
        )
        for mono, wall in clocks:
            r.wall_time = wall
            r.call(r.symbols["_ZN14CServerManager6UpdateEv"], r.manager)
            steps.append(r.snapshot(str(wall)))
        assert not r.assertions
        return dict(
            input=inp,
            responses=[],
            clocks=[list(c) for c in clocks],
            steps=steps,
            source_assertions=r.assertions,
            executed=sorted(r.executed),
            patch_hits=r.patch_hits,
        )
    events = [dict(result=0)]
    if path == "result":
        events = [dict(result=inp["result"])]
    if path == "bad_device":
        events = [dict(token_device=DID + 1)]
    if path == "bad_pin":
        events = [dict(pin=b"0043")]
    if path == "bad_padding":
        events = [dict(corrupt=True)]
    if path == "bad_plain_length":
        events = [dict(plain=b"1234567")]
    if path == "key_length":
        events = [dict(key_length=inp["length"])]
    if path == "cached_failure":
        events = [dict(token_device=DID + 1), dict()]
    if path == "cache_alternation":
        events = [dict(index=i, token_device=DID + 1) for i in (0, 1, 0, 2)]
    if path == "third_success":
        events = [
            dict(index=0, token_device=DID + 1),
            dict(index=1, token_device=DID + 1),
            dict(index=2),
        ]
    if path == "fourth_success":
        events = [dict(index=i, token_device=DID + 1) for i in (0, 1, 2)] + [
            dict(index=3)
        ]
    if path == "duplicate_after_success":
        events = [dict(), dict()]
    if path == "cached_success_reauthorization":
        events = [dict(), dict(reauthorize=True)]
    for n, e in enumerate(events):
        if e.get("reauthorize"):
            r.response(1)
            steps.append(r.snapshot("unauthorized_again"))
        auth, token, secret = material(
            e.get("index", 0),
            e.get("token_device", DID),
            e.get("pin", b"0042"),
            e.get("plain"),
        )
        if e.get("corrupt"):
            token = token[:-1] + bytes([token[-1] ^ 255])
        length = e.get("key_length", 32)
        auth = auth[:length] + bytes(max(0, length - 32))
        inputs.append(
            dict(
                result=e.get("result", 0),
                auth_key=auth.hex(),
                device_token=token.hex(),
                expected_secret=secret.hex(),
            )
        )
        r.auth_response(e.get("result", 0), key=auth, token=token)
        steps.append(r.snapshot("response_" + str(n)))
    assert not r.assertions
    return dict(
        input=inp,
        responses=inputs,
        steps=steps,
        source_assertions=r.assertions,
        executed=sorted(r.executed),
        patch_hits=r.patch_hits,
    )


def verify(c):
    path = c["input"]["path"]
    start, last = c["steps"][0], c["steps"][-1]
    assert start["state"] == 4 and start["attempts"] == 0 and start["derived"] == 0
    confirm = [x["body"] for x in last["messages"] if x["tag"] == 14]
    if path in ("wall_clock", "wall_rollback"):
        counts = [sum(m["tag"] == 3 for m in step["messages"]) for step in c["steps"]]
        assert counts == (
            [1, 1, 1, 1, 2, 2, 3] if path == "wall_clock" else [1, 1, 1, 1, 2, 3]
        )
        assert (
            last["state"] == 4
            and last["derived"] == 0
            and not last["errors"]
            and not confirm
        )
    elif path == "result" and c["input"]["result"]:
        result = c["input"]["result"]
        assert last["derived"] == 0 and not last["saved"] and not confirm
        assert last["state"] == (4 if result == 5 else 1)
    elif path in ("bad_device", "bad_pin", "bad_padding", "bad_plain_length"):
        assert last["state"] == 4 and last["derived"] == 1 and last["attempts"] == 1
        assert (
            confirm == ["0801"]
            and not last["saved"]
            and last["secret"] == p.m.discovery.SECRET.hex()
        )
    elif path == "key_length":
        empty = c["input"]["length"] == 0
        assert (
            last["state"] == 4
            and last["derived"] == 0
            and last["attempts"] == int(not empty)
        )
        assert confirm == ["0800" if empty else "0801"] and not last["saved"]
    elif path == "cached_failure":
        assert last["state"] == 4 and last["derived"] == 1 and last["attempts"] == 1
        assert confirm == ["0801", "0801"] and not last["saved"]
    elif path in ("cache_alternation", "fourth_success"):
        assert last["state"] == 1 and last["derived"] == 3 and last["attempts"] == 4
        assert confirm == ["0801"] * 4 and last["errors"] == [2] and not last["saved"]
    elif path == "third_success":
        assert last["state"] == 5 and last["derived"] == 3 and last["attempts"] == 3
        assert confirm == ["0801", "0801", "0800"] and len(last["saved"]) == 1
        assert last["secret"] == c["responses"][-1]["expected_secret"]
    elif path == "duplicate_after_success":
        assert last["state"] == 5 and last["derived"] == 1 and len(last["saved"]) == 1
        assert confirm == ["0800", "0808"]
    elif path == "cached_success_reauthorization":
        assert (
            last["state"] == 4
            and last["derived"] == 1
            and last["attempts"] == 1
            and len(last["saved"]) == 1
        )
        assert confirm == ["0800", "0800"]
    else:
        assert (
            last["state"] == 5
            and last["derived"] == 1
            and last["attempts"] == 1
            and len(last["saved"]) == 1
        )
        assert (
            confirm == ["0800"]
            and last["secret"] == c["responses"][-1]["expected_secret"]
        )
    for s in c["steps"]:
        for row in s["saved"]:
            assert row["client"] == 123 and row["steamid"] == 76561198000000001


def main():
    a = argparse.ArgumentParser(description=__doc__)
    a.add_argument("--binary", type=Path, required=True)
    a.add_argument("--output", type=Path, required=True)
    a.add_argument("--refresh-reference", action="store_true")
    args = a.parse_args()
    binary = args.binary.read_bytes()
    sha = p.m.discovery.lifecycle.media.flow.SHA
    assert hashlib.sha256(binary).hexdigest() == sha
    ins = [
        dict(path="result", result=v, test=t) for t in (False, True) for v in range(9)
    ]
    ins += [
        dict(path=path)
        for path in (
            "bad_device",
            "bad_pin",
            "bad_padding",
            "bad_plain_length",
            "cached_failure",
            "cache_alternation",
            "third_success",
            "fourth_success",
            "duplicate_after_success",
            "cached_success_reauthorization",
        )
    ]
    ins += [dict(path="key_length", length=n) for n in (0, 1, 31, 33)]
    ins += [dict(path="wall_clock"), dict(path="wall_rollback")]
    cases = [run(binary, i) for i in ins]
    for c in cases:
        verify(c)
    pc = 0xCB4B38
    image = p.m.discovery.lifecycle.media.flow.config.BASE["load_image"](binary)[0]
    before = struct.unpack_from("<I", image, pc)[0]
    original = run(binary, dict(path="cached_failure"))
    mutant = run(binary, dict(path="cached_failure"), (pc, before, 0xD503201F))
    assert len(mutant["patch_hits"]) == 1 and not mutant["source_assertions"]
    assert original["steps"][-1]["derived"] == 1 and mutant["steps"][-1]["derived"] == 2
    assert original["steps"][-1]["state"] == 4 and mutant["steps"][-1]["state"] == 5
    report = dict(
        binary_sha256=sha,
        scope=__doc__,
        functions=p.m.inventory(binary, cases),
        cases=cases,
        negative=dict(
            site=pc, before=before, after=0xD503201F, original=original, mutant=mutant
        ),
    )
    if args.refresh_reference:
        if REFERENCE.exists():
            assert report == json.loads(gzip.decompress(REFERENCE.read_bytes()))
        REFERENCE.write_bytes(
            gzip.compress(json.dumps(report, sort_keys=True).encode(), mtime=0)
        )
    else:
        assert report == json.loads(gzip.decompress(REFERENCE.read_bytes()))
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"Official authorization crypto/cache: {len(cases)} cases; duplicate-cache mutation detected"
    )


if __name__ == "__main__":
    main()
