#!/usr/bin/env python3
"""Official per-send device tokens, cached security PIN and producer failure callers.

Original BGetDeviceToken/GetDeviceID(nonzero identity), AES, 3/5 producers,
complete authorization response crypto/save callers and Update execute. IV and
identity are explicit inputs; Qt, request RSA, file providers and final send are
§130 boundaries. Failure inputs replace BGetDeviceToken's bool, not a claimed
natural RNG/crypto failure. No real Steam, OS socket or Switch is exercised.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "lifetime", ROOT / "scripts/audit-steam-authorization-lifetime.py"
)
life = importlib.util.module_from_spec(spec)
spec.loader.exec_module(life)
TOKEN = "_ZN14CServerManager15BGetDeviceTokenER10CUtlBuffer"
DEVICE = "_ZN14CServerManager11GetDeviceIDEv"
REFERENCE = ROOT / "scripts/fixtures/steam-device-token-reference.json.gz"


def fields(body):
    b, pos, output = bytes.fromhex(body), 0, {}

    def varint():
        nonlocal pos
        value = shift = 0
        while True:
            x = b[pos]
            pos += 1
            value |= (x & 127) << shift
            if x < 128:
                return value
            shift += 7
            assert shift < 70

    while pos < len(b):
        tag = varint()
        if tag & 7 == 0:
            value = varint()
        else:
            assert tag & 7 == 2
            count = varint()
            value = b[pos : pos + count]
            pos += count
        output[tag >> 3] = value
    return output


def decrypt(token, key):
    a = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    iv = a.update(token[:16]) + a.finalize()
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    raw = d.update(token[16:]) + d.finalize()
    count = raw[-1]
    if not 1 <= count <= 16 or raw[-count:] != bytes([count]) * count:
        return None
    return raw[:-count].hex()


class Token(life.Lifetime):
    def __init__(self, binary, inp, patch=None):
        self.token_calls, self.ivs, self.token_input = [], [], inp
        super().__init__(binary, patch)
        self.connect_pin = inp.get("pin", "9876").encode()
        self.wq(self.manager + 0x10, inp.get("device_id", life.m.e.DID))
        for name in (TOKEN, DEVICE):
            self.function_entries.setdefault(self.symbols[name], []).append(name)

    def hook(self, u, pc, size, data):
        name = self.plts.get(pc, "")
        if name == TOKEN:
            i = len(self.token_calls)
            failed = i == self.token_input.get("fail_token", -1)
            self.token_calls.append(
                dict(
                    secret=bytes(
                        u.mem_read(
                            self.q(self.manager + 0x218), self.i(self.manager + 0x22C)
                        )
                    ).hex(),
                    failed=failed,
                    iv_before=len(self.ivs),
                )
            )
            if failed:
                self.ret(0)
            else:
                self.jump(self.symbols[name])
        elif name == DEVICE:
            self.jump(self.symbols[name])
        elif name == "_ZN7CCrypto19GenerateRandomBlockEPvm" and self.r(1) == 16:
            value = bytes((len(self.ivs) * 16 + n) & 255 for n in range(16))
            self.ivs.append(value.hex())
            u.mem_write(self.r(0), value)
            self.ret(1)
        else:
            super().hook(u, pc, size, data)

    def observe(self, label):
        row = super().observe(label)
        row.update(token_calls=list(self.token_calls), ivs=list(self.ivs))
        return row


def run(binary, inp, patch=None):
    r = Token(binary, inp, patch)
    r.b(life.m.PANEL + 0xD4, int(inp.get("test", False)))
    r.call(r.symbols[life.START], life.m.PANEL)
    steps = [r.observe("streaming")]
    path = inp["path"]
    if path in ("auth_retry", "reauthorize") and r.i(r.manager + 8) == 5:
        r.response(1)
        r.update()
        steps.append(r.observe("authorization"))
    if path == "reauthorize" and r.i(r.manager + 8) == 4:
        key, token, _ = life.m.e.material(
            token_device=inp.get("device_id", life.m.e.DID)
        )
        r.auth_response(key=key, token=token)
        r.update()
        steps.append(r.observe("resumed"))
    times = (1003, 1006) if path == "auth_retry" else (1001, 1002)
    for time in times:
        if r.i(r.manager + 8) not in (4, 5):
            break
        r.wall_time = time
        r.call(r.symbols["_ZN14CServerManager6UpdateEv"], r.manager)
        steps.append(r.observe(str(time)))
    assert not r.assertions
    return dict(
        input=inp,
        steps=steps,
        source_assertions=r.assertions,
        executed=sorted(r.executed),
        patch_hits=r.patch_hits,
    )


def verify(case):
    inp, last = case["input"], case["steps"][-1]
    calls = last["token_calls"]
    wires = [row for row in last["messages"] if row["tag"] in (3, 5)]
    if "fail_token" in inp:
        assert last["state"] == 1 and last["rid"] == 0 and last["errors"] == [1]
        assert len(calls) == inp["fail_token"] + 1 and calls[-1]["failed"]
        assert len(wires) == inp["fail_token"]
        assert last["messages"][-1]["tag"] == (9 if inp["fail_token"] == 1 else 10)
    else:
        assert last["state"] == (4 if inp["path"] == "auth_retry" else 5)
        assert len(calls) == len(wires) and not any(x["failed"] for x in calls)
    raw = struct.pack("<Q", inp.get("device_id", life.m.e.DID)).hex()
    tokens, pins = [], []
    for call, wire in zip(calls, wires):
        body = fields(wire["body"])
        token = body[7 if wire["tag"] == 5 else 1]
        assert len(token) == 32 and decrypt(token, bytes.fromhex(call["secret"])) == raw
        tokens.append(token)
        if wire["tag"] == 5:
            pins.append(body[8])
            assert body[12] == int(inp.get("test", False))
    assert len(set(tokens)) == len(tokens)
    assert not pins or len(set(pins)) == 1
    tickets = iter(last["tickets"])
    for index, call in enumerate(calls):
        kind = (
            wires[index]["tag"]
            if not call["failed"]
            else (3 if last["messages"][-1]["tag"] == 9 else 5)
        )
        if kind == 3:
            assert fields(next(tickets))[3].hex() == call["secret"]
    assert next(tickets, None) is None


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    args = p.parse_args()
    binary = args.binary.read_bytes()
    sha = life.m.e.p.m.discovery.lifecycle.media.flow.SHA
    assert hashlib.sha256(binary).hexdigest() == sha
    inputs = [
        dict(path=path, pin=pin, test=test)
        for path in ("stream_retry", "auth_retry", "reauthorize")
        for pin in ("", "9876", "98765432", "9876543210123456")
        for test in (False, True)
    ]
    inputs += [
        dict(path=path, device_id=did, pin="9876")
        for path in ("stream_retry", "reauthorize")
        for did in (1, 0x8877665544332211)
    ]
    inputs += [
        dict(path="reauthorize", fail_token=n, test=t, pin="9876")
        for n in range(4)
        for t in (False, True)
    ]
    cases = []
    for inp in inputs:
        case = run(binary, inp)
        verify(case)
        cases.append(case)
        print(inp, "verified", flush=True)
    pc = 0xCB3C88
    image = life.m.e.p.m.discovery.lifecycle.media.flow.config.BASE["load_image"](
        binary
    )[0]
    before = struct.unpack_from("<I", image, pc)[0]
    original = run(binary, dict(path="stream_retry", pin="9876"))
    mutant = run(
        binary, dict(path="stream_retry", pin="9876"), (pc, before, 0x52800205)
    )  # mov w5,#16
    assert mutant["patch_hits"] == [pc] * 3 and not mutant["source_assertions"]
    old = bytes(range(32, 64))
    assert all(
        decrypt(fields(x["body"])[7], old) is None
        for x in mutant["steps"][-1]["messages"]
        if x["tag"] == 5
    )
    report = dict(
        binary_sha256=sha,
        scope=__doc__,
        cases=cases,
        functions=life.m.e.p.m.inventory(binary, cases),
        negative=dict(
            site=pc, before=before, after=0x52800205, original=original, mutant=mutant
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
        f"Official device tokens: {len(cases)} per-send/secret/PIN/producer-failure cases; normal-return key-size instruction negative",
        flush=True,
    )


if __name__ == "__main__":
    main()
