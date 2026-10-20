#!/usr/bin/env python3
"""Replay official Unauthorized authorization producer and legacy resumption.

Pinned Android shell StartStreaming, Unauthorized response, authorization request
creation and ticket/request serializers, SHA256/XOR, manager retry Update,
authorization response parser/handler and legacy no-auth_key resumption execute.
Identity/server lookup/token/account/keypair, random input, wall clock, RSA key
loading/encryption/destruction, libc++ string storage and final SendMessage are
explicit adapters. RSA output is a marker, not encrypted or wire-valid evidence.
The provided public key is fixture input; X25519/key-exchange response processing,
Qt PIN presentation, persistence writes, real Steam and Switch are not proved.
"""
import argparse
import gzip
import importlib.util
import json
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "scripts/fixtures/steam-authorization-producer-reference.json.gz"
s = importlib.util.spec_from_file_location(
    "transaction", ROOT / "scripts/audit-steam-streaming-transaction.py"
)
m = importlib.util.module_from_spec(s)
s.loader.exec_module(m)


class Authorization(m.Transaction):
    def __init__(self, b, patch=None):
        self.tickets = []
        self.rsa_keys = []
        self.rsa_success = True
        self.token_success = True
        super().__init__(b, patch)
        self.wi(self.manager + 0x13C, 1)
        self.wq(self.manager + 0x30, 0x7FFFFFFFFFFFFFFF)
        self.wi(self.manager + 0x50, 3)
        for off, value in [
            (0x198, "Switch fixture"),
            (0x1A0, "Switch model fixture"),
            (0x1A8, "serial fixture"),
        ]:
            p = self.alloc(len(value) + 1)
            self.u.mem_write(p, value.encode() + b"\0")
            self.wq(self.manager + off, p)
        pub = self.alloc(32)
        self.u.mem_write(pub, bytes(range(32)))
        self.wq(self.manager + 0x270, pub)
        self.wi(self.manager + 0x278, 32)

    def hook(self, u, pc, size, data):
        name = self.plts.get(pc, "")
        if name == "_ZN14CServerManager26SendAuthorizeDeviceRequestEv":
            self.jump(self.symbols[name])
        elif name == "_ZN7CCrypto19GenerateRandomBlockEPvm":
            n = self.r(1)
            value = struct.pack("<I", 42) if n == 4 else bytes(range(n))
            u.mem_write(self.r(0), value)
            self.ret(1)
        elif name == "_ZN14CServerManager11GetDeviceIDEv":
            self.ret(0x1122334455667788)
        elif name == "_ZN14CCryptoKeyBase26SetFromBase64EncodedStringEPKc":
            self.rsa_keys.append(self.cstring(self.r(1)))
            self.ret(1)
        elif (
            name == "_ZN14CServerManager15BGetDeviceTokenER10CUtlBuffer"
            and not self.token_success
        ):
            self.ret(0)
        elif name == "_ZN7CCrypto10RSAEncryptEPKhjPhPjRK13CRSAPublicKey":
            self.tickets.append(bytes(u.mem_read(self.r(0), self.r(1))).hex())
            out = b"RSA-external-boundary"
            u.mem_write(self.r(2), out)
            self.wi(self.r(3), len(out))
            self.ret(int(self.rsa_success))
        elif (
            name
            == "_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6resizeEmc"
        ):
            dest, n, c = self.r(0), self.r(1), self.r(2) & 255
            tag = u.mem_read(dest, 1)[0]
            oldn = self.q(dest + 8) if tag & 1 else tag >> 1
            oldp = self.q(dest + 16) if tag & 1 else dest + 1
            v = bytes(u.mem_read(oldp, min(n, oldn))) + bytes([c]) * max(0, n - oldn)
            capacity = (n + 2) & ~1
            p = self.alloc(capacity)
            u.mem_write(p, v + b"\0")
            self.wq(dest, capacity | 1)
            self.wq(dest + 8, n)
            self.wq(dest + 16, p)
            self.ret()
        elif name == "_ZN13CRSAPublicKeyD1Ev":
            self.ret()
        elif name == "_ZN10CUtlString6FormatEPKcz":
            assert self.cstring(self.r(1)) == "%4.4u"
            p = self.alloc(16)
            u.mem_write(p, f"{self.r(2):04d}".encode() + b"\0")
            self.wq(self.r(0), p)
            self.ret()
        elif name == "_Z43ERemoteDeviceAuthorizationResult_descriptorv":
            self.ret()
        else:
            super().hook(u, pc, size, data)

    def observe_auth(self, label):
        wires = []
        names = {
            3: "CMsgRemoteDeviceAuthorizationRequest",
            5: "CMsgRemoteDeviceStreamingRequest",
            8: "CMsgRemoteDeviceProofResponse",
            9: "CMsgRemoteDeviceAuthorizationCancelRequest",
            10: "CMsgRemoteDeviceStreamingCancelRequest",
            14: "CMsgRemoteDeviceAuthorizationConfirmed",
        }
        for (tag, msg), host in zip(self.messages, self.destinations):
            wires.append(
                dict(tag=tag, target=host, body=self.serialize(msg, names[tag]).hex())
            )
        return dict(
            label=label,
            state=self.i(self.manager + 8),
            rid=self.i(self.manager + 0x200),
            target=self.q(self.manager + 0x1F0),
            next=self.q(self.manager + 0x208),
            messages=wires,
            errors=list(self.errors),
            tickets=list(self.tickets),
        )


def run(binary, inp, patch=None):
    r = Authorization(binary, patch)
    # The supplied connect PIN is distinct from the generated 0042 pairing PIN.
    pin = r.alloc(8)
    r.u.mem_write(pin, b"9876\0")
    r.b(r.manager + 0x1E5, int(inp.get("test", False)))
    r.call(r.symbols["_ZN14CServerManager14StartStreamingEyPKc"], r.manager, 123, pin)
    steps = [r.observe_auth("requested")]
    fail = inp.get("producer_failure")
    if fail == "universe":
        r.wi(r.manager + 0x13C, 0)
    if fail == "name":
        p = r.alloc(66)
        r.u.mem_write(p, b"N" * 65 + b"\0")
        r.wq(r.manager + 0x198, p)
    if fail == "rsa":
        r.rsa_success = False
    if fail == "token":
        r.token_success = False
    r.response(1)
    steps.append(r.observe_auth("unauthorized"))
    if inp["path"] == "retry":
        for tick in (1000, 1001, 1002, 1003, 1003, 1005, 1006, 1300):
            r.wall_time = tick
            r.call(r.symbols["_ZN14CServerManager6UpdateEv"], r.manager)
            steps.append(r.observe_auth(str(tick)))
    elif inp["path"] == "response":
        body = (
            b"\x08"
            + m.discovery.varint(inp["result"])
            + b"\x11"
            + struct.pack("<Q", 76561198000000001)
        )
        obj, peer = r.alloc(512), r.alloc(24)
        assert r.parse(obj, body, "CMsgRemoteDeviceAuthorizationResponse")
        r.call(
            r.symbols[
                "_ZN14CServerManager33HandleDeviceAuthorizationResponseERK10CIPAndPortyPK37CMsgRemoteDeviceAuthorizationResponse"
            ],
            r.manager,
            peer,
            inp.get("host", 123),
            obj,
        )
        steps.append(r.observe_auth("response"))
    elif inp["path"] == "cancel":
        r.stop()
        steps.append(r.observe_auth("cancelled"))
        r.wall_time = 1300
        r.call(r.symbols["_ZN14CServerManager6UpdateEv"], r.manager)
        steps.append(r.observe_auth("after_cancel"))
    assert not r.assertions
    return dict(
        input=inp,
        steps=steps,
        source_assertions=r.assertions,
        executed=sorted(r.executed),
        patch_hits=r.patch_hits,
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    binary = a.binary.read_bytes()
    sha = m.discovery.lifecycle.media.flow.SHA
    assert hashlib.sha256(binary).hexdigest() == sha
    inputs = [dict(path="retry", test=t) for t in (False, True)]
    inputs += [
        dict(path="response", test=t, result=v) for t in (False, True) for v in range(9)
    ]
    inputs += [dict(path="response", host=456, result=v) for v in (0, 1, 5)]
    inputs += [dict(path="cancel", test=t) for t in (False, True)]
    inputs += [
        dict(path="failure", producer_failure=v)
        for v in ("universe", "name", "rsa", "token")
    ]
    cases = [run(binary, v) for v in inputs]
    for c in cases:
        i, steps = c["input"], c["steps"]
        assert steps[0]["state"] == 5 and steps[0]["rid"] == 17
        if i.get("producer_failure"):
            assert steps[1]["state"] == 1 and steps[1]["errors"] == [1]
            assert [x["tag"] for x in steps[1]["messages"]] == [5, 9]
            continue
        assert (
            steps[1]["state"] == 4
            and steps[1]["rid"] == 17
            and steps[1]["next"] == 1003
        )
        request = m.discovery.fields(bytes.fromhex(steps[1]["messages"][1]["body"]))
        assert request["5"] == [17]
        expected = bytes(
            x ^ y for x, y in zip(bytes(range(32)), hashlib.sha256(b"0042").digest())
        )
        assert request["4"] == [expected.hex()]
        ticket = m.discovery.fields(bytes.fromhex(steps[1]["tickets"][0]))
        assert ticket["1"] == [b"0042".hex()] and ticket["3"] == [
            m.discovery.SECRET.hex()
        ]
        streaming = m.discovery.fields(bytes.fromhex(steps[0]["messages"][0]["body"]))
        assert streaming["8"] == [m.discovery.encrypted(b"9876").hex()]
        last = steps[-1]
        if i["path"] == "retry":
            assert [len(s["messages"]) for s in steps[2:]] == [2, 2, 2, 3, 3, 3, 4, 5]
            assert last["state"] == 4 and not last["errors"]
        elif i["path"] == "cancel":
            assert [x["tag"] for x in last["messages"]] == [5, 3, 9]
            assert last["state"] == 1 and last["rid"] == 0
        elif i.get("host", 123) != 123:
            assert (
                last["state"] == 4 and len(last["messages"]) == 2 and not last["errors"]
            )
        elif i["result"] == 0:
            assert last["state"] == 5 and last["rid"] == 17
            assert [x["tag"] for x in last["messages"]] == [5, 3, 5]
            assert last["messages"][0] == last["messages"][2]
        elif i["result"] == 5:
            assert (
                last["state"] == 4 and len(last["messages"]) == 2 and not last["errors"]
            )
        else:
            assert last["state"] == 1 and last["rid"] == 0
            assert last["errors"] == [
                {1: 2, 2: 3, 3: 4, 4: 5, 6: 6, 7: 1, 8: 1}[i["result"]]
            ]
    pc = 0xCB1CCC
    image = m.discovery.lifecycle.media.flow.config.BASE["load_image"](binary)[0]
    before = struct.unpack_from("<I", image, pc)[0]
    original = run(binary, dict(path="retry"))
    mutant = run(binary, dict(path="retry"), (pc, before, before - (2 << 10)))
    assert mutant["patch_hits"] and not mutant["source_assertions"]
    assert (
        len(original["steps"][3]["messages"]) == 2
        and len(mutant["steps"][3]["messages"]) == 3
    )
    report = dict(
        binary_sha256=sha,
        scope=__doc__,
        functions=m.inventory(binary, cases),
        cases=cases,
        negative=dict(
            site=pc,
            before=before,
            after=before - (2 << 10),
            original=original,
            mutant=mutant,
        ),
    )
    if a.refresh_reference:
        if REFERENCE.exists():
            assert report == json.loads(gzip.decompress(REFERENCE.read_bytes()))
        REFERENCE.write_bytes(
            gzip.compress(json.dumps(report, sort_keys=True).encode(), mtime=0)
        )
    else:
        assert report == json.loads(gzip.decompress(REFERENCE.read_bytes()))
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"Official authorization producer: {len(cases)} cases; 3-to-1-second mutation detected"
    )


if __name__ == "__main__":
    main()
