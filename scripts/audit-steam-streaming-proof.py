#!/usr/bin/env python3
"""Official shell Proof rotation, original crypto, persistence and owner lifetime.

Original Panel/Start, response and Proof protobuf parsers/handlers, SHA256,
SymmetricEncrypt/AES, SavePersistentClientKey/file helpers and serializers run.
Identity, entropy/IV/wall clock, Qt storage/presentation, request RSA, low-level
SDL files and final Send/ordinary launcher are explicit §131 adapters. Inputs
enter handlers, not the OS broadcast receiver. Encryption failure is an explicit
SymmetricEncrypt bool provider; no natural entropy failure is inferred. No
Native Proof rotation, real Steam, Switch or filesystem durability is proved.
"""

import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "token", ROOT / "scripts/audit-steam-device-token.py"
)
token = importlib.util.module_from_spec(spec)
spec.loader.exec_module(token)
life = token.life
PROOF = "_ZN14CServerManager27HandleStreamingProofRequestERK10CIPAndPortyPK28CMsgRemoteDeviceProofRequest"
HASH = "_ZN7CCrypto20GenerateSHA256DigestEPKvmPA32_h"
ENCRYPT = "_ZN7CCrypto16SymmetricEncryptEPKhjPhPjS1_j"
REFERENCE = ROOT / "scripts/fixtures/steam-streaming-proof-reference.json.gz"


class Proof(token.Token):
    def __init__(self, binary, inp, patch=None):
        self.proof_active = False
        self.proof_ops, self.requests = [], []
        self.fail_encrypt = inp.get("encrypt_failure", False)
        super().__init__(binary, dict(path="reauthorize", pin="9876"), patch)
        self.mode = inp.get("io", "ok")
        for name, address in self.symbols.items():
            if (
                address
                and "CMsgRemoteDeviceProof" in name
                and any(
                    x in name for x in ("C1Ev", "InternalParse", "InternalSerialize")
                )
            ):
                self.function_entries.setdefault(address, []).append(name)

    def hook(self, u, pc, size, data):
        name = self.plts.get(pc, "")
        if name == "__memmove_chk":
            assert self.r(2) <= self.r(3)
            if self.r(2):
                u.mem_write(self.r(0), bytes(u.mem_read(self.r(1), self.r(2))))
            self.ret(self.r(0))
        elif self.proof_active and name in (HASH, ENCRYPT):
            row = dict(
                op="hash" if name == HASH else "encrypt",
                plain=bytes(u.mem_read(self.r(0), self.r(1))).hex(),
            )
            if name == ENCRYPT:
                row.update(
                    secret=bytes(u.mem_read(self.r(4), self.r(5))).hex(),
                    failed=self.fail_encrypt,
                    io_count=len(self.io),
                )
            self.proof_ops.append(row)
            if name == ENCRYPT and self.fail_encrypt:
                self.ret(0)
            else:
                self.jump(self.symbols[name])
        else:
            if self.proof_active and name == life.m.SAVE:
                self.proof_ops.append(
                    dict(
                        op="save",
                        client=self.r(1),
                        steamid=self.r(2),
                        io_before=len(self.io),
                    )
                )
            elif self.proof_active and name == life.m.SEND:
                self.proof_ops.append(dict(op="send", tag=self.r(1)))
            super().hook(u, pc, size, data)

    def proof(
        self,
        challenge=b"challenge\0\xff",
        update=True,
        request_id=17,
        host=123,
        encrypt_failure=None,
    ):
        if encrypt_failure is not None:
            self.fail_encrypt = encrypt_failure
        v = life.m.e.p.m.discovery.varint
        body = b"\x0a" + v(len(challenge)) + challenge
        if request_id is not None:
            body += b"\x10" + v(request_id)
        if update is not None:
            body += b"\x18" + v(int(update))
        obj, peer = self.alloc(512), self.alloc(24)
        self.u.mem_write(peer, bytes(range(1, 25)))
        assert self.parse(obj, body, "CMsgRemoteDeviceProofRequest")
        self.requests.append(dict(body=body.hex(), host=host))
        self.proof_active = True
        self.call(self.symbols[PROOF], self.manager, peer, host, obj)
        self.proof_active = False

    def observe(self, label):
        row = super().observe(label)
        row.update(
            proof_updated=self.u.mem_read(self.manager + 0x210, 1)[0],
            account=self.q(self.manager + 0x1F8),
            proof_ops=list(self.proof_ops),
            requests=list(self.requests),
        )
        return row


def run(binary, inp, patch=None):
    r = Proof(binary, inp, patch)
    r.b(life.m.PANEL + 0xD4, int(inp.get("test", False)))
    r.call(r.symbols[life.START], life.m.PANEL)
    if "account" in inp:
        # Explicit current identity input, not an inferred account lookup policy.
        r.wq(r.manager + 0x1F8, inp["account"])
    steps = [r.observe("requested")]
    phase = inp.get("phase", "streaming")
    if phase in ("authorizing", "authorized"):
        r.response(1)
        if phase == "authorized":
            r.answer()
        steps.append(r.observe(phase))
    elif phase == "ticket":
        r.credentials(bytes.fromhex(steps[-1]["secret"]), 32)
        steps.append(r.observe(phase))
    elif phase == "cancelled":
        r.stop()
        steps.append(r.observe(phase))
    for index, request in enumerate(inp.get("requests", [{}])):
        options = dict(request)
        if "challenge" in options:
            options["challenge"] = bytes.fromhex(options["challenge"])
        r.proof(**options)
        steps.append(r.observe(f"proof_{index}"))
    path = inp.get("path", "requests")
    if path in ("replace", "same_start"):
        if path == "replace":
            r.stop()
        r.start(inp.get("test", False))
        steps.append(r.observe(path))
        r.proof(request_id=r.i(r.manager + 0x200))
        steps.append(r.observe("proof_after_start"))
    elif path == "credentials":
        r.credentials(bytes.fromhex(steps[-1]["secret"]), inp["length"])
        r.update()
        steps.append(r.observe("consumer"))
    elif path == "reauthorize":
        r.response(1)
        r.answer()
        steps.append(r.observe("reauthorized"))
        r.proof(challenge=b"different", update=True)
        steps.append(r.observe("proof_after_reauthorization"))
    elif path == "retry":
        r.wall_time = 1003 if phase == "authorizing" else 1001
        r.call(r.symbols["_ZN14CServerManager6UpdateEv"], r.manager)
        steps.append(r.observe("retry"))
    assert not r.assertions
    return dict(
        input=inp,
        steps=steps,
        source_assertions=r.assertions,
        executed=sorted(r.executed),
        patch_hits=r.patch_hits,
    )


def verify(case):
    inp, steps = case["input"], case["steps"]
    for previous, current in zip(steps, steps[1:]):
        if not current["label"].startswith("proof_"):
            continue
        request = current["requests"][-1]
        fields = token.fields(request["body"])
        challenge, update = fields[1], bool(fields.get(3, 0))
        foreign = not request["host"] or request["host"] != previous["target"]
        wrong_id = 2 in fields and fields[2] != previous["rid"]
        delta = current["proof_ops"][len(previous["proof_ops"]) :]
        messages = current["messages"][len(previous["messages"]) :]
        assert all(
            current[k] == previous[k]
            for k in ("state", "rid", "target", "next", "keypair_generations")
        )
        if foreign:
            assert delta == [dict(op="send", tag=8)]
            assert messages == [dict(tag=8, target=request["host"], body="0a00")]
            assert current["secret"] == previous["secret"]
            assert current["proof_updated"] == previous["proof_updated"]
            continue
        if wrong_id:
            assert not delta and not messages
            assert current["secret"] == previous["secret"]
            assert current["proof_updated"] == previous["proof_updated"]
            continue
        rotated = update and not previous["proof_updated"]
        old = bytes.fromhex(previous["secret"])
        secret = hashlib.sha256(old + challenge).digest() if rotated else old
        assert current["secret"] == secret.hex()
        assert current["proof_updated"] == int(rotated or previous["proof_updated"])
        encrypted = next(x for x in delta if x["op"] == "encrypt")
        assert (
            encrypted["plain"] == challenge.hex()
            and encrypted["secret"] == secret.hex()
        )
        assert [x["op"] for x in delta] == (
            (["hash", "save"] if rotated else [])
            + ["encrypt"]
            + ([] if encrypted["failed"] else ["send"])
        )
        if rotated:
            assert delta[0]["plain"] == (old + challenge).hex()
            assert delta[1]["client"] == 123
            assert delta[1]["steamid"] == previous["account"]
            assert encrypted["io_count"] > delta[1]["io_before"]
            saved = [x for x in current["timeline"] if x["op"] == "save_key"][-1]
            assert saved["secret"] == secret.hex() and saved["client"] == 123
            if inp.get("io", "ok") == "ok":
                assert (secret.hex().encode() + b"\n").hex() in current[
                    "files"
                ].values()
        if encrypted["failed"]:
            assert not messages
        else:
            assert (
                len(messages) == 1
                and messages[0]["tag"] == 8
                and messages[0]["target"] == 123
            )
            response = token.fields(messages[0]["body"])
            assert response[2] == previous["rid"] and response[3] == int(update)
            assert token.decrypt(response[1], secret) == challenge.hex()
    last = steps[-1]
    path = inp.get("path", "requests")
    if path == "credentials":
        assert last["state"] == 6
        assert (
            last["network_tokens"]
            if inp.get("test", False)
            else last["ordinary_launches"]
        ) == [bytes(range(inp["length"])).hex()]
    elif path in ("same_start", "replace"):
        before, restarted = steps[-3:-1]
        replaced = path == "replace" or before["state"] != 5
        assert restarted["rid"] == (19 if replaced else 17)
        assert restarted["keypair_generations"] == (2 if replaced else 1)
        assert restarted["proof_updated"] == (0 if replaced else 1)
    elif path == "reauthorize":
        accepted = steps[-2]
        assert accepted["proof_updated"] == 1 and accepted["rid"] == 17
        assert accepted["keypair_generations"] == 1
        assert accepted["secret"] == life.m.e.material()[2].hex()
    elif path == "retry":
        assert last["messages"][-1]["tag"] == (
            3 if inp.get("phase") == "authorizing" else 5
        )
        body = token.fields(last["messages"][-1]["body"])
        assert (
            token.decrypt(
                body[1 if last["messages"][-1]["tag"] == 3 else 7],
                bytes.fromhex(last["secret"]),
            )
            == struct.pack("<Q", life.m.e.DID).hex()
        )
        assert body[5 if last["messages"][-1]["tag"] == 3 else 1] == 17
        if last["messages"][-1]["tag"] == 5:
            assert body[8] == token.fields(steps[0]["messages"][0]["body"])[8]
    assert not case["source_assertions"]


def inputs():
    requests = [
        [dict(update=None)],
        [dict(update=False)],
        [{}],
        [{}, {}, dict(challenge="00ff01")],
        [dict(update=False), dict(challenge="00ff01"), dict(update=False), {}],
        [dict(host=456)],
        [dict(host=0)],
        [dict(request_id=18)],
        [dict(request_id=0)],
        [dict(request_id=None)],
        [dict(host=456, request_id=0)],
        [dict(encrypt_failure=True), dict(encrypt_failure=False)],
    ]
    cases = [dict(test=t, requests=r) for t in (False, True) for r in requests]
    cases += [
        dict(test=t, phase=p)
        for t in (False, True)
        for p in ("authorizing", "authorized", "ticket", "cancelled")
    ]
    cases += [
        dict(test=t, path="credentials", length=n)
        for t in (False, True)
        for n in (16, 32)
    ]
    cases += [dict(io=mode) for mode in ("mkdir", "open", "zero", "short", "close")]
    cases += [
        dict(path=path, phase=phase)
        for path, phase in (
            ("same_start", "streaming"),
            ("same_start", "authorizing"),
            ("replace", "streaming"),
            ("replace", "authorizing"),
            ("replace", "ticket"),
            ("reauthorize", "streaming"),
            ("retry", "streaming"),
            ("retry", "authorizing"),
        )
    ]
    cases += [
        dict(requests=[dict(challenge=bytes(range(n)).hex())])
        for n in (1, 15, 16, 17, 255)
    ]
    cases += [dict(account=account) for account in (123, 76561198000000001)]
    return cases


def negatives(binary):
    image = life.m.e.p.m.discovery.lifecycle.media.flow.config.BASE["load_image"](
        binary
    )[0]
    output = []
    patches = (
        (
            "rehash",
            0xCB4FD0,
            0x14000000 | ((0xCB51E4 - 0xCB4FD0) // 4),
            dict(requests=[{}, {}]),
            2,
        ),
        ("skip_save", 0xCB52A0, 0xD503201F, {}, 1),
        (
            "ignore_request_id",
            0xCB4FB4,
            0xD503201F,
            dict(requests=[dict(request_id=18)]),
            1,
        ),
        ("aes128", 0xCB5014, 0x52800205, {}, 1),
    )
    for name, pc, after, inp, hits in patches:
        before = struct.unpack_from("<I", image, pc)[0]
        original, mutant = run(binary, inp), run(binary, inp, (pc, before, after))
        verify(original)
        assert mutant["patch_hits"] == [pc] * hits and not mutant["source_assertions"]
        try:
            verify(mutant)
        except AssertionError:
            pass
        else:
            raise AssertionError(f"Semantic regression not detected: {name}")
        output.append(
            dict(
                name=name,
                site=pc,
                before=before,
                after=after,
                original=original,
                mutant=mutant,
            )
        )
        print(name, "normal-return semantic negative verified", flush=True)
    return output


def main():
    if not __debug__:
        raise SystemExit("This source audit requires assertions; do not use python -O")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    binary = a.binary.read_bytes()
    sha = life.m.e.p.m.discovery.lifecycle.media.flow.SHA
    assert hashlib.sha256(binary).hexdigest() == sha
    cases = []
    for inp in inputs():
        case = run(binary, inp)
        verify(case)
        cases.append(case)
        print(inp, "verified", flush=True)
    report = dict(
        binary_sha256=sha,
        scope=__doc__,
        cases=cases,
        functions=life.m.e.p.m.inventory(binary, cases),
        negative=negatives(binary),
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
    print(f"Official streaming Proof: {len(cases)} cases", flush=True)


if __name__ == "__main__":
    main()
