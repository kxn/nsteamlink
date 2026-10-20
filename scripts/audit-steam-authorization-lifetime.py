#!/usr/bin/env python3
"""Official authorization ownership, cache lifetime and discovery envelope admission.

Pinned Android shell Start/Stop/Panel, full authorization crypto/cache/save callers,
BProcess, CUtlBuffer reads and original header/body protobuf parsers execute.
Qt, identity/entropy, request RSA, low-level file providers and final send remain
§129's explicit adapters. Inputs enter a CUtlBuffer, not an OS socket or Steam.
Repeated private entropy is deliberate; keypair invocation counts and cached
results are observed separately from natural key freshness. No Native automatic
stream resumption or peer admission equivalence is claimed by this reference.
Constructor defaults now execute on A5-filled independent storage; paired-ID loading
and client-ID migration are explicit identity/file providers (§130).
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
    "ui", ROOT / "scripts/audit-steam-authorization-ui.py"
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
REFERENCE = ROOT / "scripts/fixtures/steam-authorization-lifetime-reference.json.gz"
START = "_ZN13CPanelConnect23SetPanelStateConnectingEv"
STOP = "_ZN13CPanelConnect14OnActionCancelEv"
PROCESS = "_ZN14CServerManager8BProcessEP10CIPAndPortP10CUtlBufferb"


class Lifetime(m.AuthorizationUI):
    def __init__(self, binary, patch=None):
        super().__init__(binary, random_values=[42] * 8, patch=patch)
        for name, address in self.symbols.items():
            if address and (
                name == PROCESS
                or (
                    name.startswith("_ZN10CUtlBuffer")
                    and ("GetIntEv" in name or "SeekGet" in name)
                )
                or (
                    "CMsgRemoteClientBroadcastHeader" in name
                    and ("C1Ev" in name or "InternalParse" in name)
                )
                or (
                    "CMsgRemoteDeviceAuthorizationResponse" in name
                    and "InternalParse" in name
                )
            ):
                self.function_entries.setdefault(address, []).append(name)

    def hook(self, u, pc, size, data):
        name = self.plts.get(pc, "")
        if name.startswith("_ZN10CUtlBuffer") and (
            "GetIntEv" in name or "SeekGet" in name
        ):
            self.jump(self.symbols[name])
        elif name.startswith("_ZN14CServerManager33HandleDeviceAuthorizationResponse"):
            self.jump(self.symbols[name])
        else:
            super().hook(u, pc, size, data)

    def observe(self, label):
        row = super().observe(label)
        row["keypair_generations"] = self.ui_calls.count(
            "_ZN7CCrypto26GenerateKeyExchangeKeyPairEP23CECKeyExchangePublicKeyP24CECKeyExchangePrivateKey"
        )
        return row

    def begin(self, testing):
        self.b(m.PANEL + 0xD4, int(testing))
        self.call(self.symbols[START], m.PANEL)
        assert self.i(m.PANEL + 0xD8) == 4
        self.response(1)
        self.update()
        assert self.i(m.PANEL + 0xD8) == 3

    def answer(self, index=0, valid=True, host=123):
        key, token, _ = m.e.material(index=index, token_device=m.e.DID + int(not valid))
        self.auth_response(key=key, token=token, host=host)
        return dict(auth_key=key.hex(), device_token=token.hex(), result=0, host=host)

    def packet(self, case):
        key, token, _ = m.e.material()
        v = m.e.p.m.discovery.varint
        body = b"\x08\0\x11" + struct.pack("<Q", 76561198000000001)
        body += b"\x1a" + v(len(key)) + key + b"\x22" + v(len(token)) + token
        host = 456 if case == "foreign" else 0 if case == "zero" else 123
        header = b"\x08" + v(host) + b"\x10\x04"
        if case == "bad_header":
            header = b"\x80"
        elif case == "bad_body":
            body = b"\x80"
        elif case == "missing_result":
            body = body[2:]
        elif case == "empty_body":
            body = b""
        declared = len(body) + int(case == "truncated")
        packet = b"\xff" * 4 + b"\x21\x4c\x5f\xa0"
        packet += (
            struct.pack("<I", len(header)) + header + struct.pack("<I", declared) + body
        )
        if case == "trailing":
            packet += b"\0"
        buf, pointer, peer = self.alloc(128), self.alloc(len(packet)), self.alloc(24)
        self.u.mem_write(pointer, packet)
        self.u.mem_write(peer, bytes(range(1, 25)))
        self.call(self.symbols["_ZN10CUtlBufferC1Ev"], buf)
        self.call(self.symbols["_ZN10CUtlBuffer3PutEPKvi"], buf, pointer, len(packet))
        result = self.call(self.symbols[PROCESS], self.manager, peer, buf, 0)
        return packet.hex(), result


def run(binary, inp, patch=None):
    r = Lifetime(binary, patch)
    r.begin(inp.get("test", False))
    steps, responses = [r.observe("authorization")], []
    path = inp["path"]
    packet = result = None
    if path == "routing":
        packet, result = r.packet(inp["case"])
        steps.append(r.observe("processed"))
    elif path == "empty_key":
        r.auth_response(key=b"")
        steps.append(r.observe("empty_key"))
    else:
        prior = inp.get("prior", "success")
        if path == "lifetime" or inp["action"].startswith("success"):
            indexes = range(4) if prior == "limit" else range(1)
            for index in indexes:
                responses.append(r.answer(index=index, valid=prior == "success"))
            r.update()
            steps.append(r.observe("prior"))
        action = inp.get("action", "restart")
        if action in ("cancel_then_late", "success_cancel_restart", "restart"):
            r.call(r.symbols[STOP], m.PANEL)
            steps.append(r.observe("cancelled"))
        if action == "cancel_then_late":
            responses.append(r.answer())
        else:
            r.start(inp.get("test", False), inp.get("host", 123))
        steps.append(r.observe("after_action"))
        if path == "lifetime":
            host = inp["host"]
            r.response(1, host=host)
            steps.append(r.observe("reauthorizing"))
            index = 3 if prior == "limit" else 0
            responses.append(r.answer(index=index, host=host))
            steps.append(r.observe("cached"))
            responses.append(r.answer(index=4, host=host))
            steps.append(r.observe("different"))
    assert not r.assertions
    return dict(
        input=inp,
        steps=steps,
        responses=responses,
        packet=packet,
        result=result,
        source_assertions=r.assertions,
        executed=sorted(r.executed),
        patch_hits=r.patch_hits,
    )


def verify(case):
    inp, steps = case["input"], case["steps"]
    assert steps[0]["state"] == 4 and steps[0]["rid"] == 17
    last = steps[-1]
    if inp["path"] == "routing":
        kind = inp["case"]
        if kind in ("zero", "bad_header", "truncated", "trailing"):
            assert case["result"] == 0 and last["state"] == 4 and not last["derived"]
            assert [x["tag"] for x in last["messages"]] == [5, 3]
        elif kind == "foreign":
            assert case["result"] == 1 and last["state"] == 4 and last["derived"] == 1
            assert [x["body"] for x in last["messages"] if x["tag"] == 14] == [
                "0800",
                "0808",
            ]
            assert [x["client"] for x in last["timeline"] if x["op"] == "save_key"] == [
                456
            ]
        elif kind == "target":
            assert case["result"] == 1 and last["state"] == 5 and last["derived"] == 1
        elif kind == "empty_body":
            assert case["result"] == 1 and last["state"] == 5 and not last["derived"]
        else:
            assert kind in ("bad_body", "missing_result")
            assert case["result"] == 1 and last["state"] == 1 and not last["derived"]
    elif inp["path"] == "empty_key":
        assert last["state"] == 4 and not last["derived"]
        assert last["cached_result"] == 7
        assert last["messages"][-1]["body"] == "0807"
    elif inp["path"] == "lifetime":
        previous, restarted, cached, different = (
            steps[1],
            steps[3],
            steps[-2],
            steps[-1],
        )
        assert (
            restarted["cache"] == previous["cache"]
            and restarted["cached_result"] == previous["cached_result"]
        )
        assert (
            restarted["attempts"] == 0
            and restarted["keypair_generations"] == 2
            and restarted["rid"] == 19
        )
        assert (
            cached["derived"] == previous["derived"]
            and cached["state"] == 4
            and cached["attempts"] == 0
        )
        assert (
            different["derived"] == previous["derived"] + 1
            and different["state"] == 5
            and different["attempts"] == 1
        )
    else:
        action = inp["action"]
        if action == "cancel_then_late":
            assert last["state"] == 1 and [x["tag"] for x in last["messages"]] == [
                5,
                3,
                9,
                14,
            ]
            assert last["messages"][-1]["body"] == "0808"
        elif action == "success_same":
            assert (
                last["state"] == 5
                and last["rid"] == 17
                and last["keypair_generations"] == 1
            )
        else:
            assert (
                last["state"] == 5
                and last["rid"] == 19
                and last["keypair_generations"] == 2
            )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    args = p.parse_args()
    binary = args.binary.read_bytes()
    sha = m.e.p.m.discovery.lifecycle.media.flow.SHA
    assert hashlib.sha256(binary).hexdigest() == sha
    actions = [
        "duplicate_same",
        "replace_host",
        "cancel_then_late",
        "success_same",
        "success_replace",
        "success_cancel_restart",
    ]
    inputs = [
        dict(
            path="ownership",
            action=a,
            test=t,
            host=456 if a.endswith("host") or a == "success_replace" else 123,
        )
        for t in (False, True)
        for a in actions
    ]
    inputs += [
        dict(path="lifetime", prior=p, host=h, test=t)
        for t in (False, True)
        for p in ("success", "denied", "limit")
        for h in (123, 456)
    ]
    inputs += [
        dict(path="routing", case=c)
        for c in (
            "target",
            "foreign",
            "zero",
            "bad_header",
            "bad_body",
            "missing_result",
            "empty_body",
            "truncated",
            "trailing",
        )
    ]
    inputs.append(dict(path="empty_key"))
    cases = []
    for inp in inputs:
        case = run(binary, inp)
        verify(case)
        cases.append(case)
        print(inp, "verified", flush=True)
    image = m.e.p.m.discovery.lifecycle.media.flow.config.BASE["load_image"](binary)[0]
    negatives = []
    for pc, inp in (
        (0xCB4B38, dict(path="lifetime", prior="denied", host=123)),
        (0xCB13C0, dict(path="routing", case="zero")),
        (0xCAE53C, dict(path="empty_key")),
    ):
        before = struct.unpack_from("<I", image, pc)[0]
        after = (before & ~(0xFFFF << 5)) if inp["path"] == "empty_key" else 0xD503201F
        original = run(binary, inp)
        mutant = run(binary, inp, (pc, before, after))
        assert mutant["patch_hits"] == [pc] and not mutant["source_assertions"]
        if inp["path"] == "lifetime":
            assert (
                original["steps"][-2]["derived"] + 1 == mutant["steps"][-2]["derived"]
            )
            assert (
                original["steps"][-2]["state"] == 4
                and mutant["steps"][-2]["state"] == 5
            )
        elif inp["path"] == "routing":
            assert (
                original["result"] == 0
                and mutant["result"] == 1
                and mutant["steps"][-1]["derived"] == 1
            )
        else:
            assert original["steps"][-1]["messages"][-1]["body"] == "0807"
            assert mutant["steps"][-1]["messages"][-1]["body"] == "0800"
        negatives.append(
            dict(
                site=pc,
                before=before,
                after=after,
                original=original,
                mutant=mutant,
            )
        )
    report = dict(
        binary_sha256=sha,
        scope=__doc__,
        cases=cases,
        negative=negatives,
        functions=m.e.p.m.inventory(binary, cases),
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
        f"Official authorization lifetime: {len(cases)} cases, three normal-return instruction negatives",
        flush=True,
    )


if __name__ == "__main__":
    main()
