#!/usr/bin/env python3
"""Execute official BProcess and authorization crypto before target admission.

Pinned shell instructions parse complete discovery frames and run key exchange,
cache, target checks, confirms/cancels and stream resumption. Prior lifetime/UI
providers still supply identity/entropy, request RSA, time, Qt, storage syscalls,
persistent client metadata and final send. No OS network, Steam or Switch runs.
SteamID-list promotion/subscription and durable client metadata are not projected
onto Native by this comparison; key-save identity/order and crypto are compared.
"""
import argparse
import ast
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "producer", ROOT / "scripts/audit-steam-device-token.py")
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)
life = producer.life
SHA = "15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2"
REFERENCE = ROOT / "scripts/fixtures/steam-authorization-admission-reference.json.gz"
ACCOUNT = 76561198000000001
SEND = "_ZN14CServerManager11SendMessageE25ERemoteClientBroadcastMsgPN6google8protobuf7MessageE10CIPAndPorty"


class Admission(producer.Token):
    def __init__(self, binary, inp):
        self.send_states, self.persist_states = [], []
        super().__init__(binary, inp)

    def boundary(self):
        return dict(state=self.i(self.manager + 8), rid=self.i(self.manager + 512),
                    cache=bytes(self.u.mem_read(self.q(self.manager + 0x2D8),
                                               self.i(self.manager + 0x2EC))).hex(),
                    cached_result=self.i(self.manager + 0x318), failures=len(self.errors))

    def hook(self, u, pc, size, data):
        if self.plts.get(pc) == SEND:
            self.send_states.append(dict(tag=self.r(1), **self.boundary()))
        if self.plts.get(pc) == life.m.SAVE:
            self.persist_states.append(self.boundary())
        super().hook(u, pc, size, data)

    def observe(self, label):
        row = super().observe(label)
        row["send_states"] = list(self.send_states)
        row["persist_states"] = list(self.persist_states)
        return row


def helpers():
    pending = [Path(__file__).name]
    hashes = {}
    while pending:
        name = pending.pop()
        if name in hashes:
            continue
        path = ROOT / "scripts" / name
        data = path.read_bytes()
        hashes[name] = hashlib.sha256(data).hexdigest()
        for node in ast.walk(ast.parse(data)):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                dependency = Path(node.value).name
                if (dependency.startswith("audit-steam-") and dependency.endswith(".py")
                        and (ROOT / "scripts" / dependency).is_file()):
                    pending.append(dependency)
    return dict(sorted(hashes.items()))


def packet(event):
    v = life.m.e.p.m.discovery.varint
    body = b"\x08" + v(event.get("result", 0))
    body += b"\x11" + struct.pack("<Q", ACCOUNT)
    if event.get("key", False):
        key, token, _ = life.m.e.material(
            index=event.get("index", 0),
            token_device=life.m.e.DID + int(event.get("invalid", False)))
        if event.get("empty", False):
            key = b""
        body += b"\x1a" + v(len(key)) + key + b"\x22" + v(len(token)) + token
    client = event.get("client", 456)
    header = b"\x08" + v(client) + b"\x10\x04"
    wire = b"\xff" * 4 + b"\x21\x4c\x5f\xa0"
    return wire + struct.pack("<I", len(header)) + header + struct.pack("<I", len(body)) + body


def inputs():
    paths = [
        ("foreign_valid", [dict(key=True)]),
        ("foreign_invalid", [dict(key=True, invalid=True)]),
        ("foreign_cached_then_target", [dict(key=True), dict(key=True),
                                         dict(key=True, client=123)]),
        ("foreign_then_target_new", [dict(key=True), dict(key=True, client=123, index=1)]),
        ("target_then_foreign", [dict(key=True, client=123), dict(key=True, index=1)]),
        ("cancel_then_foreign", [dict(cancel=True), dict(key=True)]),
        ("foreign_exhaustion", [dict(key=True, invalid=True, index=i) for i in range(4)]),
        ("foreign_empty_key", [dict(key=True, empty=True)]),
        ("target_empty_key", [dict(key=True, empty=True, client=123)]),
        ("zero_identity", [dict(key=True, client=0)]),
    ]
    paths += [(f"foreign_result_{result}_{int(key)}", [dict(result=result, key=key)])
              for result in range(9) for key in (False, True)]
    paths += [(f"target_result_{result}", [dict(client=123, result=result, key=True)])
              for result in range(1, 9)]
    return [dict(name=name, events=events, test=testing)
            for testing in (False, True) for name, events in paths]


def run(binary, inp):
    r = Admission(binary, dict(pin="9876", test=inp["test"]))
    r.begin(inp["test"])
    steps, packets = [r.observe("authorization")], []
    for index, event in enumerate(inp["events"]):
        if event.get("cancel"):
            r.call(r.symbols[life.STOP], life.m.PANEL)
            packets.append(None)
        else:
            wire = packet(event)
            buf, pointer, peer = r.alloc(128), r.alloc(len(wire)), r.alloc(24)
            r.u.mem_write(pointer, wire)
            r.u.mem_write(peer, bytes(range(1, 25)))
            r.call(r.symbols["_ZN10CUtlBufferC1Ev"], buf)
            r.call(r.symbols["_ZN10CUtlBuffer3PutEPKvi"], buf, pointer, len(wire))
            result = r.call(r.symbols[life.PROCESS], r.manager, peer, buf, 0)
            packets.append(dict(wire=wire.hex(), result=result))
        steps.append(r.observe(str(index)))
    assert not r.assertions
    return dict(input=inp, packets=packets, steps=steps, source_assertions=r.assertions,
                executed=sorted(r.executed))


def verify(case):
    name = case["input"]["name"]
    last = case["steps"][-1]
    confirms = [row["body"] for row in last["messages"] if row["tag"] == 14]
    saved = [row for row in last["timeline"] if row["op"] == "save_key"]
    assert case["steps"][0]["state"] == 4 and case["steps"][0]["rid"] == 17
    assert len(last["send_states"]) == len(last["messages"])
    if name == "foreign_valid":
        assert last["state"] == 4 and last["derived"] == 1
        assert confirms == ["0800", "0808"] and [row["client"] for row in saved] == [456]
    elif name == "foreign_invalid":
        assert last["state"] == 4 and last["derived"] == 1 and not saved
        assert confirms == ["0801"]
    elif name == "foreign_cached_then_target":
        assert last["state"] == 4 and last["derived"] == 1 and len(saved) == 1
        assert confirms == ["0800", "0808", "0800", "0800"]
    elif name == "foreign_then_target_new":
        assert last["state"] == 5 and last["derived"] == 2
        assert [row["client"] for row in saved] == [456, 123]
        assert confirms == ["0800", "0808", "0800"]
    elif name == "target_then_foreign":
        assert last["state"] == 5 and last["derived"] == 1
        assert [row["client"] for row in saved] == [123] and confirms == ["0800", "0808"]
    elif name == "cancel_then_foreign":
        assert last["state"] == 1 and not last["derived"] and confirms == ["0808"]
    elif name == "foreign_exhaustion":
        assert last["state"] == 1 and last["derived"] == 3 and last["attempts"] == 4
        assert confirms == ["0801"] * 4 and not saved
        assert [row["tag"] for row in last["messages"]][-2:] == [9, 14]
        cancel, confirm = last["send_states"][-2:]
        assert cancel["state"] == 4 and cancel["rid"] == 17 and cancel["failures"] == 1
        assert confirm["state"] == 1 and confirm["rid"] == 0 and confirm["failures"] == 1
        assert cancel["cache"] != confirm["cache"]
    elif name.endswith("empty_key"):
        assert last["state"] == 4 and not last["derived"] and confirms == ["0807"]
    elif name == "zero_identity":
        assert last["state"] == 4 and not last["derived"] and not confirms
        assert case["packets"][0]["result"] == 0
    elif name.startswith("foreign_result_"):
        event = case["input"]["events"][0]
        assert last["state"] == 4
        if event["result"] == 0 and event["key"]:
            assert confirms == ["0800", "0808"] and last["derived"] == 1
        else:
            assert confirms == (["0808"] if event["key"] else []) and not last["derived"]
    else:
        assert name.startswith("target_result_")
        event = case["input"]["events"][0]
        assert last["state"] == (4 if event["result"] == 5 else 1)
        assert not last["derived"] and not confirms


def main():
    if not __debug__:
        raise SystemExit("Original comparison requires assertions; do not use Python -O")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--refresh-reference", action="store_true")
    args = parser.parse_args()
    binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == SHA
    cases = []
    for inp in inputs():
        case = run(binary, inp)
        verify(case)
        cases.append(case)
        print(inp["name"], inp["test"], "verified", flush=True)
    result = dict(schema=1, binary_sha256=SHA, scope=__doc__, helpers=helpers(), cases=cases)
    wire = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    args.output.write_bytes(gzip.compress(wire, mtime=0))
    if args.refresh_reference:
        REFERENCE.write_bytes(gzip.compress(wire, mtime=0))
    else:
        assert result == json.loads(gzip.decompress(REFERENCE.read_bytes()))
    print(f"PASS {len(cases)} complete original authorization admission traces")


if __name__ == "__main__":
    main()
