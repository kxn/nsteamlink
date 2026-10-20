#!/usr/bin/env python3
"""Original LAN BProcess Proof admission and phase preservation.

CUtlBuffer, header/body parsers, full BProcess and Proof handler/crypto/save run.
Address comparison, selected identities, OS/Qt/SDL file endpoints and final
Send remain controlled providers. No natural peer admission/OS socket or real
Steam/Switch is proved. Empty-body assertion behavior is a separate boundary.
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
    "transaction", ROOT / "scripts/audit-steam-proof-transaction.py"
)
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
p = t.p
REFERENCE = ROOT / "scripts/fixtures/steam-proof-ingress-reference.json.gz"


def run(binary, kind, phase="streaming"):
    r = t.Trace(binary, {})
    r.call(r.symbols[p.life.START], p.life.m.PANEL)
    if phase in ("authorizing", "authorized"):
        r.response(1)
        if phase == "authorized":
            r.answer()
    elif phase == "ticket":
        r.credentials(bytes.fromhex(r.observe("key")["secret"]), 32)
    elif phase == "cancelled":
        r.stop()
    before = r.observe("before")
    varint = p.life.m.e.p.m.discovery.varint
    host = 456 if kind == "foreign" else 0 if kind == "zero" else 123
    body = (
        b"\x0a\x05hello"
        + (
            b""
            if kind == "absent_id"
            else b"\x10" + varint(18 if kind == "mismatch" else 17)
        )
        + b"\x18\x01"
    )
    if kind == "bad_body":
        body = b"\x80"
    elif kind == "missing_challenge":
        body = body[7:]
    elif kind == "empty_body":
        body = b""
    header = b"\x08" + varint(host) + b"\x10\x07"
    if kind == "bad_header":
        header = b"\x80"
    wire = b"\xff" * 4 + b"\x21\x4c\x5f\xa0" + struct.pack("<I", len(header)) + header
    wire += struct.pack("<I", len(body) + int(kind == "truncated")) + body
    if kind == "trailing":
        wire += b"\0"
    buf, src, peer = r.alloc(128), r.alloc(len(wire)), r.alloc(24)
    r.u.mem_write(src, wire)
    r.u.mem_write(peer, bytes(range(1, 25)))
    r.call(r.symbols["_ZN10CUtlBufferC1Ev"], buf)
    r.call(r.symbols["_ZN10CUtlBuffer3PutEPKvi"], buf, src, len(wire))
    r.wire_events.append(dict(kind="raw", wall=r.wall_time, wire=wire.hex()))
    r.proof_active = True
    result = r.call(r.symbols[p.life.PROCESS], r.manager, peer, buf, 0)
    r.proof_active = False
    after = r.observe("after")
    case = dict(
        input=dict(kind=kind, phase=phase),
        before=before,
        after=after,
        result=result,
        events=list(r.wire_events),
        source_assertions=r.assertions,
        executed=sorted(r.executed),
    )
    assert all(after[k] == before[k] for k in ("state", "rid", "next"))
    if kind == "empty_body":
        assert r.assertions == [93], r.assertions
        return case
    assert not r.assertions
    valid = kind in ("target", "foreign", "mismatch", "absent_id")
    assert result == int(valid)
    delta = after["proof_ops"][len(before["proof_ops"]) :]
    if not valid or kind == "mismatch":
        assert not delta and after["secret"] == before["secret"]
    elif kind == "foreign" or phase == "cancelled":
        assert delta == [dict(op="send", tag=8)]
        assert after["messages"][-1]["body"] == "0a00"
    else:
        assert [x["op"] for x in delta] == ["hash", "save", "encrypt", "send"]
        assert after["proof_updated"] == 1
        assert (
            after["secret"]
            == hashlib.sha256(bytes.fromhex(before["secret"]) + b"hello").hexdigest()
        )
        fields = p.token.fields(after["messages"][-1]["body"])
        assert fields[2] == before["rid"] and fields[3] == 1
        assert (
            p.token.decrypt(fields[1], bytes.fromhex(after["secret"])) == b"hello".hex()
        )
    return case


def main():
    if not __debug__:
        raise SystemExit("Assertions required")
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--binary", type=Path, required=True)
    args.add_argument("--output", type=Path, required=True)
    args.add_argument("--refresh-reference", action="store_true")
    a = args.parse_args()
    binary = a.binary.read_bytes()
    sha = p.life.m.e.p.m.discovery.lifecycle.media.flow.SHA
    assert hashlib.sha256(binary).hexdigest() == sha
    cases = [
        run(binary, kind)
        for kind in (
            "target",
            "foreign",
            "zero",
            "mismatch",
            "absent_id",
            "bad_header",
            "truncated",
            "trailing",
            "bad_body",
            "missing_challenge",
        )
    ]
    cases += [
        run(binary, "target", phase)
        for phase in ("authorizing", "authorized", "ticket", "cancelled")
    ]
    boundary = run(binary, "empty_body")
    report = dict(
        binary_sha256=sha,
        scope=__doc__,
        cases=cases,
        assertion_boundary=boundary,
        functions=p.life.m.e.p.m.inventory(binary, cases),
    )
    if a.refresh_reference and not REFERENCE.exists():
        REFERENCE.write_bytes(
            gzip.compress(json.dumps(report, sort_keys=True).encode(), mtime=0)
        )
    assert report == json.loads(gzip.decompress(REFERENCE.read_bytes()))
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        "Original Proof ingress: 14 assertion-free cases; empty-body assertion excluded"
    )


if __name__ == "__main__":
    main()
