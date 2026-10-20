#!/usr/bin/env python3
"""Official invalid streaming credentials during same-owner authorization.

Extends §132's providers and original flow with §120's bad-padding body, through
original response parser/handler/crypto/Stop and late authorization handler.
No Native implementation, full BProcess/OS admission, natural identity/entropy,
Qt pixels, filesystem durability or Steam/Switch execution is inferred.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "automatic", ROOT / "scripts/audit-steam-auto-authorization.py"
)
automatic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(automatic)
REFERENCE = ROOT / "scripts/fixtures/steam-auto-authorization-errors-reference.json.gz"


def run(binary, testing):
    r = automatic.Automatic(binary, dict(test=testing))
    r.b(automatic.PANEL + 0xD4, int(testing))
    r.call(r.symbols[automatic.START], automatic.PANEL)
    steps = [r.observe("requested")]
    r.response(1)
    r.update()
    steps.append(r.observe("authorization"))
    ref = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-network-test-discovery-reference.json.gz"
            ).read_bytes()
        )
    )
    bad = next(
        c["response"] for c in ref["responses"] if c["input"]["name"] == "bad_padding"
    )
    obj, peer = r.alloc(512), r.alloc(24)
    r.u.mem_write(peer, bytes(range(1, 25)))
    assert r.parse(obj, bytes.fromhex(bad), "CMsgRemoteDeviceStreamingResponse")
    r.call(
        r.symbols[
            "_ZN14CServerManager28HandleStartStreamingResponseERK10CIPAndPortyPK33CMsgRemoteDeviceStreamingResponse"
        ],
        r.manager,
        peer,
        123,
        obj,
    )
    steps.append(r.observe("invalid_credentials"))
    r.answer()
    steps.append(r.observe("late_key"))
    assert not r.assertions
    assert (
        steps[-2]["state"] == 1 and steps[-2]["rid"] == 0 and steps[-2]["errors"] == [1]
    )
    assert [m["tag"] for m in steps[-2]["messages"]] == [5, 3, 9]
    assert (
        steps[-1]["messages"][-1]["tag"] == 14
        and steps[-1]["messages"][-1]["body"] == "0808"
    )
    assert all(s["derived"] == 0 and s["keypair_generations"] == 1 for s in steps)
    return dict(
        input=dict(test=testing, path="invalid_credentials_while_authorizing"),
        events=r.events,
        steps=steps,
        source_assertions=r.assertions,
        executed=sorted(r.executed),
    )


def main():
    if not __debug__:
        raise SystemExit("Assertions required")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    binary = a.binary.read_bytes()
    sha = automatic.life.m.e.p.m.discovery.lifecycle.media.flow.SHA
    assert hashlib.sha256(binary).hexdigest() == sha
    cases = [run(binary, t) for t in (False, True)]
    report = dict(
        binary_sha256=sha,
        scope=__doc__,
        cases=cases,
        functions=automatic.life.m.e.p.m.inventory(binary, cases),
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
        "Official invalid credentials while authorizing: two assertion-free original flows, cancel9 then late-key Canceled"
    )


if __name__ == "__main__":
    main()
