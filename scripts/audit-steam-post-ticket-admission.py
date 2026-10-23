#!/usr/bin/env python3
"""Original success/Unauthorized -> auth+fresh ticket batches -> Panel consumer.

Actual manager/CM/UDP, auth key exchange/AES and Panel/token handoff execute.
Independent fixture X25519 computes the fresh encrypted ticket key. Qt, request
RSA/identity/entropy/clock, final sends and launch/thread endpoints are providers.
The two controlled receive batches are not a natural Steam/Qt/SDR timing claim.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('reauth_admission', ROOT / 'scripts/audit-steam-post-ticket-authorization.py')
reauth = importlib.util.module_from_spec(spec); spec.loader.exec_module(reauth)
ticket = reauth.ticket


def main():
    if not __debug__: raise RuntimeError('audit requires assertions')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args(); binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == ticket.rpc.service.m.SHELL_SHA
    cases = []
    for testing in (False, True):
        for transport in (1, 4):
            for key in (False, True):
                r = ticket.TicketConsumer(binary, testing); ticket.rpc.bootstrap(r, 'stream')
                batches = []

                def update(wires):
                    cm = [ticket.cm(w) for w in wires] if transport == 4 else []
                    udp = wires if transport == 1 else []
                    batches.append(dict(cm=[w.hex() for w in cm], udp=[w.hex() for w in udp]))
                    r.update_mixed(cm, udp); r.call(r.symbols[ticket.UPDATE], ticket.PANEL)
                    return r.result()

                before = update([ticket.streaming(transport=transport), ticket.streaming(result=1, transport=transport)])
                assert before['state'] == 4 and before['panel'] == 3 and before['launches'] == 0
                secret = ticket.rpc.service.m.admission.life.m.e.material()[2] if key else bytes(range(32, 64))
                auth = ticket.rpc.service.packet(dict(client=123, key=key, key_pin='0042'), '0042')
                after = update([auth, reauth.streaming(secret, transport)])
                assert after['state'] == 6 and after['launches'] == 1 and not r.assertions
                if testing: assert after['tokens'] == [reauth.NEW_KEY.hex()]
                cases.append(dict(testing=testing, transport=transport, key=key, batches=batches,
                    before=before, after=after, executed=sorted(r.executed), source_assertions=r.assertions))
    old = (ROOT / 'scripts/fixtures/steam-post-ticket-authorization-reference.json.gz').read_bytes()
    assert hashlib.sha256(old).hexdigest() == 'b9f3ede81f32df194efd0dcaabd2091448df99f895e793eb1938de6b1814d986'
    helpers = json.loads(gzip.decompress(old))['helper_sha256']
    helpers[Path(__file__).name] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report = dict(schema=1, sample_sha256=ticket.rpc.service.m.SHELL_SHA, scope=__doc__,
                  helper_sha256=dict(sorted(helpers.items())), cases=cases)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(report, sort_keys=True, indent=2)+'\n').encode()
    args.output.write_bytes(gzip.compress(raw, mtime=0) if args.output.suffix == '.gz' else raw)
    print('PASS 8 original post-ticket auth/admission programs; old ticket revoked, fresh ticket consumed once')


if __name__ == '__main__': main()
