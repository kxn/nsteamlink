#!/usr/bin/env python3
"""Compare post-ticket authorization with real native RPC/IHS request owners.

Native runs parsers/crypto/timers/runtime callbacks but does not create media or
a Test worker. Original Panel admission/active Test is observed separately; Qt
and thread endpoints are providers. This does not claim Steam/TLS/SDK/Switch.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('post_ticket_fields', ROOT / 'scripts/check-steam-service-pairing.py')
service = importlib.util.module_from_spec(spec); spec.loader.exec_module(service)
SHA = 'b9f3ede81f32df194efd0dcaabd2091448df99f895e793eb1938de6b1814d986'


def decrypt_pin(cipher, secret):
    d = Cipher(algorithms.AES(secret), modes.ECB()).decryptor()
    iv = d.update(cipher[:16]) + d.finalize()
    d = Cipher(algorithms.AES(secret), modes.CBC(iv)).decryptor()
    plain = d.update(cipher[16:]) + d.finalize()
    padding = plain[-1]
    assert 1 <= padding <= 16 and plain[-padding:] == bytes([padding])*padding
    return plain[:-padding]


def reference():
    raw = (ROOT / 'scripts/fixtures/steam-post-ticket-authorization-reference.json.gz').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SHA
    r = json.loads(gzip.decompress(raw))
    assert r['schema'] == 1 and r['sample_sha256'] == '15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2'
    for name, sha in r['helper_sha256'].items():
        assert hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest() == sha, name
    assert len(r['cases']) == 40
    seen = set()
    for c in r['cases']:
        seen.add((c['testing'], c['transport'], c['schedule'], c['outcome']))
        assert not c['source_assertions']
        auth = c['rows'][c['auth_index']]
        assert auth['control']['state'] == 4 and auth['control']['rid'] == 17
        assert auth['panel']['panel'] == (5 if c['schedule'] == 'active_test' else 3)
        assert auth['panel']['launches'] == int(c['schedule'] == 'active_test')
        reply = c['rows'][c['reply_index']]['control']
        assert reply['state'] == (4 if c['outcome'] == 'progress' else 1 if c['outcome'] == 'denied' else 5)
        if c['outcome'] in ('compat', 'key'):
            end = c['rows'][-1]
            assert end['control']['state'] == 6 and end['control']['rid'] == 17
            assert end['panel']['launches'] == 1
            if c['testing']:
                assert end['panel']['tokens'] == [bytes(range(32) if c['schedule'] == 'active_test' else range(128, 160)).hex()]
    assert seen == {(t, tr, schedule, o) for t in (False, True) for tr in (1, 4)
                    for schedule in (('same_update', 'split_updates', 'active_test') if t else ('same_update', 'split_updates'))
                    for o in ('compat', 'key', 'progress', 'denied')}
    return r


def main():
    if not __debug__: raise RuntimeError('comparison requires assertions')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--receiver', type=Path, required=True)
    p.add_argument('--observations', type=Path)
    args = p.parse_args(); report = reference(); differences = []; observations = []
    for c in report['cases']:
        commands = [('m '+(';'.join(op[1]) or '-')+' '+(';'.join(op[2]) or '-'))
                    if op[0] == 'mixed' else 'd '+str(op[1]) for op in c['commands']]
        run = subprocess.run([str(args.receiver.resolve()), 'reauth-test' if c['testing'] else 'reauth-stream', '1'],
                             input='\n'.join(commands)+'\n', text=True, capture_output=True, timeout=15)
        label = (c['testing'], c['transport'], c['schedule'], c['outcome'])
        assert run.returncode == 0, (label, run.returncode, run.stderr[-3000:])
        rows = [json.loads(line) for line in run.stdout.splitlines() if line.startswith('{')]
        assert len(rows) == len(c['rows'])+1
        errors = []
        native_pin = service.fields(rows[0]['controls'][0]['body'])[8]
        original_pin = service.fields(c['initial']['control']['messages'][0]['body'])[8]
        initial_secret = bytes.fromhex(c['initial']['control']['secret'])
        # IV randomness need not match across implementations. The original
        # request's ciphertext must be reused, even after authorization rekeys.
        assert decrypt_pin(native_pin, initial_secret) == decrypt_pin(original_pin, initial_secret) == b'9876'
        for step, (got, expected) in enumerate(zip(rows, [c['initial']]+c['rows'])):
            expected = expected['control']
            for k in ('state', 'rid', 'secret', 'target'):
                if got[k] != expected[k]: errors.append(dict(step=step, field=k, got=got[k], want=expected[k]))
            a, b = got['controls'], expected['messages']
            if [x['tag'] for x in a] != [x['tag'] for x in b]:
                errors.append(dict(step=step, field='tags', got=[x['tag'] for x in a], want=[x['tag'] for x in b])); continue
            for n, (native, original) in enumerate(zip(a, b)):
                nf, of = service.fields(native['body']), service.fields(original['body'])
                if native['tag'] == 5 and (nf.get(8) != native_pin or of.get(8) != original_pin):
                    errors.append(dict(step=step, field=f'message{n}_pin_cipher_reused'))
                fields = (1, 12) if native['tag'] == 5 else (2, 4, 5) if native['tag'] == 3 else None
                if fields is None:
                    if native['body'] != original['body']:
                        errors.append(dict(step=step, field=f'message{n}_body'))
                elif any(nf.get(k) != of.get(k) for k in fields):
                    errors.append(dict(step=step, field=f'message{n}_selected_fields', tag=native['tag']))
        if errors: differences.append(dict(case=label, differences=errors))
        observations.append(dict(case=label, rows=rows, differences=errors))
    if args.observations:
        args.observations.write_text(json.dumps(observations, indent=2)+'\n')
    assert not differences, differences
    print('PASS 40 original post-ticket manager/Panel programs and native RPC/IHS owners; '
          'same-ID authorization retries, key/no-key resume, progress/denial, cached security PIN')


if __name__ == '__main__': main()
