#!/usr/bin/env python3
"""Compare old-ticket withdrawal and fresh ticket admission through the actor.

Actual product actor, RPC/IHS parsers and authorization crypto run. SDK creation
and IHS Session construction are observed endpoints (the latter returns NULL),
not media/SDK execution. Clock/identity/entropy and receive/send IO are providers.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SHA = 'ca8cba8ef670f30f11255670be8e5958803b4277bb490721ccd04d452f492949'


def main():
    if not __debug__: raise RuntimeError('comparison requires assertions')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--receiver', type=Path, required=True)
    p.add_argument('--without-sns', action='store_true')
    p.add_argument('--observations', type=Path)
    args = p.parse_args()
    raw = (ROOT / 'scripts/fixtures/steam-post-ticket-admission-reference.json.gz').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SHA
    r = json.loads(gzip.decompress(raw))
    assert r['schema'] == 1 and r['sample_sha256'] == '15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2'
    for name, sha in r['helper_sha256'].items():
        assert hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest() == sha, name
    assert len(r['cases']) == 8
    seen = set(); differences = []; observations = []
    for c in r['cases']:
        seen.add((c['testing'], c['transport'], c['key']))
        assert not c['source_assertions']
        assert c['before']['state'] == 4 and c['before']['panel'] == 3 and c['before']['launches'] == 0
        assert c['after']['state'] == 6 and c['after']['launches'] == 1
        if c['testing']: assert c['after']['tokens'] == [bytes(range(128, 160)).hex()]
        if args.without_sns and c['transport'] == 4: continue
        lines = [(';'.join(b['cm']) or '-')+' '+(';'.join(b['udp']) or '-') for b in c['batches']]
        run = subprocess.run([str(args.receiver.resolve()), str(int(c['testing'])), '10', '0'],
                             input='\n'.join(lines)+'\n', text=True, capture_output=True, timeout=10)
        label = (c['testing'], c['transport'], c['key'])
        assert run.returncode == 0, (label, run.returncode, run.stderr[-3000:])
        got = json.loads(run.stdout.splitlines()[-1])
        want = dict(before_state=4, before_sessions=0, before_backends=0, admission_state=6,
                    sessions=1, backends=int(c['transport'] == 4), key_ok=True, clean=True)
        if got != want: differences.append(dict(case=label, got=got, want=want))
        observations.append(dict(case=label, actual=got))
    assert seen == {(t, tr, k) for t in (False, True) for tr in (1, 4) for k in (False, True)}
    if args.observations: args.observations.write_text(json.dumps(observations, indent=2)+'\n')
    assert not differences, differences
    print(f'PASS 8 original post-ticket admission programs and {len(observations)} product actor '
          'lifetimes; no withdrawn-ticket constructor, one fresh key/backend admission')


if __name__ == '__main__': main()
