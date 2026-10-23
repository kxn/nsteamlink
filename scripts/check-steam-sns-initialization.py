#!/usr/bin/env python3
"""Compare async config/bridge admission with original BConnect's BInit gate.

Actual product owner, HTTP handles, SDK certificate rejection, bridge factory
and cleanup execute. HTTP completions/trust import/bridge IO are providers.
The successful BInit stage is an explicit provider, not an accepted SDK cert.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess

if not __debug__:
    raise SystemExit('Original comparison requires assertions')

ROOT = Path(__file__).resolve().parents[1]

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--receiver', type=Path, required=True)
    a = p.parse_args()
    raw = (ROOT/'scripts/fixtures/steam-sns-client-call-reference.json.gz').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == 'ba7d0f4c76a119142a0728c1488bacdf0384f4b1291a2d2d59112488a25d6792'
    r = json.loads(gzip.decompress(raw))
    for name, sha in r['helpers'].items():
        assert hashlib.sha256((ROOT/'scripts'/name).read_bytes()).hexdigest() == sha, name
    expected = {binit: next(c for c in r['cases'] if c['input']['binit'] == binit)['observed']['before']['events'].count('bridge-create') for binit in [False, True]}
    assert expected == {False: 0, True: 1}
    modes = ['hold', 'config-failure', 'invalid-config', 'bad-cert', 'ready', 'bridge-failure']
    for mode in modes:
        run = subprocess.run([str(a.receiver.resolve()), mode], text=True, capture_output=True, timeout=8)
        assert run.returncode == 0, (mode, run.returncode, run.stderr)
        rows = [json.loads(s) for s in run.stdout.splitlines()]
        assert len(rows) == 2
        for row in rows:
            assert row['clean'] and row['creates'] == row['destroys'], (mode, row)
            assert not row['before_attempts'] and not row['before_activations'] and not row['before_ready'], (mode, row)
            admitted = mode in ['ready', 'bridge-failure']
            assert row['attempts'] == expected[admitted], (mode, row)
            assert row['creates'] == row['activations'] == int(mode == 'ready'), (mode, row)
            assert row['ready'] == (mode == 'ready'), (mode, row)
            assert row['state'] == (1 if mode in ['hold', 'ready'] else 3), (mode, row)
            assert row['config_attempts'] == (3 if mode in ['config-failure', 'invalid-config'] else 1), (mode, row)
            assert row['terminal'] == {'hold': 0, 'ready': 0, 'config-failure': 4, 'invalid-config': 4, 'bad-cert': 2, 'bridge-failure': 13}[mode], (mode, row)
    print('PASS 6 initialization programs, 2 consecutive owners each: original BInit gate, no early bridge/CM, real SDK certificate failure, deferred material lifetime, bridge allocation failure and balanced cleanup')

if __name__ == '__main__':
    main()
