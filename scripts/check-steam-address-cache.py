#!/usr/bin/env python3
"""Compare production address add/clear/get/sort to pinned original instructions."""
import argparse
import gzip
import json
from pathlib import Path
import subprocess

if not __debug__:
    raise SystemExit('Original-output comparison requires assertions; do not use Python -O')

ROOT = Path(__file__).resolve().parents[1]


def row(r, now=None):
    return f"{r['ip']} {r['port']} {int(r['verified'])} {int(r['remote'])} {r['time'] if now is None else now}"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--receiver', required=True, type=Path)
    p.add_argument('--reference', type=Path,
        default=ROOT/'scripts/fixtures/steam-address-cache-reference.json.gz')
    args = p.parse_args()
    with gzip.open(args.reference, 'rt') as f:
        reference = json.load(f)
    assert reference['schema'] == 2
    assert reference['sample_sha256'] == '50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e'
    cases = reference['cases']
    wire, expected = [str(len(cases))], []
    for c in cases:
        assert len(c['actions']) == len(c['results']), c['name']
        wire.append(f"{len(c['initial'])} {len(c['actions'])}")
        wire.extend(row(r) for r in c['initial'])
        for step, (a, want) in enumerate(zip(c['actions'], c['results'])):
            if a['kind'] == 'add': wire.append('0 '+row(a, a['now']))
            elif a['kind'] == 'clear': wire.append('1')
            else: wire.append('2 '+str(a.get('depth', -1)))
            expected.append((c['name'], step, want))
    result = subprocess.run([str(args.receiver.resolve())], input='\n'.join(wire)+'\n',
        text=True, capture_output=True, timeout=25)
    assert result.returncode == 0, (result.returncode, result.stderr[-2500:])
    observed = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(observed) == len(expected), (len(observed), len(expected))
    for (name, step, want), got in zip(expected, observed):
        assert got == want, (name, step, want, got)
    predicates = reference['has_ip']
    result = subprocess.run([str(args.receiver.resolve()), 'has-ip'],
        input='\n'.join(r['ip'] for r in predicates)+'\n', text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert [int(v) for v in result.stdout.splitlines()] == [int(r['result']) for r in predicates]
    print(f'PASS address cache: {len(cases)} original programs/{len(expected)} steps and {len(predicates)} HasIP inputs, including full sort and IP helpers')


if __name__ == '__main__':
    main()
