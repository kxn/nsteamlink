#!/usr/bin/env python3
"""Compare production SDK drain/RX callbacks and actual IHS receiveCycle."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SHA = '50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e'
SHELL_SHA = '15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2'
FIXTURE_SHA = 'b6d03409c37da9af951e8f4f392dc6bbad5bb497a5c05da50bcc68bdf723fd3f'


def main():
    if not __debug__: raise RuntimeError('comparison requires assertions')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--receiver', type=Path, required=True)
    p.add_argument('--reference', type=Path,
        default=ROOT/'scripts/fixtures/steam-sns-receive-reference.json.gz')
    args = p.parse_args()
    raw = args.reference.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == FIXTURE_SHA, 'unfrozen fixture'
    r = json.loads(gzip.decompress(raw))
    assert r['schema'] == 1 and r['sample_sha256'] == SHA
    for name, sha in r['helper_sha256'].items():
        assert hashlib.sha256((ROOT/'scripts'/name).read_bytes()).hexdigest() == sha, name
    assert [i['sample_sha256'] for i in r['mtu_inventory']] == [SHA, SHELL_SHA]
    for i in r['mtu_inventory']:
        assert i['target'] and not i['direct_branches'] and not i['dynamic_relocations']
        assert all('SetMaximumMTU' not in v['symbol'] for v in i['transport_vtable'])
    cases = r['cases']
    assert len(cases) == 52
    wire, expected = [str(len(cases))], []
    for c in cases:
        wire.append(f"{c['state']} {c['handle']} {len(c['actions'])}")
        for step, (a, want) in enumerate(zip(c['actions'], c['results'], strict=True)):
            wire.append(f"{a['wait_ms']} {a['now']} {len(a['batches'])} {len(a['lengths'])}")
            wire.append(' '.join(map(str, a['batches'])))
            wire.append(' '.join(map(str, a['lengths'])))
            expected.append((c['name'], step, want))
    result = subprocess.run([str(args.receiver.resolve())], input='\n'.join(wire)+'\n',
        text=True, capture_output=True, timeout=25)
    assert result.returncode == 0, (result.returncode, result.stderr[-3000:])
    observed = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(observed) == len(expected) == 60
    for (name, step, want), got in zip(expected, observed, strict=True):
        assert got == want, (name, step, want, got)
    print('PASS SNS receive: 52 original programs/60 cycles, real queue/Recv/Socket caller vs '
        'production RX callbacks/IHS receiveCycle; negative SDK counts preserve queued data/update')


if __name__ == '__main__': main()
