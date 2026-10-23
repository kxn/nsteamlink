#!/usr/bin/env python3
"""Compare actual authenticated channel/backend with original SDR signal/state."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_SHA = 'a97074942180da94d5d88b4ca886264a80379b56b8231203260fd0c5e27c423d'


def main():
    if not __debug__: raise RuntimeError('comparison requires assertions')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--receiver', type=Path, required=True)
    p.add_argument('--reference', type=Path,
        default=ROOT/'scripts/fixtures/steam-sns-signal-state-reference.json.gz')
    args = p.parse_args(); raw = args.reference.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == FIXTURE_SHA, 'unfrozen fixture'
    r = json.loads(gzip.decompress(raw))
    assert r['schema'] == 1 and r['sample_sha256'] == '50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e'
    for name, sha in r['helper_sha256'].items():
        assert hashlib.sha256((ROOT/'scripts'/name).read_bytes()).hexdigest() == sha, name
    # Native async BInit has its own earlier source/native gate. Here the
    # production signal channel exists only after SDK/config initialization.
    # Do not model original state 0 creation or SDK-null as native equivalence.
    cases = [c for c in r['cases'] if c['initial']['sdk'] and c['initial']['state'] != 0]
    assert len(r['cases']) == 57 and len(cases) == 52
    wire, expected = [str(len(cases))], []
    for c in cases:
        i = c['initial']; wire.append(f"{i['state']} {i['handle']} {i['last_check']} {len(c['actions'])}")
        for n, (a, want) in enumerate(zip(c['actions'], c['results'], strict=True)):
            wire.append(f"{a['now']} {int(a['info_ok'])} {a['status_result']} {a['sdk_state']} {len(a['signals'])}")
            for s in a['signals']: wire.append(f"{s['bytes'] or '-'} {int(s['ok'])} {s['sdk_state']}")
            expected.append((c['name'], n, want))
    result = subprocess.run([str(args.receiver.resolve())], input='\n'.join(wire)+'\n',
        text=True, capture_output=True, timeout=15)
    assert result.returncode == 0, (result.returncode, result.stderr[-3000:])
    observed = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(observed) == len(expected) == 53
    for (name, n, want), got in zip(expected, observed, strict=True):
        assert want == got, (name, n, want, got)
    print('PASS SNS signal/state: 57 original programs/58 cycles; production authenticated '
          'channel/backend compares 52 programs/53 cycles after initialization; no handle guard, '
          'close before Failed and same-message state update')


if __name__ == '__main__': main()
