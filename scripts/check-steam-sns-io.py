#!/usr/bin/env python3
"""Compare production SNS policies + actual IHS Socket send to frozen original."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SHA = '50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e'
FIXTURE_SHA = 'bcabe45b4a3a467f5708f3cd4979720295a540870cab66b6510dec77513a03fd'


def main():
    if not __debug__:
        raise RuntimeError('comparison requires assertions')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--receiver', type=Path, required=True)
    p.add_argument('--reference', type=Path,
        default=ROOT / 'scripts/fixtures/steam-sns-io-reference.json.gz')
    args = p.parse_args()
    raw = args.reference.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == FIXTURE_SHA, 'unfrozen fixture'
    r = json.loads(gzip.decompress(raw))
    assert r['schema'] == 1 and r['sample_sha256'] == SHA
    for name, want in r['helper_sha256'].items():
        assert hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest() == want, name
    assert (len(r['sends']), len(r['mtus']), len(r['releases'])) == (20, 160, 30)
    lines, expected = [], []
    for index, c in enumerate(r['sends']):
        v = c['initial']
        lines.append(f"S {v['state']} {v['handle']} {int(c['crc'])} {len(c['actions'])}")
        for step, (action, result) in enumerate(zip(c['actions'], c['results'], strict=True)):
            lines.append(' '.join(str(action[k]) for k in ('sdk_result', 'now', 'kind', 'size')))
            expected.append((f'send-{index}-{step}', result))
    for index, c in enumerate(r['mtus']):
        v = c['input']
        lines.append('M ' + ' '.join(str(int(v[k])) for k in
            ('handle', 'mtu', 'set_ok', 'get_result', 'value', 'out_size')))
        expected.append((f'mtu-{index}', c['result']))
    for index, c in enumerate(r['releases']):
        v = c['input']
        if v['refs'] != 1: continue # Port owner destruction, not natural refcount implementation.
        lines.append(f"R {v['state']} {v['handle']}")
        expected.append((f'destroy-{index}', c['result']))
    child = subprocess.run([str(args.receiver.resolve())], input='\n'.join(lines)+'\n',
        capture_output=True, text=True, timeout=25)
    assert child.returncode == 0, (child.returncode, child.stderr[-3000:])
    observed = [json.loads(line) for line in child.stdout.splitlines()]
    assert len(observed) == len(expected), (len(observed), len(expected))
    for (name, want), got in zip(expected, observed, strict=True):
        assert got == want, (name, want, got)
    # Positive collector evidence prevents an accidentally disabled stats adapter
    # making comparisons vacuous. Busy/fail leave prior totals/deadlines alone.
    assert any(result['sent_bytes'] > 0 for c in r['sends'] for result in c['results'])
    print(f'PASS SNS IO: {len(expected)} steps, original Socket->SNS/CRC/accounting, '
        'MTU set/query and final Release close; SDK outcomes are controlled')


if __name__ == '__main__':
    main()
