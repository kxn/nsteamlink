#!/usr/bin/env python3
"""Compare the production SNS connection policy to original-instruction traces."""
import argparse
import gzip
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SHA = '50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--receiver', required=True, type=Path)
    p.add_argument('--reference', type=Path,
        default=ROOT / 'scripts/fixtures/steam-sns-state-reference.json.gz')
    args = p.parse_args()
    opener = gzip.open if args.reference.suffix == '.gz' else open
    with opener(args.reference, 'rt') as f:
        reference = json.load(f)
    assert reference['schema'] == 1 and reference['sample_sha256'] == SHA
    programs = reference['cases']
    wire = [str(len(programs))]
    expected = []
    for c in programs:
        v = c['initial']
        wire.append(f"{v['state']} {v['handle']} {v['last_check']} {len(c['actions'])}")
        assert len(c['actions']) == len(c['results'])
        for index, (a, want) in enumerate(zip(c['actions'], c['results'])):
            wire.append(f"{a['now']} {int(a['info_ok'])} {a['sdk_state']} {int(a['quick_ok'])}")
            expected.append((c['name'], index, want))
    result = subprocess.run([str(args.receiver.resolve())], input='\n'.join(wire)+'\n',
        text=True, capture_output=True, timeout=20)
    assert result.returncode == 0, (result.returncode, result.stderr[-2000:])
    observed = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(observed) == len(expected), (len(observed), len(expected))
    for (name, step, want), got in zip(expected, observed):
        assert got == want, (name, step, want, got)
    print(f'PASS SNS state: {len(programs)} original programs/{len(expected)} steps; '
          'SDK calls, handle, signaling unlink, state and exact microsecond deadline')


if __name__ == '__main__':
    main()
