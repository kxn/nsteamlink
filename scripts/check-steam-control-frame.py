#!/usr/bin/env python3
"""Compare production cloud control/signal framing with complete original sends.

The other original manager route cases are retained as evidence, not claimed as
native coverage. Native manager sending has no complete explicit endpoint; shared
UDP/cloud transaction routing and caller key selection require separate tests.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess

if not __debug__:
    raise SystemExit('Original comparison requires assertions; do not use Python -O')

ROOT = Path(__file__).resolve().parents[1]
SHA = '50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--receiver', required=True, type=Path)
    p.add_argument('--reference', type=Path,
        default=ROOT/'scripts/fixtures/steam-control-route-reference.json.gz')
    args = p.parse_args()
    reference = json.loads(gzip.decompress(args.reference.read_bytes()))
    assert reference['schema'] == 1 and reference['original_sha256'] == SHA
    for name, digest in reference['helpers'].items():
        assert hashlib.sha256((ROOT/'scripts'/name).read_bytes()).hexdigest() == digest, name
    checked = 0
    for case in reference['cases']:
        if case['name'] != 'empty' and not case['name'].startswith('manager_type_'):
            continue
        observed = subprocess.run([str(args.receiver), 'manager', str(case['input'].get('type', 0))],
                                  capture_output=True, text=True, check=True).stdout.strip()
        assert observed == case['output']['cloud'][0]['wire'], (case['name'], observed)
        checked += 1
    signal = subprocess.run([str(args.receiver), 'signal'], capture_output=True,
                            text=True, check=True).stdout.strip()
    assert signal == reference['signal']['wire'], ('transport bridge', signal)
    for case in reference['receives']:
        received = subprocess.run([str(args.receiver), 'receive', case['wire']],
            capture_output=True, text=True, check=True)
        assert received.stdout.strip() == ''.join(case['output']['delivered']), (case['name'], received.stdout)
        assert int(received.stderr.strip()) == case['output']['result'], (case['name'], received.stderr)
    assert checked == 9
    print(f'PASS {checked} manager frames + separate transport send + {len(reference["receives"])} receives')


if __name__ == '__main__':
    main()
