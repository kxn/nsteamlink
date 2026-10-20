#!/usr/bin/env python3
"""Compare production cloud control/signal framing with complete original sends.

Other original manager startup/socket/session cases are retained as evidence,
not claimed as native coverage. The actual IHS sender covers address-less cloud,
explicit UDP, current verified cache and incomplete explicit source resolution.
Shared transaction/key behavior is exercised separately by control_route_runtime;
neither harness establishes real NAT traversal or SDK network behavior.
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
        routed = subprocess.run([str(args.receiver), 'ihs', str(case['input'].get('type', 0))],
                                capture_output=True, text=True, check=True).stdout.strip()
        assert routed == observed, ('IHS '+case['name'], routed)
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
    cases = {c['name']:c for c in reference['cases']}
    for mode, name in [('ihs-direct','explicit'),('ihs-cache','cache'),
                       ('ihs-incomplete-source','partial_explicit_port')]:
        observed = subprocess.run([str(args.receiver), mode, '0'], capture_output=True,
                                  text=True, check=True).stdout.strip()
        assert observed == cases[name]['output']['udp'][0]['wire'], (name, observed)
    print(f'PASS {checked} manager + {checked} IHS frames, 3 IHS UDP routes, bridge send + {len(reference["receives"])} receives')


if __name__ == '__main__':
    main()
