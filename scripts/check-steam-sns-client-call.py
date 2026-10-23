#!/usr/bin/env python3
"""Compare original BInit/connection-wait caller with the product SNS worker.

Backend construction/config completion, application preparation readiness
(including its CM gate), state and transport IO are providers. This checks the
post-admission IHS deadline, not equivalence of the new preparation schedule.
The product worker creates real IHS threads and retries; clock freezing tests
the original deadline boundary without a wall-clock sleep or Steam host.
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
    args = p.parse_args()
    r = json.loads(gzip.decompress((ROOT/'scripts/fixtures/steam-sns-client-call-reference.json.gz').read_bytes()))
    assert r['schema'] == 1 and r['binary_sha256'] == '50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e'
    for name, sha in r['helpers'].items():
        assert hashlib.sha256((ROOT/'scripts'/name).read_bytes()).hexdigest() == sha, name
    assert sorted(s['address'] for s in r['static_backend_slots'].values()) == [0x7ffcd4, 0x7ffd30, 0x8011f0]
    assert hashlib.sha256((ROOT/'scripts/fixtures/steam-ticket-consumer-reference.json.gz').read_bytes()).hexdigest() == r['ticket_reference_sha256']
    assert len(r['cases']) == 4
    for case in r['cases']:
        inp, expected = case['input'], case['observed']
        assert not expected['source_assertions'] and len(expected['executed']) == 1
        before, after = expected['before'], expected['after']
        assert bool(before['result']) == inp['binit']
        assert before['events'].count('backend-release') == 1
        creates = before['events'].count('connection-create')
        assert creates == int(inp['binit'])
        expired = after is not None and ['error', 4] in after['events']
        if after:
            assert after['phase'] == 1 and ('quit_boundary' in after['events']) == expired
        run = subprocess.run([str(args.receiver.resolve()), '0', '1' if inp['binit'] else '2',
                              str(inp['elapsed_ms'])], input=';'.join(r['native_ticket'])+' -\n',
                             text=True, capture_output=True, timeout=8)
        assert not run.returncode, (inp, run.returncode, run.stderr[-3000:])
        actual = json.loads(run.stdout.splitlines()[-1])
        assert actual['clean'] and actual['attempts'] == 1
        assert actual['sessions'] == actual['joins'] == creates, (inp, actual, expected)
        assert actual['backends'] == int(inp['binit'])
        assert actual['early_close'] == int(expired), (inp, actual, expected)
        assert bool(actual['pending_sends']) == inp['binit']
    print('PASS 4 original BConnect/SDL callers: initialized SNS still finding route starts real IHS worker, retries, exact 9999/10000ms deadline and joined cleanup; init failure creates no IHS')


if __name__ == '__main__': main()
