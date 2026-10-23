#!/usr/bin/env python3
"""Compare original late-error/consumer behavior with the actual product worker.

Original launch/token entry is compared with native IHS Session construction;
SDK creation is an observed terminal and must not occur for a rejected ticket.
This is a consumer-admission check, not SDK/media execution or Qt timing proof.
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
    p.add_argument('--reference', type=Path, default=ROOT/'scripts/fixtures/steam-ticket-consumer-reference.json.gz')
    p.add_argument('--without-sns', action='store_true', help='Compare the UDP-only product build')
    args = p.parse_args()
    report = json.loads(gzip.decompress(args.reference.read_bytes()))
    assert report['schema'] == 1
    assert report['binary_sha256'] == '15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2'
    for name, sha in report['helpers'].items():
        assert hashlib.sha256((ROOT/'scripts'/name).read_bytes()).hexdigest() == sha, name
    assert len(report['cases']) == 20
    checked = 0
    for case in report['cases']:
        assert not case['source_assertions']
        for method in ('_ZN14CServerManager6UpdateEv', '_ZN20CRemoteClientSession6UpdateEv',
                       '_ZN13CPanelConnect8OnUpdateEv',
                       '_ZN14CServerManager28HandleStartStreamingResponseERK10CIPAndPortyPK33CMsgRemoteDeviceStreamingResponse'):
            assert method in case['executed'], (case['name'], method)
        expected = case['steps'][-1]
        if expected['errors']:
            assert '_ZN13CPanelConnect13OnServerErrorE12EServerError' in case['executed']
            assert '_ZThn192_N13CPanelConnect13OnServerErrorE12EServerError' in case['executed']
            assert expected['panel'] == 1 and not expected['launches']
        if args.without_sns and case['transport'] == 4:
            continue
        raw = (';'.join(case['cm']) or '-')+' '+(';'.join(case['udp']) or '-')+'\n'
        run = subprocess.run([str(args.receiver.resolve()), str(int(case['testing']))],
                             input=raw, text=True, capture_output=True, timeout=8)
        label = (case['name'], case['testing'], case['transport'])
        assert run.returncode == 0, (label, run.returncode, run.stderr[-4000:])
        actual = json.loads(run.stdout.splitlines()[-1])
        # The old fixture ends at launch admission, before outer Qt Quit. The
        # ordinary handoff is compared separately against that outer caller.
        assert actual['clean'] and actual['admission_state'] == expected['state'], (label, actual, expected)
        assert actual['sessions'] == expected['launches'], (label, actual, expected)
        assert actual['backends'] == (expected['launches'] if case['transport'] == 4 else 0), (label, actual, expected)
        checked += 1
    print(f'PASS {checked} original manager/OnServerError/Panel consumer programs against actual runtime worker; ordinary/network-test, success/duplicate/busy/CM or UDP failure; no rejected-ticket backend or media construction')


if __name__ == '__main__':
    main()
