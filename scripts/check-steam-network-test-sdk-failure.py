#!/usr/bin/env python3
"""Compare Test SDK failure owner policy; SDK/config/route outcomes are providers.

Original BInit=false, Test Run and Panel acknowledgement execute; the existing
original lifecycle fixture separately covers disconnect -> Failed. Native uses
the actual actor, RPC/IHS parser, Test worker and cleanup with SDK state providers.
This checks failure ownership, not the SDK/HTTP failure cause, real SDR or Switch.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SHA = '5bd445fff735c3a5fd93cc55d2419564499f1b8ce9d4b81a0c4e08c0e3c9b0fe'


def main():
    if not __debug__: raise RuntimeError('comparison requires assertions')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--receiver', type=Path, required=True)
    p.add_argument('--without-late', action='store_true')
    args = p.parse_args()
    raw = (ROOT / 'scripts/fixtures/steam-network-test-sdk-failure-reference.json.gz').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SHA
    r = json.loads(gzip.decompress(raw))
    assert r['schema'] == 1
    assert r['sample_sha256'] == '15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2'
    for name, sha in r['helper_sha256'].items():
        assert hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest() == sha, name
    assert [c['action'] for c in r['cases']] == [2, 3]
    for c in r['cases']:
        assert not c['source_assertions']
        assert c['ran']['test_status'] == 4 and c['ran']['test_session'] == 0
        assert c['ran']['backend_events'] == ['sdr-create', 'binit-false', 'backend-release']
        assert c['ran']['backend_cleared'] and c['ran']['connection_cleared']
        assert c['error']['manager'] == 6 and c['error']['request_id'] == 17
        assert c['error']['panel'] == 1 and not c['error']['joined']
        assert [m['tag'] for m in c['error']['messages']] == [5]
        assert [m['tag'] for m in c['ack']['messages']] == [5, 10]
        assert c['ack']['manager'] == 1 and c['ack']['request_id'] == 0
        assert c['destroyed']['joined'] == 1
        assert {'error_style': 0} in c['error']['ui']
        assert {'signal': '2finished( int )', 'slot': '1OnActionCancel()'} in c['error']['ui']
    raw = (ROOT / 'scripts/fixtures/steam-network-test-lifecycle-reference.json.gz').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == '82d5bd10743b29b255caee4308ac56de05de306afa64f0c27b0d001d601cfb2b'
    lifecycle = json.loads(gzip.decompress(raw))
    for phase in (2, 3, 4):
        c = next(c for c in lifecycle['cases'] if c['input']['name'] == f'X_phase{phase}')
        assert not c['source_assertions'] and c['trace'][-1]['status'] == 4
        assert c['trace'][-1]['state'] == 0 and c['closes']
    late_raw = (ROOT / 'scripts/fixtures/steam-network-test-late-control-reference.json.gz').read_bytes()
    assert hashlib.sha256(late_raw).hexdigest() == 'cac45896775795badde1a18eb8e09768fd8b65268798780ff65a6b3c0a03bd11'
    late = json.loads(gzip.decompress(late_raw))
    differences = []
    for manual in (0, 1):
        for mode in range(4, 8 if args.without_late else 10):
            wire = r['cases'][manual]['cm']+' -\n'
            if mode >= 8:
                c = next(c for c in late['cases'] if c['transport'] == 4 and c['phase'] == 4
                         and c['kind'] == ('cm' if mode == 8 else 'udp')
                         and c['result'] == (2 if mode == 8 else 11))
                wire += (';'.join(c['late_cm']) or '-')+' '+(';'.join(c['late_udp']) or '-')+'\n'
            run = subprocess.run([str(args.receiver.resolve()), str(manual), str(mode), '0'],
                                 input=wire, text=True,
                                 capture_output=True, timeout=12)
            assert run.returncode == 0, (manual, mode, run.returncode, run.stderr[-3000:])
            got = json.loads(run.stdout.splitlines()[-1])
            want = dict(mode=mode, clean=True, failed=True, pending=True, failed_view=True,
                        detailed_error=True, cancel_before=0, cancel_after=1,
                        sessions=int(mode >= 6), joins=int(mode >= 6),
                        backends=int(mode >= 5), early_close=int(mode >= 5))
            if mode >= 8:
                want.update(detailed_error=False, early_close=0, cancel_before=1)
                if mode == 9: want.update(failed=False, pending=False, failed_view=False)
                assert f'late_sdk_pin_events={int(mode == 9)}' in run.stdout.splitlines()
            if got != want:
                differences.append(dict(manual=manual, got=got, want=want))
    assert not differences, differences
    print('PASS Test SDK failure: 2 original SDR BInit-failure/Panel programs, 3 existing '
          f'disconnect Run branches and {8 if args.without_late else 12} native actor/Test lifetimes; failed snapshot, '
          'acknowledgement, single cancel and joined backend cleanup (SDK outcomes provided)')


if __name__ == '__main__': main()
