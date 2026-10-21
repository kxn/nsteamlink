#!/usr/bin/env python3
"""Compare original late Test control callbacks with the actual application owner.

Source worker phase 0/4, Qt, thread endpoints and final sends are providers.
Native runs real application/runtime/IHS UDP and Test workers with a controlled
loopback peer. Service error is delivered at the owner callback boundary, not
through a live CM service; this is not real Steam/SDR or Switch validation.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_SHA = 'cac45896775795badde1a18eb8e09768fd8b65268798780ff65a6b3c0a03bd11'
MODES = [('udp', 3), ('cm', 2), ('udp', 11), ('udp', 1), ('udp', 4), ('udp', 0)]


def counts(snapshot):
    return {tag: sum(m['tag'] == tag for m in snapshot['messages']) for tag in (9, 10)}


def main():
    if not __debug__:
        raise RuntimeError('comparison requires assertions')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--receiver', type=Path, required=True)
    args = p.parse_args()
    raw = (ROOT / 'scripts/fixtures/steam-network-test-late-control-reference.json.gz').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == FIXTURE_SHA
    report = json.loads(gzip.decompress(raw))
    assert report['schema'] == 1
    assert report['sample_sha256'] == '15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2'
    for name, sha in report['helper_sha256'].items():
        assert hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest() == sha, name
    cases = report['cases']
    assert len(cases) == 24
    keys = {(c['transport'], c['phase'], c['kind'], c['result']) for c in cases}
    assert keys == {(t, phase, k, r) for t in (1, 4) for phase in (0, 4) for k, r in MODES}
    for c in cases:
        before, after, ack, destroyed = (c[k] for k in ('before', 'after', 'ack', 'destroy'))
        fatal = c['kind'] == 'cm' or c['result'] == 3
        pin = c['result'] == 11
        auth = c['kind'] == 'udp' and c['result'] == 1
        assert before['manager'] == 6 and before['panel'] == 5
        assert before['request_id'] == 17 and before['target'] == 123
        assert after['manager'] == (1 if fatal or pin else 4 if auth else 6)
        assert after['panel'] == (1 if fatal else 6 if pin else 5)
        assert after['request_id'] == (0 if fatal or pin else 17)
        assert after['test_session'] == c['phase'] and after['test_status'] == 1
        assert after['launches'] == 1 and after['joined'] == ack['joined'] == 0
        assert ack['manager'] == 1 and ack['request_id'] == 0
        assert destroyed['joined'] == 1
        assert destroyed['test_session'] == 0
        assert destroyed['test_status'] == (3 if c['phase'] else 1)
        assert not c['source_assertions']
        assert counts(after) == {9: 0, 10: int(fatal or pin)}
        assert counts(ack) == {9: int(auth), 10: int(not auth)}
        if fatal:
            assert {'error_style': 0} in after['ui']
            assert {'signal': '2finished( int )', 'slot': '1OnActionCancel()'} in after['ui']
        elif pin:
            assert {'pin': True} in after['ui']
        else:
            assert after['ui'] == before['ui']
    for mode, (kind, result) in enumerate(MODES, 1):
        source = next(c for c in cases if (c['transport'], c['phase'], c['kind'], c['result']) == (1, 4, kind, result))
        run = subprocess.run([str(args.receiver.resolve()), str(mode)], text=True,
                             capture_output=True, timeout=40)
        assert run.returncode == 0, (mode, run.returncode, run.stderr[-3000:])
        rows = [json.loads(line) for line in run.stdout.splitlines() if line.startswith('{')]
        assert len(rows) == 4 and sum(row['manual'] for row in rows) == 2
        for row in rows:
            assert row['clean'] and row['mode'] == mode
            assert row['before_ack'] == counts(source['after'])[10], row
            assert row['cancel10'] == counts(source['ack'])[10], row
            assert row['cancel9'] == counts(source['ack'])[9], row
    print('PASS late Test control: 24 original manager/Panel programs; 24 real native '
          'application/Test lifetimes, persistent error acknowledgement, PIN/auth display, '
          'cancel9/10 order and joined cleanup (no real Steam/SDR/Switch)')


if __name__ == '__main__':
    main()
