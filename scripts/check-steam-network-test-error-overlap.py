#!/usr/bin/env python3
"""Check original dialog ownership and a real application late-error replacement.

Source has 22 normal branches and two explicitly diagnostic branches. Native
uses real application/runtime/IHS UDP/Test workers, supplies auth refusal as the
initial media failure, then delivers service failure at the owner callback. No
natural Qt/SDK/CM/SDR network or Switch display is exercised.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SHA = '801cff15cc1cec12f5ea10f18555742a905fd470a902fc54521175d7084a327f'


def main():
    if not __debug__: raise RuntimeError('comparison requires assertions')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--receiver', type=Path, required=True)
    args = p.parse_args()
    raw = (ROOT / 'scripts/fixtures/steam-network-test-error-overlap-reference.json.gz').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SHA
    report = json.loads(gzip.decompress(raw))
    assert report['schema'] == 1
    assert report['sample_sha256'] == '15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2'
    for name, sha in report['helper_sha256'].items():
        assert hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest() == sha, name
    cases = report['cases']
    assert len(cases) == 24
    diagnostic = []
    for c in cases:
        before, after, ack = (c[k] for k in ('before', 'after', 'ack'))
        control = c['kind'] == 'cm' or c['result'] in (3, 11)
        pin = c['kind'] == 'udp' and c['result'] == 11
        auth = c['kind'] == 'udp' and c['result'] == 1
        if c['source_assertions']:
            diagnostic.append(c)
            assert auth and not c['shown'] and c['source_assertions'] == [208]
            assert after['diagnostics'] == [dict(file='../../src/streaming/client/servermanager.h',
                                                  line=208, expression='BIsStreaming()')]
        else:
            assert not after['diagnostics']
        assert after['test_status'] == 4 and after['test_session'] == 0 and after['launches'] == 1
        assert after['manager'] == (1 if control else 4 if auth else 6)
        assert after['panel'] == (6 if pin else 1)
        assert after['joined'] == ack['joined'] == 0 and c['destroyed']['joined'] == 1
        assert '_ZN10CPanelBase10ShowDialogEP12CPanelDialog' in c['executed']
        shows = [w for w in after['widgets'] if w['op'] == 'show']
        hides = [w for w in after['widgets'] if w['op'] == 'hide']
        assert len(shows) == 1 + int(c['shown'] and control)
        if c['shown'] and control:
            assert hides == [dict(op='hide', pointer=before['dialog_owner'])]
            assert after['widgets'][-2:] == [hides[0], dict(op='show', pointer=after['dialog_owner'])]
            assert after['dialog_owner'] != before['dialog_owner']
        elif c['shown']:
            assert not hides and after['dialog_owner'] == before['dialog_owner']
        if control and not pin:
            assert after['dialogs'][-1]['title'] != 'Network Test Failed'
        elif not pin:
            assert after['dialogs'][-1]['title'] == 'Network Test Failed'
        assert [m['tag'] for m in after['messages'] if m['tag'] in (9, 10)] == ([10] if control else [])
        assert [m['tag'] for m in ack['messages'] if m['tag'] in (9, 10)] == [9 if auth else 10]
        assert ack['manager'] == 1 and ack['request_id'] == 0
    assert len(diagnostic) == 2 and {c['action'] for c in diagnostic} == {2, 3}
    run = subprocess.run([str(args.receiver.resolve()), '7'], capture_output=True, text=True, timeout=40)
    assert run.returncode == 0, (run.returncode, run.stderr[-3000:])
    rows = [json.loads(line) for line in run.stdout.splitlines() if line.startswith('{')]
    assert len(rows) == 4 and sum(row['manual'] for row in rows) == 2
    for row in rows:
        assert row['mode'] == 7 and row['clean']
        assert row['before_ack'] == row['cancel10'] == 1 and row['cancel9'] == 0
    print('PASS overlap: 22 normal original dialog-owner programs + 2 recorded diagnostic '
          'branches; 4 native application lifetimes replace owned errors without Retry, '
          'restart or duplicate cancellation; UI separately rejects stale/unrelated snapshots')


if __name__ == '__main__': main()
