#!/usr/bin/env python3
"""Check custom result-dialog signals and native queued-confirm ownership.

Qt activate is a same-GUI-thread provider, file save is an observed endpoint,
and finished Test state is seeded in the original. Native uses a real result
action delayed across a real IHS control callback; that delay is an explicit
port scheduling input, not a claimed natural Qt race or real Steam session.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SHA = 'c76104e1d3f0fd2e43de1ff1dbe48aa004c7c4f9f4f297775e0f3298573a8c25'
OPERATIONS = ('accept', 'reject', 'done', 'hide', 'pin', 'failed', 'cm', 'unauthorized')


def source():
    raw = (ROOT / 'scripts/fixtures/steam-network-test-dialog-reference.json.gz').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SHA
    r = json.loads(gzip.decompress(raw))
    assert r['schema'] == 1 and r['sample_sha256'] == '15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2'
    for name, sha in r['helper_sha256'].items():
        assert hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest() == sha, name
    assert len(r['cases']) == 32
    seen = set()
    for c in r['cases']:
        seen.add((c['action'], c['transport'], c['operation']))
        before, after = c['before'], c['after']; old = before['dialog_owner']
        assert not c['source_assertions'] and before['panel'] == 1 and before['test_status'] == 2
        confirmed = c['operation'] in ('accept', 'reject', 'done')
        kept = c['operation'] == 'unauthorized'
        events = after['events'][len(before['events']):]
        signals = [e['signal'] for e in events if e['op'] == 'signal' and e['dialog'] == old]
        assert signals == ([2 if c['operation'] == 'reject' else 0, 1, 3] if confirmed else [] if kept else [3])
        assert len(after['saved_stats']) == int(confirmed)
        slots = [e['name'] for e in events if e['op'] == 'slot']
        assert ('_ZN13CPanelConnect21OnNetworkTestCompleteEi' in slots) == confirmed
        assert ('_ZN10CPanelBase14OnDialogHiddenEP12CPanelDialog' in slots) == (not kept)
        if confirmed:
            first = next(i for i, e in enumerate(events) if e.get('signal') == 1)
            assert first < next(i for i, e in enumerate(events) if e['op'] == 'hide')
            assert first < next(i for i, e in enumerate(events) if e['op'] == 'save_stats')
        assert sum(e == dict(op='deleteLater', dialog=old) for e in events) == int(not kept)
        assert (after['dialog_owner'] == old) == kept
        connects = [e for e in after['connections'] if e['sender'] == old]
        assert any(e['slot'] == '1OnNetworkTestComplete( int )' and e['type'] == 0 for e in connects)
    assert seen == {(a, t, op) for a in (2, 3) for t in (1, 4) for op in OPERATIONS}


def main():
    if not __debug__: raise RuntimeError('comparison requires assertions')
    p = argparse.ArgumentParser(description=__doc__)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--receiver', type=Path)
    g.add_argument('--observations', type=Path, nargs='+')
    args = p.parse_args(); source(); rows = []
    if args.receiver:
        for flag in ('--stale-pin', '--stale-error', '--kept-auth'):
            run = subprocess.run([str(args.receiver.resolve()), flag], text=True,
                                 capture_output=True, timeout=18)
            assert run.returncode == 0, (flag, run.returncode, run.stderr[-3000:])
            rows += [json.loads(line) for line in run.stdout.splitlines() if line.startswith('{')]
    else:
        for path in args.observations:
            rows += [json.loads(line) for line in path.read_text().splitlines() if line.startswith('{')]
    assert len(rows) == 6
    assert {(r['scenario'], r['manual']) for r in rows} == {
        (s, m) for s in ('stale_pin', 'stale_error', 'stale_kept_auth') for m in (False, True)}
    differences = []
    for row in rows:
        kept = row['scenario'] == 'stale_kept_auth'
        want = dict(held=not kept, page_preserved=True, saved_old_stats=kept,
                    requests=2 if kept and not row['manual'] else 1, sessions=1, joins=1, clean=True)
        mismatch = {k: dict(got=row.get(k), want=v) for k, v in want.items() if row.get(k) != v}
        if mismatch: differences.append(dict(scenario=row['scenario'], manual=row['manual'], differences=mismatch))
    assert not differences, differences
    print('PASS custom dialog: 32 original signal/slot programs + 6 real application/IHS '
          'lifetimes; retired confirmation ignored, still-owned authorization result accepted')


if __name__ == '__main__': main()
