#!/usr/bin/env python3
"""Compare PIN retry ownership against original manager/Panel/Test instructions.

Original thread Join/Start and seeded worker phase are providers. Native runs
real application/IHS UDP/Test threads against a controlled peer; no Steam, SDR,
Qt or Switch is exercised. In particular, source's post-Join seeded phase is
not a native worker expectation.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SHA = 'd8a9faa268472af4e1c19e2098d07c1c96b0aeb14c57e1b812d92f961ddb25f1'
OUTCOMES = ('cancel_wait', 'success', 'failure', 'pin', 'unauthorized', 'busy',
            'duplicate_success', 'failure_after_ticket')


def source():
    raw = (ROOT / 'scripts/fixtures/steam-network-test-pin-retry-reference.json.gz').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SHA
    r = json.loads(gzip.decompress(raw))
    assert r['schema'] == 1
    assert r['sample_sha256'] == '15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2'
    for name, sha in r['helper_sha256'].items():
        assert hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest() == sha, name
    assert len(r['cases']) == 32
    seen = set()
    for c in r['cases']:
        outcome, phase = c['outcome'], c['phase']
        seen.add((c['transport'], phase, outcome))
        assert not c['source_assertions']
        pin, wait, after, ack, destroyed = (c[k] for k in ('pin', 'waiting', 'after', 'ack', 'destroyed'))
        replacement = outcome in ('success', 'duplicate_success')
        assert pin['panel'] == 6 and pin['manager'] == 1
        assert wait['panel'] == 4 and wait['manager'] == 5 and wait['request_id'] == 19
        assert pin['joins'] == wait['joins'] == 0 and wait['starts'] == 1
        assert pin['test_status'] == wait['test_status'] == 1
        assert pin['test_session'] == wait['test_session'] == phase
        assert after['starts'] == 1 + replacement and after['joins'] == int(replacement)
        assert after['panel'] == (5 if replacement else 6 if outcome == 'pin' else
                                 3 if outcome == 'unauthorized' else
                                 4 if outcome in ('busy', 'cancel_wait') else 1)
        assert after['manager'] == (6 if replacement else 4 if outcome == 'unauthorized' else
                                   5 if outcome in ('busy', 'cancel_wait') else 1)
        if replacement:
            assert after['tokens'][-1] == bytes(range(128, 160)).hex()
            assert not any(e['stage'] == 'consume' and e['function'] == '_ZN12CNetworkTest6CancelEv'
                           for e in after['test_events'])
            events = [e['op'] for e in after['thread_events'] if e['stage'] == 'consume']
            assert events == ['join', 'start']
        assert destroyed['joins'] == 1 + replacement and not destroyed['thread_alive']
        assert ack['manager'] == 1 and ack['request_id'] == 0
        tags = [m['tag'] for m in ack['messages'] if m['tag'] in (9, 10)]
        assert tags == [10, 9 if outcome == 'unauthorized' else 10]
    assert seen == {(t, p, o) for t in (1, 4) for p in (0, 4) for o in OUTCOMES}


def finished_source():
    raw = (ROOT / 'scripts/fixtures/steam-network-test-finished-pin-reference.json.gz').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == '59ec6bfdf35e608fefe5f4f72bd8383037a4128252bc3722480e53c76241cd13'
    report = json.loads(gzip.decompress(raw))
    assert report['schema'] == 1
    assert report['sample_sha256'] == '15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2'
    for name, sha in report['helper_sha256'].items():
        assert hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest() == sha, name
    assert len(report['cases']) == 32
    seen = set()
    for c in report['cases']:
        outcome = c['outcome']; replacement = outcome in ('success', 'duplicate_success')
        seen.add((c['transport'], c['shown'], outcome))
        assert not c['source_assertions']
        before, pin, wait, after, ack, destroyed = (c[k] for k in
            ('before', 'pin', 'waiting', 'after', 'ack', 'destroyed'))
        assert before['test_status'] == pin['test_status'] == wait['test_status'] == 2
        assert pin['panel'] == 6 and wait['panel'] == 4 and wait['manager'] == 5
        assert pin['joins'] == wait['joins'] == after['joins'] == 0
        assert after['test_status'] == (1 if replacement else 2)
        assert after['starts'] == 1 + replacement
        assert after['panel'] == (5 if replacement else 6 if outcome == 'pin' else
                                 3 if outcome == 'unauthorized' else
                                 4 if outcome in ('busy', 'cancel_wait') else 1)
        assert after['manager'] == (6 if replacement else 4 if outcome == 'unauthorized' else
                                   5 if outcome in ('busy', 'cancel_wait') else 1)
        if c['shown']:
            assert before['panel'] == 1 and before['dialog_owner']
            assert pin['widgets'][-2:] == [dict(op='hide', pointer=before['dialog_owner']),
                                          dict(op='show', pointer=pin['dialog_owner'])]
            assert {'signal': '2finished( int )', 'slot': '1OnNetworkTestComplete( int )'} in before['ui']
        if replacement:
            assert after['tokens'][-1] == bytes(range(128, 160)).hex()
            assert [e['op'] for e in after['thread_events'] if e['stage'] == 'consume'] == ['start']
        assert destroyed['joins'] == int(replacement) and not destroyed['thread_alive']
        assert ack['manager'] == 1 and ack['request_id'] == 0
        assert [m['tag'] for m in ack['messages'] if m['tag'] in (9, 10)] == [
            10, 9 if outcome == 'unauthorized' else 10]
    assert seen == {(t, shown, o) for t in (1, 4) for shown in (False, True) for o in OUTCOMES}


def main():
    if not __debug__:
        raise RuntimeError('comparison requires assertions')
    p = argparse.ArgumentParser(description=__doc__)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--receiver', type=Path)
    g.add_argument('--observations', type=Path)
    variants = p.add_mutually_exclusive_group()
    variants.add_argument('--sdk', action='store_true', help='provide pending old SDK startup, then a new UDP ticket')
    variants.add_argument('--cancel-join', action='store_true', help='cancel locally while waiting for old worker')
    variants.add_argument('--sdk-fail', action='store_true', help='old SDK BInit fails after the replacement ticket')
    variants.add_argument('--sdk-session-fail', action='store_true', help='old IHS setup fails after the replacement ticket')
    variants.add_argument('--completed', action='store_true', help='finish and show the old result before requesting PIN')
    args = p.parse_args()
    source()
    if args.completed:
        finished_source()
    if args.receiver:
        variant = next((flag for flag in ('sdk', 'cancel_join', 'sdk_fail', 'sdk_session_fail', 'completed')
                        if getattr(args, flag)), None)
        run = subprocess.run([str(args.receiver.resolve())] +
                             (['--'+variant.replace('_', '-')] if variant else []),
                             capture_output=True, text=True, timeout=120 if args.completed else 75)
        assert run.returncode == 0, (run.returncode, run.stderr[-4000:])
        output = run.stdout
    else:
        output = args.observations.read_text()
    rows = [json.loads(line) for line in output.splitlines() if line.startswith('{')]
    outcomes = ('cancel_join',) if args.cancel_join else ('sdk_fail',) if args.sdk_fail else \
               ('sdk_session_fail',) if args.sdk_session_fail else OUTCOMES
    assert len(rows) == len(outcomes)*2
    assert {(row['scenario'], row['manual']) for row in rows} == {
        (outcome, manual) for outcome in outcomes for manual in (False, True)}
    differences = []
    for row in rows:
        outcome = row['scenario']
        replacement = outcome in ('success', 'duplicate_success', 'sdk_session_fail')
        want = dict(retained=True, sample_held=True, held_at_response=True,
                    unexpected_stop=False, requests=2, sessions=1 + replacement,
                    joins=1 + replacement, before_ack=2 if outcome in
                    ('failure', 'pin', 'failure_after_ticket') else 1,
                    cancel10=1 if outcome == 'unauthorized' else 2,
                    cancel9=int(outcome == 'unauthorized'), clean=True)
        mismatch = {k: dict(got=row.get(k), want=v) for k, v in want.items() if row.get(k) != v}
        if mismatch:
            differences.append(dict(scenario=outcome, manual=row['manual'], differences=mismatch))
        if args.receiver:
            sdk = args.sdk or args.sdk_fail or args.sdk_session_fail
            assert row['preinit'] == sdk and row['backends'] == int(sdk)
            assert row['completed'] == args.completed
            # Replacing a live old test must wait naturally; a final local
            # cancellation may disconnect an old test that is still running.
            assert row['early_disconnects'] == (0 if replacement or args.sdk_fail or args.completed else 1), row
            if (replacement or args.cancel_join or args.sdk_fail) and not args.completed:
                assert row['control_held'], row
    assert not differences, differences
    print(f'PASS PIN retry: 32 original {"finished-Test" if args.completed else "manager/Panel/Test"} programs and {len(rows)} real native '
          'application/IHS UDP/Test lifetimes; retain old owner while requesting, '
          'replace once after ticket, preserve PIN/auth/error/cancel ownership')


if __name__ == '__main__':
    main()
