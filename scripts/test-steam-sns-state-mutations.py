#!/usr/bin/env python3
"""Check that original SNS traces reject normally-running policy regressions."""
import argparse
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--compiler', default='c++')
    args = p.parse_args()
    source = (ROOT/'app/platforms/common/sns_connection_policy.h').read_text()
    edits = {
        'peer-close-reason': ('out.failure == SnsCheckFailure::Unknown ? 2001 : 0', '2001'),
        'one-second-boundary': ('now < deadline', 'now <= deadline'),
        'millisecond-budget': ('+ 1000000u', '+ 1000u'),
        'erase-failed-state': ('if (v.state.load() != SL_SNS_FAILED) v.state = SL_SNS_CLOSED;',
                              'v.state = SL_SNS_CLOSED;'),
        'query-before-deadline': ('v.state.load() == SL_SNS_CONNECTED && now < deadline',
                                 'false && now < deadline'),
        'retain-invalid-handle': ('v.handle = k_HSteamNetConnection_Invalid;\n        v.state = SL_SNS_FAILED;',
                                  'v.state = SL_SNS_FAILED;'),
        'connecting-means-false': ('return true; // The caller separately checks transport == Connected.',
                                   'return false; // regression'),
    }
    with tempfile.TemporaryDirectory(prefix='nsl-sns-state-') as tmp:
        work = Path(tmp)
        for name, edit in [('baseline', None)] + list(edits.items()):
            if edit is not None:
                assert edit[0] in source, name
            (work/'sns_connection_policy.h').write_text(
                source if edit is None else source.replace(*edit))
            receiver = work/name
            build = subprocess.run([args.compiler, '-std=c++17', '-Wall', '-Wextra', '-UNDEBUG',
                '-I'+str(work), '-I'+str(ROOT/'app/platforms/common'),
                '-I'+str(ROOT/'third_party/ihslib/include'),
                '-I'+str(ROOT/'third_party/GameNetworkingSockets/include'),
                str(ROOT/'app/tests/sns_state_oracle.cpp'), '-o', str(receiver)],
                capture_output=True, text=True, timeout=30)
            assert build.returncode == 0, (name, build.stderr[-2000:])
            result = subprocess.run(['python3', str(ROOT/'scripts/check-steam-sns-state.py'),
                '--receiver', str(receiver)], capture_output=True, text=True, timeout=30)
            if edit is None:
                assert result.returncode == 0, result.stderr
            else:
                # A compiler error, crash or assertion in the receiver is not
                # proof that the reference comparator rejected a wrong result.
                assert 'assert got == want' in result.stderr, (name, result.stderr[-1500:])
                assert result.returncode != 0, name
            print('PASS', name, 'accepted' if edit is None else 'rejected by reference comparison')


if __name__ == '__main__':
    main()
