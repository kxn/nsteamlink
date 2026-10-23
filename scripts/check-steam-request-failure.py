#!/usr/bin/env python3
"""Compare original local sender failure with production RPC/runtime/IHS."""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path

if not __debug__:
    raise SystemExit('Original comparison requires assertions; do not use Python -O')
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('rpc', ROOT/'scripts/check-steam-pairing-rpc.py')
rpc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rpc)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--receiver', type=Path, required=True)
    p.add_argument('--reference', type=Path,
                   default=ROOT/'scripts/fixtures/steam-request-failure-reference.json.gz')
    args = p.parse_args()
    reference = json.loads(gzip.decompress(args.reference.read_bytes()))
    assert reference['schema'] == 1
    assert reference['binary_sha256'] == '15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2'
    assert len(reference['cases']) == 18
    for name, sha in reference['helpers'].items():
        assert hashlib.sha256((ROOT/'scripts'/name).read_bytes()).hexdigest() == sha, name
    for case in reference['cases']:
        assert not case['source_assertions']
        final = case['steps'][-1]
        send_case = case['name'].endswith('-send')
        failed_tokens = sum(call['failed'] for call in final['token_calls'])
        assert failed_tokens == (0 if send_case else int(case['hint'] or case['name'] == 'service-publication'))
        phase = (2 if case['name'] == 'service-publication'
                 else 4 if case['name'].startswith('authorize-retry') else 5)
        if send_case and case['hint']:
            assert final['state'] == phase and final['rid'] == 17 and final['target'] == 123
            assert not final['events']
        else:
            assert final['state'] == 1 and final['target'] == 0 and final['rid'] == 0
            failure = final['events'][-1]
            assert failure['kind'] == 'failed'
            assert failure['error'] == (1 if failed_tokens else 18)
            assert failure['state'] == phase
        actual = rpc.check(args.receiver, case)[-1]
        assert actual['token_failures'] == failed_tokens
        assert actual['send_failures'] == int(send_case and case['hint'])
    print('PASS 18 original token-failure/availability/void-send programs: classification, notify-before-clear, cancel phase, no cleanup duplicate or invented send-failure Stop')


if __name__ == '__main__':
    main()
