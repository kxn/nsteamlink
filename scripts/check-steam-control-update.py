#!/usr/bin/env python3
"""Compare complete original manager mixed-input updates with product actor.

The receiver enters actual runtime update_control and IHS_ClientUpdate. Only
CM transport delivery and recvfrom bytes are replaced at the receive boundary;
runtime callbacks, protocol parsers, crypto and transaction owners execute.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path

if not __debug__:
    raise SystemExit('Original comparison requires assertions')
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('rpc', ROOT/'scripts/check-steam-pairing-rpc.py')
rpc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rpc)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--receiver', type=Path, required=True)
    p.add_argument('--reference', type=Path, default=ROOT/'scripts/fixtures/steam-control-update-reference.json.gz')
    args = p.parse_args()
    reference = json.loads(gzip.decompress(args.reference.read_bytes()))
    assert reference['schema'] == 1
    assert reference['binary_sha256'] == '15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2'
    for name, sha in reference['helpers'].items():
        assert hashlib.sha256((ROOT/'scripts'/name).read_bytes()).hexdigest() == sha, name
    assert len(reference['cases']) == 60
    for case in reference['cases']:
        assert not case['source_assertions']
        for method in ('_ZN14CServerManager6UpdateEv', '_ZN20CRemoteClientSession6UpdateEv',
                       '_ZN20CRemoteClientSession22HandleWebSocketPacketsEv'):
            assert method in case['executed'], (case['name'], method)
        udp = case['inputs'][0][2]
        udp_stages = case['stages'][case['stages'].index('udp-read'):]
        assert udp_stages.count(['BProcess-return', 1]) == len(udp)
        assert case['stages'].count('udp-read') == len(udp)+1
        rpc.check(args.receiver, case)
    print('PASS 60 complete original manager mixed CM/UDP updates: five phases, hint present/absent, failure/PIN/key/denial/duplicate inputs; product actor and real parsers/crypto')


if __name__ == '__main__':
    main()
