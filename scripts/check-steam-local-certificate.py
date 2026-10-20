#!/usr/bin/env python3
"""Check original combined certificate flow and actual SDK unknown-CA behavior.

Only the unknown/missing CA projection is compared with the real SDK. The other
original programs retain declared parser/CA/key/clock/install providers and are
not represented as successful SDK/peer/network authentication.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
if not __debug__: raise SystemExit('Original comparison requires assertions')
ROOT=Path(__file__).resolve().parents[1]
def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--receiver',type=Path,required=True); a=p.parse_args()
    r=json.loads(gzip.decompress((ROOT/'scripts/fixtures/steam-local-certificate-reference.json.gz').read_bytes()))
    assert r['schema']==1 and r['binary_sha256']=='50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e'
    for name,sha in r['helpers'].items():assert hashlib.sha256((ROOT/'scripts'/name).read_bytes()).hexdigest()==sha,name
    cases={c['input']['name']:c['observed'] for c in r['cases']}; assert len(cases)==14
    good={'valid','expired','revoked','preset-private'}
    for name,result in cases.items():
        assert result['result']==(name in good), (name,result)
        assert result['installed']==(2 if name in good else 0), (name,result)
        assert result['assertions']==int(name=='expired'), (name,result)
    original=cases['unknown-ca']; assert not original['parsed'] and 'body-parse' not in original['events']
    assert not original['scope']
    for name in ['expired','revoked']:
        assert cases[name]['scope'] is False and cases[name]['parsed'] and cases[name]['result']
    assert r['mutation']['result'] and r['mutation']['parsed'] and r['mutation']['patch_hits']==1
    run=subprocess.run([str(a.receiver.resolve())],text=True,capture_output=True,timeout=10)
    assert run.returncode==0,(run.returncode,run.stderr)
    rows=[json.loads(s) for s in run.stdout.splitlines()]; assert len(rows)==3
    for row in rows:
        assert row['parsed']==original['parsed'] and row['accepted']==original['result'],row
        assert not row['scope'] and row['localhost'],row
    print('PASS 14 frozen original combined flows; real SDK unknown/missing CA and missing signature reject without parsing/installing. This is not an official-vs-SDK difference; no trusted-peer/network claim')
if __name__=='__main__':main()
