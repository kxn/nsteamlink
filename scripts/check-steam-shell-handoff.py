#!/usr/bin/env python3
"""Compare original ordinary Qt teardown with the actual polled runtime handoff.

The port intentionally retains its discovery owner, so original destroyed/
uninitialized state0 is compared with no live handshake, not byte-identical
manager storage. Real IHS workers stay pending while late CM/UDP is injected;
SDK/config construction and datagram IO are providers. No Qt/JNI or media.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
FIXTURE_SHA='40c9cb69c01858c0c7273d6044aaa2cce6efb651c075e43523161d74d104f890'


def main():
    if not __debug__: raise RuntimeError('comparison requires assertions')
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--receiver',type=Path,required=True)
    p.add_argument('--without-sns',action='store_true')
    p.add_argument('--owner',type=Path)
    p.add_argument('--owner-only',action='store_true')
    args=p.parse_args()
    raw=(ROOT/'scripts/fixtures/steam-shell-handoff-reference.json.gz').read_bytes()
    assert hashlib.sha256(raw).hexdigest()==FIXTURE_SHA,'unfrozen handoff fixture'
    r=json.loads(gzip.decompress(raw))
    assert r['schema']==1 and r['sample_sha256']=='15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2'
    for name,sha in r['helper_sha256'].items():
        assert hashlib.sha256((ROOT/'scripts'/name).read_bytes()).hexdigest()==sha,name
    assert len(r['cases'])==20
    if args.owner:
        good=next(c for c in r['cases'] if c['name']=='success' and not c['testing'] and c['transport']==1)['udp'][0]
        run=subprocess.run([str(args.owner.resolve())],input=good+'\n',text=True,capture_output=True,timeout=10)
        assert run.returncode==0,(run.returncode,run.stderr[-3000:])
        got=json.loads(run.stdout.splitlines()[-1])
        assert got==dict(accepts=3,failures=0,statuses=3,clean=True),got
        print('PASS handoff owner: three actual IHS request/parse/handoff lifetimes; later '
              'results and Proof suppressed, secret preserved, discovery and explicit pairing reopen')
    if args.owner_only:
        assert args.owner
        return
    ordinary=[c for c in r['cases'] if c['handoff']]
    assert len(ordinary)==5
    checked=0
    for c in ordinary:
        h=c['handoff']
        assert not c['testing'] and h['state']==0 and not h['manager_present']
        assert not h['discovery_socket'] and not h['cloud_session'] and not h['cancel_sent']
        assert h['recent_key_freed'] and h['fresh_cache_length']==0 and h['fresh_cached_result']==7
        assert h['request_id_storage']==17 and h['target_storage']==123
        assert not c['source_assertions']
        if args.without_sns and c['transport']==4: continue
        # Actual late wire frames from already frozen source consumer programs.
        # They would have gone to the retired manager/session in the original.
        variants=[('none',[],[]),('udp-in-progress',[],[r['late_inprogress']])]
        failed=next(x for x in r['cases'] if not x['testing'] and x['transport']==c['transport'] and 'failure-after' in x['name'])
        if c['transport']==4:
            variants += [('cm-service-failure',[failed['cm'][-1]],[]),
                         ('udp-stream-failure',[],next(x for x in r['cases'] if x['name']=='udp-failure-after-cm-ticket' and not x['testing'])['udp'])]
        else:
            variants += [('udp-stream-failure',[],failed['udp'][-1:])]
        for name,cm,udp in variants:
            wire=(';'.join(c['cm']) or '-')+' '+(';'.join(c['udp']) or '-')+'\n'
            wire+=(';'.join(cm) or '-')+' '+(';'.join(udp) or '-')+'\n'
            run=subprocess.run([str(args.receiver.resolve()),'0','3','0'],input=wire,
                text=True,capture_output=True,timeout=8)
            label=(c['name'],c['transport'],name)
            assert run.returncode==0,(label,run.returncode,run.stderr[-3000:])
            got=json.loads(run.stdout.splitlines()[-1])
            assert got['clean'] and got['admission_state']==6,label
            assert got['handoffs']==1 and got['state']==1,(label,got)
            assert not got['failed_after_late'] and not got['early_close'],(label,got)
            assert not got['handoff_controls'] and not got['late_controls'],(label,got)
            assert got['sessions']==got['joins']==1,(label,got)
            assert got['backends']==int(c['transport']==4),(label,got)
            checked+=1
    print(f'PASS ordinary handoff: {len(r["cases"])} original consumer cases/5 actual Quit '
          f'chains, {checked} actual runtime launches with late CM/UDP; discovery retained, '
          'no active handshake and joined IHS before backend destruction')


if __name__=='__main__': main()
