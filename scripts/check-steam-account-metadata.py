#!/usr/bin/env python3
"""Compare original metadata operations with production lists, files and IHS RX.

The account receiver invokes production list/file/session functions. The actual
IHS oracle receives the same full auth frames through its UDP/RX/deferred owner;
its metadata callbacks expose call order, not a simulated crypto result. Fixtures
provide time/entropy, metadata storage identity and final service send. No real
Steam, network reachability, cold Switch launch or original loader parser proof.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess

if not __debug__:
    raise SystemExit('Original comparison requires assertions; do not use Python -O')
ROOT=Path(__file__).resolve().parents[1]
A=76561198000000001
INITIAL=[A+1,A,A+2,A+3]

def run(binary,args=(),text=''):
    proc=subprocess.run([str(binary.resolve()),*map(str,args)],input=text,text=True,capture_output=True,timeout=20)
    assert proc.returncode==0,(args,proc.returncode,proc.stderr[-3000:])
    return [json.loads(s) for s in proc.stdout.splitlines()]

def lists(binary,initial,ops):
    text=f'{len(initial)} {len(ops)}\n'+' '.join(map(str,initial))+'\n'
    text+=''.join(f'{kind} {account}\n' for kind,account in ops)
    rows=run(binary,text=text)
    assert len(rows)==len(ops)
    return rows

def check_auth(receiver,authorization,case):
    commands=['p 1000 6 123 08111001']
    commands+=['c 1000' if wire is None else 'r 1000 '+wire for wire in case['packets']]
    rows=run(authorization,[int(case['test']),0,'routed'],'\n'.join(commands)+'\n')
    assert len(rows)==len(commands)+1
    for actual,expected in zip(rows[1:],case['steps']):
        assert actual['metadata_ops']==expected['events'],(case['name'],actual['metadata_ops'],expected['events'])
        files={}
        for client,ids in expected['accounts'].items():
            ops=[(2,e['steam']) for e in actual['metadata_ops'] if e['op']=='identity' and str(e['client'])==client]
            changes=lists(receiver,INITIAL,ops)
            assert (changes[-1]['ids'] if changes else INITIAL)==ids,(case['name'],client,changes,ids)
            if changes and changes[-1]['file'] is not None:
                namespace=int(client).to_bytes(8,'little').hex()
                files[f'/fixture/{namespace}/steamid.txt']=changes[-1]['file']
        paired=lists(receiver,[],[(1,e['steam']) for e in actual['metadata_ops'] if e['op']=='key'])
        assert (paired[-1]['ids'] if paired else [])==expected['paired']
        if paired and paired[-1]['file'] is not None:files['/fixture/paired_steamid.txt']=paired[-1]['file']
        assert files==expected['files'],(case['name'],files,expected['files'])

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--receiver',type=Path,required=True);p.add_argument('--authorization',type=Path,required=True)
    p.add_argument('--reference',type=Path,default=ROOT/'scripts/fixtures/steam-account-metadata-reference.json.gz')
    args=p.parse_args();r=json.loads(gzip.decompress(args.reference.read_bytes()))
    assert r['schema']==1 and r['core_sha256']=='50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e'
    assert r['shell_sha256']=='15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2'
    for name,sha in r['helpers'].items():assert hashlib.sha256((ROOT/'scripts'/name).read_bytes()).hexdigest()==sha,name
    assert len(r['lists'])==10 and len(r['sessions'])==48 and len(r['auth'])==26
    for case in r['lists']:
        ops=[(0 if case['kind']=='status' else 1,step['account']) for step in case['steps']]
        actual=lists(args.receiver,case['initial'],ops)
        assert [{k:row[k] for k in ('added','ids')} for row in actual]==[{k:row[k] for k in ('added','ids')} for row in case['steps']],case
    for case in r['sessions']:
        actual=run(args.receiver,['session',case['state'],case['universe'],int(case['reconnect'])],
                   f"{len(case['accounts'])}\n"+' '.join(map(str,case['accounts']))+'\n')
        assert actual==case['wires'],(case,actual)
    for case in r['auth']:check_auth(args.receiver,args.authorization,case)
    print('PASS 10 list programs/70 steps, 48 original session registrations/replays, 26 full-frame authorization metadata traces; actual list-file bytes and side-effect order')
if __name__=='__main__':main()
