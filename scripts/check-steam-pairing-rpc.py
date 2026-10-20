#!/usr/bin/env python3
"""Compare whole original cloud response dispatch with product RPC/IHS owners.

Original queue/protobuf parser/session/manager instructions are frozen inputs.
The native receiver invokes production remote_protocol and runtime callbacks,
real IHS timers and crypto. Final WebRequest/CM, manager control sends, clocks,
entropy, identity and GetServerInfo/hint are explicit providers. This checks RPC
policy and observable ordering, not TLS, NAT, real Steam or Switch lifecycle.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

if not __debug__:
    raise SystemExit('Original comparison requires assertions; do not use Python -O')
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('service',ROOT/'scripts/check-steam-service-pairing.py')
service=importlib.util.module_from_spec(spec);spec.loader.exec_module(service)


def varint(value):
    raw=bytearray()
    while value>=128:
        raw.append((value&127)|128);value>>=7
    raw.append(value);return bytes(raw)


def command(event):
    op=event[0]
    if op=='wire':
        kind,result,pin=event[1:]
        body=b'\x08'+varint(pin) if kind==3 else b''
        raw=b'\x08'+varint(result)+varint(kind*8+2)+varint(len(body))+body
        return 'r '+raw.hex()
    if op=='raw':return 'r '+event[1]
    if op=='batch':return 'b '+' '.join(event[1])
    if op=='fail-token':return 'f'
    if op=='fail-send':return f'e {event[1]}'
    if op=='due':return f'd {event[1]}'
    if op=='update':return f'u {event[1]} {event[2]}'
    return {'start':'s','cancel':'c','known':'k','stream':'t','reconnect':'o'}[op]


def state(actual,expected,label):
    for key in ('state','rid','session_state','secret','target'):
        assert actual[key]==expected[key],(label,key,actual,expected)


def check(receiver,case):
    run=subprocess.run([str(receiver.resolve()),case['phase'],str(int(case['hint']))],
        input='\n'.join(command(e) for e in case['inputs'])+'\n',text=True,capture_output=True,timeout=15)
    assert run.returncode==0,(case['name'],case['hint'],run.returncode,run.stderr[-3000:])
    rows=[json.loads(line) for line in run.stdout.splitlines()]
    assert len(rows)==len(case['steps'])
    for n,(actual,expected) in enumerate(zip(rows,case['steps'])):
        label=(case['name'],case['hint'],n)
        state(actual,expected,label)
        assert actual['reply_metadata']==bool(expected['accounts'].get('456')),label
        assert actual['paired_count']==len(expected['paired']),label
        assert actual['keypairs']==expected['keypairs'],(label,'keypairs',actual,expected)
        assert actual['tickets']==expected['tickets'],(label,'tickets',actual['tickets'],expected['tickets'])
        events=[e for e in expected['events'] if e['kind'] not in ('release','reconnect')]
        assert len(actual['events'])==len(events),(label,actual['events'],events)
        for a,e in zip(actual['events'],events):
            state(a,e,label)
            assert a['kind']==e['kind'] and a['error']==e.get('error',0),(label,a,e)
        assert len(actual['rpc'])==len(expected['rpc']),(label,actual['rpc'],expected['rpc'])
        for a,e in zip(actual['rpc'],expected['rpc']):
            state(a['state'],e['state'],label)
            ap,ep=service.fields(a['wire']),service.fields(e['wire'])
            assert set(ap)==set(ep) and len(ap)==1,(label,ap,ep)
            kind=next(iter(ap))
            if kind!=3:
                assert a['wire']==e['wire'],(label,a,e)
                continue
            ab,eb=service.fields(ap[3].hex()),service.fields(ep[3].hex())
            assert ab.keys()==eb.keys()=={1,2,3} and ab[1]==eb[1] and ab[2]==eb[2],(label,ab,eb)
            auth,source=service.fields(ab[3].hex()),service.fields(eb[3].hex())
            assert auth.keys()==source.keys()=={1,2,3,4,5}
            assert all(auth[k]==source[k] for k in (2,4,5)),(label,auth,source)
            service.device_token(auth[1],e['state']['secret'])
            service.device_token(source[1],e['state']['secret'])
            assert len(auth[3])==256
        assert len(actual['controls'])==len(expected['messages']),(label,actual['controls'],expected['messages'])
        for a,e,boundary,recipient in zip(actual['controls'],expected['messages'],expected['send_states'],expected['control_targets']):
            state(a,boundary,label)
            assert a['tag']==e['tag'] and a['recipient']==recipient,(label,a,e,recipient)
            if a['tag'] in (3,5):
                ap,ep=service.fields(a['body']),service.fields(e['body'])
                selected=(2,4,5) if a['tag']==3 else (1,12,13)
                assert all(ap.get(k)==ep.get(k) for k in selected),(label,ap,ep)
                service.device_token(ap[1 if a['tag']==3 else 7],a['secret'])
                service.device_token(ep[1 if a['tag']==3 else 7],a['secret'])
            else:assert a['body']==e['body'],(label,a,e)
    return rows


def verify_source(case):
    assert not case['source_assertions']
    assert '_ZN20CRemoteClientSession22HandleWebSocketPacketsEv' in case['executed'] or case['inputs'][0][0]=='update'
    if case['name'].endswith('connected-clock-jump'):
        assert case['steps'][0]==case['steps'][1],case['name']
    if case['name']=='waiting-disconnect':
        assert case['steps'][-1]['state']==2 and not case['steps'][-1]['failures']
    if case['name']=='auth-disconnect':
        events=case['steps'][-1]['events']
        assert [(e['kind'],e['state'],e['session_state']) for e in events[-4:]]==[
            ('failed',3,5),('disconnected',1,5),('release',1,5),('reconnect',1,0)]
        assert events[-4]['error']==18
    if case['name']=='auth-rpc-3-1':
        assert case['steps'][-1]['state']==3 and case['steps'][-1]['keypairs']==1
        assert len(case['steps'][-1]['rpc'])==len(case['steps'][0]['rpc'])+1
    if case['name']=='cancel-then-known-failure':
        assert case['steps'][-1]['state']==1 and case['steps'][-1]['failures']==1
        assert case['steps'][-1]['events'][-1]['state']==4
    if case['name'].startswith('batch-1-4-success-failure'):
        final = case['steps'][-1]
        assert final['state'] == 1 and final['paired'] == [76561198000000001]
        assert not final['failures']
        assert final['messages'][0] == dict(tag=14, body='0800')
        assert len(final['messages']) == (2 if case['hint'] else 1)
    if case['name'] in ('known-resume-0', 'known-resume-1'):
        final = case['steps'][-1]
        if case['hint']:
            assert final['state'] == 5 and final['rid'] == 17 and final['target'] == 123
            assert not final['events']
        else:
            assert final['state'] == 1 and final['rid'] == 0 and final['target'] == 0
            failure = final['events'][-1]
            assert (failure['kind'], failure['error'], failure['state'], failure['rid'],
                    failure['target']) == ('failed', 18, 5, 17, 123)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--receiver',type=Path,required=True)
    p.add_argument('--reference',type=Path,default=ROOT/'scripts/fixtures/steam-pairing-rpc-reference.json.gz')
    args=p.parse_args();r=json.loads(gzip.decompress(args.reference.read_bytes()))
    assert r['schema']==1 and r['binary_sha256']=='15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2'
    for name,sha in r['helpers'].items():assert hashlib.sha256((ROOT/'scripts'/name).read_bytes()).hexdigest()==sha,name
    assert len(r['cases'])==202
    for case in r['cases']:
        verify_source(case)
        check(args.receiver,case)
    print('PASS 202 whole original response-queue/RPC/manager programs: late/duplicate PIN, failure/cancel, phase2/3 disconnect, replacement, 48 service batches and 28 known-host resume/late-RPC programs')


if __name__=='__main__':main()
