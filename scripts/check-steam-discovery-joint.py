#!/usr/bin/env python3
"""Compare joint discovery/launch ordering, not Source launch payload/tickets.

Source launch is a declared producer terminal. Native uses actual client/RX,
request serializer, UDP and cleanup, with controlled late actions/send outcomes
and a held then joined real timer worker. Deferred cases pump the actual API.
Warmup [discovery, initial request] is a Native prerequisite, not Source ticket
proof. No LAN, natural callbacks, Switch or full-manager equivalence claim.
"""
import argparse
import gzip
import hashlib
import json
import re
import subprocess
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
IDENTITIES = {'core':'50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e',
              'shell':'15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2'}
FIELDS = ('sequence','next_status','fast_status','status_tries','broadcast_owners')
def require(value, why):
    if not value:
        raise ValueError(why)
def policy():
    source = json.loads(gzip.decompress((ROOT/'scripts/fixtures/steam-discovery-joint-reference.json.gz').read_bytes()))
    for name, digest in source['helpers'].items():
        require(hashlib.sha256((ROOT/'scripts'/name).read_bytes()).hexdigest() == digest, 'Source helper identity '+name)
    wanted=[]
    for identity,digest in IDENTITIES.items():
        binary=source['binaries'][identity]
        require(binary['sha256']==digest and len(binary['cases'])==6,'pinned original programs')
        rows={}
        for case in binary['cases']:
            final=case['final']
            require(all(len(bytes.fromhex(s['sockaddr']))==16 and bytes.fromhex(s['sockaddr'])[:2]==b'\x02\x00' for s in case['discovery_sends']), 'explicit IPv4 Source shape')
            destinations=[int.from_bytes(bytes.fromhex(s['sockaddr'])[4:8],'big') for s in case['discovery_sends']]
            rows[case['name']]=dict(types=case['order'], destinations=destinations,
                first=dict(types=case['first_order'], destinations=destinations[:case['first_sends']],
                           state={k:case['first'][k] for k in FIELDS}),
                final={k:final[k] for k in FIELDS})
        wanted.append(rows)
    require(wanted[0]==wanted[1],'both official clients agree')
    return wanted[0]
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--receiver',required=True,type=Path)
    p.add_argument('--output',type=Path)
    args=p.parse_args();rows=[]
    for name,expected in policy().items():
        for suffix in ('','_deferred'):
            mode=name+suffix
            proc=subprocess.run([str(args.receiver.resolve()),mode],text=True,capture_output=True,timeout=22)
            require(proc.returncode==0,f'{mode} observer failed: {proc.stderr}')
            for line in proc.stderr.splitlines():
                require(re.fullmatch(r'IHS_UDPSocketOpen: SO_RCVBUF capped at \d+ bytes \(wanted \d+\); raise net.core.rmem_max to avoid dropped video packets',line),f'{mode} unexpected stderr: {line}')
            got=json.loads(proc.stdout)
            require(got['cleanup'] is True and got['types'][:2]==[0,5],mode+' real warmup/cleanup')
            final=got['stages'][-1]
            require(len(final['destinations'])==len(got['types']),mode+' complete send capture')
            first=got['joint_first']; end=first['sends']
            require(2 <= end <= len(got['types']), mode+' first cycle capture bounds')
            actual=dict(types=got['types'][2:],destinations=[dst for kind,dst in zip(got['types'][2:],final['destinations'][2:]) if kind==0],
                first=dict(types=got['types'][2:end],destinations=[dst for kind,dst in zip(got['types'][2:end],final['destinations'][2:end]) if kind==0],
                           state={k:first[k] for k in FIELDS}), final={k:final[k] for k in FIELDS})
            rows.append(dict(mode=mode,compatible=actual==expected,observed=actual,expected=expected,stderr=proc.stderr))
    result=dict(scope=__doc__,compatible=all(r['compatible'] for r in rows),cases=rows)
    if args.output:args.output.write_text(json.dumps(result,indent=2)+'\n')
    gaps=[r['mode'] for r in rows if not r['compatible']]
    print(f'Joint update: {len(rows)-len(gaps)}/{len(rows)} compatible; gaps={gaps}')
    raise SystemExit(1 if gaps else 0)
if __name__=='__main__':main()
