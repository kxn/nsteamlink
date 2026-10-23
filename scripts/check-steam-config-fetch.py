#!/usr/bin/env python3
"""Compare the production config fetch policy with original shared-state programs.

The value-policy gate does not prove HTTP adapter, JSON/trust import, disk cache,
application startup or SDK/stream success. A separate real-owner refresh test
covers the production HTTP callback with explicit validation/network providers.
"""
import argparse,gzip,hashlib,json,subprocess
from pathlib import Path
if not __debug__:raise SystemExit('Original comparison requires assertions')
ROOT=Path(__file__).resolve().parents[1]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--receiver',type=Path,required=True);p.add_argument('--owner',type=Path,required=True);a=p.parse_args()
 r=json.loads(gzip.decompress((ROOT/'scripts/fixtures/steam-config-fetch-reference.json.gz').read_bytes()))
 assert r['schema']==1 and r['binary_sha256']=='50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e'
 for n,sha in r['helpers'].items():assert hashlib.sha256((ROOT/'scripts'/n).read_bytes()).hexdigest()==sha,n
 assert len(r['cases'])==19
 for case in r['cases']:
  i=case['input']; lines=[f"{int(i['available'])} {i.get('attempts',0)} {i.get('state',100 if i['available'] else 1)}"]
  for action in i['actions']:lines.append(f"{action[0]} {int(action[1])} {int(action[2]) if len(action)>2 else 0}")
  run=subprocess.run([str(a.receiver.resolve())],input='\n'.join(lines)+'\n',capture_output=True,text=True,timeout=5)
  assert run.returncode==0,(i,run.returncode,run.stderr)
  rows=[json.loads(s) for s in run.stdout.splitlines()];assert len(rows)==len(case['observed'])
  for got,want in zip(rows,case['observed']):
   assert all(got[k]==want[k] for k in ['available','completed','active']),(i,got,want)
   assert got['realms']==['&realm=' in req['url'] for req in want['requests']],(i,got,want)
 reference=next(c for c in r['cases'] if c['input']['name']=='failure-or-parse-500')['observed']
 for mode in ['cold-failover','cold-dns']:
  run=subprocess.run([str(a.owner.resolve()),mode],capture_output=True,text=True,timeout=10)
  assert run.returncode==0,(run.returncode,run.stderr)
  rows=[json.loads(line) for line in run.stdout.splitlines()];assert len(rows)==8
  for index,got in enumerate(rows):
   want=reference[index%4]
   assert all(got[k]==want[k] for k in ['available','completed','active']),(got,want)
   assert got['urls']==[req['url'] for req in want['requests']],(got,want)
 print('PASS 19 original config programs: one active request, signed/wrapping completion counts, cache-success refresh, no retry on failed refresh with usable config, cold exhaustion and realm alternation')
if __name__=='__main__':main()
