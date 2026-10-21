#!/usr/bin/env python3
"""Compare complete player SDK lifetime, not just transport destruction.

Original BInit/destructor/SDL cleanup call sites/Init/Kill run with SDK, JSON,
CA/certificate and IO providers. Nine explicit-config programs are compared
with production SNS + real SDK/bridge; native trust and parsed-body/null-scope
are providers, not actual CA/signature verification. The real native SDK checks
protobuf/key/identity/AppID. SDK init failure is also a provider. No Steam,
network/media, complete SDL/JNI cleanup or Switch is proved.
"""
import argparse,gzip,hashlib,json,subprocess
from pathlib import Path
if not __debug__:raise SystemExit('Original comparison requires assertions')
ROOT=Path(__file__).resolve().parents[1]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--receiver',type=Path,required=True);a=p.parse_args()
 ref=json.loads(gzip.decompress((ROOT/'scripts/fixtures/steam-sns-lifetime-reference.json.gz').read_bytes()))
 assert ref['schema']==1 and ref['binary_sha256']=='50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e'
 for name,sha in ref['helpers'].items():assert hashlib.sha256((ROOT/'scripts'/name).read_bytes()).hexdigest()==sha,name
 assert len(ref['cases'])==18
 assert ref['mutation']['address']=='0x75cfc4' and ref['mutation']['hits']==3
 assert ref['mutation']['original']!=ref['mutation']['mutant']
 assert all(not row['assertions'] and row['initialized'] for row in ref['mutation']['mutant'])
 compared=0
 for case in ref['cases']:
  for source in case['observed']:
   assert not source['assertions'] and not source['instances'] and not source['initialized']
   assert source['transport']['initialized']==source['before']['initialized']
   assert source['transport']['instances']==0
   events=source['events'];assert 'network-shutdown' in events
   if source['before']['initialized']:assert events.index('network-shutdown')<events.index('sdk-destroy')
  if not case['name'].endswith('-True'):continue
  lines=[]
  for inp in case['actions']:
   fields=[int(inp.get(k,k not in ['stun','webrtc'])) for k in ['init','network','certificate','decode','has_cert','stun','webrtc']]
   if inp.get('empty_cert'):fields[4]=2
   lines.append(' '.join(map(str,fields))+' '+str(inp['generation'])+' '+(inp['data'] or '-'))
  r=subprocess.run([str(a.receiver.resolve())],input='\n'.join(lines)+'\n',capture_output=True,text=True,timeout=10)
  assert r.returncode==0,(case['name'],r.returncode,r.stdout,r.stderr)
  rows=[json.loads(line) for line in r.stdout.splitlines()];assert rows[-1]=={'clean':True} and len(rows)==4
  for source,native in zip(case['observed'],rows):
   want={k:source[k] for k in ['result','initialized','initializations','destructions','imports','certificates','pending']}
   assert native==want,(case['name'],native,want)
  compared+=1;print('PASS',case['name'])
 assert compared==9
 print('PASS 18 original player lifetimes: transport destructor retains SDK but outer network shutdown/Kill destroys it; 9 explicit-config programs compare real SDK/bridge cleanup and new identities/keys across launches. CA/signature/body/import remain providers.')
if __name__=='__main__':main()
