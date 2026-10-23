#!/usr/bin/env python3
"""Original Shell cache/HTTP rules vs real cache owner on a loopback server.

The original fixture uses explicit SDL/curl/buffer providers. Production uses
real files and libcurl, with only the URL redirected and write/publication
failures injected. This does not prove trust parsing, accepted certificates,
Shell Qt scheduling, actual Steam endpoints or Switch networking.
"""
import argparse,gzip,hashlib,json,os,subprocess,tempfile,threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
if not __debug__:raise SystemExit('Original comparison requires assertions')
ROOT=Path(__file__).resolve().parents[1]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--receiver',type=Path,required=True);a=p.parse_args()
 ref=json.loads(gzip.decompress((ROOT/'scripts/fixtures/steam-config-cache-reference.json.gz').read_bytes()))
 assert ref['schema']==1 and ref['binary_sha256']=='15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2'
 for name,digest in ref['helpers'].items():assert hashlib.sha256((ROOT/'scripts'/name).read_bytes()).hexdigest()==digest,name
 assert len(ref['cases'])==47
 start=next(c for c in ref['cases'] if c['kind']=='start');assert start['ok'] and start['status']==1
 options=dict(start['options']);assert options[52]==1 and options[45]==1
 loaded=next(c for c in ref['cases'] if c['kind']=='load' and c['input']=='success');assert loaded['ok'] and loaded['events'][0]==['open','rb']
 saved=next(c for c in ref['cases'] if c['kind']=='save' and c['input']=='success');assert saved['ok'] and saved['events'][1]==['open','wb']
 def completion(result):
  return next(c for c in ref['cases'] if c['kind']=='complete' and c['curl']==result and not c['streaming'] and not c['released'])
 assert completion(0)['status']==4 and completion(0)['calls']==1
 assert completion(22)['status']==5 and completion(22)['calls']==1
 requests=[]
 class HTTP(BaseHTTPRequestHandler):
  def do_GET(self):
   requests.append(self.path)
   if self.path=='/redirect':
    self.send_response(302);self.send_header('Location','/created');self.send_header('Content-Length','0');self.end_headers();return
   status,body={'/ok':(200,b'new-config'),'/created':(201,b'new-config'),'/empty':(204,b''),
    '/bad':(503,b'error-page'),'/nul':(200,b'new\0tail'),'/large':(200,b'X'*(1024*1024+1)),
    '/invalid':(200,b'not-json')}[self.path]
   self.send_response(status);self.send_header('Content-Length',str(len(body)));self.end_headers()
   try:self.wfile.write(body)
   except (BrokenPipeError,ConnectionResetError):pass
  def log_message(self,*args):pass
 server=ThreadingHTTPServer(('127.0.0.1',0),HTTP);server.daemon_threads=True
 worker=threading.Thread(target=server.serve_forever);worker.start()
 cases=[
  ('missing-success',None,'/ok','none',None,b'new-config',b'new-config'),
  ('old-still-refresh',b'old','/ok','none',b'old',b'new-config',b'new-config'),
  ('old-503',b'old','/bad','none',b'old',b'old',b'old'),
  ('missing-503',None,'/bad','none',None,None,None),
  ('redirect-201',b'old','/redirect','none',b'old',b'new-config',b'new-config'),
  ('empty-response',b'old','/empty','none',b'old',b'',b''),
  ('write-fails',b'old','/ok','write',b'old',b'new-config',b'old'),
  ('publish-fails',b'old','/ok','rename',b'old',b'new-config',b'old'),
  ('cancel-pending',b'old','/ok','cancel',b'old',None,b'old'),
  ('nul-cache',b'old\0tail','/bad','none',b'old',b'old',b'old\0tail'),
  ('nul-response',b'old','/nul','none',b'old',b'new',b'new\0tail'),
  ('no-parser-at-shell',b'old','/invalid','none',b'old',b'not-json',b'not-json'),
  ('oversize-response',b'old','/large','none',b'old',b'old',b'old'),
  ('switch-overwrite',b'old','/ok','switch-rename',b'old',b'new-config',b'new-config'),
  ('switch-rollback',b'old','/ok','switch-publish-fails',b'old',b'new-config',b'old'),
  ('switch-recovery',None,'/ok','switch-recovery',b'old',b'new-config',b'new-config'),
  ('oversize-cache',b'X'*(1024*1024+1),'/bad','none',None,None,b'X'*(1024*1024+1)),
 ]
 try:
  for name,seed,path,fault,before,after,disk in cases:
   with tempfile.TemporaryDirectory(prefix='nsl-config-cache-') as directory:
    file=Path(directory)/'sdr_config.txt'
    if name=='switch-recovery':Path(str(file)+'.old').write_bytes(b'old')
    if seed is not None:file.write_bytes(seed);os.utime(file,(1,1)) # no invented TTL
    requests.clear()
    run=subprocess.run([str(a.receiver.resolve()),directory,f'http://127.0.0.1:{server.server_port}'+path,fault],capture_output=True,text=True,timeout=10)
    assert run.returncode==0,(name,run.returncode,run.stderr)
    rows=[json.loads(line) for line in run.stdout.splitlines()];assert rows[-1]=={'clean':True},(name,rows)
    assert rows[0]['stage']=='loaded' and rows[0]['data']==(before or b'').hex(),(name,rows)
    for row in rows[:-1]:assert row['follow']==options[52] and row['fail_http']==options[45],(name,row)
    if fault=='cancel':assert len(rows)==3 and all(row['active'] for row in rows[:-1]) and not requests
    else:
     assert len(rows)==5
     for row in [rows[1],rows[3]]:assert row['stage']=='complete' and not row['active'] and row['data']==(after or b'').hex(),(name,row)
     # Second owner reads whatever was actually published, rather than a stale in-process singleton.
     second=(disk or b'').split(b'\0',1)[0] if disk is not None and len(disk)<=1024*1024 else b''
     assert rows[2]['data']==second.hex(),(name,rows[2])
     assert len(requests)==(4 if path=='/redirect' else 2),(name,requests)
    assert (file.read_bytes() if file.exists() else None)==disk,name
    assert not Path(str(file)+'.tmp').exists(),name
    assert not Path(str(file)+'.old').exists(),name
    print('PASS',name)
 finally:
  server.shutdown();worker.join();server.server_close()
 print('PASS 47 original cache/HTTP programs and 17 production loopback/file sequences; repeated owners, no TTL, retained failed download, response independent of save, redirects/201/HTTP failures, cancellation and local 1MiB bounds')
if __name__=='__main__':main()
