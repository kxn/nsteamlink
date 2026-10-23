#!/usr/bin/env python3
"""Original SDR BeginFetch/Completed/Failed/GetURL with shared state.

Config parser/import, HTTP factory/submit/header storage, callback storage,
URL formatting, logs/locks/status notification are providers. Original WebAPI
base selection, state,
attempt counter, retry/refresh gating, realm selection and request exclusion
execute. Headers describe the abstract request, not guaranteed wire headers.
"""
import argparse,gzip,hashlib,importlib.util,json,re
from pathlib import Path
from unicorn import arm64_const as arm
if not __debug__:raise SystemExit('Original audit requires assertions')
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('packet',ROOT/'scripts/audit-steam-sns-message.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
U,VT,AV,LEVEL,MSG,PING,UNIVERSE,REALM,CHINA=[0x20080000+n*0x1000 for n in range(9)]
APP,FACTORY,SUBMIT=[base.STOP+n*0x100 for n in range(1,4)]
CURRENT,COUNT=0xf49598,0xf495a0
class Run(base.Machine):
 def __init__(self,binary,available=False,attempts=0,state=None):
  self.next=0x20010000;self.requests=[];self.parsed=False;self.events=[];self.assertions=0
  super().__init__(binary);self.u.reg_write(arm.UC_ARM64_REG_TPIDR_EL0,0x200f0000)
  self.wq(U,VT);self.wq(VT+264,APP);self.wq(VT+312,FACTORY)
  for off,p in [(0xa80,AV),(0x888,LEVEL),(0xa88,MSG),(0xb58,PING),(0xa90,UNIVERSE),(0xaa0,REALM),(0xaa8,CHINA)]:self.wq(0xc80000+off,p)
  self.wi(AV,(state if state is not None else 100 if available else 1)&0xffffffff);self.wi(PING,100);self.wi(UNIVERSE,1);self.wi(REALM,1)
  self.wq(CURRENT,0);self.wi(COUNT,attempts)
 def r(self,n):return self.u.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
 def ret(self,v=0):
  self.u.reg_write(arm.UC_ARM64_REG_X0,v);self.u.reg_write(arm.UC_ARM64_REG_PC,self.u.reg_read(arm.UC_ARM64_REG_X30))
 def alloc(self,n):
  p=self.next;self.next+=(n+15)//16*16;self.u.mem_write(p,bytes(n));return p
 def string(self,p,data):
  q=self.alloc(len(data)+1);self.u.mem_write(q,data+b'\0');self.wq(p,1);self.wq(p+8,len(data));self.wq(p+16,q)
 def cstr(self,p):
  raw=bytes(self.u.mem_read(p,2048));return raw.split(b'\0',1)[0].decode()
 def hook(self,u,pc,size,data):
  if pc==base.STOP:return super().hook(u,pc,size,data)
  if pc==APP:return self.ret(353380)
  if pc==FACTORY:
   req=self.alloc(256);vt=self.alloc(64);self.wq(req,vt);self.wq(vt+32,SUBMIT)
   self.requests.append(dict(pointer=req,url=self.cstr(self.r(1)),headers=[],submitted=False))
   return self.ret(req)
  if pc==SUBMIT:
   self.requests[-1]['submitted']=True;return self.ret()
  if pc==0x828424:
   self.wq(self.r(0)+32,0);self.wq(self.u.reg_read(arm.UC_ARM64_REG_SP)+32,0);return self.ret()
  if pc==0xc127a0:return u.reg_write(arm.UC_ARM64_REG_PC,0x8214a0)
  if pc==0xc11da0:return u.reg_write(arm.UC_ARM64_REG_PC,0x8210b8)
  if pc==0xc127e0:return u.reg_write(arm.UC_ARM64_REG_PC,0x821938)
  if pc==0xc0a450:
   self.events.append(['realm',self.r(2)]);return u.reg_write(arm.UC_ARM64_REG_PC,0x75a8ac)
  if pc==0xc09ff0:
   dest,cap,fmt,baseurl,appid,suffix=[self.r(n) for n in range(6)]
   value=self.cstr(fmt).replace('%s',self.cstr(baseurl),1).replace('%u',str(appid),1).replace('%s',self.cstr(suffix),1).encode()
   assert len(value)<cap;u.mem_write(dest,value+b'\0');return self.ret(len(value))
  if pc==0xc127b0:
   self.requests[-1]['headers'].append([self.cstr(self.r(1)),self.cstr(self.r(2))]);return self.ret()
  if pc==0xc0aaf0:
   self.events.append(['parse',self.parsed])
   if self.parsed:self.wi(AV,100)
   return self.ret(int(self.parsed))
  if pc==0x81fbdc:self.events.append(['notify',self.signed(self.i(AV))]);return self.ret()
  if pc in (0xc097e0,0xc09b00):self.assertions+=1;return self.ret(1)
  if pc in (0xc11e20,0xc118a0,0xc09f60):return self.ret()
  assert (0x8210b8<=pc<0x8213c4 or 0x8214a0<=pc<0x8215d4 or 0x821938<=pc<0x821c80 or 0x75a8ac<=pc<0x75a96c),hex(pc)
 def call(self,pc,*args):
  for n,v in enumerate(args):self.u.reg_write(getattr(arm,'UC_ARM64_REG_X'+str(n)),v)
  self.u.reg_write(arm.UC_ARM64_REG_SP,0x300ff000);self.u.reg_write(arm.UC_ARM64_REG_X30,base.STOP)
  self.u.emu_start(pc,base.STOP+4,count=100000);assert self.u.reg_read(arm.UC_ARM64_REG_PC)==base.STOP
 @staticmethod
 def signed(v):return v if v<2**31 else v-2**32
 def step(self,action):
  self.events=[]
  if action[0]=='begin':self.call(0x8210b8,U,0,int(action[1]))
  else:
   assert self.q(CURRENT)
   self.parsed=action[2];response=self.alloc(128);self.wi(response,action[1]);self.string(response+8,b'fixture response')
   body=self.alloc(32);self.u.mem_write(body,b'{"fixture":true}');self.wq(response+32,body);self.wi(response+52,16)
   self.call(0x821b14,U,response)
  return dict(available=self.signed(self.i(AV)),completed=self.i(COUNT),active=bool(self.q(CURRENT)),
              requests=[{k:v for k,v in r.items() if k!='pointer'} for r in self.requests],events=self.events[:])
def programs():
 yield dict(name='first-success-refresh-fails',available=False,actions=[['begin',False],['complete',200,True],['complete',500,False]])
 yield dict(name='first-success-refresh-succeeds',available=False,actions=[['begin',False],['complete',200,True],['complete',200,True]])
 for status in [0,199,200,204,299,300,500]:
  yield dict(name='failure-or-parse-'+str(status),available=False,actions=[['begin',False],['complete',status,False],['complete',status,False],['complete',status,False]])
 yield dict(name='first-fails-second-succeeds',available=False,actions=[['begin',False],['complete',500,False],['complete',200,True]])
 yield dict(name='available-not-forced',available=True,actions=[['begin',False]])
 yield dict(name='available-forced-refresh-fails',available=True,actions=[['begin',True],['complete',500,False]])
 yield dict(name='single-request',available=False,actions=[['begin',False],['begin',False],['begin',True],['complete',200,True],['begin',True],['complete',500,False]])
 yield dict(name='explicit-retry-after-exhaustion',available=False,actions=[['begin',False],['complete',500,False],['complete',500,False],['complete',500,False],['begin',False],['complete',200,True]])
 yield dict(name='available-late-failure',available=True,attempts=2,actions=[['begin',True],['complete',500,False]])
 for count in [0x7fffffff,0x80000000,0xfffffffe,0xffffffff]:
  yield dict(name='signed-wrap-'+str(count),available=False,state=-101,attempts=count,actions=[['begin',False],['complete',500,False]])
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--refresh-reference',action='store_true');a=p.parse_args()
 binary=a.binary.read_bytes();assert hashlib.sha256(binary).hexdigest()==base.SHA
 cases=[]
 for program in programs():
  m=Run(binary,program['available'],program.get('attempts',0),program.get('state'));steps=[m.step(v) for v in program['actions']];assert not m.assertions,(program,m.assertions)
  cases.append(dict(input=program,observed=steps));print(program['name'],[(s['available'],s['completed'],s['active'],len(s['requests'])) for s in steps])
 report=dict(schema=1,binary_sha256=base.SHA,scope=__doc__,cases=cases,helpers={n:hashlib.sha256((ROOT/'scripts'/n).read_bytes()).hexdigest() for n in [Path(__file__).name,'audit-steam-sns-message.py']})
 raw=gzip.compress(json.dumps(report,sort_keys=True,separators=(',',':')).encode(),mtime=0);a.output.write_bytes(raw)
 ref=ROOT/'scripts/fixtures/steam-config-fetch-reference.json.gz'
 if a.refresh_reference:ref.write_bytes(raw)
 else:assert raw==ref.read_bytes()
 print('PASS',len(cases),'original shared config fetch programs')
if __name__=='__main__':main()
