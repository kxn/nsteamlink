#!/usr/bin/env python3
"""Original SNS BInit/destructor followed by player SDK shutdown.

Execute BInit, transport destructor, SDL cleanup call sites 0x75cfc0/0x75cfc4,
SteamDatagramClient_Init/Kill and LibV13 getter. Transport storage/sequence,
SDK object create/destroy, Utils storage,
JSON/CA/certificate result, base64/buffer/string, module IO, locks/logs and
network-thread shutdown are providers. Final SDL/JNI cleanup is out of scope.
The transport alone retains an interface; the outer player explicitly kills
it. No actual SDK networking, trusted Steam certificate or Switch is executed.
"""
if not __debug__:raise SystemExit('Original audit requires assertions')
from pathlib import Path
import argparse,gzip,hashlib,importlib.util,json,struct
from unicorn import arm64_const as arm
ROOT=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('base',ROOT/'scripts/audit-steam-sns-message.py');base=importlib.util.module_from_spec(s);s.loader.exec_module(base)
T,SDK,UTILS,SVT,UVT,COUNT,CONFIG,RAW,CERT,STUN,MEM=[0x20010000+n*0x1000 for n in range(11)]
DEBUG,SETCONFIG,MANUAL,FACTORY,NETWORK,CERTIFICATE,AUTH,PING,UTILS_DESTROY=[base.STOP+n*0x100 for n in range(1,10)]
SDK_GLOBAL,UTILS_GLOBAL,POLICY_GLOBAL=0x2001b000,0x2001c000,0x2001d000
class Run(base.Machine):
 def __init__(self,binary,patch=False):
  self.events=[];self.input={};self.assertions=0;self.initializations=0;self.destructions=0;self.imports=0;self.certificates=0
  super().__init__(binary);self.u.reg_write(arm.UC_ARM64_REG_TPIDR_EL0,0x200f0000)
  self.patch_hits=0
  if patch:
   instruction=int.from_bytes(self.u.mem_read(0x75cfc4,4),'little')
   assert instruction&0xfc000000==0x94000000
   self.u.mem_write(0x75cfc4,bytes.fromhex('1f2003d5'))
  self.wq(0xc80810,COUNT);self.wq(0xc80448,CONFIG);self.wq(0xc80808,0xc46798)
  self.wq(0xc80ab0,SDK_GLOBAL);self.wq(0xc80ac0,UTILS_GLOBAL);self.wq(0xc80ab8,POLICY_GLOBAL)
  self.wq(SDK,SVT);self.wq(UTILS,UVT)
  for off,cb in [(104,DEBUG),(128,SETCONFIG),(216,MANUAL),(232,FACTORY),(240,NETWORK),(56,PING),(256,UTILS_DESTROY)]:self.wq(UVT+off,cb)
  for off,cb in [(312,CERTIFICATE),(176,AUTH)]:self.wq(SVT+off,cb)
 def r(self,n):return self.u.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
 def ret(self,v=0):self.u.reg_write(arm.UC_ARM64_REG_X0,v);self.u.reg_write(arm.UC_ARM64_REG_PC,self.r(30))
 def text(self,p):return bytes(self.u.mem_read(p,4096)).split(b'\0',1)[0].decode() if p else ''
 def hook(self,u,pc,size,data):
  if pc==0x75cfc4:self.patch_hits+=1
  if pc==base.STOP:return super().hook(u,pc,size,data)
  c=self.input
  if pc==0xc115e0:self.events.append('utils');self.wq(UTILS_GLOBAL,UTILS);return self.ret(UTILS)
  if pc==0xc115f0:return u.reg_write(arm.UC_ARM64_REG_PC,0x80e750)
  if pc==0x80e750:self.events.append(['sockets',bool(self.q(SDK_GLOBAL))])
  if pc==0xc11600:return u.reg_write(arm.UC_ARM64_REG_PC,0x80e8fc)
  if pc==0xc0aab0:
   self.events.append(['sdk-create',c.get('init',True)]);self.initializations+=1;return self.ret(SDK if c.get('init',True) else 0)
  if pc==0xc0aad0:self.events.append('sdk-destroy');self.destructions+=1;return self.ret()
  if pc in (0xc0ab50,0xc0ab90):return self.ret()
  if pc==UTILS_DESTROY:self.events.append('utils-destroy');return self.ret()
  if pc==0xc0a980:self.events.append('network-shutdown');return self.ret()
  if pc==0xc0a990:return u.reg_write(arm.UC_ARM64_REG_PC,0x80ea14)
  if pc==0x75cfc8:u.reg_write(arm.UC_ARM64_REG_PC,base.STOP);u.emu_stop();return
  if pc==DEBUG:self.events.append(['debug',self.r(1)]);return self.ret()
  if pc==SETCONFIG:
   self.events.append(['option',self.r(1),self.text(self.r(5)) if self.r(4)==4 else self.i(self.r(5))]);return self.ret(1)
  if pc==MANUAL:self.events.append(['manual',self.r(1)]);return self.ret()
  if pc==FACTORY:self.events.append('factory');return self.ret()
  if pc==NETWORK:
   self.imports+=1;self.events.append(['network',self.text(self.r(1))]);return self.ret(int(c.get('network',True)))
  if pc==CERTIFICATE:self.certificates+=1;self.events.append('certificate');return self.ret(int(c.get('certificate',True)))
  if pc==AUTH:self.events.append('authenticate');return self.ret(100)
  if pc==PING:self.events.append(['ping',u.reg_read(arm.UC_ARM64_REG_S0)]);return self.ret()
  if pc==0xc09c30:
   self.wq(self.r(0),self.r(1));self.events.append('clear-config');return self.ret()
  if pc==0xc09a90:return self.ret(len(self.text(self.r(0))))
  if pc==0xc09d10:return self.ret(1 if c.get('webrtc') else 0)
  if pc==0xc09de0:return self.ret(1)
  if pc==0xc0a430:self.wq(self.r(0),MEM);self.wi(self.r(0)+8,self.r(1));return self.ret()
  if pc==0xc09c00:
   self.events.append('decode');self.wi(self.r(3),1);u.mem_write(self.r(2),b'X');return self.ret(int(c.get('decode',True)))
  if pc in (0xc09f90,0xc09990,0xc0b870,0xc09e70):return self.ret()
  if pc==0xc097e0:self.assertions+=1;return self.ret(1)
  assert (0x7ffd30<=pc<0x800100 or 0x7ffa8c<=pc<0x7ffb60 or 0x80e8fc<=pc<0x80e988 or 0x80ea14<=pc<0x80eaa4 or 0x75cfc0<=pc<0x75cfc8 or 0x80e750<=pc<0x80e760),hex(pc)
 def call(self,pc):
  self.u.reg_write(arm.UC_ARM64_REG_X0,T);self.u.reg_write(arm.UC_ARM64_REG_SP,0x300ff000);self.u.reg_write(arm.UC_ARM64_REG_X30,base.STOP)
  self.u.emu_start(pc,base.STOP+4,count=100000);assert self.u.reg_read(arm.UC_ARM64_REG_PC)==base.STOP
  return self.r(0)
 def attempt(self,action):
  self.input=action;self.events=[]
  self.u.mem_write(T,bytes(512));self.u.mem_write(CERT,b'\0' if action.get('empty_cert') else b'AA==\0');self.u.mem_write(STUN,b'stun:fixture.invalid\0')
  self.u.mem_write(RAW,action['data'].encode()+b'\0');self.wq(CONFIG,RAW)
  self.wq(T+32,CERT if action.get('has_cert',True) else 0);self.wq(T+40,STUN if action.get('stun') else 0)
  result=bool(self.call(0x7ffd30));before=dict(instances=self.i(COUNT),initialized=bool(self.q(SDK_GLOBAL)))
  self.call(0x7ffa8c);transport=dict(instances=self.i(COUNT),initialized=bool(self.q(SDK_GLOBAL)))
  self.call(0x75cfc0)
  return dict(result=result,before=before,transport=transport,initialized=bool(self.q(SDK_GLOBAL)),
   instances=self.i(COUNT),initializations=self.initializations,destructions=self.destructions,
   imports=self.imports,certificates=self.certificates,pending=self.text(self.q(CONFIG)),
   events=self.events[:],assertions=self.assertions)
def programs():
 for name,settings in [('normal',{}),('init-failure',{'init':False}),('bad-config',{'network':False}),('bad-cert',{'certificate':False}),('bad-base64',{'decode':False}),('no-cert',{'has_cert':False}),('empty-cert',{'empty_cert':True}),('with-stun',{'stun':True}),('with-webrtc',{'webrtc':True})]:
  for explicit in (False,True):
   data='public-config' if explicit else ''
   actions=[dict(data=data,generation=0,**settings),dict(data=data,generation=1),dict(data=data,generation=0)]
   yield dict(name=name+'-'+str(explicit),actions=actions)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',required=True,type=Path);p.add_argument('--output',required=True,type=Path);p.add_argument('--refresh-reference',action='store_true');a=p.parse_args()
 raw=a.binary.read_bytes();assert hashlib.sha256(raw).hexdigest()==base.SHA
 out=[]
 for program in programs():
  m=Run(raw);program['observed']=[m.attempt(action) for action in program['actions']];assert not m.assertions;out.append(program)
 normal=next(c for c in out if c['name']=='normal-True')
 mutant=Run(raw,True);changed=[mutant.attempt(action) for action in normal['actions']]
 assert not mutant.assertions and mutant.patch_hits==3 and changed!=normal['observed']
 report=dict(schema=1,binary_sha256=base.SHA,scope=__doc__,cases=out,
  mutation=dict(address='0x75cfc4',hits=mutant.patch_hits,original=normal['observed'],mutant=changed),
  helpers={name:hashlib.sha256((ROOT/'scripts'/name).read_bytes()).hexdigest() for name in [Path(__file__).name,'audit-steam-sns-message.py']})
 data=gzip.compress(json.dumps(report,sort_keys=True,separators=(',',':')).encode(),mtime=0);a.output.write_bytes(data)
 ref=ROOT/'scripts/fixtures/steam-sns-lifetime-reference.json.gz'
 if a.refresh_reference:ref.write_bytes(data)
 else:assert data==ref.read_bytes()
 print('PASS',len(out),'original repeated SNS lifetimes')
if __name__=='__main__':main()
