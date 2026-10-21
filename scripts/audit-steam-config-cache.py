#!/usr/bin/env python3
"""Original raw cache load/save and Shell curl request lifecycle.

SDL file/IO, CUtlBuffer allocation/termination/seek, curl/mutex/string/function
storage, logging and final callback are explicit providers. Original load/save
branches, option selection and completion status/callback guards execute.
No real filesystem/network, Shell BInit/Qt loop, SDK or stream is executed.
"""
if not __debug__:raise SystemExit('Original audit requires assertions')
from pathlib import Path
import argparse,gzip,importlib.util,hashlib,io,json,struct
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
ROOT=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('base',ROOT/'scripts/audit-steam-sns-message.py');base=importlib.util.module_from_spec(s);s.loader.exec_module(base)
SHA='15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2'
O,B,F,CB,VT,FUN,STR= [0x20010000+i*0x1000 for i in range(7)]
class Run(base.Machine):
 def __init__(self,binary):
  super().__init__(binary);self.u.reg_write(arm.UC_ARM64_REG_TPIDR_EL0,0x200f0000)
  e=ELFFile(io.BytesIO(binary));d=e.get_section_by_name('.dynsym');p=e.get_section_by_name('.plt');self.plts={p['sh_addr']+32+i*16:d.get_symbol(r['r_info_sym']).name for i,r in enumerate(e.get_section_by_name('.rela.plt').iter_relocations())}
  self.events=[];self.options=[];self.file=b'old';self.opened=True;self.dirs=True;self.closed=True;self.read_count=3;self.write_count=3;self.calls=0
  self.u.mem_write(STR,b'/fixture/sdr_config.txt\0');self.wq(B,F);self.wi(B+20,3)
 def r(self,n):return self.u.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(n)))
 def ret(self,v=0):self.u.reg_write(arm.UC_ARM64_REG_X0,v);self.u.reg_write(arm.UC_ARM64_REG_PC,self.r(30))
 def cstr(self,p):return bytes(self.u.mem_read(p,4096)).split(b'\0',1)[0].decode()
 def hook(self,u,pc,size,data):
  if pc==base.STOP:return super().hook(u,pc,size,data)
  name=self.plts.get(pc,'')
  if name=='SDL_IOFromFile':self.events.append(['open',self.cstr(self.r(1))]);return self.ret(O if self.opened else 0)
  if name=='SDL_GetIOSize':return self.ret(len(self.file))
  if name=='SDL_ReadIO':
   n=min(self.read_count,self.r(2));u.mem_write(self.r(1),self.file[:n]);self.events.append(['read',self.r(2),n]);return self.ret(n)
  if name=='SDL_WriteIO':self.events.append(['write',bytes(u.mem_read(self.r(1),self.r(2))).hex()]);return self.ret(self.write_count)
  if name=='SDL_CloseIO':self.events.append(['close']);return self.ret(int(self.closed))
  if name=='_ZN10CUtlBuffer18AddNullTerminationEv':return self.ret()
  if name=='_ZN10CUtlBuffer14EnsureCapacityEi':self.wq(self.r(0),F);return self.ret()
  if name=='_ZN10CUtlBuffer7SeekPutENS_10SeekType_tEi':self.wi(self.r(0)+20,self.r(2));return self.ret()
  if name=='_Z17BCreateDirsInPath10StringView':self.events.append(['dirs']);return self.ret(int(self.dirs))
  if name in ('Log','pthread_mutex_lock','pthread_mutex_unlock','_ZN11CWebRequest7CleanupEv'):return self.ret()
  if name=='_ZN10CUtlString8SetValueEPKc':return self.ret()
  if name=='strncmp':return self.ret(0 if self.cstr(self.r(0)).startswith('wss://') else 1)
  if pc==0xfa0ab8:return self.ret(FUN)
  if pc==0xfd1080:self.options.append([self.r(1),self.r(2)]);return self.ret()
  if pc in (0xcc2db8,0xfa0df8):return self.ret()
  if pc==0xfc3c14:return self.ret()
  if pc==0xfd3668:return self.ret(STR)
  if pc==base.STOP+0x100:self.calls+=1;return self.ret()
  assert (0xca75f4<=pc<0xca76bc or 0xca7998<=pc<0xca7a28 or 0xcc2078<=pc<0xcc2348 or 0xcc1a78<=pc<0xcc1b58),hex(pc)
 def call(self,pc,*args):
  for n,v in enumerate(args):self.u.reg_write(getattr(arm,'UC_ARM64_REG_X'+str(n)),v)
  self.u.reg_write(arm.UC_ARM64_REG_SP,0x300ff000);self.u.reg_write(arm.UC_ARM64_REG_X30,base.STOP)
  self.u.emu_start(pc,base.STOP+4,count=100000);assert self.u.reg_read(arm.UC_ARM64_REG_PC)==base.STOP
  return self.r(0)
def generate(binary):
 out=[]
 for op in ('load','save'):
  for state in ('success','missing','close-failed','partial','empty','zero-io','dirs-failed'):
   m=Run(binary);m.file=b'old' if state!='empty' else b'';m.read_count=0 if state=='zero-io' else 1 if state=='partial' else len(m.file);m.write_count=m.read_count
   m.opened=state!='missing';m.closed=state!='close-failed';m.dirs=state!='dirs-failed';m.u.mem_write(F,m.file+b'\0');m.wi(B+20,len(m.file))
   ok=m.call(0xca75f4 if op=='load' else 0xca7998,STR,B)
   out.append(dict(kind=op,input=state,ok=bool(ok),events=m.events,length=m.i(B+20)))
 m=Run(binary);m.u.mem_write(STR,b'https://api.steampowered.com/ISteamApps/GetSDRConfig/v1?appid=353380\0');m.wq(O,VT)
 ok=m.call(0xcc2078,O,STR,0,CB)
 out.append(dict(kind='start',ok=bool(ok),status=m.i(O+8),options=[v for v in m.options if v[0]<10000]))
 for streaming in (False,True):
  for result in (0,6,7,22,28,35,56,60):
   for released in (False,True):
    m=Run(binary);m.u.mem_write(O+32,bytes([streaming]));m.u.mem_write(O+12,bytes([released]));m.wq(O+160,CB);m.wq(CB,VT);m.wq(VT+48,base.STOP+256)
    m.call(0xcc1a78,O,result,503)
    out.append(dict(kind='complete',curl=result,http=503,streaming=streaming,released=released,status=m.i(O+8),calls=m.calls))
 return out
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--refresh-reference',action='store_true');a=p.parse_args()
 binary=a.binary.read_bytes();assert hashlib.sha256(binary).hexdigest()==SHA
 cases=generate(binary)
 report=dict(schema=1,binary_sha256=SHA,scope=__doc__,cases=cases,helpers={n:hashlib.sha256((ROOT/'scripts'/n).read_bytes()).hexdigest() for n in [Path(__file__).name,'audit-steam-sns-message.py']})
 raw=gzip.compress(json.dumps(report,sort_keys=True,separators=(',',':')).encode(),mtime=0);a.output.write_bytes(raw)
 ref=ROOT/'scripts/fixtures/steam-config-cache-reference.json.gz'
 if a.refresh_reference:ref.write_bytes(raw)
 else:assert raw==ref.read_bytes()
 print('PASS',len(cases),'original cache/HTTP programs')
if __name__=='__main__':main()
