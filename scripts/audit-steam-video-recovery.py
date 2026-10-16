#!/usr/bin/env python3
"""Audit selected instructions from Steam Link Android 1.3.32 ARM64.

Requires Python unicorn and the user-supplied, SHA-256-pinned libmain.so.
Executes original ELF instructions; external/platform/window helpers are stubbed.
Does not validate the whole client, Windows host, codec output or device display.
"""
import argparse,hashlib,json,struct
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *
ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binary',type=Path,default=ROOT/'build/video-recovery-re/libmain-arm64.so')
parser.add_argument('--output',type=Path,default=ROOT/'build/video-recovery-re/emulated-branches.json')
args=parser.parse_args()
BINARY=args.binary.read_bytes()
assert hashlib.sha256(BINARY).hexdigest()=='50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e'
STOP=0x40000000
class Run:
 def __init__(self,now=1000000):
  self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM); self.u.mem_map(0,0x1000000)
  off=struct.unpack_from('<Q',BINARY,32)[0];size,n=struct.unpack_from('<HH',BINARY,54)
  for i in range(n):
   typ,flags,p,v,_,fs,ms,al=struct.unpack_from('<IIQQQQQQ',BINARY,off+i*size)
   if typ==1:self.u.mem_write(v,BINARY[p:p+fs])
  self.u.mem_map(0x20000000,0x400000); self.u.mem_map(0x30000000,0x100000);self.u.mem_map(STOP,0x1000)
  self.u.reg_write(UC_ARM64_REG_SP,0x300ff000);self.u.reg_write(UC_ARM64_REG_TPIDR_EL0,0x20300000)
  self.u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20)
  self.u.reg_write(UC_ARM64_REG_X30,STOP)
  self.now=now;self.events=[];self.next=0x20100000;self.accept=False;self.releases=[]
  self.callbacks={};self.stop_at={}
  self.w32(0xf47988,3276);self.w32(0xf4798c,65)
  self.u.hook_add(UC_HOOK_CODE,self.hook)
 def r(self,i):return self.u.reg_read(UC_ARM64_REG_X0+i)
 def w(self,i,v):self.u.reg_write(UC_ARM64_REG_X0+i,v&0xffffffffffffffff)
 def q(self,p):return struct.unpack('<Q',self.u.mem_read(p,8))[0]
 def i(self,p):return struct.unpack('<I',self.u.mem_read(p,4))[0]
 def h(self,p):return struct.unpack('<H',self.u.mem_read(p,2))[0]
 def wq(self,p,v):self.u.mem_write(p,struct.pack('<Q',v))
 def w32(self,p,v):self.u.mem_write(p,struct.pack('<I',v&0xffffffff))
 def wh(self,p,v):self.u.mem_write(p,struct.pack('<H',v&65535))
 def b(self,p,v):self.u.mem_write(p,bytes([v]))
 def ret(self,v=0):self.w(0,v);self.u.reg_write(UC_ARM64_REG_PC,self.u.reg_read(UC_ARM64_REG_X30))
 def alloc(self,n):
  p=self.next;self.next+=(n+4095)&~4095;return p
 def packet(self,p,typ=3,stamp=999900,received=999900,retry=1,id=101):
  self.wq(p+40,p+64);self.wq(p+56,p+64);self.w32(p+48,2200);self.w32(p+52,13)
  self.w32(p+32,received);self.b(p+64,typ);self.b(p+65,retry);self.wh(p+71,id);self.w32(p+73,stamp)
 def hook(self,u,pc,size,_):
  if pc==STOP:u.emu_stop();return
  if pc in self.stop_at:self.stop_at[pc]();u.emu_stop();return
  if pc in self.callbacks:self.callbacks[pc]();return
  if pc==0xc0a950:self.ret(self.now)
  elif pc in (0xc09f90,0xc09990,0xc09f10,0xc09f30,0xbff250):self.ret()
  elif pc==0xc0e090:self.events.append({'event':'DataLost','media':self.r(1)});self.ret()
  elif pc==0xc0baa0:self.events.append({'event':'FrameComplete','id':self.r(2),'result':self.r(3)});self.ret()
  elif pc==0xbff420:self.ret(self.alloc(self.r(0)))
  elif pc==0xc10fd0:self.packet(self.r(0),0,0,0,0,0);self.ret()
  elif pc==0xc11170:
   p=self.r(2);n=self.i(p+52);self.events.append({'event':'SocketSend','hex':bytes(self.u.mem_read(self.q(p+56),n)).hex()});self.ret()
  elif pc==0xc11120:self.ret(0) # isolate UpdateUnreliableState's gap/feedback decisions
  elif pc==0xc11130:
   p,n=self.r(0),self.r(1);self.events.append({'event':'Advance','head':self.h(p+8),'count':n});self.wh(p+8,self.h(p+8)+n);self.ret()
  elif pc==0xc112b0:self.releases.append(self.r(1));self.ret()
  elif pc==0xc11270:self.events.append({'event':'PacketStats','count':self.r(2)});self.ret()
  elif pc==0xc0a390:self.ret(1)
  elif 0xbff000<=pc<0xc20000:raise AssertionError(f'unstubbed external call {pc:x}')
 def run(self,entry,*args):
  for i,v in enumerate(args):self.w(i,v)
  self.u.emu_start(entry,STOP+4,count=200000)
  assert self.u.reg_read(UC_ARM64_REG_PC) in self.stop_at or self.u.reg_read(UC_ARM64_REG_PC)==STOP

def decoder(label,hard=0,soft=0,seq=7,expected=7,key=False,age=0):
 r=Run();p=0x20000000;f=p+4096;packet=f+4096;data=packet+4096;vt=data+4096
 r.wq(p,vt);r.wq(vt+120,STOP+0x100);r.wq(p+8,p+0x8000)
 r.b(p+404,hard);r.b(p+405,soft);r.w32(p+408,r.now-age);r.wh(p+416,expected);r.wh(p+418,9)
 r.wq(f+8,packet);r.wq(packet+56,data);r.wh(f+26,10);r.wh(data+13,seq);r.b(data+15,16 if key else 0)
 r.b(0xf477f8,1);r.w32(0xf477f0,6553)
 def flush():r.events.append({'event':'FlushPending'});r.ret()
 r.callbacks[STOP+0x100]=flush
 r.stop_at[0x7b2170]=lambda:setattr(r,'accept',True)
 r.run(0x7b2000,p,f)
 return {'case':label,'accepted_for_assembly':r.accept,'hard':r.u.mem_read(p+404,1)[0],'soft':r.u.mem_read(p+405,1)[0],'events':r.events}

def gap(label,span=100,receive_age=100,retry=1,srtt=10,extra_packet=False):
 r=Run();p=0x20000000;conn=p+4096;ptr=conn+4096;times=ptr+4096;packet=times+4096
 r.wq(p+8,conn);r.b(p+16,3);r.w32(p+28,6553);r.b(p+176,1)
 r.w32(p+180,999900);r.w32(p+184,r.now-20)
 r.u.mem_write(conn+732,struct.pack('<f',srtt));r.wh(conn+12,12)
 r.w32(p+284,7);r.wh(p+288,100);r.wh(p+290,102);r.wq(p+296,ptr);r.wq(p+304,times)
 r.w32(times+(100&7)*4,999900-span);r.w32(times+(101&7)*4,999900)
 r.packet(packet,stamp=999900,received=r.now-receive_age,retry=retry);r.wq(ptr+(101&7)*8,packet)
 if extra_packet:
  r.wh(p+290,104);r.packet(packet+4096,id=103,stamp=999900,received=r.now-receive_age,retry=retry)
  r.wq(ptr+(103&7)*8,packet+4096);r.w32(times+(103&7)*4,999900)
 r.run(0x7fa3b0,p,r.now)
 return {'case':label,'head_after':r.h(p+288),'dirty_after':r.u.mem_read(p+176,1)[0],'events':r.events}

def handle_nack(label,age=2000):
 r=Run();p=0x20000000;state=p+176;conn=p+4096;ptr=conn+4096;feedback=ptr+4096
 r.wq(p+8,conn);r.u.mem_write(conn+732,struct.pack('<f',10))
 r.w32(state+76,7);r.wh(state+80,100);r.wh(state+82,104);r.wq(state+88,ptr);r.wh(state+68,104)
 originals=[]
 for ident in range(100,104):
  pkt=feedback+4096*(ident-99);r.packet(pkt,id=ident,stamp=r.now-age);originals.append(pkt);r.wq(ptr+(ident&7)*8,pkt)
 r.packet(feedback,typ=10,id=101,stamp=r.now-10);r.w32(feedback+52,20)
 r.w32(feedback+64+13,r.now-100);r.wh(feedback+64+17,99);r.b(feedback+64+19,5)
 r.run(0x7f95dc,p,state,feedback)
 return {'case':label,'released':r.releases,'marked_for_resend':[100+i for i,pkt in enumerate(originals) if r.i(pkt+64+9)==0]}

def final_decode(label,backend=True,ok=False):
 r=Run();p=0x20000000;backend_obj=p+4096;vt=p+8192;player=p+12288;frame=p+16384
 r.wq(p+8,p+0x8000);r.wq(p+16,player);r.wq(player,vt)
 r.wq(p+624,backend_obj if backend else 0);r.wq(backend_obj,vt);r.wq(vt+48,STOP+0x200);r.wq(vt+72,STOP+0x208)
 r.w32(p+396,1280);r.w32(p+400,720);r.w32(frame+20,1280);r.w32(frame+24,720)
 def decode():r.wq(r.r(4),frame);r.w32(r.r(5),7);r.ret(int(ok))
 def present():r.events.append({'event':'PutVideoFrame'});r.ret()
 def reset():r.events.append({'event':'ResetVideoDecoder','synchronous':r.r(1)});r.ret()
 r.callbacks[STOP+0x200]=decode;r.callbacks[STOP+0x208]=present;r.callbacks[0xc0e7b0]=reset
 r.run(0x7b1088,p,10,r.now,0)
 return {'case':label,'events':r.events}

def send_window(label,force=False,age=1000):
 r=Run();p=0x20000000;conn=p+4096;ptr=conn+4096;times=ptr+4096;packet=times+4096
 r.wq(p+8,conn);r.u.mem_write(conn+732,struct.pack('<f',10))
 r.wh(p+244,101);r.w32(p+252,7);r.wh(p+256,100);r.wh(p+258,101);r.wq(p+264,ptr);r.wq(p+272,times)
 r.wq(ptr+(100&7)*8,packet);r.w32(times+(100&7)*4,r.now-age);r.packet(packet,id=100,stamp=0)
 r.b(0xf479a8,1);r.w32(0xf479a0,13107)
 r.run(0x7f8cbc,p,int(force))
 return {'case':label,'head_after':r.h(p+256),'events':r.events}

def overflow(label,span=9830,hard=0,soft=0,previous=0):
 r=Run();p=0x20000000;nodes=p+4096
 r.wq(p+8,p+8192);r.b(p+404,hard);r.b(p+405,soft);r.w32(p+412,previous)
 r.wq(p+424,nodes);r.w32(p+440,0);r.w32(p+444,1);r.w32(p+452,2)
 r.wh(nodes+2,10);r.w32(nodes+4,100000);r.wh(nodes+42,11);r.w32(nodes+44,100000+span)
 r.b(0xf47808,1);r.w32(0xf47800,9830)
 def notify():r.events.append({'event':'VideoOverflow','first':r.r(1),'last':r.r(2)});r.ret()
 r.callbacks[0xc0e6a0]=notify
 r.run(0x7b2854,p)
 return {'case':label,'hard':r.u.mem_read(p+404,1)[0],'soft':r.u.mem_read(p+405,1)[0],'events':r.events}

results=[decoder('continuous'),decoder('hard_wait',hard=1),decoder('soft_sync_continuous',soft=1),decoder('soft_sync_gap',soft=1,seq=8),decoder('keyframe_clears_both',hard=1,soft=1,key=True,seq=20),decoder('retry_before_boundary',hard=1,age=6553),decoder('retry_after_boundary',hard=1,age=6554),gap('young_gap_feedback'),gap('recent_first_send_defers_feedback',receive_age=64),gap('retransmitted_packet_no_initial_delay',receive_age=0,retry=2),gap('aged_gap_advance',span=8000)]
results += [gap('gap_age_equal_boundary',span=6946),gap('gap_age_over_boundary',span=6947),gap('same_span_higher_rtt_keeps_gap',span=8000,srtt=60),gap('initial_delay_equal_boundary',receive_age=65),gap('bitmap_received_101_and_103',extra_packet=True),handle_nack('nack_old_packets'),handle_nack('nack_packet_sent_after_feedback_echo',age=50),final_decode('backend_failed'),final_decode('backend_missing',backend=False),final_decode('backend_accepted',ok=True)]
results += [send_window('normal_tick_does_not_resend'),send_window('low_priority_may_resend',force=True),send_window('expired_unreliable_packet_is_retired',force=True,age=20000),send_window('retention_equal_boundary',force=True,age=14679),send_window('retention_over_boundary',force=True,age=14680)]
results += [overflow('overflow_equal_150ms_threshold'),overflow('overflow_over_150ms_threshold',span=9831),overflow('overflow_while_soft_sync',span=20000,soft=1),overflow('overflow_while_hard_wait',span=20000,hard=1),overflow('overflow_range_equal_previous',previous=2),overflow('overflow_range_below_previous',previous=3)]
assert results[0]['accepted_for_assembly'] and not results[1]['accepted_for_assembly']
assert results[2]['accepted_for_assembly'] and not results[3]['accepted_for_assembly']
assert results[4]['accepted_for_assembly'] and (results[4]['hard'],results[4]['soft'])==(0,0)
assert not results[5]['events'] and any(e['event']=='DataLost' for e in results[6]['events'])
assert any(e['event']=='SocketSend' for e in results[7]['events'])
assert not any(e['event']=='SocketSend' for e in results[8]['events'])
assert any(e['event']=='SocketSend' for e in results[9]['events'])
assert results[10]['head_after']>100
assert results[11]['head_after']==100 and results[12]['head_after']==101 and results[13]['head_after']==100
assert any(e['event']=='SocketSend' for e in results[14]['events'])
assert results[15]['events'][0]['hex'].endswith('05')
assert results[16]['released']==[101,103] and results[16]['marked_for_resend']==[100,102]
assert results[17]['released']==[101,103] and results[17]['marked_for_resend']==[]
assert [e['event'] for e in results[18]['events']]==['FrameComplete','DataLost']
assert [e['event'] for e in results[19]['events']]==['FrameComplete','ResetVideoDecoder']
assert [e['event'] for e in results[20]['events']]==['PutVideoFrame']
assert not results[21]['events'] and any(e['event']=='SocketSend' for e in results[22]['events'])
assert results[23]['head_after']==101 and not any(e['event']=='SocketSend' for e in results[23]['events'])
assert results[24]['head_after']==100 and results[25]['head_after']==101
assert results[26]['soft']==0 and [e['event'] for e in results[26]['events']]==['VideoOverflow']
assert results[27]['soft']==1 and results[27]['hard']==0 and [e['event'] for e in results[27]['events']]==['DataLost','VideoOverflow']
assert not results[28]['events'] and not results[29]['events']
assert results[30]['events'] and not results[31]['events']
args.output.parent.mkdir(parents=True,exist_ok=True)
args.output.write_text(json.dumps({'scope':'official ARM64 instructions with stubbed external/window helpers; no host, codec or display validation','cases':results},indent=2)+'\n')
print(json.dumps({'binary_sha256':hashlib.sha256(BINARY).hexdigest(),'checked_cases':len(results),'result':'passed','output':str(args.output)}))
