#!/usr/bin/env python3
"""Pinned unknown-host pairing producer and shared state3/state4 authorization.

Whole original OnPairingStarted, authorization request protobuf/ticket/AES,
BProcess/parser, auth crypto/cache/save/confirm/Stop and delegate callers execute.
Clock, identity/entropy, request RSA, metadata lookup, file syscalls, Qt/delegates,
service publication and final SendMessage are explicit providers. Sends are
manager CALLS, not an original final UDP/CM sender/interop proof. Current key and
cache survive replacements; a controlled usable hint exercises cancel10 with ID0.
"""
import argparse
import ast
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

if not __debug__:
    raise SystemExit('Original-instruction audit requires assertions; do not use Python -O')
ROOT=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('metadata',ROOT/'scripts/audit-steam-account-metadata.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
REFERENCE=ROOT/'scripts/fixtures/steam-service-pairing-reference.json.gz'
PAIRED, CODE, FAILED, KNOWN_PIN=0x40000300,0x40000308,0x40000310,0x40000318

class Service(m.Metadata):
    def __init__(self,binary):
        self.preparing=False;self.secret_draws=[];self.publications=[];self.service_notifications=[]
        self.secret_draw_index=0
        super().__init__(binary,False)
        self.session=self.alloc(128);self.wq(self.manager+24,self.session)
        self.wi(self.session+24,5);self.wi(self.session+16,1)
        table,delegate,rows=self.alloc(64),self.alloc(64),self.alloc(8)
        self.wq(delegate,table);self.wq(rows,delegate)
        self.wq(self.manager+384,rows);self.wi(self.manager+400,1)
        self.wq(table+16,CODE);self.wq(table+24,PAIRED);self.wq(table+32,KNOWN_PIN);self.wq(table+48,FAILED)
        self.hint=self.q(self.manager+0x120)
        for name in ('_ZN14CServerManager16OnPairingStartedEj', m.HANDLER):
            self.function_entries.setdefault(self.symbols[name], []).append(name)

    def boundary(self):
        out=super().boundary()
        out['secret']=bytes(self.u.mem_read(self.q(self.manager+0x218),self.i(self.manager+0x22c))).hex()
        return out

    def hook(self,u,pc,size,data):
        name=self.plts.get(pc,'')
        if pc in (PAIRED,CODE,FAILED,KNOWN_PIN):
            if pc==FAILED:self.errors.append(self.r(1))
            if pc!=KNOWN_PIN:
                self.service_notifications.append(dict(kind={PAIRED:'paired',CODE:'code',FAILED:'failed'}[pc],
                    client=self.r(1) if pc==PAIRED else 0,error=self.r(1) if pc==FAILED else 0,
                    state=self.i(self.manager+8),rid=self.i(self.manager+512)))
            return self.ret()
        if (name=='_ZN7CCrypto19GenerateRandomBlockEPvm' and self.preparing and self.r(1)==32
                and self.r(0)==self.q(self.manager+0x218)):
            secret=bytes(range(32)) if self.secret_draw_index==0 else bytes(range(64,96))
            self.secret_draw_index+=1;self.secret_draws.append(secret.hex())
            u.mem_write(self.r(0),secret);return self.ret(1)
        if name=='_ZN20CRemoteClientSession14SetPairingInfoEyPN6google8protobuf7MessageE':
            assert self.r(1)==m.admission.life.m.e.DID
            self.publications.append(self.freeze(self.r(2),128));return self.ret()
        return super().hook(u,pc,size,data)

    def prepare(self,pin,rid=None):
        if rid is not None:self.wi(self.manager+512,rid)
        self.wi(self.manager+8,2);self.preparing=True;self.secret_draw_index=0
        self.call(self.symbols['_ZN14CServerManager16OnPairingStartedEj'],self.manager,int(pin))
        self.preparing=False
        assert self.i(self.manager+8)==3

    def service_snapshot(self):
        observed=self.observe('service')
        out=self.observe_metadata()
        out.update(state=self.i(self.manager+8),rid=self.i(self.manager+512),
            secret=bytes(self.u.mem_read(self.q(self.manager+0x218),self.i(self.manager+0x22c))).hex(),
            cache=bytes(self.u.mem_read(self.q(self.manager+0x2d8),self.i(self.manager+0x2ec))).hex(),
            cached_result=self.i(self.manager+0x318),derived=self.derive_count,failures=len(self.errors),
            secret_draws=list(self.secret_draws),notifications=list(self.service_notifications),
            tickets=list(self.tickets),publications=[self.serialize(p,'CMsgRemoteDeviceAuthorizationRequest').hex() for p in self.publications],
            messages=[dict(tag=row['tag'],body=row['body']) for row in observed['messages']],
            saved_keys=[{k:row[k] for k in ('client','steamid','secret')}
                        for row in self.timeline if row['op']=='save_key'],
            token_calls=list(self.token_calls),keypairs=observed['keypair_generations'],
            send_states=list(self.send_states),persist_states=list(self.persist_states))
        return out

def packet(event,pin):
    v=m.admission.life.m.e.p.m.discovery.varint
    body=b'\x08'+v(event.get('result',0))
    if not event.get('absent'):body+=b'\x11'+struct.pack('<Q',event.get('account',m.A))
    if event.get('key'):
        key,token,_=m.admission.life.m.e.material(index=event.get('index',0),pin=event.get('key_pin',pin).encode(),
                   token_device=m.admission.life.m.e.DID+int(event.get('invalid',False)))
        if event.get('empty'):key=b''
        body+=b'\x1a'+v(len(key))+key+b'\x22'+v(len(token))+token
    client=event.get('client',456);header=b'\x08'+v(client)+b'\x10\x04'
    return b'\xff'*4+b'\x21\x4c\x5f\xa0'+struct.pack('<I',len(header))+header+struct.pack('<I',len(body))+body

def process(r,wire):
    buf,p,peer=r.alloc(128),r.alloc(len(wire)),r.alloc(24)
    r.u.mem_write(p,wire);r.u.mem_write(peer,bytes(range(1,25)))
    r.call(r.symbols['_ZN10CUtlBufferC1Ev'],buf)
    r.call(r.symbols['_ZN10CUtlBuffer3PutEPKvi'],buf,p,len(wire))
    return r.call(r.symbols[m.admission.life.PROCESS],r.manager,peer,buf,0)

def cases():
    prepare=dict(op='prepare',pin='1234')
    rows=[
      ('valid-late-key',[prepare,dict(key=True),dict(key=True,index=1)]),
      ('no-key',[prepare,dict()]),('no-key-zero',[prepare,dict(account=0)]),
      ('no-key-absent',[prepare,dict(absent=True)]),('key-zero',[prepare,dict(key=True,account=0)]),
      ('key-absent',[prepare,dict(key=True,absent=True)]),
      ('bad-then-good',[prepare,dict(key=True,invalid=True),dict(key=True,index=1)]),
      ('empty-key',[prepare,dict(key=True,empty=True)]),
      ('zero-client',[prepare,dict(key=True,client=0)]),
      ('exhaustion',[prepare]+[dict(key=True,invalid=True,index=i,account=m.A+i) for i in range(4)]),
      ('invalid-cache-replacement',[prepare,dict(key=True,invalid=True),prepare,dict(key=True)]),
      ('valid-cache-new-pin',[prepare,dict(key=True),dict(op='prepare',pin='1235'),
                             dict(key=True,key_pin='1234'),dict(key=True,index=1)]),
      ('cancel-late-key',[prepare,dict(op='cancel'),dict(key=True)]),
      ('residual-id',[dict(op='prepare',pin='0000',rid=27),dict(key=True)]),
      ('known-then-service',[dict(op='known'),dict(key=True,client=123,key_pin='0042'),prepare,
                            dict(key=True,key_pin='0042'),dict(key=True,index=1)]),
      ('service-then-known',[prepare,dict(key=True),dict(op='known'),
                            dict(key=True,client=123,key_pin='1234'),dict(key=True,client=123,index=1,key_pin='0042')]),
    ]
    rows += [(f'result-{i}',[prepare,dict(result=i,key=True)]) for i in range(1,9)]
    return [(name,hint,ops) for hint in (False,True) for name,ops in rows]

def run(binary,name,hint,ops):
    r=Service(binary);steps=[r.service_snapshot()];inputs=[];pin='1234'
    for op in ops:
        if op.get('op')=='prepare':
            pin=op['pin'];r.prepare(pin,op.get('rid'));inputs.append(dict(command='prepare',pin=pin,rid=op.get('rid')))
        elif op.get('op')=='known':
            r.wq(r.manager+0x120,r.hint)
            r.begin(False);inputs.append(dict(command='known'));pin='0042'
        elif op.get('op')=='cancel':
            r.call(r.symbols['_ZN14CServerManager13StopStreamingE12EServerError'],r.manager,0)
            inputs.append(dict(command='cancel'))
        else:
            wire=packet(op,pin);result=process(r,wire)
            inputs.append(dict(command='packet',wire=wire.hex(),result=result))
        # The original fixture supplies a named hint; vary its usability only
        # for state3's Stop caller. This is controlled metadata, not reachability.
        if op.get('op')=='prepare':r.wq(r.manager+0x120,r.hint if hint else 0)
        steps.append(r.service_snapshot())
    assert not r.assertions
    result=dict(name=name,hint=hint,inputs=inputs,steps=steps,executed=sorted(r.executed),source_assertions=r.assertions)
    verify(result)
    return result

def verify(case):
    steps=case['steps'];last=steps[-1];name=case['name']
    assert '_ZN14CServerManager16OnPairingStartedEj' in case['executed']
    assert not case['source_assertions']
    if name=='zero-client':
        assert m.HANDLER not in case['executed'] and case['inputs'][-1]['result']==0
    else:assert m.HANDLER in case['executed']
    for i,event in enumerate(case['inputs']):
        if event['command']=='prepare':
            before,after=steps[i],steps[i+1]
            assert after['state']==3 and after['rid']==(before['rid'] if event['rid'] is None else event['rid'])
            assert after['cache']==before['cache'] and after['cached_result']==before['cached_result']
            assert after['secret']==bytes(range(64,96)).hex()
            assert after['secret_draws'][-2:]==[bytes(range(32)).hex(),bytes(range(64,96)).hex()]
            assert after['keypairs']==before['keypairs']+1
    if name=='no-key':assert last['state']==1 and len(last['saved_keys'])==1 and last['saved_keys'][0]['secret']==steps[1]['secret']
    if name=='valid-cache-new-pin':
        assert steps[4]['state']==3 and steps[4]['derived']==steps[2]['derived']==1
        assert steps[4]['secret']==steps[3]['secret'] and len(steps[4]['saved_keys'])==1
    if name=='exhaustion':
        assert last['state']==1 and last['derived']==3 and last['failures']==1
        assert last['notifications'][-1]['kind']=='failed' and last['notifications'][-1]['state']==3
        assert last['send_states'][-1]['tag']==14 and last['send_states'][-1]['state']==1
    if name=='residual-id':assert steps[1]['rid']==27 and last['rid']==0

def helpers():
    pending=[Path(__file__).name];out={}
    while pending:
        name=pending.pop()
        if name in out:continue
        data=(ROOT/'scripts'/name).read_bytes();out[name]=hashlib.sha256(data).hexdigest()
        for n in ast.walk(ast.parse(data)):
            if isinstance(n,ast.Constant) and isinstance(n.value,str):
                dep=Path(n.value).name
                if dep.startswith('audit-steam-') and dep.endswith('.py') and (ROOT/'scripts'/dep).is_file():pending.append(dep)
    return dict(sorted(out.items()))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--refresh-reference',action='store_true');a=p.parse_args()
    binary=a.binary.read_bytes();assert hashlib.sha256(binary).hexdigest()==m.SHELL_SHA
    output=[]
    for name,hint,ops in cases():
        output.append(run(binary,name,hint,ops));print(name,hint,flush=True)
    report=dict(schema=1,binary_sha256=m.SHELL_SHA,scope=__doc__,helpers=helpers(),cases=output)
    raw=gzip.compress(json.dumps(report,sort_keys=True,separators=(',',':')).encode(),mtime=0);a.output.write_bytes(raw)
    if a.refresh_reference:REFERENCE.write_bytes(raw)
    else:assert raw==REFERENCE.read_bytes()
    print(f'PASS {len(output)} whole service pairing producer/parser/crypto/Stop traces')
if __name__=='__main__':main()
