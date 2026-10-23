#!/usr/bin/env python3
"""Execute original CertStore_CheckCert -> InternalSetCertificate -> CheckCertAppID.

Protobuf constructors/parsers/storage, CA signature result, key derivation,
revocation lookup, clock/config and final install/status/scheduler endpoints
are providers. The original parse-before/after-CA ordering, null-scope caller,
identity/key/AppID gates and final return execute. No actual signature verifier,
protobuf parser, SDK network, Steam certificate or Switch is executed here.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
from unicorn import arm64_const as arm

if not __debug__: raise SystemExit('Original audit requires assertions')
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('packet', Path(__file__).with_name('audit-steam-sns-message.py'))
base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
SDK, UTILS, UVT, SVT, SCOPE, LEVEL, GRACE, REVOKED = [0x20080000+n*0x1000 for n in range(8)]
GETTIME, GETAPP, IDENTITY, AUTH = [base.STOP+n*0x100 for n in range(1, 5)]

class Run(base.Machine):
    def __init__(self, binary, case, mutate=False):
        self.case = case; self.events = []; self.inner = self.outer = 0
        self.next = 0x20010000; self.private = case.get('preset_private', False)
        self.parsed = False; self.installed = 0; self.assertions = 0; self.scope_result = None
        super().__init__(binary)
        self.patch_hits = 0
        if mutate:
            # Deliberately model the discarded "CA failure may still parse" assumption.
            assert bytes(self.u.mem_read(0x8adec8, 4)) == bytes.fromhex('600300b4')
            self.u.mem_write(0x8adec8, bytes.fromhex('1f2003d5'))
        self.u.reg_write(arm.UC_ARM64_REG_TPIDR_EL0, 0x200f0000)
        self.wq(SDK, SVT); self.wq(SDK+8, UTILS); self.wq(UTILS, UVT)
        self.wq(UVT+272, GETTIME); self.wq(UVT+264, GETAPP)
        self.wq(SVT+440, IDENTITY); self.wq(SVT+424, AUTH)
        self.wq(0xc80888, LEVEL); self.wi(LEVEL, 5)
        self.wq(0xc80e80, GRACE); self.wi(GRACE, 0)
        self.wq(SCOPE+0x38, 1); self.wi(SCOPE+0x50, 0xffffffff)
        self.wi(REVOKED, 0xfffffffd)
        self.u.mem_write(SDK+0xf0, bytes(range(32)))

    def r(self, n): return self.u.reg_read(getattr(arm, 'UC_ARM64_REG_X'+str(n)))
    def ret(self, n=0):
        self.u.reg_write(arm.UC_ARM64_REG_X0, n)
        self.u.reg_write(arm.UC_ARM64_REG_PC, self.u.reg_read(arm.UC_ARM64_REG_X30))
    def alloc(self, n):
        p = self.next; self.next += (n+15)//16*16; self.u.mem_write(p, bytes(n)); return p
    def string(self, data):
        p = self.alloc(24); q = self.alloc(len(data)+1)
        self.u.mem_write(q, data+b'\0'); self.wq(p, 1); self.wq(p+8, len(data)); self.wq(p+16, q)
        return p
    def hook(self, u, pc, size, unused):
        c = self.case
        if pc == 0x8adec8: self.patch_hits += 1
        if pc == base.STOP: return super().hook(u, pc, size, unused)
        if pc in (0x804958, 0x8ade88, 0x8ae240):
            self.events.append({0x804958:'import',0x8ade88:'check-cert',0x8ae240:'app-check'}[pc])
        if pc == 0x8adf34: self.scope_result = bool(self.r(0))
        if pc == GETTIME: return self.ret(1000)
        if pc == GETAPP: return self.ret(353380)
        if pc in (IDENTITY, AUTH): return self.ret()
        if pc == 0xc08b60:
            self.outer = self.r(0); u.mem_write(self.outer, bytes(160)); return self.ret()
        if pc == 0xc08b40:
            self.inner = self.r(0); u.mem_write(self.inner, bytes(128)); return self.ret()
        if pc == 0xc0a790:
            self.events.append('signed-parse')
            if c.get('signed_ok', True):
                self.wq(self.outer+32, self.string(b'cert-body'))
                self.wq(self.outer+48, self.string(bytes(64)))
                self.wq(self.outer+40, 123)
                if c.get('has_private', True):
                    self.wi(self.outer+16, 1); self.wq(self.outer+24, self.string(bytes(range(32))))
            return self.ret(int(c.get('signed_ok', True)))
        if pc == 0xc11930:
            return u.reg_write(arm.UC_ARM64_REG_PC, 0x8ade88)
        if pc == 0xc14bc0:
            self.events.append('ca-check'); return self.ret(SCOPE if c['ca_ok'] else 0)
        if pc == 0xc11bf0:
            self.events.append('body-parse')
            if c.get('body_ok', True):
                self.parsed = True
                self.wi(self.inner+16, 2); self.wq(self.inner+88, self.string(b'str:fixture'))
                self.wi(self.inner+112, c.get('key_type', 1))
                self.wq(self.inner+80, self.string(bytes(range(c.get('key_length', 32)))))
                self.wi(self.inner+120, 900 if c.get('expired') else 2000)
                apps = self.alloc(4); self.wi(apps, c.get('app', 353380))
                self.wi(self.inner+40, 1); self.wq(self.inner+48, apps)
            return self.ret(int(c.get('body_ok', True)))
        if pc == 0xc14a50:
            return self.ret(111 if c.get('key_length', 32)==32 else 0)
        if pc == 0x8acdb8: return self.ret(REVOKED if c.get('revoked') else 0)
        if pc == 0xc14bd0: return self.ret()
        if pc == 0xc11940:
            u.mem_write(self.r(0), bytes(136)); self.wi(self.r(0), 16)
            return self.ret(1)
        if pc == 0xc098f0: return self.ret(int(self.private))
        if pc == 0xc0a140: return self.ret(int(c.get('private_match', True)))
        if pc == 0xc11980:
            self.private = c.get('private_valid', True)
            if not c.get('public_match', True): u.mem_write(SDK+0xf0, bytes(32))
            return self.ret(int(self.private))
        if pc == 0xc11990: return u.reg_write(arm.UC_ARM64_REG_PC, 0x8ae240)
        if pc == 0xc119a0: self.installed += 1; return self.ret()
        if pc == 0xc119b0: self.installed += 1; return self.ret()
        if pc == 0xc118f0: return self.ret(0 if c.get('expired') else 100)
        if pc == 0xc097e0: self.assertions += 1; return self.ret(1)
        if pc == 0xc119c0: self.events.append('status-current'); return self.ret()
        if pc == 0xc119d0: return self.ret(1000000)
        if pc in (0xc09f60,0xc11910,0xc118a0,0xc11970,0xc08ba0,0xc08c20): return self.ret()
        assert (0x804958 <= pc < 0x804ed4 or 0x8ade88 <= pc < 0x8ae038 or
                0x8ae240 <= pc < 0x8ae490), hex(pc)
    def run(self):
        for n, value in enumerate((SDK, 0x20070000, 64, 0x20071000, 0)):
            self.u.reg_write(getattr(arm, 'UC_ARM64_REG_X'+str(n)), value)
        self.u.reg_write(arm.UC_ARM64_REG_SP, 0x300ff000)
        self.u.reg_write(arm.UC_ARM64_REG_X30, base.STOP)
        self.u.emu_start(0x804958, base.STOP+4, count=100000)
        assert self.u.reg_read(arm.UC_ARM64_REG_PC)==base.STOP
        return dict(result=bool(self.r(0)), parsed=self.parsed, installed=self.installed,
                    scope=self.scope_result, patch_hits=self.patch_hits,
                    assertions=self.assertions, events=self.events)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    p.add_argument('--refresh-reference', action='store_true'); a=p.parse_args()
    binary=a.binary.read_bytes(); assert hashlib.sha256(binary).hexdigest()==base.SHA
    cases=[]
    for case in [dict(name='unknown-ca',ca_ok=False),dict(name='bad-signed',ca_ok=True,signed_ok=False),
                 dict(name='bad-body',ca_ok=True,body_ok=False),dict(name='valid',ca_ok=True),
                 dict(name='expired',ca_ok=True,expired=True),dict(name='revoked',ca_ok=True,revoked=True),
                 dict(name='bad-key-type',ca_ok=True,key_type=0),dict(name='bad-key-length',ca_ok=True,key_length=31),
                 dict(name='public-mismatch',ca_ok=True,public_match=False),dict(name='wrong-app',ca_ok=True,app=1),
                 dict(name='no-private',ca_ok=True,has_private=False),
                 dict(name='preset-private-mismatch',ca_ok=True,preset_private=True,private_match=False),
                 dict(name='preset-private',ca_ok=True,preset_private=True,has_private=False),
                 dict(name='bad-private',ca_ok=True,private_valid=False)]:
        cases.append(dict(input=case,observed=Run(binary,case).run()))
    mutation = Run(binary, dict(name='unknown-ca', ca_ok=False), mutate=True).run()
    assert mutation['result'] and mutation['parsed'] and not mutation['scope'] and mutation['patch_hits']==1
    report=dict(schema=1,binary_sha256=base.SHA,scope=__doc__,cases=cases,mutation=mutation,
                helpers={n:hashlib.sha256((ROOT/'scripts'/n).read_bytes()).hexdigest()
                         for n in [Path(__file__).name,'audit-steam-sns-message.py']})
    raw=gzip.compress(json.dumps(report,sort_keys=True,separators=(',',':')).encode(),mtime=0)
    a.output.write_bytes(raw)
    ref=ROOT/'scripts/fixtures/steam-local-certificate-reference.json.gz'
    if a.refresh_reference:ref.write_bytes(raw)
    else:assert raw==ref.read_bytes()
    print('PASS',len(cases),'original combined certificate programs')

if __name__=='__main__':main()
