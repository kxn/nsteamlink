#!/usr/bin/env python3
"""Pinned original SteamID ordering, auth metadata side effects and subscriptions.

Core BAddSteamID/SavePairedSteamID/OnConnected/RegisterForStatusUpdates and their
vector/protobuf instructions execute. Persistent lookup, preallocated vectors,
final WebSocket send, clock and heap/libc storage are providers. Shell full
BProcess/auth parser/key exchange/cache/target checks and persistent-client-info
serializer execute; Qt, entropy, request RSA, low-level file I/O and final send
are the existing admission audit's explicit providers. No Steam or Switch runs.
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
ROOT = Path(__file__).resolve().parents[1]

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / path)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

admission = module('admission', 'audit-steam-authorization-admission.py')
route = module('route', 'audit-steam-control-route.py')
CORE_SHA = '50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e'
SHELL_SHA = admission.SHA
REFERENCE = ROOT / 'scripts/fixtures/steam-account-metadata-reference.json.gz'
A = admission.ACCOUNT
REGISTER = '_ZN20CRemoteClientSession24RegisterForStatusUpdatesEyy'
SAVE_INFO = '_ZN14CServerManager24SavePersistentClientInfoEy'
LOAD_INFO = '_ZN14CServerManager24LoadPersistentClientInfoEy'
HANDLER = '_ZN14CServerManager33HandleDeviceAuthorizationResponseERK10CIPAndPortyPK37CMsgRemoteDeviceAuthorizationResponse'

def event(op, client=0, steam=0, tag=0):
    return dict(op=op, client=client, steam=steam, tag=tag)

class Accounts(route.Route):
    def __init__(self, binary):
        self.captures, self.paired_saves, self.register_calls = [], [], []
        super().__init__(binary)
        self.accounts = self.alloc(1024)
        self.wq(self.record + 8, self.accounts)
        self.wi(self.record + 16, 128)
        self.wq(self.manager + 984, self.accounts)
        self.wi(self.manager + 992, 128)
        self.wq(self.session + 8, 0x123456789abcdef)
        self.wq(self.manager + 24, self.session)

    def hook(self, u, pc, size, data):
        name = self.plts.get(pc, '')
        if name == '_ZN14CServerManager18SavePairedSteamIDsEv':
            self.paired_saves.append(self.ids(self.manager + 984, 16))
            return self.ret()
        if name == REGISTER:
            self.register_calls.append(self.r(1))
            return self.jump(self.symbols[name])
        if name == '_ZN20CRemoteClientSession13SendWebSocketERKN6google8protobuf7MessageE':
            # Freeze both generated objects before their destructors run. All
            # nested fields here are scalar RegisterStatus notification fields.
            top = self.freeze(self.r(1), 80)
            self.wq(top + 24, self.freeze(self.q(top + 24), 128))
            self.captures.append(top)
            return self.ret()
        return super().hook(u, pc, size, data)

    def ids(self, vector, count_offset):
        return [self.q(self.q(vector) + 8*i) for i in range(self.i(vector + count_offset))]

    def initial(self, values):
        self.wi(self.record + 24, len(values))
        self.wi(self.manager + 1000, len(values))
        for i, value in enumerate(values): self.wq(self.accounts + 8*i, value)

    def wires(self):
        return [self.serialize(p, 'CCMRemoteClient_ClientMessage').hex() for p in self.captures]

class Metadata(admission.Admission):
    def __init__(self, binary, testing):
        self.metadata_ready = False
        super().__init__(binary, dict(test=testing))
        self.rows = self.alloc(24*24)
        self.wq(self.manager + 0x480, self.rows)
        self.records, self.metadata_events = {}, []
        self.response_object = None
        self.metadata_ready = True

    def record(self, client):
        if client not in self.records:
            assert len(self.records) < 24
            i, p, array = len(self.records), self.alloc(128), self.alloc(128*8)
            self.wq(p+8, array); self.wi(p+16, 128); self.wi(p+24, 4)
            for n, value in enumerate([A+1, A, A+2, A+3]): self.wq(array+8*n, value)
            self.wq(self.rows+24*i, client); self.wq(self.rows+24*i+8, p)
            self.records[client] = (i, p)
        return self.records[client]

    def hook(self, u, pc, size, data):
        name = self.plts.get(pc, '')
        if self.metadata_ready:
            if name == HANDLER: self.response_object = self.r(3)
            if name == LOAD_INFO:
                self.record(self.r(1))
                # This call is reached only after original state/result gates.
                # Observe protobuf steamid presence, not key-validity inference.
                if self.response_object and self.i(self.response_object+16) & 4:
                    self.metadata_events.append(event('identity', self.r(1), self.q(self.response_object+40)))
                return self.ret()
            if 'PersistentClientInfo_t' in name and '4Find' in name:
                return self.ret(self.record(self.q(self.r(1)))[0])
            if name == '_ZN14CServerManager23GetPersistentClientInfoEy':
                return self.ret(self.record(self.r(1))[1])
            if name == SAVE_INFO: return self.jump(self.symbols[name])
            if name == REGISTER:
                self.metadata_events.append(event('subscribe', steam=self.r(1)))
                return self.ret()  # Session guard/wire tested separately in Core.
            if name == admission.life.m.SAVE:
                self.metadata_events.append(event('key', self.r(1), self.r(2)))
            if name == admission.SEND:
                self.metadata_events.append(event('send', tag=self.r(1)))
        return super().hook(u, pc, size, data)

    def observe_metadata(self):
        lists = {}
        for client, (_, p) in self.records.items():
            lists[str(client)] = [self.q(self.q(p+8)+8*i) for i in range(self.i(p+24))]
        return dict(events=list(self.metadata_events), accounts=lists,
                    paired=[self.q(self.q(self.manager+984)+8*i)
                            for i in range(self.i(self.manager+1000))],
                    files={k: v.hex() for k, v in sorted(self.file_bytes.items())
                           if k.endswith('/steamid.txt') or k.endswith('/paired_steamid.txt')})

def packet(inp):
    wire = admission.packet(inp)
    hs = struct.unpack_from('<I', wire, 8)[0]
    body = wire[16+hs:]
    # Baseline producer puts result varint then fixed64 account; keep all
    # original key/token bytes and change only this explicit fixture field.
    assert body[2:3] == b'\x11'
    body = body[:2] + (b'' if inp.get('absent') else b'\x11'+struct.pack('<Q', inp.get('account', A))) + body[11:]
    return wire[:12+hs] + struct.pack('<I', len(body)) + body

def auth_cases():
    return [
        ('invalid-promotes', [dict(key=True, invalid=True)]),
        ('valid-foreign', [dict(key=True)]),
        ('valid-target', [dict(key=True, client=123)]),
        ('cached-changes-account', [dict(key=True), dict(key=True, account=A+4)]),
        ('existing-nonfront-promotion', [dict(account=A+2), dict(account=A+1)]),
        ('zero-before-invalid', [dict(key=True, invalid=True, account=0)]),
        ('zero-valid', [dict(key=True, account=0)]),
        ('absent-valid', [dict(key=True, absent=True)]),
        ('absent-no-key', [dict(absent=True)]),
        ('no-key-target', [dict(client=123)]),
        ('failed-does-not-promote', [dict(result=1, key=True, account=A+4)]),
        ('exhaustion-promotes-first', [dict(key=True, invalid=True, index=i, account=A+i) for i in range(4)]),
        ('cancel-then-key', [dict(cancel=True), dict(key=True)]),
    ]

def auth_run(binary, name, inputs, testing):
    r = Metadata(binary, testing)
    r.begin(testing)
    session = r.alloc(128)
    r.wq(r.manager+24, session); r.wi(session+24, 5); r.wi(session+16, 1)
    result = dict(name=name, test=testing, input=inputs, steps=[r.observe_metadata()], packets=[])
    for inp in inputs:
        if inp.get('cancel'):
            r.call(r.symbols[admission.life.STOP], admission.life.m.PANEL)
            result['packets'].append(None)
        else:
            wire = packet(inp)
            buf, pointer, peer = r.alloc(128), r.alloc(len(wire)), r.alloc(24)
            r.u.mem_write(pointer, wire); r.u.mem_write(peer, bytes(range(1, 25)))
            r.call(r.symbols['_ZN10CUtlBufferC1Ev'], buf)
            r.call(r.symbols['_ZN10CUtlBuffer3PutEPKvi'], buf, pointer, len(wire))
            r.call(r.symbols[admission.life.PROCESS], r.manager, peer, buf, 0)
            result['packets'].append(wire.hex())
        result['steps'].append(r.observe_metadata())
    assert not r.assertions
    return result

def helpers():
    pending, hashes = [Path(__file__).name], {}
    while pending:
        name = pending.pop()
        if name in hashes: continue
        data = (ROOT/'scripts'/name).read_bytes()
        hashes[name] = hashlib.sha256(data).hexdigest()
        for node in ast.walk(ast.parse(data)):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                dep = Path(node.value).name
                if dep.startswith('audit-steam-') and dep.endswith('.py') and (ROOT/'scripts'/dep).is_file(): pending.append(dep)
    return dict(sorted(hashes.items()))

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--core', type=Path, required=True); p.add_argument('--shell', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True); p.add_argument('--refresh-reference', action='store_true')
    args = p.parse_args(); core, shell = args.core.read_bytes(), args.shell.read_bytes()
    assert hashlib.sha256(core).hexdigest() == CORE_SHA
    assert hashlib.sha256(shell).hexdigest() == SHELL_SHA
    r, lists = Accounts(core), []
    for initial in [[], [0], [A], [A+1,A,A+2,A+3], [A,A+1,A,A+2]]:
        for kind in ['status','pair']:
            r.initial(initial)
            case = dict(initial=initial, kind=kind, steps=[])
            for account in [0,A,A+2,A+4,A+1,A,A]:
                before = len(r.paired_saves)
                if kind == 'status':
                    added = bool(r.call(r.symbols['_ZN14CServerManager11BAddSteamIDEyy'], r.manager,123,account))
                    values = r.ids(r.record+8,16)
                else:
                    r.call(r.symbols['_ZN14CServerManager17SavePairedSteamIDEy'],r.manager,account)
                    added = len(r.paired_saves) != before; values = r.ids(r.manager+984,16)
                case['steps'].append(dict(account=account,added=added,ids=values))
            lists.append(case)
    sessions = []
    for state in [0,1,3,4,5,6]:
        for universe in [1,2,3,4]:
            for reconnect in [False,True]:
                r.captures=[];r.register_calls=[];r.wi(r.session+24,state);r.wi(r.session+16,universe)
                accounts=[0,A,(2<<56)+42,A,(3<<56)+33,(4<<56)+44]
                if reconnect:
                    r.initial(accounts)
                    r.call(r.symbols['_ZN14CServerManager11OnConnectedEv'],r.manager)
                else:
                    for account in accounts:r.call(r.symbols[REGISTER],r.session,account,42)
                sessions.append(dict(state=state,universe=universe,reconnect=reconnect,accounts=accounts,wires=r.wires()))
    auth=[]
    for testing in [False,True]:
        for name, inputs in auth_cases():
            auth.append(auth_run(shell,name,inputs,testing)); print(name,testing,flush=True)
    report=dict(schema=1,core_sha256=CORE_SHA,shell_sha256=SHELL_SHA,scope=__doc__,helpers=helpers(),lists=lists,sessions=sessions,auth=auth)
    raw=gzip.compress(json.dumps(report,sort_keys=True,separators=(',',':')).encode(),mtime=0)
    args.output.write_bytes(raw)
    if args.refresh_reference: REFERENCE.write_bytes(raw)
    else: assert raw == REFERENCE.read_bytes()
    print(f'PASS {len(lists)} original list programs, {len(sessions)} session programs, {len(auth)} complete auth metadata traces')
if __name__ == '__main__':main()
