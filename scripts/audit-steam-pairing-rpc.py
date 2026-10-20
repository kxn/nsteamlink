#!/usr/bin/env python3
"""Original cloud response queue/parser, manager callbacks and pairing RPC policy.

Complete HandleWebSocketPackets/UpdateWebSocket, generated protobuf parsing,
Start/CancelPairing, OnPairingStarted/Failed/Disconnected, authorization producer
and Stop instructions execute. Session object/queue storage, WebRequest state,
clock, entropy, identity, RSA, final WebSocket/manager sends, persistent lookup,
file syscalls, libc++ heap/string storage and Qt are explicit providers. This is
not TLS, Steam or Switch.
"""
import argparse
import ast
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
from unicorn.arm64_const import UC_ARM64_REG_D0

if not __debug__:
    raise SystemExit('Original-instruction audit requires assertions; do not use Python -O')
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('service', ROOT / 'scripts/audit-steam-service-pairing.py')
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)
REFERENCE = ROOT / 'scripts/fixtures/steam-pairing-rpc-reference.json.gz'
WS_STATE, WS_RELEASE, CONNECTED, DISCONNECTED = 0x40000340, 0x40000348, 0x40000350, 0x40000358
PREFIX = '_ZN20CRemoteClientSession'
START = '_ZN14CServerManager12StartPairingEv'
CANCEL = '_ZN14CServerManager13CancelPairingEv'
PACKETS = PREFIX + '22HandleWebSocketPacketsEv'
UPDATE = PREFIX + '15UpdateWebSocketEv'
SEND = PREFIX + '13SendWebSocketERKN6google8protobuf7MessageE'


class PairRPC(service.Service):
    def __init__(self, binary, hint=False):
        self.rpc, self.rpc_events = [], []
        self.ws_state = 3
        self.has_hint = hint
        super().__init__(binary)
        self.session = self.alloc(256)
        self.wq(self.manager + 24, self.session)
        self.wq(self.session, self.manager)
        self.wq(self.manager, self.symbols['_ZTV14CServerManager'] + 16)
        self.wq(self.manager + 0x120, self.hint if hint else 0)
        self.wq(self.session + 8, 1001)
        self.wi(self.session + 16, 1)
        self.wi(self.session + 24, 5)
        for offset in (52, 56, 132, 136):
            self.wi(self.session + offset, 0xffffffff)
        request, table = self.alloc(64), self.alloc(64)
        self.wq(request, table)
        self.wq(table, WS_RELEASE)
        self.wq(table + 16, WS_STATE)
        self.wq(self.session + 72, request)
        delegate = self.q(self.q(self.manager + 384))
        table = self.q(delegate)
        self.wq(table, CONNECTED)
        self.wq(table + 8, DISCONNECTED)
        for name in (START, CANCEL, PACKETS, UPDATE, PREFIX+'10DisconnectEv',
                     '_ZN14CServerManager14OnDisconnectedEv', '_ZN14CServerManager15OnPairingFailedEv'):
            self.function_entries.setdefault(self.symbols[name], []).append(name)

    def boundary(self):
        row = super().boundary()
        row['target']=self.q(self.manager+0x1f0)
        if hasattr(self, 'session'):
            row['session_state'] = self.i(self.session + 24)
        return row

    def hook(self, u, pc, size, data):
        name = self.plts.get(pc, '')
        if pc == WS_STATE:
            return self.ret(self.ws_state)
        if pc == WS_RELEASE:
            self.rpc_events.append(dict(kind='release', **self.boundary()))
            return self.ret()
        if pc in (CONNECTED, DISCONNECTED):
            self.rpc_events.append(dict(kind='connected' if pc == CONNECTED else 'disconnected',
                                    **self.boundary()))
            return self.ret()
        if pc in (service.CODE, service.FAILED, service.PAIRED):
            self.rpc_events.append(dict(kind={service.CODE:'code', service.FAILED:'failed', service.PAIRED:'paired'}[pc],
                                    error=self.r(1) if pc == service.FAILED else 0, **self.boundary()))
        if pc == self.symbols['_ZN14CServerManager16OnPairingStartedEj']:
            self.preparing = True
            self.secret_draw_index = 0
        if name == SEND:
            top = self.freeze(self.r(1), 80)
            self.wq(top + 24, self.freeze(self.q(top + 24), 128))
            self.rpc.append((top, self.boundary()))
            return self.ret()
        if name == service.m.REGISTER:
            # The parent audit deliberately stops at this boundary. A completed
            # CM batch needs the real session guard/notification too, so it can
            # compare all WebSocket sends before the following RPC reply.
            self.metadata_events.append(service.m.event('subscribe', steam=self.r(1)))
            return self.jump(self.symbols[name])
        if name == 'Plat_FloatTime':
            u.reg_write(UC_ARM64_REG_D0, struct.unpack('<Q', struct.pack('<d', float(self.wall_time)))[0])
            return self.ret()
        if name == '_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev':
            return self.ret()  # Like free/delete, original string storage is an arena provider.
        if name == PREFIX+'8BConnectEv':
            self.rpc_events.append(dict(kind='reconnect', **self.boundary()))
            return self.ret(1)  # Resolver/WebRequest creation is outside this audit.
        if name in (PREFIX+'12StartPairingEv', PREFIX+'13CancelPairingEv',
                    PREFIX+'14SetPairingInfoEyPN6google8protobuf7MessageE',
                    PREFIX+'10DisconnectEv', PREFIX+'16CleanupWebSocketEv', PACKETS):
            return self.jump(self.symbols[name])
        return super().hook(u, pc, size, data)

    def wire(self, wire):
        self.wires([wire])

    def wires(self, wires):
        assert self.i(self.session + 132) == 0xffffffff
        assert 0 < len(wires) <= 8
        slots = self.alloc(64)
        for index, wire in enumerate(wires):
            packet, raw = self.alloc(128), self.alloc(len(wire))
            self.u.mem_write(raw, wire)
            self.wq(packet, raw)
            self.wi(packet + 8, len(wire))
            self.wi(packet + 20, len(wire))
            self.wq(slots + index * 8, packet)
        self.wi(self.session + 128, 7)
        self.wi(self.session + 132, 0)
        self.wi(self.session + 136, len(wires) - 1)
        self.wq(self.session + 144, slots)
        self.call(self.symbols[PACKETS], self.session)
        self.preparing = False

    def observe_rpc(self):
        row = self.service_snapshot()
        row.update(session_state=self.i(self.session + 24), session_id=self.q(self.session + 8),
                   target=self.q(self.manager+0x1f0), control_targets=list(self.destinations),
                   events=list(self.rpc_events), rpc=[dict(wire=self.serialize(p, 'CCMRemoteClient_ClientMessage').hex(),
                                                       state=state) for p, state in self.rpc])
        return row


def wire(kind, result=1, pin=1234):
    varint = service.m.admission.life.m.e.p.m.discovery.varint
    body = b'\x08' + varint(pin) if kind == 3 else b''
    return b'\x08' + varint(result) + varint(kind * 8 + 2) + varint(len(body)) + body


def cases():
    rows=[]
    for phase in ('idle','waiting','auth','known','stream','ticket'):
        for kind in (3,4,5):
            for result in (1,2):
                rows.append((f'{phase}-rpc-{kind}-{result}',phase,[('wire',kind,result,4321)]))
        rows.append((f'{phase}-connected-clock-jump',phase,[('update',3,1000000)]))
        rows.append((f'{phase}-disconnect',phase,[('update',4,1000)]))
    rows += [
        ('cancel-late-pin','waiting',[('cancel',),('wire',3,1,1234),('wire',5,1,0)]),
        ('cancel-repeat-late-pin','waiting',[('cancel',),('wire',3,1,1234),('wire',3,1,1234)]),
        ('cancel-start-before-ack','waiting',[('cancel',),('start',),('wire',3,1,4321),('wire',5,1,0)]),
        ('cancel-then-known-failure','waiting',[('cancel',),('known',),('wire',5,2,0)]),
        ('cancel-then-stream-failure','waiting',[('cancel',),('stream',),('wire',5,2,0)]),
        ('auth-duplicate-pin-then-cancel','auth',[('wire',3,1,4321),('cancel',)]),
        ('waiting-disconnect-reconnect-pin','waiting',[('update',4,1000),('reconnect',),('wire',3,1,4321)]),
        ('waiting-disconnect-cancel','waiting',[('update',4,1000),('cancel',)]),
        ('waiting-disconnect-start','waiting',[('update',4,1000),('start',)]),
        ('known-start-pair','known',[('start',),('wire',3,1,1234)]),
        ('auth-start-pair','auth',[('start',),('wire',3,1,4321)]),
        ('auth-missing-pin','waiting',[('raw',b'\x08\x01\x1a\x00'.hex())]),
    ]
    def reply(event):
        packet=service.packet(event,'1234')
        v=service.m.admission.life.m.e.p.m.discovery.varint
        body=b'\x0a'+v(len(packet))+packet
        return ('raw',(b'\x08\x01\x32'+v(len(body))+body).hex())
    rows += [
        ('waiting-late-authorization','waiting',[reply(dict(key=True))]),
        ('waiting-no-key-authorization','waiting',[reply(dict())]),
        ('auth-restart-late-authorization','auth',[('start',),reply(dict(key=True))]),
    ]
    # All frames are present in the original FIFO before one invocation of
    # HandleWebSocketPackets. There is no synthetic manager pump between them.
    for keyed in (False, True):
        auth = reply(dict(key=keyed) if keyed else dict())[1]
        for kind in (3, 4, 5):
            failure = wire(kind, 2).hex()
            success = wire(kind, 1, 4321).hex()
            for label, frames in (
                ('success-failure', [auth, failure]),
                ('failure-success', [failure, auth]),
                ('success-rpc-success-failure', [auth, success, failure]),
                ('duplicate-success-failure', [auth, auth, failure]),
            ):
                rows.append((f'batch-{int(keyed)}-{kind}-{label}', 'auth', [('batch', frames)]))
    return [(name,hint,phase,ops) for hint in (False,True) for name,phase,ops in rows]


def bootstrap(r, phase):
    if phase in ('waiting','auth'):
        r.call(r.symbols[START],r.manager)
        if phase=='auth':r.wire(wire(3,1,1234))
    elif phase=='known':
        r.wq(r.manager+0x120,r.hint)
        r.begin(False)
        r.wq(r.manager+0x120,r.hint if r.has_hint else 0)
    elif phase in ('stream','ticket'):
        r.wq(r.manager+0x120,r.hint)
        pin=r.alloc(5);r.u.mem_write(pin,b'9876\0')
        r.call(r.symbols['_ZN14CServerManager14StartStreamingEyPKc'],r.manager,123,pin)
        if phase=='ticket':r.credentials(bytes(range(32,64)),16)
        r.wq(r.manager+0x120,r.hint if r.has_hint else 0)
    else:assert phase=='idle'


def run(binary, name, hint, phase, commands):
    r = PairRPC(binary, hint)
    bootstrap(r,phase)
    rows = [r.observe_rpc()]
    inputs = []
    for command in commands:
        if command[0] == 'start':
            r.call(r.symbols[START], r.manager)
        elif command[0] == 'cancel':
            r.call(r.symbols[CANCEL], r.manager)
        elif command[0] == 'wire':
            raw = wire(*command[1:])
            r.wire(raw)
        elif command[0] == 'update':
            r.ws_state = command[1]
            r.wall_time=command[2]
            r.call(r.symbols[UPDATE], r.session)
        elif command[0] in ('known','stream'):
            bootstrap(r,command[0])
        elif command[0]=='reconnect':
            r.wi(r.session+24,5);r.wq(r.session+8,1002)
            r.ws_state=3
            r.call(r.symbols['_ZN14CServerManager11OnConnectedEv'],r.manager)
        elif command[0]=='raw':
            r.wire(bytes.fromhex(command[1]))
        elif command[0]=='batch':
            r.wires([bytes.fromhex(raw) for raw in command[1]])
        else:
            raise AssertionError(command)
        inputs.append(command)
        rows.append(r.observe_rpc())
    assert not r.assertions
    return dict(name=name, hint=hint, phase=phase, inputs=inputs, steps=rows, executed=sorted(r.executed), source_assertions=r.assertions)


def helpers():
    pending, out = [Path(__file__).name], {}
    while pending:
        name = pending.pop()
        if name in out:
            continue
        raw = (ROOT/'scripts'/name).read_bytes()
        out[name] = hashlib.sha256(raw).hexdigest()
        for node in ast.walk(ast.parse(raw)):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                dep = Path(node.value).name
                if dep.startswith('audit-steam-') and dep.endswith('.py') and (ROOT/'scripts'/dep).is_file():
                    pending.append(dep)
    return dict(sorted(out.items()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--refresh-reference', action='store_true')
    args = parser.parse_args()
    binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == service.m.SHELL_SHA
    output = []
    for name, hint, phase, commands in cases():
        output.append(run(binary, name, hint, phase, commands))
        print(name, hint, flush=True)
    report = dict(schema=1, binary_sha256=service.m.SHELL_SHA, scope=__doc__, helpers=helpers(), cases=output)
    raw = gzip.compress(json.dumps(report, sort_keys=True, separators=(',',':')).encode(), mtime=0)
    args.output.write_bytes(raw)
    if args.refresh_reference:
        REFERENCE.write_bytes(raw)
    else:
        assert raw == REFERENCE.read_bytes()
    print(f'PASS {len(output)} original response-queue/RPC/manager programs')


if __name__ == '__main__':
    main()
