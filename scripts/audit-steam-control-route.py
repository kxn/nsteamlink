#!/usr/bin/env python3
"""Execute complete original manager SendMessage, including route/header selection.

Original HasIP/cache-first selection, header/body protobuf serialization, UDP
socket startup, BSend and Stop with empty visible/cloud maps execute. Persistent
lookup, token bytes, session state/destructor, final cloud send, syscalls, time
and libc storage are providers.
Separate transport bridge send/receive framing, protobuf and HMAC-admission
branches execute; HMAC and final parsed backend delivery are providers. Tokens
are supplied fixture bytes, not a cryptographic or service acceptance proof. No
cloud-online membership provider exists: manager SendMessage does not read it.
No Steam traffic, Switch or caller retry/authorization behavior is proved.
"""
import argparse
import gzip
import importlib.util
import ipaddress
import hashlib
import hmac
import json
from pathlib import Path
import struct

if not __debug__:
    raise SystemExit('Original-instruction audit requires assertions; do not use Python -O')

spec = importlib.util.spec_from_file_location('discovery_send',
    Path(__file__).with_name('audit-steam-discovery-send.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
REFERENCE = Path(__file__).with_name('fixtures') / 'steam-control-route-reference.json.gz'
TOKEN = bytes(range(32))


class Route(base.Sender):
    def __init__(self, binary):
        super().__init__(binary)
        self.record = self.alloc(128)
        self.map = self.alloc(24)
        self.rows = self.alloc(80)
        self.accounts = self.alloc(24)
        self.session = self.alloc(64)
        self.wq(self.manager+1152, self.map)
        self.wq(self.map+8, self.record)
        self.wq(self.record+32, self.rows)
        self.wq(self.record+8, self.accounts)
        self.cloud_sends, self.lookups, self.tokens, self.stops = [], [], 0, []
        self.session_destroys = 0
        self.token_ok = True

    def hook(self, u, pc, size, data):
        name = self.plts.get(pc, '')
        if name == '_ZN14CServerManager4StopEv':
            assert self.i(self.manager+168) == self.i(self.manager+260) == 0
            return self.jump(self.symbols[name])
        if name == '_ZN20CRemoteClientSessionD1Ev':
            assert self.r(0) == self.session
            self.session_destroys += 1
            return self.ret()
        if name == '_ZN14CServerManager24LoadPersistentClientInfoEy':
            assert self.r(0) == self.manager
            self.lookups.append(['load', self.r(1)])
            return self.ret()
        if 'CUtlHashMap' in name and 'PersistentClientInfo_t' in name and '4Find' in name:
            assert self.r(0) == self.manager+1104
            self.lookups.append(['find', self.q(self.r(1))])
            return self.ret(0)
        if name == '_ZN14CServerManager23GetPersistentClientInfoEy':
            assert self.r(0) == self.manager
            self.lookups.append(['get', self.r(1)])
            return self.ret(self.record)
        if name == '_ZN14CServerManager15BGetDeviceTokenER10CUtlBuffer':
            assert self.r(0) == self.manager
            self.tokens += 1
            if self.token_ok:
                p = self.alloc(len(TOKEN))
                u.mem_write(p, TOKEN)
                self.wq(self.r(1), p)
                self.wi(self.r(1)+8, len(TOKEN))
                self.wi(self.r(1)+20, len(TOKEN))
            return self.ret(int(self.token_ok))
        if name == '_ZN14CServerManager13StopStreamingE12EServerError':
            self.stops.append(self.r(1))
            return self.ret()
        if name == '_ZN20CRemoteClientSession11SendMessageEyPKvm':
            assert self.r(0) == self.session
            self.cloud_sends.append(dict(account=self.r(1),
                wire=bytes(u.mem_read(self.r(2), self.r(3))).hex()))
            return self.ret()
        return super().hook(u, pc, size, data)

    def address(self, p, ip, port):
        address = ipaddress.ip_address(ip)
        raw = int(address).to_bytes(4, 'little') if address.version == 4 else address.packed
        self.u.mem_write(p, bytes(24))
        self.u.mem_write(p, raw)
        self.u.mem_write(p+20, struct.pack('<HH', 3 if address.version == 4 else 4, port))

    def program(self, inp):
        explicit = inp.get('explicit', ['0.0.0.0', 0])
        self.address(self.peer, *explicit)
        rows = inp.get('cache', [])
        assert len(rows) <= 2
        self.wi(self.record+48, len(rows))
        for i, (ip, port, verified) in enumerate(rows):
            p = self.rows+40*i
            self.b(p, int(verified))
            self.address(p+16, ip, port)
        accounts = inp.get('accounts', [88, 99])
        self.wi(self.record+24, len(accounts))
        for i, account in enumerate(accounts):
            self.wq(self.accounts+8*i, account)
        state = inp.get('session', 5)
        self.wq(self.manager+24, self.session if state is not None else 0)
        if state is not None:
            self.wi(self.session+24, state)
        self.b(self.manager+12, int(inp.get('local', True)))
        if inp.get('socket', True):
            socket = self.alloc(16)
            self.wi(socket+4, 37)
            self.wq(self.manager+32, socket)
        self.socket_result = inp.get('start_result', -1)
        self.token_ok = inp.get('token_ok', True)
        if inp.get('send_failure'):
            self.send_plan = [(-1, 5)]
        self.call(self.symbols[base.FUNCTIONS['send']], self.manager, inp.get('type', 0),
                  self.message, self.peer, inp.get('client', 123))
        assert not self.return_points
        return dict(lookups=self.lookups, token_calls=self.tokens, stops=self.stops,
                    udp=self.sends, cloud=self.cloud_sends, udp_returns=self.send_returns,
                    session_destroys=self.session_destroys,
                    socket_calls=[row for row in self.trace if row[0] in ('socket', 'bind')])


class Signal(Route):
    """Separate original transport bridge, not manager SendMessage."""
    def hook(self, u, pc, size, data):
        if self.plts.get(pc) == '_ZN7CCrypto15GenerateHMAC256EPKvmS1_mPA32_h':
            payload = bytes(u.mem_read(self.r(0), self.r(1)))
            key = bytes(u.mem_read(self.r(2), self.r(3)))
            assert key == bytes(range(16))
            u.mem_write(self.r(4), hmac.digest(key, payload, 'sha256'))
            return self.ret(1)
        return super().hook(u, pc, size, data)

    def bridge(self):
        bridge, key, message = self.alloc(128), self.alloc(16), self.alloc(256)
        self.u.mem_write(key, bytes(range(16)))
        self.wq(bridge+16, 88)
        self.wq(bridge+24, key)
        self.wi(bridge+44, 16)
        self.wq(bridge+88, self.session)
        self.wi(self.session+24, 5)
        return bridge, message

    def send_signal(self):
        bridge, message = self.bridge()
        assert self.parse(message, bytes.fromhex('1202380112025801'), 'CTransportSignalMsg')
        symbol = '_ZN22CStreamTransportClient19SendTransportSignalERK19CTransportSignalMsg'
        self.call(self.symbols[symbol], bridge, message)
        assert len(self.cloud_sends) == 1 and not self.sends and self.tokens == 0
        return self.cloud_sends[0]

    def receive_signal(self, wire):
        bridge, _ = self.bridge()
        backend, table = self.alloc(16), self.alloc(48)
        self.wq(bridge+8, backend)
        self.wq(backend, table)
        callback = base.config.STOP+0x800
        self.wq(table+40, callback)
        delivered = []
        def consume():
            delivered.append(self.freeze(self.r(1), 56))
            self.ret(1)
        self.callbacks[callback] = consume
        buffer, data = self.alloc(64), self.alloc(len(wire))
        self.u.mem_write(data, wire)
        self.call(self.symbols['_ZN10CUtlBufferC1Ev'], buffer)
        self.call(self.symbols['_ZN10CUtlBuffer3PutEPKvi'], buffer, data, len(wire))
        symbol = '_ZN22CStreamTransportClient19BProcessReplyPacketER10CUtlBuffer'
        result = self.call(self.symbols[symbol], bridge, buffer)
        assert result in (0, 1)
        return dict(result=result,
                    delivered=[self.serialize(p, 'CTransportSignalMsg').hex() for p in delivered])


def receive_programs(signal):
    wire = bytes.fromhex(signal['wire'])
    size = struct.unpack_from('<I', wire, 8)[0]
    body = wire[16+size:]
    magic = wire[:8]
    def packet(header, payload=body):
        return magic+struct.pack('<I', len(header))+header+struct.pack('<I',len(payload))+payload
    def authenticated(payload, include_payload=True):
        token = hmac.digest(bytes(range(16)), payload, 'sha256')
        assert len(payload) < 128
        return b'\x0a\x20'+token+(b'\x12'+bytes([len(payload)])+payload if include_payload else b'')
    cases = [('absent_client', packet(b'\x10\x0c')),
             ('zero_client', packet(b'\x08\0\x10\x0c')),
             ('matching_client', packet(b'\x08\x7b\x10\x0c')),
             ('other_nonzero_client', packet(b'\x08\x7c\x10\x0c')),
             ('wrong_type', packet(b'\x08\x7b\x10\x0b')),
             ('bad_hmac', packet(b'\x08\x7b\x10\x0c', body[:2]+bytes([body[2]^1])+body[3:])),
             ('bad_outer_body', packet(b'\x08\x7b\x10\x0c', b'\x12\xff')),
             ('missing_payload_valid_empty_hmac', packet(b'\x08\x7b\x10\x0c', authenticated(b'', False))),
             ('empty_payload_valid_empty_hmac', packet(b'\x08\x7b\x10\x0c', authenticated(b''))),
             ('missing_token', packet(b'\x08\x7b\x10\x0c', b'\x12\x00')),
             ('short_token', packet(b'\x08\x7b\x10\x0c', b'\x0a\x1f'+bytes(31)+b'\x12\x00')),
             ('bad_inner_valid_hmac', packet(b'\x08\x7b\x10\x0c', authenticated(b'\x12\xff'))),
             ('duplicate_sdr', packet(b'\x08\x7b\x10\x0c', authenticated(bytes.fromhex('1202380112023801'))))]
    return [dict(name=name, wire=raw.hex()) for name, raw in cases]


def programs():
    cases = [
        ('empty', {}),
        ('explicit', dict(explicit=['192.0.2.4', 27036])),
        ('explicit_ignores_cache', dict(explicit=['192.0.2.4', 27036], cache=[['10.0.0.8', 31000, True]])),
        ('explicit_ipv6', dict(explicit=['2001:db8::4', 27036])),
        ('cache', dict(cache=[['10.0.0.8', 31000, True]])),
        ('cache_ipv6', dict(cache=[['2001:db8::8', 32000, True]])),
        ('cache_unverified', dict(cache=[['10.0.0.8', 31000, False]])),
        ('only_first_cache_entry', dict(cache=[['10.0.0.8', 31000, False], ['10.0.0.9', 32000, True]])),
        ('cache_port_zero', dict(cache=[['10.0.0.8', 0, True]])),
        ('cache_zero_ip', dict(cache=[['0.0.0.0', 31000, True]])),
        ('partial_explicit_port', dict(explicit=['192.0.2.4', 0], cache=[['10.0.0.8', 31000, True]])),
        ('partial_explicit_ip', dict(explicit=['0.0.0.0', 27036], cache=[['10.0.0.8', 31000, True]])),
        ('zero_client_no_lookup', dict(client=0, cache=[['10.0.0.8', 31000, True]])),
        ('zero_client_explicit', dict(client=0, explicit=['192.0.2.4', 27036])),
        ('local_disabled_valid', dict(local=False, explicit=['192.0.2.4', 27036])),
        ('local_disabled_empty', dict(local=False)),
        ('udp_failure_no_cloud_fallback', dict(explicit=['192.0.2.4', 27036], send_failure=True)),
        ('socket_start_failure', dict(explicit=['192.0.2.4', 27036], socket=False)),
        ('socket_start_success', dict(explicit=['192.0.2.4', 27036], socket=False, start_result=37)),
        ('token_failure', dict(token_ok=False)),
        ('valid_address_needs_no_token', dict(explicit=['192.0.2.4', 27036], token_ok=False)),
        ('no_steam_ids', dict(accounts=[])),
        ('first_steam_id_even_zero', dict(accounts=[0,99])),
    ]
    cases += [('session_'+str(state), dict(session=state)) for state in (None, 0, 1, 2, 3, 4, 5)]
    cases += [('manager_type_'+str(kind), dict(type=kind)) for kind in (3, 4, 5, 8, 9, 10, 11, 14)]
    return [dict(name=name, input=inp) for name, inp in cases]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', required=True, type=Path)
    p.add_argument('--output', type=Path)
    p.add_argument('--check', type=Path)
    args = p.parse_args()
    sha = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    assert sha == base.IDENTITIES['core'], 'Unexpected original ELF identity'
    rows = [dict(**case, output=Route(args.binary.read_bytes()).program(case['input'])) for case in programs()]
    signal = Signal(args.binary.read_bytes()).send_signal()
    receives = [dict(**case, output=Signal(args.binary.read_bytes()).receive_signal(bytes.fromhex(case['wire'])))
                for case in receive_programs(signal)]
    report = dict(schema=1, original_sha256=sha, cases=rows, signal=signal, receives=receives,
                  helpers={name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                           for name in ('audit-steam-control-route.py', 'audit-steam-discovery-send.py',
                                        'audit-steam-client-config.py', 'audit-steam-client-fec-policy.py')})
    raw = (json.dumps(report, sort_keys=True, indent=2)+'\n').encode()
    if args.check:
        assert json.loads(gzip.decompress(args.check.read_bytes())) == report, 'Original output differs'
    if args.output:
        args.output.write_bytes(gzip.compress(raw, mtime=0))
    print(f'PASS original complete SendMessage: {len(rows)} cases; bridge send + {len(receives)} receives')


if __name__ == '__main__':
    main()
