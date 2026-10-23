#!/usr/bin/env python3
"""Execute original complete manager Update with mixed CM and UDP inputs.

Session Update, WebSocket FIFO/parser, UDP BProcess, authorization crypto,
callbacks and Stop execute original instructions. BReceive bytes, empty visible
map, future discovery deadlines, initial objects/FIFO storage and the inherited
lookup/clock/entropy/RSA/final-send providers are explicit boundaries. This does
not prove nonempty directory expiry, physical networking, Steam or Switch.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
from unicorn.arm64_const import UC_ARM64_REG_X30

if not __debug__:
    raise SystemExit('Original-instruction audit requires assertions')
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('rpc', ROOT/'scripts/audit-steam-pairing-rpc.py')
rpc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rpc)
MANAGER = '_ZN14CServerManager6UpdateEv'
SESSION = rpc.PREFIX+'6UpdateEv'
RECEIVE = '_ZN16CDiscoverySocket8BReceiveEP10CIPAndPortP10CUtlBuffer'
PROCESS = rpc.service.m.admission.life.PROCESS
REFERENCE = ROOT/'scripts/fixtures/steam-control-update-reference.json.gz'


class ControlUpdate(rpc.PairRPC):
    def __init__(self, binary, hint):
        self.ingress, self.udp, self.process_return = [], [], None
        super().__init__(binary, hint)
        self.wq(self.manager+32, self.alloc(64))
        self.wq(self.manager+48, 2000)
        self.wq(self.manager+88, 2000)
        self.wi(self.manager+80, 3)
        for name in (MANAGER, SESSION, PROCESS):
            self.function_entries.setdefault(self.symbols[name], []).append(name)

    def hook(self, u, pc, size, data):
        name = self.plts.get(pc, '')
        if pc == self.process_return:
            self.ingress.append(['BProcess-return', self.r(0)])
            self.process_return = None
        if name == RECEIVE:
            self.ingress.append('udp-read')
            if not self.udp:
                return self.ret(0)
            u.mem_write(self.r(2), self.udp.pop(0))
            u.mem_write(self.r(1), struct.pack('<I', 0x7f000001)+bytes(16)+struct.pack('<HH', 3, 27036))
            return self.ret(1)
        if name in (SESSION, rpc.UPDATE, PROCESS):
            self.ingress.append(name)
            if name == PROCESS:
                self.process_return = u.reg_read(UC_ARM64_REG_X30)
            return self.jump(self.symbols[name])
        return super().hook(u, pc, size, data)

    def queue(self, wires):
        slots = self.alloc(64)
        assert len(wires) <= 8
        for n, wire in enumerate(wires):
            packet, raw = self.alloc(128), self.alloc(len(wire))
            self.u.mem_write(raw, wire)
            self.wq(packet, raw)
            self.wi(packet+8, len(wire))
            self.wi(packet+20, len(wire))
            self.wq(slots+8*n, packet)
        self.wi(self.session+128, 7)
        self.wi(self.session+132, 0 if wires else 0xffffffff)
        self.wi(self.session+136, len(wires)-1)
        self.wq(self.session+144, slots)

    def update_mixed(self, cm, datagrams):
        self.queue(cm)
        # Use the real buffer constructor/Put, including maxPut; an incomplete
        # synthetic CUtlBuffer can silently make BProcess reject valid bytes.
        self.udp = []
        for wire in datagrams:
            buffer, pointer = self.alloc(128), self.alloc(len(wire))
            self.u.mem_write(pointer, wire)
            self.call(self.symbols['_ZN10CUtlBufferC1Ev'], buffer)
            self.call(self.symbols['_ZN10CUtlBuffer3PutEPKvi'], buffer, pointer, len(wire))
            self.udp.append(bytes(self.u.mem_read(buffer, 48)))
        self.ingress = []
        self.call(self.symbols[MANAGER], self.manager)
        assert not self.udp and not self.assertions
        assert self.ingress[:2] == [SESSION, rpc.UPDATE], self.ingress
        udp_stages = self.ingress[self.ingress.index('udp-read'):]
        assert udp_stages.count(['BProcess-return', 1]) == len(datagrams), self.ingress
        assert self.ingress.count('udp-read') == len(datagrams)+1, self.ingress


def cases():
    for hint in (False, True):
        for phase in ('waiting', 'auth', 'known', 'stream', 'ticket'):
            event = dict(key=True)
            pin = '1234'
            if phase in ('known', 'stream', 'ticket'):
                event.update(client=123, key_pin='0042')
                pin = '0042'
            valid = rpc.service.packet(event, pin)
            no_key = rpc.service.packet(dict(event, key=False), pin)
            denied = rpc.service.packet(dict(event, result=1), pin)
            v = rpc.service.m.admission.life.m.e.p.m.discovery.varint
            def cm_auth(packet):
                body = b'\x0a'+v(len(packet))+packet
                return b'\x08\x01\x32'+v(len(body))+body
            for name, cm, udp in (
                ('cm-failure-udp-key', [rpc.wire(4, 2)], [valid]),
                ('cm-failure-udp-no-key', [rpc.wire(4, 2)], [no_key]),
                ('cm-pin-udp-key', [rpc.wire(3, 1, 1234)], [valid]),
                ('cm-key-udp-denied', [cm_auth(valid)], [denied]),
                ('udp-duplicate-key', [], [valid, valid]),
                ('cm-denied-udp-key', [cm_auth(denied)], [valid]),
            ):
                yield f'{phase}-{name}', hint, phase, cm, udp


def helpers():
    result = rpc.helpers()
    result[Path(__file__).name] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return dict(sorted(result.items()))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--refresh-reference', action='store_true')
    args = p.parse_args()
    binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == rpc.service.m.SHELL_SHA
    cases_out = []
    for name, hint, phase, cm, udp in cases():
        r = ControlUpdate(binary, hint)
        rpc.bootstrap(r, phase)
        first = r.observe_rpc()
        r.update_mixed(cm, udp)
        cases_out.append(dict(name=name, hint=hint, phase=phase,
                              inputs=[['mixed', [w.hex() for w in cm], [w.hex() for w in udp]]],
                              steps=[first, r.observe_rpc()], stages=r.ingress,
                              executed=sorted(r.executed), source_assertions=r.assertions))
        print(name, hint, flush=True)
    report = dict(schema=1, binary_sha256=rpc.service.m.SHELL_SHA, scope=__doc__,
                  helpers=helpers(), cases=cases_out)
    raw = gzip.compress(json.dumps(report, sort_keys=True, separators=(',', ':')).encode(), mtime=0)
    args.output.write_bytes(raw)
    if args.refresh_reference:
        REFERENCE.write_bytes(raw)
    else:
        assert raw == REFERENCE.read_bytes()
    print(f'PASS {len(cases_out)} original complete manager mixed-input programs')


if __name__ == '__main__':
    main()
