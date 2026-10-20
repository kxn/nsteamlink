#!/usr/bin/env python3
"""Original manager update, late error delegate and panel ticket consumer.

Complete manager/session/WS FIFO/UDP dispatch, response parser/AES, Stop,
OnServerError and Panel OnUpdate execute. Panel/dialog/QString storage and
presentation, initial objects and the inherited clock/identity/lookup/random/
request-RSA/final-send boundaries are providers. Ordinary StartStreaming is
observed at its launcher boundary; network-test entry executes through token
handoff with thread start adapted. No Qt event loop, SDK, Steam or Switch.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

if not __debug__:
    raise SystemExit('Original instruction audit requires assertions')
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('joint', ROOT/'scripts/audit-steam-control-update.py')
joint = importlib.util.module_from_spec(spec)
spec.loader.exec_module(joint)
rpc = joint.rpc
PANEL = rpc.service.m.admission.life.m.PANEL
ERROR = '_ZN13CPanelConnect13OnServerErrorE12EServerError'
ERROR_THUNK = '_ZThn192_N13CPanelConnect13OnServerErrorE12EServerError'
UPDATE = '_ZN13CPanelConnect8OnUpdateEv'
REFERENCE = ROOT/'scripts/fixtures/steam-ticket-consumer-reference.json.gz'


class TicketConsumer(joint.ControlUpdate):
    def __init__(self, binary, testing):
        self.panel_errors = []
        super().__init__(binary, True)
        self.wi(PANEL+0xd8, 4)
        self.b(PANEL+0xd4, int(testing))
        self.b(self.manager+0x1e5, int(testing))
        self.wq(PANEL+0xe8, 123)
        self.wq(PANEL+0xf0, self.qstring('Fixture Host'))
        self.wq(PANEL+0xf8, self.empty)
        # The real secondary vtable's +0x30 slot is the original -192 thunk,
        # not a synthetic error callback. Supply only observer/object storage.
        self.wq(PANEL+0xc0, self.symbols['_ZTV13CPanelConnect']+0x2b8)
        self.wq(self.q(self.manager+384), PANEL+0xc0)
        for name in (ERROR, ERROR_THUNK, UPDATE):
            self.function_entries.setdefault(self.symbols[name], []).append(name)

    def hook(self, u, pc, size, data):
        name = self.plts.get(pc, '')
        if name == '_ZNK10CIPAddress5HasIPEv':
            return self.jump(self.symbols[name])
        if 'basic_string' in name and '6__initEPKcm' in name:
            destination, source, count = (self.r(n) for n in range(3))
            pointer = self.alloc(count+1)
            if count:
                u.mem_write(pointer, bytes(u.mem_read(source, count)))
            self.wq(destination, ((count+16) & ~15) | 1)
            self.wq(destination+8, count)
            self.wq(destination+16, pointer)
            return self.ret(destination)
        if name == '__memmove_chk':
            destination, source, count, capacity = (self.r(n) for n in range(4))
            assert count <= capacity
            if count:
                u.mem_write(destination, bytes(u.mem_read(source, count)))
            return self.ret(destination)
        if pc == self.symbols.get(ERROR):
            self.panel_errors.append(dict(error=self.r(1), manager=self.i(self.manager+8),
                                          panel=self.i(PANEL+0xd8)))
            self.errors.append(self.r(1))
        return super().hook(u, pc, size, data)

    def result(self):
        return dict(state=self.i(self.manager+8), panel=self.i(PANEL+0xd8),
                    launches=len(self.ordinary_launches)+len(self.auth_tokens),
                    errors=list(self.panel_errors), tokens=list(self.auth_tokens))


def streaming(result=0, transport=1):
    discovery = rpc.service.m.admission.life.m.e.p.m.discovery
    v = discovery.varint
    body = b'\x08\x11\x10'+v(result)
    if not result:
        cipher = discovery.encrypted()
        body += b'\x18'+v(61024)+b'\x22'+v(len(cipher))+cipher+b'\x30'+v(transport)
        if transport == 4:
            for tag, value in ((0x42, b'fixture-certificate'), (0x3a, b'stun:fixture.invalid:3478')):
                body += bytes([tag])+v(len(value))+value
    header = b'\x08\x7b\x10\x06'
    return b'\xff'*4+b'\x21\x4c\x5f\xa0'+struct.pack('<I', len(header))+header+struct.pack('<I', len(body))+body


def cm(packet):
    v = rpc.service.m.admission.life.m.e.p.m.discovery.varint
    body = b'\x0a'+v(len(packet))+packet
    return b'\x08\x01\x32'+v(len(body))+body


def cases():
    for testing in (False, True):
        for transport in (1, 4):
            good, bad = streaming(transport=transport), streaming(result=3)
            failure = rpc.wire(4, 2)
            programs = (
                ('success', [cm(good)], []),
                ('cm-duplicate-success', [cm(good), cm(good)], []),
                ('cm-failure-after-ticket', [cm(good), failure], []),
                ('cm-failure-before-ticket', [failure, cm(good)], []),
                ('udp-failure-after-cm-ticket', [cm(good)], [bad]),
            ) if transport == 4 else (
                ('success', [], [good]),
                ('udp-duplicate-success', [], [good, good]),
                ('udp-busy-after-ticket', [], [good, streaming(result=4)]),
                ('cm-failure-before-udp-ticket', [failure], [good]),
                ('udp-failure-after-udp-ticket', [], [good, bad]),
            )
            for name, service, udp in programs:
                yield name, testing, transport, service, udp


def helpers():
    out = joint.helpers()
    out[Path(__file__).name] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return dict(sorted(out.items()))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--refresh-reference', action='store_true')
    args = p.parse_args()
    binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == rpc.service.m.SHELL_SHA
    cases_out = []
    for name, testing, transport, service, udp in cases():
        r = TicketConsumer(binary, testing)
        rpc.bootstrap(r, 'stream')
        first = r.result()
        r.update_mixed(service, udp)
        before_consume = r.result()
        r.call(r.symbols[UPDATE], PANEL)
        final = r.result()
        assert not r.assertions
        cases_out.append(dict(name=name, testing=testing, transport=transport,
                              cm=[w.hex() for w in service], udp=[w.hex() for w in udp],
                              steps=[first, before_consume, final], stages=r.ingress,
                              executed=sorted(r.executed), source_assertions=r.assertions))
        print(name, testing, transport, final, flush=True)
    report = dict(schema=1, binary_sha256=rpc.service.m.SHELL_SHA, helpers=helpers(),
                  scope=__doc__, cases=cases_out)
    raw = gzip.compress(json.dumps(report, sort_keys=True, separators=(',', ':')).encode(), mtime=0)
    args.output.write_bytes(raw)
    if args.refresh_reference:
        REFERENCE.write_bytes(raw)
    else:
        assert raw == REFERENCE.read_bytes()


if __name__ == '__main__':
    main()
