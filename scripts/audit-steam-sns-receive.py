#!/usr/bin/env python3
"""Execute original Socket Wait -> SNS BWait -> queue/Recv -> Socket Update.

SDK Poll/Receive, message producer, clock, allocation and final HandlePacket/
Connection Update are providers. Packet constructor/SDK attachment, original
queue allocation/append/free/Recv and Socket caller branches execute. No SDK
network or full IHS packet parsing/connection lifecycle is claimed.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sns_receive_wire',
    Path(__file__).with_name('audit-steam-network-wire.py'))
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)
SHA = wire.config.SHA
SHELL_SHA = '15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2'
POLL, RECEIVE = wire.config.STOP + 0x600, wire.config.STOP + 0x700


def mtu_inventory(path, sha):
    assert hashlib.sha256(path.read_bytes()).hexdigest() == sha, 'wrong MTU inventory sample'
    with path.open('rb') as f:
        e = ELFFile(f)
        d = e.get_section_by_name('.dynsym')
        symbols = list(d.iter_symbols())
        name = '_ZN19CStreamTransportSDR13SetMaximumMTUEi'
        target = next(s['st_value'] for s in symbols if s.name == name)
        targets = {target}
        plt = e.get_section_by_name('.plt')
        for i, r in enumerate(e.get_section_by_name('.rela.plt').iter_relocations()):
            if d.get_symbol(r['r_info_sym']).name == name:
                targets.add(plt['sh_addr'] + 32 + 16*i)
        relocations = [r['r_offset'] for r in e.get_section_by_name('.rela.dyn').iter_relocations()
            if d.get_symbol(r['r_info_sym']).name == name]
        vt = next(s for s in symbols if s.name == '_ZTV19CStreamTransportSDR')
        vtable = []
        for r in e.get_section_by_name('.rela.dyn').iter_relocations():
            if vt['st_value'] + 16 <= r['r_offset'] < vt['st_value'] + vt['st_size']:
                vtable.append(dict(slot=r['r_offset']-vt['st_value']-16,
                    symbol=d.get_symbol(r['r_info_sym']).name))
        text = e.get_section_by_name('.text')
        data, addr = text.data(), text['sh_addr']
        calls = []
        for n in range(0, len(data), 4):
            v = struct.unpack_from('<I', data, n)[0]
            if v & 0x7c000000 != 0x14000000: continue
            offset = v & 0x3ffffff
            if offset & (1 << 25): offset -= 1 << 26
            if addr+n+offset*4 in targets: calls.append(addr+n)
        assert not calls and not relocations and all(v['symbol'] != name for v in vtable)
        return dict(sample_sha256=sha, target=target, direct_branches=calls,
            dynamic_relocations=relocations, transport_vtable=sorted(vtable, key=lambda v:v['slot']),
            scope='B/BL in .text, PLT targets, .rela.dyn and SDR vtable; excludes external dlsym/indirect address construction')


class Receive(wire.Wire):
    def __init__(self, binary, handle, state):
        super().__init__(binary)
        self.events, self.batches, self.lengths = [], [], []
        self.serial = 0
        sdk, vt, utils, uvt = [self.alloc(512) for _ in range(4)]
        self.wi(self.transport + 48, handle)
        self.wi(self.transport + 20, state)
        self.wq(self.transport + 56, sdk)
        self.wq(self.transport + 64, utils)
        self.wq(sdk, vt)
        self.wq(utils, uvt)
        self.wq(vt + 112, RECEIVE)
        self.wq(uvt + 224, POLL)
        tvt = self.q(self.transport)
        self.wq(tvt + 64, 0x80010c)
        self.wq(tvt + 80, 0x8002c0)
        self.callbacks.update({POLL:self.poll, RECEIVE:self.receive,
            0xc10fd0:lambda:self.jump(0x7f6d90), 0xc110e0:lambda:self.jump(0x7f6f30),
            0xc09e50:lambda:self.jump(0x8ef4f0), 0xc09e60:lambda:self.jump(0x8ef458),
            0xc11550:self.packet_received, 0xc11490:self.connection_update})
        self.call(0x8ef1e0, self.transport + 240, 8)

    def poll(self):
        self.events.append(['poll', self.r(1)])
        self.ret()

    def receive(self):
        assert (self.r(1), self.r(3)) == (1, 128)
        count, out = self.batches.pop(0), self.r(2)
        self.events.append(['receive', count])
        for i in range(max(0, count)):
            size = self.lengths[self.serial % len(self.lengths)]
            self.serial += 1
            message, data = self.alloc(256), self.alloc(max(size, 4))
            raw = (struct.pack('<I', self.serial) + bytes(max(0, size-4)))[:size]
            self.u.mem_write(data, raw)
            self.wq(message, data)
            self.wi(message + 8, size)
            self.wq(out + i*8, message)
        self.ret(count & 0xffffffff)

    def packet_received(self):
        p = self.r(1)
        raw = bytes(self.u.mem_read(self.q(p + 56), self.i(p + 52)))
        self.events.append(['packet', len(raw), hashlib.sha256(raw).hexdigest()])
        self.ret()

    def connection_update(self):
        self.events.append(['update', self.r(1)])
        self.ret(1)

    def cycle(self, action):
        self.events = []
        self.batches, self.lengths = action['batches'][:], action['lengths']
        self.now = action['now']
        self.call(0x7feb90, self.sock, action['wait_ms'])
        readable = bool(self.u.mem_read(self.sock + 56, 1)[0])
        keep = bool(self.call(0x7fecd4, self.sock))
        # Missing SDK handle bypasses the receive method altogether.
        assert not self.batches or not self.i(self.transport + 48)
        return dict(readable=readable, keep=keep, state=self.i(self.transport + 20),
            handle=self.i(self.transport + 48), events=self.events[:])


def programs():
    for state in (1, 2):
        for wait in (0, 2):
            for batch in ([0], [-1], [-2], [1], [127], [128, 0], [128, -1],
                    [128, 1], [128, 128, -1], [128, 128, 7]):
                yield dict(name=f'matrix-{state}-{wait}-{batch}', state=state, handle=1,
                    actions=[dict(wait_ms=wait, batches=batch, lengths=[20], now=1000000)])
    for state in (1, 2):
        yield dict(name=f'error-recovery-{state}', state=state, handle=1,
            actions=[dict(wait_ms=2, batches=b, lengths=[20, 0, 1, 13, 1300, 3000], now=1000000+i)
                for i,b in enumerate(([128,-1],[-1],[1],[0],[128,1]))])
    for size in (0, 1, 13, 2048, 2049, 3000, 65536, 524288):
        yield dict(name=f'message-{size}', state=2, handle=1,
            actions=[dict(wait_ms=2, batches=[1], lengths=[size], now=1000000)])
    yield dict(name='exact-local-count-bound', state=2, handle=1,
        actions=[dict(wait_ms=2, batches=[128]*32+[-1], lengths=[20], now=1000000)])
    yield dict(name='pre-handle', state=1, handle=0,
        actions=[dict(wait_ms=2, batches=[], lengths=[20], now=1000000)])


def main():
    if not __debug__: raise RuntimeError('audit requires assertions')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--shell', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == SHA, 'wrong official sample'
    cases = []
    for program in programs():
        m = Receive(binary, program['handle'], program['state'])
        program['results'] = [m.cycle(a) for a in program['actions']]
        cases.append(program)
    result = dict(schema=1, sample_sha256=SHA, scope=__doc__, cases=cases,
        mtu_inventory=[mtu_inventory(args.binary, SHA), mtu_inventory(args.shell, SHELL_SHA)],
        helper_sha256={name: hashlib.sha256((ROOT/'scripts'/name).read_bytes()).hexdigest()
            for name in ('audit-steam-sns-receive.py', 'audit-steam-network-wire.py',
                'audit-steam-network-collectors.py', 'audit-steam-frame-stats.py',
                'audit-steam-client-config.py', 'audit-steam-client-fec-policy.py')})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(result, indent=2)+'\n').encode()
    args.output.write_bytes(gzip.compress(data, mtime=0))
    print(f'PASS original SNS receive: {len(cases)} programs/{sum(len(c["actions"]) for c in cases)} cycles; core/shell MTU call inventories')


if __name__ == '__main__': main()
