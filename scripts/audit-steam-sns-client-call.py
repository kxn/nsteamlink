#!/usr/bin/env python3
"""Original CStreamClient BConnect and subsequent SDL initial-wait caller.

Original transport selection, BInit result branch, bridge/Connection creation
order, SetAuthToken caller and selected SDL/OnThink wait instructions execute. Backend
constructor/BInit/Release, bridge and Connection storage/Connect are providers;
auth-buffer storage is a provider. SDK connected is deliberately not asserted. Clock, endpoint formatting and
inherited player/OS/IO boundaries remain providers. No actual SDK, Host or NRO.
"""
import argparse
import ast
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile

if not __debug__:
    raise SystemExit('Original audit requires assertions')
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('wait', ROOT/'scripts/audit-steam-connection-wait.py')
w = importlib.util.module_from_spec(spec); spec.loader.exec_module(w)
CONNECT = '_ZN13CStreamClient8BConnectE16EStreamTransport9EUniverse11ESteamRealmyRK10CIPAndPortPKcS7_b'
REFERENCE = ROOT/'scripts/fixtures/steam-sns-client-call-reference.json.gz'


def backend_slots(binary):
    """Resolve the actual SDR vtable; this is static evidence, not BInit execution."""
    elf = ELFFile(io.BytesIO(binary))
    dynsym = elf.get_section_by_name('.dynsym')
    symbols = {s.name: s for s in dynsym.iter_symbols()}
    base = symbols['_ZTV19CStreamTransportSDR']['st_value']
    relocations = {r['r_offset']: r['r_addend']+dynsym.get_symbol(r['r_info_sym'])['st_value']
                   for r in elf.get_section_by_name('.rela.dyn').iter_relocations()}
    out = {}
    for offset, name, address in (
            (0x18, '_ZN42CStreamTransportSteamNetworkingSocketsBase7ReleaseEv', 0x7ffcd4),
            (0x20, '_ZN42CStreamTransportSteamNetworkingSocketsBase5BInitEv', 0x7ffd30),
            (0x28, '_ZN19CStreamTransportSDR11UpdateStateEv', 0x8011f0)):
        symbol = symbols[name]
        assert relocations[base+offset] == symbol['st_value'] == address
        segment = next(s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD'
                       and s['p_vaddr'] <= address < s['p_vaddr']+s['p_filesz'])
        start = address-segment['p_vaddr']
        raw = segment.data()[start:start+symbol['st_size']]
        out[name] = dict(address=address, vtable_offset=offset,
                         sha256=hashlib.sha256(raw).hexdigest())
    return out


class Caller(w.Wait):
    def __init__(self, binary, inp):
        self.caller_events = []
        self.backend = self.bridge = self.connection = 0
        self.caller_executed = []
        super().__init__(binary, dict(phase=0, start=0, now=inp['elapsed_ms']*65536//1000,
                                      previous_display=0))
        self.binit = inp['binit']
        self.wq(self.main_client+0x118, 0)
        self.wq(self.main_client+0x108, 0)
        self.callbacks[w.c.STOP+0xc00] = self.init_backend
        self.callbacks[w.c.STOP+0xc10] = lambda: self.release('backend')
        self.callbacks[w.c.STOP+0xc20] = lambda: self.release('bridge')

    def init_backend(self):
        self.caller_events.append('binit')
        self.ret(int(self.binit))

    def release(self, kind):
        self.caller_events.append(kind+'-release')
        self.ret()

    def hook(self, u, pc, size, data):
        if pc == self.symbols.get(CONNECT):
            self.caller_executed.append(CONNECT)
        name = self.plts.get(pc, '')
        if (name == '_ZN10CUtlBuffer3PutEPKvi' and hasattr(self, 'main_client')
                and self.r(0) == self.main_client+0x40):
            destination, source, count = (self.r(n) for n in range(3))
            pointer = self.alloc(count or 1)
            if count: u.mem_write(pointer, bytes(u.mem_read(source, count)))
            self.wq(destination, pointer); self.wi(destination+8, count); self.wi(destination+20, count)
            return self.ret()
        if name == '_ZN19CStreamTransportSDRC1EbPKcS1_b':
            assert self.r(1) == 1 and self.r(4) == 1
            self.backend = self.r(0)
            vt = self.alloc(160); self.wq(self.backend, vt)
            self.wq(vt+16, w.c.STOP+0xc00); self.wq(vt+8, w.c.STOP+0xc10)
            self.caller_events.append('backend-create')
            return self.ret()
        if name == '_ZN22CStreamTransportClientC1EP16IStreamTransport9EUniverse11ESteamRealmyRK10CUtlBuffer':
            token = self.r(5)
            assert self.i(token+20) == 32
            assert bytes(u.mem_read(self.q(token), 32)) == bytes(range(32))
            self.bridge = self.r(0)
            vt = self.alloc(128); self.wq(self.bridge, vt); self.wq(vt+56, w.c.STOP+0xc20)
            self.caller_events.append('bridge-create')
            return self.ret()
        if name == '_ZN17CStreamConnection6CreateEP16IStreamTransport':
            self.connection = self.alloc(4096); self.wi(self.connection+16, 1)
            self.caller_events.append('connection-create')
            return self.ret(self.connection)
        if name == '_ZN17CStreamConnection7ConnectERK10CIPAndPort':
            self.caller_events.append('connection-connect')
            return self.ret()
        return super().hook(u, pc, size, data)

    def run_caller(self):
        peer, cert, stun, token = (self.alloc(64) for _ in range(4))
        self.u.mem_write(cert, b'fixture-cert\0')
        self.u.mem_write(stun, b'stun:fixture.invalid\0')
        self.u.mem_write(token, bytes(range(32)))
        self.call(self.symbols['_ZN13CStreamClient12SetAuthTokenEPKvi'], self.main_client, token, 32)
        # AAPCS64 ninth argument: share_ip belongs on the caller stack, not X8.
        self.b(0x300ff000, 1)
        result = self.call(self.symbols[CONNECT], self.main_client, 4, 1, 1, 123, peer, cert, stun)
        before = dict(result=result, phase=self.i(self.main_client+256), events=list(self.caller_events))
        after = self.run_loop() if result else None
        assert not self.assertions
        return dict(before=before, after=after, executed=self.caller_executed,
                    source_assertions=list(self.assertions))


def helpers():
    pending, out = [Path(__file__).name], {}
    while pending:
        name = pending.pop()
        if name in out: continue
        raw = (ROOT/'scripts'/name).read_bytes()
        out[name] = hashlib.sha256(raw).hexdigest()
        for node in ast.walk(ast.parse(raw)):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                dep = Path(node.value).name
                if dep.startswith('audit-steam-') and dep.endswith('.py') and (ROOT/'scripts'/dep).is_file():
                    pending.append(dep)
    return dict(sorted(out.items()))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    p.add_argument('--refresh-reference', action='store_true'); args = p.parse_args()
    binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == w.SHA
    cases = []
    for binit, elapsed in ((True, 9999), (True, 10000), (True, 11000), (False, 0)):
        inp = dict(binit=binit, elapsed_ms=elapsed)
        cases.append(dict(input=inp, observed=Caller(binary, inp).run_caller()))
    ticket_raw = (ROOT/'scripts/fixtures/steam-ticket-consumer-reference.json.gz').read_bytes()
    ticket = next(c for c in json.loads(gzip.decompress(ticket_raw))['cases']
                  if c['name']=='success' and c['transport']==4 and not c['testing'])
    report = dict(schema=1, binary_sha256=w.SHA, scope=__doc__, helpers=helpers(), cases=cases,
                  static_backend_slots=backend_slots(binary),
                  ticket_reference_sha256=hashlib.sha256(ticket_raw).hexdigest(), native_ticket=ticket['cm'])
    raw = gzip.compress(json.dumps(report, sort_keys=True, separators=(',', ':')).encode(), mtime=0)
    args.output.write_bytes(raw)
    if args.refresh_reference: REFERENCE.write_bytes(raw)
    else: assert raw == REFERENCE.read_bytes()
    print('PASS 4 original BConnect/SDL wait caller programs')


if __name__ == '__main__': main()
