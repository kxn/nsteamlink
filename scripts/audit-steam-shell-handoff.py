#!/usr/bin/env python3
"""Original ticket consumer -> Shell Quit -> manager destructor/Stop.

Actual manager/session ingress, response/AES and Panel consumer run as in the
ticket audit. Ordinary launcher is observed at its existing boundary; Quit is
then explicitly invoked as the outer main caller does. Settings/cursor, sound,
final discovery/session destructors and hash-map destruction are providers.
No real Qt loop, Android Activity launch, SDK or media is claimed.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('shell_ticket',
    Path(__file__).with_name('audit-steam-ticket-consumer.py'))
ticket = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ticket)
QUIT = '_ZN17CShellApplication4QuitEv'
STOP = '_ZN14CServerManager4StopEv'
DTOR = '_ZN14CServerManagerD1Ev'
DELETE = '_ZN14CServerManagerD0Ev'
VTABLE = '_ZTV14CServerManager'


def static_caller(path):
    with path.open('rb') as f:
        elf = ELFFile(f); dyn = elf.get_section_by_name('.dynsym')
        symbols = {s.name:s for s in dyn.iter_symbols()}
        def raw(address, size):
            for segment in elf.iter_segments():
                if segment['p_type'] == 'PT_LOAD' and segment['p_vaddr'] <= address and address+size <= segment['p_vaddr']+segment['p_filesz']:
                    offset = address-segment['p_vaddr']; return segment.data()[offset:offset+size]
            raise AssertionError(hex(address))
        plt = elf.get_section_by_name('.plt')
        targets = {plt['sh_addr']+32+n*16:dyn.get_symbol(r['r_info_sym']).name
            for n,r in enumerate(elf.get_section_by_name('.rela.plt').iter_relocations())}
        def branch(address, name):
            instruction = int.from_bytes(raw(address, 4),'little')
            assert instruction >> 26 == 0b100101
            offset = instruction & 0x3ffffff
            if offset & (1<<25): offset -= 1<<26
            assert targets[address+4*offset] == name, (hex(address),name)
            return dict(address=address, target=name, bytes=raw(address,4).hex())
        slot = symbols[VTABLE]['st_value']+16+56
        reloc = next(r for r in elf.get_section_by_name('.rela.dyn').iter_relocations() if r['r_offset']==slot)
        assert dyn.get_symbol(reloc['r_info_sym']).name == DELETE
        # Main calls Run -> Quit -> destructor before its JNI branch. The
        # StartStreaming overload requests Qt quit. No synthetic call order.
        calls = [branch(a,n) for a,n in (
            (0xc98240,'_ZN14CServerManagerC1Ev'),
            (0xc9980c,'_ZN16QCoreApplication4quitEv'),
            (0xc6580c,'_ZN17CShellApplication3RunEv'),
            (0xc65814,QUIT), (0xc6581c,'_ZN17CShellApplicationD1Ev'),
            (0xcaeccc,STOP))]
        windows = {name:dict(address=symbols[name]['st_value'],size=symbols[name]['st_size'],
            sha256=hashlib.sha256(raw(symbols[name]['st_value'],symbols[name]['st_size'])).hexdigest())
            for name in (QUIT,STOP,DTOR,DELETE)}
        # BInit stores the constructed manager into app+24. Quit dispatches
        # its +56 virtual deleting dtor and clears the app pointer afterwards.
        opcodes = {a:raw(a,4).hex() for a in (0xc9824c,0xc97f94,0xc97fa0,0xc97fa4,0xc97fa8)}
        assert list(opcodes.values()) == ['760e00f9','600e40f9','081d40f9','00013fd6','7f0e00f9']
        return dict(calls=calls,windows=windows,opcodes=opcodes,
            manager_delete_slot=dict(address=slot,offset=56,symbol=DELETE))


class Handoff(ticket.TicketConsumer):
    def __init__(self,binary,testing):
        self.teardown=[]
        self.freed=[]
        super().__init__(binary,testing)
        for name in (QUIT,STOP,DTOR,DELETE):
            self.function_entries.setdefault(self.symbols[name],[]).append(name)

    def hook(self,u,pc,size,data):
        name=self.plts.get(pc,'')
        if name=='free': self.freed.append(self.r(0))
        if name in ('_ZN16CDiscoverySocketD1Ev','_ZN20CRemoteClientSessionD1Ev'):
            self.teardown.append(name); return self.ret()
        if name == '_ZN22CStreamingClientConfigC1Ev':
            u.mem_write(self.r(0),bytes(176)); u.mem_write(self.r(0)+0x73,b'\1')
            return self.ret()  # Config suppresses the unrelated cursor restore.
        if name in ('_ZN17CShellApplication21LoadStreamingSettingsEP22CStreamingClientConfig',
                    '_ZN22CStreamingClientConfigD1Ev','_Z9QuitSoundv'):
            self.teardown.append(name); return self.ret()
        if name in (STOP,DTOR): return self.jump(self.symbols[name])
        if 'CUtlHashMap' in name and ('PurgeAndDeleteElements' in name or 'D2Ev' in name):
            self.teardown.append(name); return self.ret()
        return super().hook(u,pc,size,data)

    def prepare_app(self):
        self.app = self.alloc(256)
        vt = self.alloc(512)
        self.wq(self.manager,vt)
        self.wq(vt+56,self.symbols[DELETE])
        self.wq(self.app+24,self.manager)

    def handoff(self):
        cache=self.alloc(16)
        self.u.mem_write(cache,b'fixture-keybytes')
        self.wq(self.manager+0x2d8,cache);self.wi(self.manager+0x2ec,16)
        self.wi(self.manager+0x318,0)
        before = self.observe_rpc()
        self.call(self.symbols[QUIT],self.app)
        after = self.observe_rpc()
        # Stop is distinct from StopStreaming; no cancel9/10 or error callback.
        assert after['messages'] == before['messages'] and after['rpc'] == before['rpc']
        assert after['notifications'] == before['notifications']
        assert self.q(self.app+24) == self.q(self.manager+24) == self.q(self.manager+32) == 0
        assert after['state'] == 0 and not self.assertions
        assert cache in self.freed
        assert self.constructor_defaults['cache_length']==0 and self.constructor_defaults['cached_result']==7
        assert all(name in self.executed for name in (QUIT,STOP,DTOR,DELETE))
        return dict(manager_present=False,discovery_socket=False,cloud_session=False,
            state=after['state'],cancel_sent=False,request_id_storage=after['rid'],
            target_storage=after['target'],teardown=self.teardown[:],recent_key_freed=True,
            fresh_cache_length=self.constructor_defaults['cache_length'],
            fresh_cached_result=self.constructor_defaults['cached_result'])


def main():
    if not __debug__: raise RuntimeError('audit requires assertions')
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();binary=args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest()==ticket.rpc.service.m.SHELL_SHA,'wrong shell sample'
    static=static_caller(args.binary)
    cases=[]
    prior=json.loads(gzip.decompress(ticket.REFERENCE.read_bytes()))['cases']
    for name,testing,transport,cm,udp in ticket.cases():
        r=Handoff(binary,testing);ticket.rpc.bootstrap(r,'stream')
        r.update_mixed(cm,udp);r.call(r.symbols[ticket.UPDATE],ticket.PANEL)
        r.prepare_app()
        admitted=r.result();handoff=None
        previous=next(c for c in prior if (c['name'],c['testing'],c['transport'])==(name,testing,transport))
        assert admitted==previous['steps'][-1], (name,testing,transport,admitted,previous['steps'][-1])
        r.teardown=[]
        if not testing and admitted['launches']:
            handoff=r.handoff()
        else:
            assert r.q(r.app+24)==r.manager and not r.teardown
        cases.append(dict(name=name,testing=testing,transport=transport,
            cm=[w.hex() for w in cm],udp=[w.hex() for w in udp],admitted=admitted,
            handoff=handoff,executed=sorted(r.executed),source_assertions=r.assertions))
    helper=ticket.helpers()
    helper[Path(__file__).name]=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result=dict(schema=1,sample_sha256=ticket.rpc.service.m.SHELL_SHA,scope=__doc__,
        helper_sha256=dict(sorted(helper.items())),static_caller=static,cases=cases,
        late_inprogress=ticket.streaming(result=5).hex())
    raw=(json.dumps(result,indent=2,sort_keys=True)+'\n').encode()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_bytes(gzip.compress(raw,mtime=0) if args.output.suffix=='.gz' else raw)
    print(f'PASS: {len(cases)} original consumer programs, {sum(c["handoff"] is not None for c in cases)} ordinary Quit/destructor/Stop handoffs; network-test excluded')


if __name__=='__main__': main()
