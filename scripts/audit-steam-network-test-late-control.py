#!/usr/bin/env python3
"""Original active Test panel -> mixed manager ingress -> error/PIN/auth -> cancel.

Manager/session/UDP parsers, response handling/crypto, observer thunk, Panel
OnUpdate/OnServerError/PIN/OnActionCancel and final NetworkTest destructor run.
The worker's session phase 0/4 is controlled input, not a real established
connection. Qt widget/storage/display, thread IsAlive/Join and inherited initial
objects/clock/identity/request-RSA/final sends are providers. Panel destruction
after Pop is an explicit driver boundary; no Qt scheduling, media or SDK claim.
"""
import argparse
import copy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('late_test_ticket',
    Path(__file__).with_name('audit-steam-ticket-consumer.py'))
ticket=importlib.util.module_from_spec(spec);spec.loader.exec_module(ticket)
TEST=ticket.PANEL+280
PIN='_ZN13CPanelConnect24SetPanelStateEnteringPINEv'
CANCEL='_ZN13CPanelConnect14OnActionCancelEv'
DTOR='_ZN12CNetworkTestD1Ev'


class Late(ticket.TicketConsumer):
    def __init__(self,binary):
        self.ui=[];self.joined=0;self.stage='initial'
        super().__init__(binary,True)
        for name in (PIN,CANCEL,DTOR):
            self.function_entries.setdefault(self.symbols[name],[]).append(name)

    def hook(self,u,pc,size,data):
        name=self.plts.get(pc,'')
        if name.startswith('_ZN9CPINEntryC'):
            self.wq(self.r(0)+64,self.alloc(64));self.wq(self.r(0)+72,self.alloc(64))
            self.ui.append(dict(pin=True));return self.ret()
        if name.startswith('_ZN12CPanelDialogC'):
            # The 5-argument error overload supplies style in x4; PIN uses
            # the separate 3-argument overload. Qt storage is a provider.
            if 'EDialogStyle' in name:self.ui.append(dict(error_style=self.r(4)))
            return self.ret()
        if name.startswith('_ZN12CPanelDialog') or name=='_ZN15QAbstractButton7setTextERK7QString':
            return self.ret()
        if name=='_ZN7QObject7connectEPKS_PKcS1_S3_N2Qt14ConnectionTypeE':
            self.ui.append(dict(signal=self.cstring(self.r(1)),slot=self.cstring(self.r(3))))
        if name=='_ZN17CShellApplication8PopStateEv':
            self.ui.append(dict(pop=True));return self.ret()
        if self.stage=='destroy' and name=='_ZNK16SteamThreadTools7CThread7IsAliveEv':
            return self.ret(1) # Controlled live thread; execute the real Join branch.
        if self.stage=='destroy' and name=='_ZN16SteamThreadTools7CThread4JoinEj':
            assert self.r(1)==0xffffffff
            self.joined+=1;return self.ret(1)
        return super().hook(u,pc,size,data)

    def observe_late(self):
        rpc=self.observe_rpc()
        return dict(manager=rpc['state'],request_id=rpc['rid'],target=rpc['target'],
            panel=self.i(ticket.PANEL+0xd8),test_status=self.i(TEST+12),
            test_session=self.i(TEST+0x114),launches=len(self.auth_tokens),
            errors=copy.deepcopy(self.panel_errors),ui=copy.deepcopy(self.ui),
            messages=copy.deepcopy(rpc['messages']),joined=self.joined)


def main():
    if not __debug__:raise RuntimeError('audit requires assertions')
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();binary=args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest()==ticket.rpc.service.m.SHELL_SHA,'wrong shell'
    cases=[]
    for transport in (1,4):
        for phase in (0,4):
            for kind,result in (('udp',3),('cm',2),('udp',11),('udp',1),('udp',4),('udp',0)):
                r=Late(binary);ticket.rpc.bootstrap(r,'stream')
                good=ticket.streaming(transport=transport)
                r.update_mixed([ticket.cm(good)] if transport==4 else [],[good] if transport==1 else [])
                r.call(r.symbols[ticket.UPDATE],ticket.PANEL)
                assert r.i(ticket.PANEL+0xd8)==5 and r.i(TEST+12)==1
                r.wi(TEST+0x114,phase) # Worker state is an explicit input boundary.
                before=r.observe_late()
                late=ticket.streaming(result=result,transport=transport) if kind=='udp' else ticket.rpc.wire(4,result)
                r.stage='late';r.update_mixed([late] if kind=='cm' else [],[late] if kind=='udp' else [])
                error=r.observe_late();r.call(r.symbols[ticket.UPDATE],ticket.PANEL);after=r.observe_late()
                assert after['test_session']==phase and after['test_status']==1 and not after['joined']
                assert after['launches']==1
                assert DTOR not in r.executed
                if kind=='cm' or result==3:
                    assert after['manager']==after['panel']==1
                    assert dict(error_style=0) in after['ui']
                    assert dict(signal='2finished( int )',slot='1OnActionCancel()') in after['ui']
                elif result==11:
                    assert after['manager']==1 and after['panel']==6 and dict(pin=True) in after['ui']
                else:
                    assert after['panel']==5 and after['manager']==(4 if result==1 else 6)
                r.stage='ack';r.call(r.symbols[CANCEL],ticket.PANEL);ack=r.observe_late()
                # Explicit final panel-owner cleanup, separate from the Pop provider.
                r.stage='destroy';r.call(r.symbols[DTOR],TEST);destroy=r.observe_late()
                assert r.joined==1 and not r.assertions
                cases.append(dict(transport=transport,phase=phase,kind=kind,result=result,
                    initial_cm=[ticket.cm(good).hex()] if transport==4 else [],
                    initial_udp=[good.hex()] if transport==1 else [],
                    late_cm=[late.hex()] if kind=='cm' else [],late_udp=[late.hex()] if kind=='udp' else [],
                    before=before,error=error,after=after,ack=ack,destroy=destroy,
                    executed=sorted(r.executed),source_assertions=r.assertions))
    helpers=ticket.helpers();helpers[Path(__file__).name]=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report=dict(schema=1,sample_sha256=ticket.rpc.service.m.SHELL_SHA,scope=__doc__,
        helper_sha256=dict(sorted(helpers.items())),cases=cases)
    raw=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_bytes(gzip.compress(raw,mtime=0) if args.output.suffix=='.gz' else raw)
    print(f'PASS {len(cases)} original Test-panel late-control programs; error/PIN/auth, '
          'no early test destruction, acknowledgement then explicit destructor/Join')


if __name__=='__main__':main()
