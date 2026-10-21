#!/usr/bin/env python3
"""Original Test's SDR BInit=false -> Run failure -> Panel error -> cancel.

Full manager/CM parser/AES, Panel OnUpdate, Test Run/BConnect and failed-dialog
wiring/cancel/destructor execute. SDR constructor/storage, virtual BInit=false
and Release are explicit providers; no SDK, Connection/bridge or natural thread
is created. Inherited Qt/identity/clock/final IO providers remain. Pop and final
Test destruction are separately driven, not natural Qt event scheduling.
"""
import argparse
import copy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('test_sdk_late', ROOT / 'scripts/audit-steam-network-test-late-control.py')
late = importlib.util.module_from_spec(spec); spec.loader.exec_module(late)


class InitFailure(late.Late):
    def __init__(self, binary):
        self.backend_events = []
        super().__init__(binary)
        stop = next(cls.__dict__['hook'].__globals__['STOP'] for cls in type(self).__mro__
                    if 'hook' in cls.__dict__ and isinstance(cls.__dict__['hook'].__globals__.get('STOP'), int))
        self.callbacks[stop + 0xe40] = self.binit
        self.callbacks[stop + 0xe44] = self.release
        self.stop = stop
        for name in ('_ZN12CNetworkTest8BConnectEv', '_ZN12CNetworkTest14RunNetworkTestEv'):
            self.function_entries.setdefault(self.symbols[name], []).append(name)

    def binit(self):
        self.backend_events.append('binit-false'); return self.ret(0)

    def release(self):
        self.backend_events.append('backend-release'); return self.ret()

    def hook(self, u, pc, size, data):
        name = self.plts.get(pc, '')
        if name == '_ZN12CNetworkTest8BConnectEv':
            return self.jump(self.symbols[name])
        if name == '_ZN19CStreamTransportSDRC1EbPKcS1_b':
            self.backend_events.append('sdr-create')
            vt = self.alloc(128); self.wq(self.r(0), vt)
            self.wq(vt + 16, self.stop + 0xe40); self.wq(vt + 8, self.stop + 0xe44)
            return self.ret()
        return super().hook(u, pc, size, data)

    def observe_sdk(self):
        return dict(**self.observe_late(), backend_events=copy.deepcopy(self.backend_events),
                    backend_cleared=self.q(late.TEST + 0x120) == 0,
                    connection_cleared=self.q(late.TEST + 0x128) == 0)


def main():
    if not __debug__: raise RuntimeError('audit requires assertions')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args(); binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == late.ticket.rpc.service.m.SHELL_SHA
    cases = []
    for action in (2, 3):
        r = InitFailure(binary); late.ticket.rpc.bootstrap(r, 'stream')
        r.wi(late.ticket.PANEL + 0xd0, action)
        wire = late.ticket.cm(late.ticket.streaming(transport=4))
        r.update_mixed([wire], []); r.call(r.symbols[late.ticket.UPDATE], late.ticket.PANEL)
        before = r.observe_sdk()
        r.call(r.symbols['_ZN12CNetworkTest14RunNetworkTestEv'], late.TEST)
        ran = r.observe_sdk()
        assert ran['test_status'] == 4 and ran['test_session'] == 0
        assert ran['backend_cleared'] and ran['connection_cleared']
        assert ran['backend_events'] == ['sdr-create', 'binit-false', 'backend-release']
        r.call(r.symbols[late.ticket.UPDATE], late.ticket.PANEL); error = r.observe_sdk()
        assert error['manager'] == 6 and error['request_id'] == 17 and error['panel'] == 1
        assert dict(error_style=0) in error['ui']
        assert dict(signal='2finished( int )', slot='1OnActionCancel()') in error['ui']
        assert not any(m['tag'] in (9, 10) for m in error['messages'])
        r.call(r.symbols[late.CANCEL], late.ticket.PANEL); ack = r.observe_sdk()
        assert ack['manager'] == 1 and ack['request_id'] == 0
        assert [m['tag'] for m in ack['messages']] == [5, 10]
        assert not ack['joined']
        r.stage = 'destroy'; r.call(r.symbols[late.DTOR], late.TEST); destroyed = r.observe_sdk()
        assert destroyed['joined'] == 1 and not r.assertions
        cases.append(dict(action=action, cm=wire.hex(), before=before, ran=ran,
                          error=error, ack=ack, destroyed=destroyed,
                          executed=sorted(r.executed), source_assertions=r.assertions))
    helpers = late.ticket.helpers()
    for file in (Path(late.__file__), Path(__file__)):
        helpers[file.name] = hashlib.sha256(file.read_bytes()).hexdigest()
    report = dict(schema=1, sample_sha256=late.ticket.rpc.service.m.SHELL_SHA, scope=__doc__,
                  helper_sha256=dict(sorted(helpers.items())), cases=cases)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode()
    args.output.write_bytes(gzip.compress(raw, mtime=0) if args.output.suffix == '.gz' else raw)
    print('PASS 2 original SDR BInit-failure -> Test Run/Panel/cancel/destructor programs')


if __name__ == '__main__': main()
