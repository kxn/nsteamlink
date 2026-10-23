#!/usr/bin/env python3
"""Original Test Failed -> late control -> actual ShowDialog owner replacement.

Full ticket manager/CM/UDP/AES, Test Run/BConnect with supplied SDK BInit=false,
Panel OnUpdate/OnServerError/PIN, CPanelBase::ShowDialog ownership and cancel /
Test destructor execute. Widget hide/show, dialog storage/presentation, SDK and
thread endpoints remain providers. No natural Qt signal delivery, SDK failure,
real Steam or Switch. Test Failed before/after its initial dialog is explicit. Two Unauthorized-before-
failed-dialog cases execute an original BIsStreaming assertion; these are recorded
diagnostic branches, not normal equivalence or an instruction to copy that assert.
"""
import argparse
import copy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sdk_overlap', ROOT / 'scripts/audit-steam-network-test-sdk-failure.py')
sdk = importlib.util.module_from_spec(spec); spec.loader.exec_module(sdk)
late = sdk.late
ticket = late.ticket
SHOW = '_ZN10CPanelBase10ShowDialogEP12CPanelDialog'


class DialogOwner(sdk.InitFailure):
    def __init__(self, binary):
        self.dialogs = []; self.widgets = []; self.diagnostics = []
        super().__init__(binary)
        self.function_entries.setdefault(self.symbols[SHOW], []).append(SHOW)

    def hook(self, u, pc, size, data):
        name = self.plts.get(pc, '')
        if 'AssertFailed' in name:
            self.diagnostics.append(dict(file=self.cstring(self.r(0)), line=self.r(1),
                                         expression=self.cstring(self.r(2))))
        if name.startswith('_ZN12CPanelDialogC') and 'EDialogStyle' in name:
            self.dialogs.append(dict(pointer=self.r(0),
                title=self.qt_strings.get(self.q(self.r(2))),
                body=self.qt_strings.get(self.q(self.r(3)))))
        if name == SHOW:
            return self.jump(self.symbols[name])
        if name in ('_ZN7QWidget4hideEv', '_ZN12CPanelDialog4showEv'):
            self.widgets.append(dict(op='hide' if 'hide' in name else 'show', pointer=self.r(0)))
            return self.ret()
        return super().hook(u, pc, size, data)

    def overlap(self):
        return dict(**self.observe_sdk(), dialog_owner=self.q(ticket.PANEL + 0xb8),
                    dialogs=copy.deepcopy(self.dialogs), widgets=copy.deepcopy(self.widgets),
                    diagnostics=copy.deepcopy(self.diagnostics))


def main():
    if not __debug__: raise RuntimeError('audit requires assertions')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args(); binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == ticket.rpc.service.m.SHELL_SHA
    cases = []
    for action in (2, 3):
        for shown in (False, True):
            for kind, result in (('cm', 2), ('udp', 3), ('udp', 11), ('udp', 1), ('udp', 4), ('udp', 0)):
                r = DialogOwner(binary); ticket.rpc.bootstrap(r, 'stream')
                r.wi(ticket.PANEL + 0xd0, action)
                initial = ticket.cm(ticket.streaming(transport=4))
                r.update_mixed([initial], []); r.call(r.symbols[ticket.UPDATE], ticket.PANEL)
                r.call(r.symbols['_ZN12CNetworkTest14RunNetworkTestEv'], late.TEST)
                if shown: r.call(r.symbols[ticket.UPDATE], ticket.PANEL)
                before = r.overlap()
                wire = ticket.rpc.wire(4, result) if kind == 'cm' else ticket.streaming(result=result, transport=4)
                r.update_mixed([wire] if kind == 'cm' else [], [wire] if kind == 'udp' else [])
                r.call(r.symbols[ticket.UPDATE], ticket.PANEL); after = r.overlap()
                control = kind == 'cm' or result in (3, 11)
                pin = kind == 'udp' and result == 11
                auth = kind == 'udp' and result == 1
                assert before['test_status'] == after['test_status'] == 4
                assert not after['test_session'] and not after['joined'] and after['launches'] == 1
                assert after['manager'] == (1 if control else 4 if auth else 6)
                assert after['panel'] == (6 if pin else 1)
                assert len([w for w in after['widgets'] if w['op'] == 'show']) == 1+int(shown and control)
                if shown and control:
                    assert dict(op='hide', pointer=before['dialog_owner']) in after['widgets']
                    assert after['dialog_owner'] != before['dialog_owner']
                elif shown:
                    assert after['dialog_owner'] == before['dialog_owner']
                if control and not pin:
                    assert after['dialogs'][-1]['title'] != 'Network Test Failed'
                elif not pin:
                    assert after['dialogs'][-1]['title'] == 'Network Test Failed'
                r.call(r.symbols[late.CANCEL], ticket.PANEL); ack = r.overlap()
                assert ack['manager'] == 1 and ack['request_id'] == 0
                tags = [m['tag'] for m in ack['messages'] if m['tag'] in (9, 10)]
                assert tags == [9 if auth else 10]
                r.stage = 'destroy'; r.call(r.symbols[late.DTOR], late.TEST)
                assert r.joined == 1
                # Original getter diagnoses BIsStreaming after Unauthorized
                # changed manager6 to4 before the first failed-Test dialog.
                # Keep these two diagnostic cases separate from normal equivalence.
                assert r.assertions == ([208] if auth and not shown else [])
                if r.assertions:
                    assert r.diagnostics == [dict(file='../../src/streaming/client/servermanager.h',
                                                  line=208, expression='BIsStreaming()')]
                cases.append(dict(action=action, shown=shown, kind=kind, result=result,
                    initial_cm=initial.hex(), late_cm=[wire.hex()] if kind == 'cm' else [],
                    late_udp=[wire.hex()] if kind == 'udp' else [], before=before, after=after,
                    ack=ack, destroyed=r.overlap(), executed=sorted(r.executed), source_assertions=r.assertions))
    raw = (ROOT / 'scripts/fixtures/steam-network-test-sdk-failure-reference.json.gz').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == '5bd445fff735c3a5fd93cc55d2419564499f1b8ce9d4b81a0c4e08c0e3c9b0fe'
    helpers = json.loads(gzip.decompress(raw))['helper_sha256']
    for name, sha in helpers.items():
        assert hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest() == sha
    helpers[Path(__file__).name] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report = dict(schema=1, sample_sha256=ticket.rpc.service.m.SHELL_SHA, scope=__doc__,
                  helper_sha256=dict(sorted(helpers.items())), cases=cases)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(report, indent=2, sort_keys=True)+'\n').encode()
    args.output.write_bytes(gzip.compress(data, mtime=0) if args.output.suffix == '.gz' else data)
    print('PASS 22 normal + 2 explicitly diagnostic original overlap programs; actual ShowDialog owner replacement')


if __name__ == '__main__': main()
