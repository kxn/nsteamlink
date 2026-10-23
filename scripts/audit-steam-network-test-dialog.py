#!/usr/bin/env python3
"""Original custom CPanelDialog hide/accept/reject and result-slot ownership.

Actual ShowDialog/HideDialog, accept/reject/done, hideEvent and generated signal
wrappers execute. QMetaObject::activate is a declared same-GUI-thread direct
dispatch provider using the actual connect strings/type0; no Qt event loop or
queued signal is run. QWidget show/hide storage, absent previous focus,
deleteLater, no recommendation, completed Test and file Save are providers.
Other manager/Test/crypto/identity/IO boundaries inherit the pinned PIN audit.
This is not QDialog behavior, a natural GUI schedule, Steam, SDK, or Switch.
"""
import argparse
import copy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('dialog_finished_pin',
    ROOT / 'scripts/audit-steam-network-test-finished-pin.py')
finished = importlib.util.module_from_spec(spec); spec.loader.exec_module(finished)
ticket, late = finished.ticket, finished.late
HIDE = '_ZN10CPanelBase10HideDialogEv'
HIDDEN = '_ZN10CPanelBase14OnDialogHiddenEP12CPanelDialog'
COMPLETE = '_ZN13CPanelConnect21OnNetworkTestCompleteEi'
ACCEPT = '_ZN12CPanelDialog6acceptEv'
REJECT = '_ZN12CPanelDialog6rejectEv'
DONE = '_ZN12CPanelDialog4doneEi'
HIDE_EVENT = '_ZN12CPanelDialog9hideEventEP10QHideEvent'
ACTIVATE = '_ZN11QMetaObject8activateEP7QObjectPKS_iPPv'
SIGNALS = ('_ZN12CPanelDialog8acceptedEv', '_ZN12CPanelDialog8finishedEi',
           '_ZN12CPanelDialog8rejectedEv', '_ZN12CPanelDialog6hiddenEPS_')


class Dialog(finished.Finished):
    def __init__(self, binary):
        self.dialog_connections = []; self.dialog_events = []; self.visible = set(); self.saved_stats = []
        self.continuations = []
        super().__init__(binary)
        self.trampoline = self.alloc(4)
        self.u.mem_write(self.trampoline, bytes.fromhex('c0035fd6'))
        self.callbacks[self.trampoline] = self.resume
        for name in (HIDE, HIDDEN, COMPLETE, ACCEPT, REJECT, DONE, HIDE_EVENT, *SIGNALS):
            self.function_entries.setdefault(self.symbols[name], []).append(name)

    def invoke(self, name, *args):
        self.continuations.append(self.u.context_save())
        for i, value in enumerate(args):
            self.u.reg_write(finished.retry.DISC.lifecycle.UC_ARM64_REG_X0 + i, value)
        self.u.reg_write(finished.retry.DISC.lifecycle.UC_ARM64_REG_X30, self.trampoline)
        self.jump(self.symbols[name])

    def resume(self):
        self.u.context_restore(self.continuations.pop())
        self.ret()

    def hook(self, u, pc, size, data):
        name = self.plts.get(pc, '')
        if name == '_ZN7QObject7connectEPKS_PKcS1_S3_N2Qt14ConnectionTypeE':
            self.dialog_connections.append(dict(sender=self.r(0), signal=self.cstring(self.r(1)),
                receiver=self.r(2), slot=self.cstring(self.r(3)), type=self.r(4)))
        if name in (HIDE, HIDDEN, ACCEPT, REJECT, DONE, HIDE_EVENT, *SIGNALS):
            return self.jump(self.symbols[name])
        if name == '_ZN12CPanelDialog4showEv':
            dialog = self.r(0); self.visible.add(dialog)
            self.wq(dialog + 0x78, 0)  # Absent previous-focus input.
            self.dialog_events.append(dict(op='show', dialog=dialog))
            return self.ret()
        if name == '_ZN7QWidget4hideEv':
            dialog = self.r(0)
            if dialog not in self.visible:
                return self.ret()
            self.visible.remove(dialog); self.dialog_events.append(dict(op='hide', dialog=dialog))
            return self.invoke(HIDE_EVENT, dialog, 0)
        if name == '_ZN7QObject11deleteLaterEv':
            self.dialog_events.append(dict(op='deleteLater', dialog=self.r(0)))
            return self.ret()
        if name == ACTIVATE:
            sender, index, args = self.r(0), self.r(2), self.r(3)
            assert self.r(1) == self.symbols['_ZN12CPanelDialog16staticMetaObjectE']
            value = self.i(self.q(args + 8)) if index == 1 else \
                    self.q(self.q(args + 8)) if index == 3 else None
            self.dialog_events.append(dict(op='signal', dialog=sender, signal=index, value=value))
            connections = [c for c in self.dialog_connections if c['sender'] == sender]
            if index == 1:
                c = next(c for c in connections if c['slot'] == '1OnNetworkTestComplete( int )')
                assert c['type'] == 0 and c['receiver'] == ticket.PANEL
                self.dialog_events.append(dict(op='slot', name=COMPLETE))
                return self.invoke(COMPLETE, ticket.PANEL, value)
            if index == 3:
                c = next(c for c in connections if 'OnDialogHidden' in c['slot'])
                assert c['type'] == 0 and value == sender
                self.dialog_events.append(dict(op='slot', name=HIDDEN))
                return self.invoke(HIDDEN, c['receiver'], sender)
            return self.ret()
        if name == '_ZN17CShellApplication16SaveNetworkStatsEPK13CNetworkStats':
            self.saved_stats.append(self.r(1)); self.dialog_events.append(dict(op='save_stats'))
            return self.ret()
        return super().hook(u, pc, size, data)

    def dialog_snapshot(self):
        return dict(**self.finished_snapshot(), connections=copy.deepcopy(self.dialog_connections),
                    events=copy.deepcopy(self.dialog_events), saved_stats=list(self.saved_stats))


def main():
    if not __debug__:
        raise RuntimeError('audit requires assertions')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args(); binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == ticket.rpc.service.m.SHELL_SHA
    cases = []
    for action in (2, 3):
        for transport in (1, 4):
            for operation in ('accept', 'reject', 'done', 'hide', 'pin', 'failed', 'cm', 'unauthorized'):
                r = Dialog(binary); ticket.rpc.bootstrap(r, 'stream')
                r.wi(ticket.PANEL + 0xd0, action)
                initial = ticket.streaming(transport=transport)
                r.update_mixed([ticket.cm(initial)] if transport == 4 else [],
                               [initial] if transport == 1 else [])
                r.call(r.symbols[ticket.UPDATE], ticket.PANEL)
                r.wi(late.TEST + 12, 2); r.wi(late.TEST + 0x114, 0); r.thread_alive = False
                r.call(r.symbols[ticket.UPDATE], ticket.PANEL)
                r.wi(ticket.PANEL + 704, 0)  # No recommendation, separate from config-save flow.
                before = r.dialog_snapshot(); old = before['dialog_owner']; assert old in r.visible
                if operation in ('accept', 'reject', 'done'):
                    r.call(r.symbols[dict(accept=ACCEPT, reject=REJECT, done=DONE)[operation]], old, 1)
                elif operation == 'hide':
                    r.call(r.symbols[HIDE], ticket.PANEL)
                else:
                    wire = ticket.rpc.wire(4, 2) if operation == 'cm' else \
                           ticket.streaming(result=11 if operation == 'pin' else
                                             1 if operation == 'unauthorized' else 3, transport=transport)
                    r.update_mixed([wire] if operation == 'cm' else [], [wire] if operation != 'cm' else [])
                after = r.dialog_snapshot()
                assert not r.assertions and not r.continuations
                signals = [e['signal'] for e in after['events'] if e['op'] == 'signal' and e['dialog'] == old]
                confirmed = operation in ('accept', 'reject', 'done')
                kept = operation == 'unauthorized'
                assert signals == ([2 if operation == 'reject' else 0, 1, 3] if confirmed else [] if kept else [3])
                assert len(after['saved_stats']) == int(confirmed)
                assert (old in r.visible) == kept
                assert [e for e in after['events'] if e == dict(op='deleteLater', dialog=old)] == ([] if kept else [dict(op='deleteLater', dialog=old)])
                cases.append(dict(action=action, transport=transport, operation=operation,
                    before=before, after=after, executed=sorted(r.executed), source_assertions=r.assertions))
    old_raw = (ROOT / 'scripts/fixtures/steam-network-test-finished-pin-reference.json.gz').read_bytes()
    assert hashlib.sha256(old_raw).hexdigest() == '59ec6bfdf35e608fefe5f4f72bd8383037a4128252bc3722480e53c76241cd13'
    helpers = json.loads(gzip.decompress(old_raw))['helper_sha256']
    helpers[Path(__file__).name] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report = dict(schema=1, sample_sha256=ticket.rpc.service.m.SHELL_SHA, scope=__doc__,
                  helper_sha256=dict(sorted(helpers.items())), cases=cases)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(report, indent=2, sort_keys=True)+'\n').encode()
    args.output.write_bytes(gzip.compress(raw, mtime=0) if args.output.suffix == '.gz' else raw)
    print('PASS 32 original custom dialog/manager/result-slot programs; hide differs from finished')


if __name__ == '__main__':
    main()
