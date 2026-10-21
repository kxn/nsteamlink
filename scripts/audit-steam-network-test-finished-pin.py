#!/usr/bin/env python3
"""Original finished Test -> optional result dialog -> PIN -> new ticket.

Manager/CM/UDP/AES, real Panel result polling, ShowDialog owner replacement,
OnPINEntered/request producer, ticket consumer and Test::Start/destructor run.
Completed status/phase0/statistics and IsAlive=false are seeded providers, not
natural worker finalization. Qt objects/text/hide/show, new thread Start/Join,
identity/entropy/RSA/clock/final sends are also providers. No real Steam/SDK,
Qt event loop, native thread, or Switch is exercised here.
"""
import argparse
import copy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('finished_pin_retry',
    ROOT / 'scripts/audit-steam-network-test-pin-retry.py')
retry = importlib.util.module_from_spec(spec); spec.loader.exec_module(retry)
ticket, late = retry.ticket, retry.late
SHOW = '_ZN10CPanelBase10ShowDialogEP12CPanelDialog'
OUTCOMES = ('cancel_wait', 'success', 'failure', 'pin', 'unauthorized', 'busy',
            'duplicate_success', 'failure_after_ticket')


class Finished(retry.Retry):
    def __init__(self, binary):
        self.widgets = []
        super().__init__(binary)
        self.function_entries.setdefault(self.symbols[SHOW], []).append(SHOW)

    def hook(self, u, pc, size, data):
        name = self.plts.get(pc, '')
        if name == SHOW:
            return self.jump(self.symbols[name])
        if name in ('_ZN7QWidget4hideEv', '_ZN12CPanelDialog4showEv'):
            self.widgets.append(dict(op='hide' if 'hide' in name else 'show', pointer=self.r(0)))
            return self.ret()
        return super().hook(u, pc, size, data)

    def finished_snapshot(self):
        return dict(**self.retry_snapshot(), dialog_owner=self.q(ticket.PANEL + 0xb8),
                    widgets=copy.deepcopy(self.widgets))


def main():
    if not __debug__:
        raise RuntimeError('audit requires assertions')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args(); binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == ticket.rpc.service.m.SHELL_SHA
    cases = []
    for transport in (1, 4):
        for shown in (False, True):
            for outcome in OUTCOMES:
                r = Finished(binary); ticket.rpc.bootstrap(r, 'stream')
                initial = ticket.streaming(transport=transport)
                r.update_mixed([ticket.cm(initial)] if transport == 4 else [],
                               [initial] if transport == 1 else [])
                r.call(r.symbols[ticket.UPDATE], ticket.PANEL)
                r.wi(late.TEST + 12, 2); r.wi(late.TEST + 0x114, 0)
                r.u.mem_write(late.TEST + 16 + 112, struct.pack('<fff', 0, 2.5, 0.5))
                r.thread_alive = False
                if shown:
                    r.call(r.symbols[ticket.UPDATE], ticket.PANEL)
                before = r.finished_snapshot()
                r.stage = 'pin'
                r.update_mixed([], [ticket.streaming(result=11, transport=transport)])
                pin = r.finished_snapshot()
                assert pin['manager'] == 1 and pin['panel'] == 6
                assert pin['test_status'] == 2 and pin['joins'] == 0
                if shown:
                    assert before['panel'] == 1 and before['dialog_owner']
                    assert pin['widgets'][-2:] == [
                        dict(op='hide', pointer=before['dialog_owner']),
                        dict(op='show', pointer=pin['dialog_owner'])]
                    assert {'signal': '2finished( int )', 'slot': '1OnNetworkTestComplete( int )'} in before['ui']
                r.stage = 'retry'; r.call(r.symbols[retry.PIN_ENTERED], ticket.PANEL)
                wait = r.finished_snapshot()
                assert wait['manager'] == 5 and wait['panel'] == 4 and wait['request_id'] == 19
                assert wait['test_status'] == 2 and wait['joins'] == 0 and wait['starts'] == 1
                requests = [m for m in wait['messages'] if m['tag'] == 5]
                assert len(requests) == 2 and retry.decrypted_pin(requests[-1]['body']) == '9876'
                result = dict(success=0, failure=3, pin=11, unauthorized=1, busy=4,
                              duplicate_success=0, failure_after_ticket=0).get(outcome)
                wires = [] if result is None else [retry.response(result, transport)]
                if outcome == 'duplicate_success': wires *= 2
                if outcome == 'failure_after_ticket': wires.append(retry.response(3, transport))
                r.stage = 'consume'
                r.update_mixed([ticket.cm(w) for w in wires] if transport == 4 else [],
                               wires if transport == 1 else [])
                r.call(r.symbols[ticket.UPDATE], ticket.PANEL)
                after = r.finished_snapshot()
                replaced = outcome in ('success', 'duplicate_success')
                assert after['starts'] == 1 + replaced and after['joins'] == 0
                assert after['test_status'] == (1 if replaced else 2)
                if replaced:
                    assert after['tokens'][-1] == retry.NEW_KEY.hex()
                    assert [e['op'] for e in after['thread_events'] if e['stage'] == 'consume'] == ['start']
                r.stage = 'ack'; r.call(r.symbols[late.CANCEL], ticket.PANEL)
                ack = r.finished_snapshot()
                r.stage = 'destroy'; r.call(r.symbols[late.DTOR], late.TEST)
                destroyed = r.finished_snapshot()
                assert destroyed['joins'] == int(replaced) and not destroyed['thread_alive']
                assert not r.assertions
                cases.append(dict(transport=transport, shown=shown, outcome=outcome,
                    before=before, pin=pin, waiting=wait, after=after, ack=ack, destroyed=destroyed,
                    executed=sorted(r.executed), source_assertions=r.assertions))
    old = ROOT / 'scripts/fixtures/steam-network-test-pin-retry-reference.json.gz'
    assert hashlib.sha256(old.read_bytes()).hexdigest() == 'd8a9faa268472af4e1c19e2098d07c1c96b0aeb14c57e1b812d92f961ddb25f1'
    helpers = json.loads(gzip.decompress(old.read_bytes()))['helper_sha256']
    helpers[Path(__file__).name] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report = dict(schema=1, sample_sha256=ticket.rpc.service.m.SHELL_SHA, scope=__doc__,
                  helper_sha256=dict(sorted(helpers.items())), cases=cases)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(report, indent=2, sort_keys=True)+'\n').encode()
    args.output.write_bytes(gzip.compress(data, mtime=0) if args.output.suffix == '.gz' else data)
    print('PASS 32 original finished-Test PIN retry programs; result-dialog replacement and no old live-thread Join')


if __name__ == '__main__':
    main()
