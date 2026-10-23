#!/usr/bin/env python3
"""Original active Test -> connect/security PIN -> new ticket -> Test replacement.

Full manager/CM/UDP parsing/AES, OnPINEntered/SetPanelStateConnecting, new request
producer/serializer, Panel ticket consumer and Test Start/destructor run. Start
requests Join(-1) on the old live thread, without Cancel. Join/Start providers
do not run old-worker finalization/new Run, so the seeded phase is not a natural
post-Join or new-worker state and is not projected onto native media phase.
QLineEdit/QString input, Qt display/storage, thread IsAlive/Join/Start, worker
session phase0/4, identity/entropy/request RSA/clock/final sends are providers.
Test worker phase is seeded, not a natural thread/SDK connection. Final Pop/Test
destruction are driven separately. This is not real Steam/Qt/SDK or Switch.
"""
import argparse
import copy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('pin_retry_late', ROOT / 'scripts/audit-steam-network-test-late-control.py')
late = importlib.util.module_from_spec(spec); spec.loader.exec_module(late)
ticket = late.ticket
DISC = ticket.rpc.service.m.admission.life.m.e.p.m.discovery
PIN_ENTERED = '_ZN13CPanelConnect12OnPINEnteredEv'
CONNECTING = '_ZN13CPanelConnect23SetPanelStateConnectingEv'
START_STREAM = '_ZN14CServerManager14StartStreamingEyPKc'
CANCEL_TEST = '_ZN12CNetworkTest6CancelEv'
NEW_KEY = bytes(range(128, 160))


def response(result=0, transport=1, request_id=19):
    raw = bytearray(ticket.streaming(result=result, transport=transport))
    hs = struct.unpack_from('<I', raw, 8)[0]
    offset = 16 + hs
    assert raw[offset:offset + 2] == b'\x08\x11'
    raw[offset + 1] = request_id
    if not result:
        old, new = DISC.encrypted(), DISC.encrypted(NEW_KEY)
        assert len(old) == len(new) and raw.count(old) == 1
        raw = raw.replace(old, new)
    return bytes(raw)


def decrypted_pin(body):
    value = DISC.fields(bytes.fromhex(body))['8'][0]
    data = bytes.fromhex(value)
    d = Cipher(algorithms.AES(DISC.SECRET), modes.ECB()).decryptor()
    iv = d.update(data[:16]) + d.finalize()
    d = Cipher(algorithms.AES(DISC.SECRET), modes.CBC(iv)).decryptor()
    plain = d.update(data[16:]) + d.finalize()
    pad = plain[-1]
    assert 1 <= pad <= 16 and plain[-pad:] == bytes([pad])*pad
    return plain[:-pad].decode()


class Retry(late.Late):
    def __init__(self, binary):
        self.thread_alive = False; self.thread_starts = 0; self.thread_joins = 0
        self.thread_events = []; self.test_events = []
        super().__init__(binary)
        self.test_entries = {address: name for name, address in self.symbols.items()
                             if name == CANCEL_TEST or name.startswith('_ZN12CNetworkTest5Start')}
        for name in (PIN_ENTERED, CONNECTING, START_STREAM, CANCEL_TEST):
            self.function_entries.setdefault(self.symbols[name], []).append(name)

    def hook(self, u, pc, size, data):
        if pc in getattr(self, 'test_entries', {}):
            self.test_events.append(dict(stage=self.stage, function=self.test_entries[pc],
                status=self.i(late.TEST + 12), phase=self.i(late.TEST + 0x114)))
        name = self.plts.get(pc, '')
        if name == '_ZNK9QLineEdit4textEv':
            self.wq(self.r(8), self.qstring('9876')); return self.ret()
        if name in (CONNECTING, START_STREAM):
            return self.jump(self.symbols[name])
        if name == '_ZNK16SteamThreadTools7CThread7IsAliveEv':
            return self.ret(int(self.thread_alive))
        if name == '_ZN16SteamThreadTools7CThread4JoinEj':
            assert self.r(1) == 0xffffffff
            self.thread_events.append(dict(stage=self.stage, op='join', timeout=self.r(1)))
            self.thread_joins += 1; self.thread_alive = False
            if self.stage == 'destroy': self.joined += 1
            return self.ret(1)
        if name == '_ZN16SteamThreadTools7CThread5StartEm':
            self.thread_events.append(dict(stage=self.stage, op='start'))
            self.thread_starts += 1; self.thread_alive = True
            return self.ret(1)
        return super().hook(u, pc, size, data)

    def retry_snapshot(self):
        return dict(**self.observe_late(), starts=self.thread_starts, joins=self.thread_joins,
                    thread_alive=self.thread_alive, thread_events=copy.deepcopy(self.thread_events),
                    test_events=copy.deepcopy(self.test_events), tokens=list(self.auth_tokens))


def main():
    if not __debug__: raise RuntimeError('audit requires assertions')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args(); binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == ticket.rpc.service.m.SHELL_SHA
    cases = []
    outcomes = ('cancel_wait', 'success', 'failure', 'pin', 'unauthorized', 'busy',
                'duplicate_success', 'failure_after_ticket')
    for transport in (1, 4):
        for phase in (0, 4):
            for outcome in outcomes:
                r = Retry(binary); ticket.rpc.bootstrap(r, 'stream')
                initial = ticket.streaming(transport=transport)
                r.update_mixed([ticket.cm(initial)] if transport == 4 else [],
                               [initial] if transport == 1 else [])
                r.call(r.symbols[ticket.UPDATE], ticket.PANEL)
                r.wi(late.TEST + 0x114, phase)
                before = r.retry_snapshot()
                r.stage = 'pin'; r.update_mixed([], [ticket.streaming(result=11, transport=transport)])
                pin = r.retry_snapshot()
                assert pin['manager'] == 1 and pin['panel'] == 6
                assert pin['test_status'] == 1 and pin['test_session'] == phase
                r.stage = 'retry'; r.call(r.symbols[PIN_ENTERED], ticket.PANEL)
                waiting = r.retry_snapshot()
                assert waiting['manager'] == 5 and waiting['request_id'] == 19 and waiting['panel'] == 4
                assert waiting['starts'] == 1 and waiting['joins'] == 0
                assert waiting['test_status'] == 1 and waiting['test_session'] == phase
                requests = [m for m in waiting['messages'] if m['tag'] == 5]
                assert len(requests) == 2 and decrypted_pin(requests[-1]['body']) == '9876'
                result = dict(success=0, failure=3, pin=11, unauthorized=1, busy=4,
                              duplicate_success=0, failure_after_ticket=0).get(outcome)
                replies = [] if result is None else [response(result, transport)]
                if outcome == 'duplicate_success': replies *= 2
                if outcome == 'failure_after_ticket': replies.append(response(3, transport))
                r.stage = 'consume'
                r.update_mixed([ticket.cm(w) for w in replies] if transport == 4 else [],
                               replies if transport == 1 else [])
                r.call(r.symbols[ticket.UPDATE], ticket.PANEL); after = r.retry_snapshot()
                replaced = outcome in ('success', 'duplicate_success')
                assert after['starts'] == (2 if replaced else 1)
                assert after['joins'] == int(replaced)
                assert after['launches'] == (2 if replaced else 1)
                if replaced:
                    assert after['panel'] == 5 and after['test_status'] == 1
                    # Start itself does not reset phase or Cancel the old Test.
                    # Join/Start are providers; no worker-side finalization or
                    # new Run has executed, so this storage remains the input.
                    assert after['test_session'] == phase
                    assert after['tokens'][-1] == NEW_KEY.hex()
                    assert not any(e['stage'] == 'consume' and e['function'] == CANCEL_TEST
                                   for e in after['test_events'])
                r.stage = 'ack'; r.call(r.symbols[late.CANCEL], ticket.PANEL); ack = r.retry_snapshot()
                r.stage = 'destroy'; r.call(r.symbols[late.DTOR], late.TEST); destroyed = r.retry_snapshot()
                assert destroyed['joins'] == (2 if replaced else 1) and not destroyed['thread_alive']
                assert ack['manager'] == 1 and ack['request_id'] == 0 and not r.assertions
                cases.append(dict(transport=transport, phase=phase, outcome=outcome,
                    initial=initial.hex(), replies=[w.hex() for w in replies], before=before,
                    pin=pin, waiting=waiting, after=after, ack=ack, destroyed=destroyed,
                    executed=sorted(r.executed), source_assertions=r.assertions))
    helpers = ticket.helpers()
    for file in (Path(late.__file__), Path(__file__)):
        helpers[file.name] = hashlib.sha256(file.read_bytes()).hexdigest()
    report = dict(schema=1, sample_sha256=ticket.rpc.service.m.SHELL_SHA, scope=__doc__,
                  helper_sha256=dict(sorted(helpers.items())), cases=cases)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(report, sort_keys=True, indent=2)+'\n').encode()
    args.output.write_bytes(gzip.compress(raw, mtime=0) if args.output.suffix == '.gz' else raw)
    print('PASS 32 original PIN-retry manager/Panel/Test lifetimes; old Test held until new ticket or final cleanup')


if __name__ == '__main__': main()
