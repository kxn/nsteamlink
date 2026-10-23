#!/usr/bin/env python3
"""Original success ticket -> Unauthorized -> same-owner authorization/resume.

Full manager/CM/UDP parsing, AES/key exchange, clocks/resends, Panel auth and
ticket consumption execute. Unconsumed cases hold the Panel until the stated
boundary; split Updates are explicit scheduling inputs, not natural Qt timing.
Active cases create the original Test through token handoff, with its thread
Start/Join provided. Ordinary launch ends at the launcher boundary. Qt, identity,
RNG/RSA, persistent/file endpoints, clocks and final sends inherit their explicit
providers. No real Steam/SDR, natural Test worker, Qt event loop, or Switch.
"""
import argparse
import copy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('reauth_ticket', ROOT / 'scripts/audit-steam-ticket-consumer.py')
ticket = importlib.util.module_from_spec(spec); spec.loader.exec_module(ticket)
DISC = ticket.rpc.service.m.admission.life.m.e.p.m.discovery
NEW_KEY = bytes(range(128, 160))


def streaming(secret, transport):
    iv = bytes(range(16)); plain = NEW_KEY + bytes([16])*16
    e = Cipher(algorithms.AES(secret), modes.ECB()).encryptor()
    first = e.update(iv) + e.finalize()
    e = Cipher(algorithms.AES(secret), modes.CBC(iv)).encryptor()
    cipher = first + e.update(plain) + e.finalize()
    raw, old = ticket.streaming(transport=transport), DISC.encrypted()
    assert len(cipher) == len(old) and raw.count(old) == 1
    return raw.replace(old, cipher)


def main():
    if not __debug__: raise RuntimeError('audit requires assertions')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args(); binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == ticket.rpc.service.m.SHELL_SHA
    cases = []
    for testing in (False, True):
        for transport in (1, 4):
            for schedule in ('same_update', 'split_updates', 'active_test') if testing else ('same_update', 'split_updates'):
                for outcome in ('compat', 'key', 'progress', 'denied'):
                    r = ticket.TicketConsumer(binary, testing); ticket.rpc.bootstrap(r, 'stream')
                    commands = []; rows = []

                    def snapshot():
                        return dict(control=copy.deepcopy(r.observe_rpc()), panel=copy.deepcopy(r.result()))

                    def update(wires, consume=True):
                        commands.append(['mixed', [ticket.cm(w).hex() for w in wires] if transport == 4 else [],
                                         [w.hex() for w in wires] if transport == 1 else []])
                        r.update_mixed([ticket.cm(w) for w in wires] if transport == 4 else [],
                                       wires if transport == 1 else [])
                        if consume: r.call(r.symbols[ticket.UPDATE], ticket.PANEL)
                        rows.append(snapshot())

                    def due(wall):
                        commands.append(['due', wall]); r.wall_time = wall
                        r.update_mixed([], []); r.call(r.symbols[ticket.UPDATE], ticket.PANEL)
                        rows.append(snapshot())

                    initial = snapshot()
                    good, unauthorized = ticket.streaming(transport=transport), ticket.streaming(result=1, transport=transport)
                    if schedule == 'same_update':
                        update([good, unauthorized])
                    else:
                        update([good], consume=schedule == 'active_test')
                        update([unauthorized])
                    auth_index = len(rows)-1
                    assert rows[-1]['control']['state'] == 4
                    assert rows[-1]['panel']['panel'] == (5 if schedule == 'active_test' else 3)
                    assert rows[-1]['panel']['launches'] == int(schedule == 'active_test')
                    tags_before = [m['tag'] for m in rows[-1]['control']['messages']]
                    due(1002)
                    assert [m['tag'] for m in rows[-1]['control']['messages']] == tags_before
                    due(1003)
                    assert [m['tag'] for m in rows[-1]['control']['messages']] == tags_before + [3]
                    event = dict(client=123, key=outcome == 'key', key_pin='0042',
                                 result=5 if outcome == 'progress' else 1 if outcome == 'denied' else 0)
                    reply = ticket.rpc.service.packet(event, '0042')
                    update([reply])
                    reply_index = len(rows)-1
                    expected = 4 if outcome == 'progress' else 1 if outcome == 'denied' else 5
                    assert rows[-1]['control']['state'] == expected
                    due(1004)
                    if outcome in ('compat', 'key'):
                        final = streaming(bytes.fromhex(rows[-1]['control']['secret']), transport)
                        update([final])
                        assert rows[-1]['control']['state'] == 6
                        assert rows[-1]['panel']['launches'] == 1
                        if testing:
                            assert rows[-1]['panel']['tokens'] == [
                                bytes(range(32)).hex() if schedule == 'active_test' else NEW_KEY.hex()]
                    assert not r.assertions
                    cases.append(dict(testing=testing, transport=transport, schedule=schedule, outcome=outcome,
                        initial=initial, commands=commands, rows=rows, auth_index=auth_index, reply_index=reply_index,
                        executed=sorted(r.executed), source_assertions=r.assertions))
    helpers = ticket.helpers()
    helpers[Path(__file__).name] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report = dict(schema=1, sample_sha256=ticket.rpc.service.m.SHELL_SHA, scope=__doc__,
                  helper_sha256=dict(sorted(helpers.items())), cases=cases)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(report, sort_keys=True, indent=2)+'\n').encode()
    args.output.write_bytes(gzip.compress(raw, mtime=0) if args.output.suffix == '.gz' else raw)
    print('PASS 40 original post-ticket authorization programs; resume same ID, retract unconsumed admission, retain active Test')


if __name__ == '__main__': main()
