#!/usr/bin/env python3
"""Original local sender failure, notification, cancellation and cleanup order.

Execute the original CM FIFO/parser, auth crypto/save, service producer or due
request producer and Stop. Replace one BGetDeviceToken bool with failure, as an
explicit fault boundary; this is not a naturally observed RNG/crypto failure.
Final SendMessage providers return zero at a void boundary; native-only final
sender false must not become a producer failure. Due producers are called
directly, not a whole manager Update. All inherited
RPC audit providers remain: CM/WebRequest/platform/final send, not real Steam.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path

if not __debug__:
    raise SystemExit('Original audit requires assertions; do not use Python -O')
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('rpc', ROOT/'scripts/audit-steam-pairing-rpc.py')
rpc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rpc)
REFERENCE = ROOT/'scripts/fixtures/steam-request-failure-reference.json.gz'


def authorization(keyed):
    packet = rpc.service.packet(dict(client=123, key=keyed, key_pin='0042'), '0042')
    varint = rpc.service.m.admission.life.m.e.p.m.discovery.varint
    body = b'\x0a' + varint(len(packet)) + packet
    return (b'\x08\x01\x32' + varint(len(body)) + body).hex()


def cases():
    programs = [
        ('resume-no-key', 'known', [('raw', authorization(False))]),
        ('resume-key', 'known', [('raw', authorization(True))]),
        ('authorize-retry', 'known', [('due', 1003)]),
        ('stream-retry', 'stream', [('due', 1001)]),
        ('service-publication', 'waiting', [('wire', 3, 1, 1234)]),
    ]
    sends = [
        ('resume-no-key-send', 'known', [('fail-send', 5), ('raw', authorization(False))]),
        ('resume-key-send', 'known', [('fail-send', 5), ('raw', authorization(True))]),
        ('authorize-retry-send', 'known', [('fail-send', 3), ('due', 1003)]),
        ('stream-retry-send', 'stream', [('fail-send', 5), ('due', 1001)]),
    ]
    return [(name, hint, phase, [('fail-token',), *commands])
            for hint in (False, True) for name, phase, commands in programs] + [
            (name, hint, phase, commands)
            for hint in (False, True) for name, phase, commands in sends]


def run(binary, name, hint, phase, commands):
    r = rpc.PairRPC(binary, hint)
    rpc.bootstrap(r, phase)
    steps = [r.observe_rpc()]
    for command in commands:
        if command[0] == 'fail-token':
            r.token_input['fail_token'] = len(r.token_calls)
        elif command[0] == 'fail-send':
            # The inherited final SendMessage endpoint already returns zero.
            # Original producer instructions do not branch on that value.
            pass
        elif command[0] == 'raw':
            r.wire(bytes.fromhex(command[1]))
        elif command[0] == 'wire':
            r.wire(rpc.wire(*command[1:]))
        elif command[0] == 'due':
            r.wall_time = command[1]
            producer = 'SendAuthorizeDeviceRequest' if phase == 'known' else 'SendStartStreamingRequest'
            r.call(r.symbols[f'_ZN14CServerManager{len(producer)}{producer}Ev'], r.manager)
        else:
            raise AssertionError(command)
        steps.append(r.observe_rpc())
    assert not r.assertions
    return dict(name=name, hint=hint, phase=phase, inputs=commands, steps=steps,
                executed=sorted(r.executed), source_assertions=r.assertions)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--refresh-reference', action='store_true')
    args = p.parse_args()
    binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == rpc.service.m.SHELL_SHA
    rows = []
    for name, hint, phase, commands in cases():
        rows.append(run(binary, name, hint, phase, commands))
        print(name, hint, flush=True)
    helpers = rpc.helpers()
    helpers[Path(__file__).name] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report = dict(schema=1, binary_sha256=rpc.service.m.SHELL_SHA, scope=__doc__,
                  helpers=helpers, cases=rows)
    raw = gzip.compress(json.dumps(report, sort_keys=True, separators=(',', ':')).encode(), mtime=0)
    args.output.write_bytes(raw)
    if args.refresh_reference:
        REFERENCE.write_bytes(raw)
    else:
        assert raw == REFERENCE.read_bytes()
    print('PASS 18 original sender-failure/void-send programs')


if __name__ == '__main__':
    main()
