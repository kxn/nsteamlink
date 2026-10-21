#!/usr/bin/env python3
"""Execute original SDR signal consumer -> UpdateState -> CheckConnection.

SDK signal/info/status/connect/config methods, clock, allocation and diagnostics
are providers. Actual original signal iteration, failure close ordering and
state update branches execute. No rendezvous parsing or live network claimed.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
from unicorn import arm64_const as arm

spec = importlib.util.spec_from_file_location('sns_signal_state',
    Path(__file__).with_name('audit-steam-sns-state.py'))
state = importlib.util.module_from_spec(spec)
spec.loader.exec_module(state)
base = state.base
RECEIVE, CONNECT, SET = [base.STOP + n*0x100 for n in (11, 12, 13)]
MESSAGE, FIELD, STRINGS, SIGNALVT = [0x200a0000 + n*0x1000 for n in range(4)]


class Run(state.Run):
    def r(self, n):
        return self.u.reg_read(getattr(arm, 'UC_ARM64_REG_X'+str(n)))

    def ret(self, value=0):
        self.u.reg_write(arm.UC_ARM64_REG_X0, value)
        self.u.reg_write(arm.UC_ARM64_REG_PC, self.r(30))

    def hook(self, u, pc, size, unused):
        if pc == RECEIVE:
            raw = bytes(u.mem_read(self.r(1), self.r(2)))
            expected = self.action['signals'][self.received]
            assert raw.hex() == expected['bytes']
            self.events.append(['signal', raw.hex()])
            self.received += 1
            # Controlled SDK result/SDK-side state transition. The actual
            # original caller must observe it in its following state update.
            self.action['sdk_state'] = expected['sdk_state']
            return self.ret(int(expected['ok']))
        if pc == CONNECT:
            assert (self.r(0), self.r(2), self.r(3), self.r(4)) == (state.SDK, 0, 0, 2)
            self.events.append('connect')
            return self.ret(self.action['connect_handle'])
        if pc == SET:
            assert (self.r(2), self.r(3), self.r(4)) == (4, self.action['connect_handle'], 1)
            self.events.append(['set', self.r(1), self.i(self.r(5))])
            return self.ret(1)
        if pc == 0xbff420:
            assert self.r(0) == 16
            self.events.append('allocate-signaling')
            return self.ret(state.SIGNAL)
        if pc == 0xc11610:
            return u.reg_write(arm.UC_ARM64_REG_PC, 0x800348)
        if pc == state.CLOSE:
            assert (self.r(0), self.r(1), self.r(4)) == (state.SDK, 1, 0)
            # BHandle explicitly clears the owner-side pointer even when the
            # controlled SDK failure leaves the signaling object unreleased.
            # Its preceding assertion is diagnostic, not an abort here.
            assert self.q(state.T + 288) == 0
            debug = '' if not self.r(3) else bytes(u.mem_read(self.r(3), 128)).split(b'\0')[0].decode()
            self.events.append(['close', self.r(2), self.i(state.T+20), debug])
            return self.ret(1)
        if pc in (0xc09f90, 0xc09c30, 0xc0a680, 0xc11620, 0xc11630, 0xc11640):
            return self.ret()
        if pc in (0xc09b00, 0xc097e0):
            return self.ret(1)
        if 0x8011f0 <= pc < 0x8014f4 or 0x801754 <= pc < 0x8018a4:
            return
        return super().hook(u, pc, size, unused)

    def setup(self, initial):
        self.u.reg_write(arm.UC_ARM64_REG_TPIDR_EL0, 0x200f0000)
        super().start(initial)
        for p in (MESSAGE, FIELD, STRINGS, SIGNALVT): self.u.mem_write(p, bytes(4096))
        self.wq(state.VT+296, RECEIVE)
        self.wq(state.VT+288, CONNECT)
        self.wq(state.UVT+128, SET)
        self.wq(state.TVT+24, 0x8011f0)
        self.u.mem_write(state.T+24, bytes([initial['ready']]))
        self.u.mem_write(state.T+400, b'\1')
        self.wq(0xc80828, SIGNALVT-16)
        if not initial['linked']:
            self.wq(state.T+288, 0); self.wq(state.SIGNAL+8, 0)
        if not initial['sdk']:
            self.wq(state.T+56, 0)

    def step(self, action):
        self.events, self.received = [], 0
        self.action = dict(action)
        self.wi(MESSAGE+32, len(action['signals']))
        self.wq(MESSAGE+40, FIELD)
        for n, signal in enumerate(action['signals']):
            p = STRINGS+n*64
            raw = bytes.fromhex(signal['bytes'])
            assert len(raw) < 23
            self.wq(FIELD+8+n*8, p)
            self.u.mem_write(p, bytes([len(raw)*2])+raw+b'\0')
        self.call(0x801754, state.T, MESSAGE)
        return dict(result=bool(self.r(0)), state=self.i(state.T+20),
            handle=self.i(state.T+48), last_check=self.q(state.T+264),
            owner_linked=bool(self.q(state.T+288) and self.q(state.SIGNAL+8)),
            events=self.events[:])


def programs():
    action = dict(now=100000000, info_ok=True, status_result=1, sdk_state=1,
        connect_handle=1, signals=[])
    sequences = [[], [dict(bytes='010203', ok=True, sdk_state=3)],
        [dict(bytes='', ok=True, sdk_state=4)],
        [dict(bytes='aabb', ok=False, sdk_state=1)],
        [dict(bytes='00', ok=True, sdk_state=2), dict(bytes='01', ok=True, sdk_state=3)],
        [dict(bytes='00', ok=True, sdk_state=3), dict(bytes='01', ok=False, sdk_state=5),
         dict(bytes='02', ok=True, sdk_state=3)]]
    for transport in (1, 2, 3, 4):
        for handle in (0, 1):
            for signals in sequences:
                yield dict(name=f'state-{transport}-handle-{handle}-sequence-{sequences.index(signals)}',
                    initial=dict(state=transport, handle=handle, last_check=90000000,
                        ready=True, linked=True, sdk=True), actions=[dict(action, signals=signals)])
    for ready in (False, True):
        for created in (0, 1):
            yield dict(name=f'initial-{ready}-{created}',
                initial=dict(state=0, handle=0, last_check=0, ready=ready, linked=False, sdk=True),
                actions=[dict(action, connect_handle=created)])
    yield dict(name='no-sdk', initial=dict(state=1, handle=0, last_check=0,
        ready=False, linked=False, sdk=False), actions=[dict(action, signals=sequences[1])])
    for info_ok, status in ((False,1), (True,0), (True,3)):
        yield dict(name=f'query-{info_ok}-{status}', initial=dict(state=1, handle=1,
            last_check=0, ready=True, linked=True, sdk=True),
            actions=[dict(action, signals=sequences[1], info_ok=info_ok, status_result=status)])
    yield dict(name='connected-throttle', initial=dict(state=2, handle=1,
        last_check=99500000, ready=True, linked=True, sdk=True),
        actions=[dict(action, signals=sequences[2]), dict(action, now=100500000)])


def main():
    if not __debug__: raise RuntimeError('audit requires assertions')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args(); binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == base.SHA, 'wrong official sample'
    cases = []
    for program in programs():
        m = Run(binary); m.setup(program['initial'])
        program['results'] = [m.step(a) for a in program['actions']]
        cases.append(program)
    helpers = ['audit-steam-sns-signal-state.py', 'audit-steam-sns-state.py', 'audit-steam-sns-message.py']
    result = dict(schema=1, sample_sha256=base.SHA,
        scope=__doc__, helper_sha256={n:hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest() for n in helpers}, cases=cases)
    raw=(json.dumps(result,indent=2)+'\n').encode()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_bytes(gzip.compress(raw,mtime=0) if args.output.suffix=='.gz' else raw)
    print(f'PASS: {len(cases)} original signal/state programs/{sum(len(c["actions"]) for c in cases)} cycles')


if __name__ == '__main__': main()
