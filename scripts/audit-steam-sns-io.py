#!/usr/bin/env python3
"""Execute original Socket::Send -> SNS::Send, SDR MTU and final Release.

SDK send/config/close, refcount decrement, deleting destructor, clock, allocation
and diagnostics are providers. Socket CRC/collector/shaper and transport branch
instructions execute. No SDK networking, natural references or MTU caller claimed.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
from unicorn import arm64_const as arm

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'),
        Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


wire = load('audit-steam-network-wire')
state = load('audit-steam-sns-state')
base = state.base
SHA = base.SHA
SEND, SET, GET, DESTROY = [base.STOP + i * 0x100 for i in range(7, 11)]


class Send(wire.Wire):
    def __init__(self, binary, initial, crc):
        super().__init__(binary, crc=crc)
        self.events = []
        self.sdk_result = 1
        sdk, vt = self.alloc(512), self.alloc(512)
        self.wq(self.q(self.transport) + 72, 0x800224)
        self.wi(self.transport + 20, initial['state'])
        self.wi(self.transport + 48, initial['handle'])
        self.wq(self.transport + 56, sdk)
        self.wq(sdk, vt)
        self.wq(vt + 88, SEND)
        self.callbacks[SEND] = self.send_sdk

    def send_sdk(self):
        assert self.r(1) == 1 and self.r(4) == 0x15 and self.r(5) == 0
        raw = bytes(self.u.mem_read(self.r(2), self.r(3)))
        self.events.append(dict(flags=self.r(4), wire=raw.hex()))
        self.ret(self.sdk_result & 0xffffffff)

    def step(self, action):
        self.sdk_result = action['sdk_result']
        self.now = action['now']
        self.events = []
        p = self.packet(action['kind'], 1, False, 12, 34, action['size'])
        result = self.call(0x7ff1dc, self.sock, self.connection, p) & 0xffffffff
        shaper = self.q(self.sock + 64)
        return dict(result=result, state=self.i(self.transport + 20),
            handle=self.i(self.transport + 48), events=self.events[:],
            sent_bytes=self.observe_collectors()['rates'][0]['sum'],
            deadlines=[self.i(shaper + n) for n in (8, 12)])


class Mtu(base.Machine):
    def __init__(self, binary):
        self.events = []
        super().__init__(binary)
        self.u.reg_write(arm.UC_ARM64_REG_TPIDR_EL0, 0x200f0000)
        for p in (state.T, state.UTILS, state.UVT):
            self.u.mem_write(p, bytes(512))
        self.wq(state.T + 64, state.UTILS)
        self.wq(state.UTILS, state.UVT)
        self.wq(state.UVT + 128, SET)
        self.wq(state.UVT + 136, GET)

    def r(self, n):
        return self.u.reg_read(getattr(arm, 'UC_ARM64_REG_X' + str(n)))

    def hook(self, u, pc, size, data):
        if pc == base.STOP:
            return super().hook(u, pc, size, data)
        if pc in (SET, GET):
            assert (self.r(0), self.r(2), self.r(3)) == (state.UTILS, 4, self.case['handle'])
            if pc == SET:
                assert self.r(1) == 32 and self.r(4) == 1
                self.events.append(['set', self.i(self.r(5))])
                result = int(self.case['set_ok'])
            else:
                assert self.r(1) == 33 and self.q(self.r(6)) == 4
                self.events.append('get')
                self.wi(self.r(4), 1)
                self.wi(self.r(5), self.case['value'] & 0xffffffff)
                self.wq(self.r(6), self.case['out_size'])
                result = self.case['get_result']
            u.reg_write(arm.UC_ARM64_REG_X0, result & 0xffffffff)
            return u.reg_write(arm.UC_ARM64_REG_PC, self.r(30))
        assert 0x801084 <= pc < 0x801130, hex(pc)

    def run_case(self, case):
        self.case, self.events = case, []
        self.wi(state.T + 48, case['handle'])
        self.call(0x801084, state.T, case['mtu'] & 0xffffffff)
        value = self.r(0) & 0xffffffff
        return dict(result=value if value < (1 << 31) else value - (1 << 32),
                    events=self.events[:])


class Release(state.Run):
    def hook(self, u, pc, size, data):
        if pc == 0xc0a390:
            assert u.reg_read(arm.UC_ARM64_REG_X0) == state.T + 16
            refs = self.i(state.T + 16) - 1
            self.wi(state.T + 16, refs)
            u.reg_write(arm.UC_ARM64_REG_X0, refs)
            return u.reg_write(arm.UC_ARM64_REG_PC, u.reg_read(arm.UC_ARM64_REG_X30))
        if pc == state.CLOSE:
            p = u.reg_read(arm.UC_ARM64_REG_X3)
            self.debug = bytes(u.mem_read(p, 128)).split(b'\0')[0].decode()
        if pc == DESTROY:
            self.events.append('destroy')
            return u.reg_write(arm.UC_ARM64_REG_PC, u.reg_read(arm.UC_ARM64_REG_X30))
        if 0x7ffcd4 <= pc < 0x7ffd30:
            return
        return super().hook(u, pc, size, data)

    def run_case(self, case):
        self.start(dict(state=case['state'], handle=case['handle'], last_check=0))
        self.events, self.debug = [], None
        self.wi(state.T + 16, case['refs'])
        self.wq(state.TVT + 112, DESTROY)
        self.call(0x7ffcd4, state.T)
        return dict(result=self.u.reg_read(arm.UC_ARM64_REG_X0),
            state=self.i(state.T + 20), handle=self.i(state.T + 48),
            owner_linked=bool(self.q(state.T + 288) and self.q(state.SIGNAL + 8)),
            debug=self.debug, events=self.events[:])


def main():
    if not __debug__:
        raise RuntimeError('audit requires assertions')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == SHA, 'wrong official sample'
    sends, mtus, releases = [], [], []
    # Compose success, busy and failure through the real Socket caller. Time
    # advances enough to exclude a previous successful send's shaper deadline.
    for s in range(5):
        for h in (0, 1):
            for crc in (False, True):
                initial = dict(state=s, handle=h)
                actions = [dict(sdk_result=r, now=1000000+i*65536, kind=kind, size=20)
                    for i, (r, kind) in enumerate(
                        [(25, 5), (41, 5), (1, 5), (3, 5), (1, 9), (8, 5), (2, 5), (-1, 5)])]
                m = Send(binary, initial, crc)
                sends.append(dict(initial=initial, crc=crc, actions=actions,
                    results=[m.step(a) for a in actions]))
    m = Mtu(binary)
    for handle in (0, 1):
        for mtu in (-1, 0, 1300, 1500):
            for set_ok in (False, True):
                for get_result in (-2, -1, 0, 1, 2):
                    for out_size in (4, 8):
                        c = dict(handle=handle, mtu=mtu, set_ok=set_ok,
                            get_result=get_result, value=1200, out_size=out_size)
                        mtus.append(dict(input=c, result=m.run_case(c)))
    m = Release(binary)
    for refs in (1, 2, 3):
        for s in range(5):
            for h in (0, 1):
                c = dict(refs=refs, state=s, handle=h)
                releases.append(dict(input=c, result=m.run_case(c)))
    result = dict(schema=1, sample_sha256=SHA, scope=__doc__,
        helper_sha256={name: hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest()
            for name in ('audit-steam-sns-io.py', 'audit-steam-network-wire.py',
                'audit-steam-network-collectors.py', 'audit-steam-frame-stats.py',
                'audit-steam-client-config.py', 'audit-steam-client-fec-policy.py',
                'audit-steam-sns-state.py', 'audit-steam-sns-message.py')},
        sends=sends, mtus=mtus, releases=releases)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(result, indent=2) + '\n').encode()
    args.output.write_bytes(gzip.compress(data, mtime=0) if args.output.suffix == '.gz' else data)
    print(f'PASS: original Socket/SNS send {len(sends)} programs, MTU {len(mtus)}, Release/SDR close {len(releases)}')


if __name__ == '__main__':
    main()
