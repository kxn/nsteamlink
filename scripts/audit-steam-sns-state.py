#!/usr/bin/env python3
"""Execute pinned official SNS CheckConnection and SDR CloseConnection.

The SDK clock/info/status/close methods, diagnostic strings and assertion sink
are controlled providers. Actual original state, deadline, handle and signaling
back-reference branches run unmodified. No SDK networking/handshake is tested.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_X0, UC_ARM64_REG_X30

spec = importlib.util.spec_from_file_location('sns_message_original',
    Path(__file__).with_name('audit-steam-sns-message.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
T, SDK, UTILS, VT, UVT, TVT, SIGNAL = [0x20080000 + n * 0x1000 for n in range(7)]
TIME, INFO, QUICK, CLOSE = [base.STOP + n * 0x100 for n in range(2, 6)]


class Run(base.Machine):
    def __init__(self, binary):
        self.events = []
        self.action = {}
        super().__init__(binary)

    def hook(self, uc, pc, size, unused):
        def reg(n):
            # X0..X7 are contiguous Unicorn IDs.
            from unicorn import arm64_const as arm
            return uc.reg_read(getattr(arm, 'UC_ARM64_REG_X' + str(n)))

        def ret(value=0):
            uc.reg_write(UC_ARM64_REG_X0, value)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))

        if pc == base.STOP:
            return super().hook(uc, pc, size, unused)
        if pc == TIME:
            self.events.append('time')
            return ret(self.action['now'])
        if pc == INFO:
            assert (reg(0), reg(1)) == (SDK, 1)
            self.events.append('info')
            p = reg(2)
            uc.mem_write(p, bytes(512))
            self.wi(p + 176, self.action['sdk_state'] & 0xffffffff)
            self.wi(p + 180, 4321)
            return ret(int(self.action['info_ok']))
        if pc == QUICK:
            assert (reg(0), reg(1), reg(3), reg(4)) == (SDK, 1, 0, 0)
            self.events.append('quick')
            p = reg(2)
            uc.mem_write(p, bytes(128))
            self.wi(p + 4, 0xffffffff)
            for offset in (16, 20, 24, 28):
                uc.mem_write(p + offset, struct.pack('<f', -1.0))
            return ret(int(self.action['quick_ok']))
        if pc == CLOSE:
            assert (reg(0), reg(1), reg(4)) == (SDK, 1, 0)
            # Execute original SDR close's unlink order before the SDK boundary.
            assert self.q(T + 288) == 0 and self.q(SIGNAL + 8) == 0
            self.events.append(['close', reg(2), self.i(T + 20)])
            return ret(1)
        if pc in (0xc09f90, 0xc09c30, 0xc0a680, 0xc11620, 0xc11630, 0xc11640):
            return ret()  # Only diagnostic string/log operations.
        if pc in (0xc09b00, 0xc097e0):
            return ret(1)  # Assertion sink declines a debugger trap.
        assert 0x800348 <= pc < 0x800960 or 0x800f94 <= pc < 0x801084, hex(pc)

    def start(self, initial):
        for p in (T, SDK, UTILS, VT, UVT, TVT, SIGNAL):
            self.u.mem_write(p, bytes(512))
        self.wq(T, TVT)
        self.wq(TVT + 120, 0x800f94)
        self.wi(T + 20, initial['state'])
        self.wi(T + 48, initial['handle'])
        self.wq(T + 56, SDK)
        self.wq(T + 64, UTILS)
        self.wq(T + 264, initial['last_check'] & 0xffffffffffffffff)
        self.wq(T + 288, SIGNAL)
        self.wq(SIGNAL + 8, T)
        self.wq(SDK, VT)
        self.wq(UTILS, UVT)
        self.wq(UVT + 96, TIME)
        self.wq(VT + 120, INFO)
        self.wq(VT + 128, QUICK)
        self.wq(VT + 40, CLOSE)

    def step(self, action):
        self.events = []
        self.action = action
        self.call(0x800348, T)
        last = self.q(T + 264)
        if last >= 1 << 63:
            last -= 1 << 64
        return dict(state=self.i(T + 20), handle=self.i(T + 48),
                    last_check=last, result=bool(self.u.reg_read(UC_ARM64_REG_X0)),
                    owner_linked=bool(self.q(T + 288) and self.q(SIGNAL + 8)),
                    events=self.events[:])


def programs():
    action = dict(now=100000000, info_ok=True, quick_ok=True, sdk_state=3)
    # Includes impossible/inconsistent input states deliberately; proves local
    # branch behavior, not that every combination is reachable on the wire.
    for state in range(5):
        for handle in (0, 1):
            for sdk in (-1, 0, 1, 2, 3, 4, 5, 6, 2147483647):
                for info_ok, quick_ok in ((True, True), (False, True), (True, False)):
                    yield dict(name=f'matrix-{state}-{handle}-{sdk}-{int(info_ok)}-{int(quick_ok)}',
                        initial=dict(state=state, handle=handle, last_check=90000000),
                        actions=[dict(action, sdk_state=sdk, info_ok=info_ok, quick_ok=quick_ok)])
    for elapsed in (-1000, 0, 999999, 1000000, 1000001):
        yield dict(name=f'throttle-{elapsed}',
            initial=dict(state=2, handle=1, last_check=action['now']-elapsed),
            actions=[dict(action, sdk_state=5), dict(action, now=action['now']+1000000, sdk_state=5)])
    # Original adds in 64 bits then compares a signed timestamp.
    yield dict(name='deadline-wrap',
        initial=dict(state=2, handle=1, last_check=(1 << 63)-500000), actions=[dict(action)])
    for failure in ('info_ok', 'quick_ok'):
        yield dict(name='detach-'+failure,
            initial=dict(state=1, handle=1, last_check=0),
            actions=[dict(action), dict(action, now=101000000, **{failure: False}),
                     dict(action, now=102000000)])
    yield dict(name='connecting-finding-connected-peer-close',
        initial=dict(state=0, handle=1, last_check=0),
        actions=[dict(action, now=100000000+n*1000000, sdk_state=sdk)
                 for n, sdk in enumerate((1, 2, 3, 3, 4, 3))])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == base.SHA
    m, cases = Run(binary), []
    for program in programs():
        m.start(program['initial'])
        program['results'] = [m.step(a) for a in program['actions']]
        cases.append(program)
    result = dict(schema=1, sample_sha256=base.SHA,
        scope='Original CheckConnection/SDR Close; SDK results, clock and diagnostics are controlled',
        cases=cases)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(result, indent=2) + '\n').encode()
    if args.output.suffix == '.gz':
        args.output.write_bytes(gzip.compress(data, mtime=0))
    else:
        args.output.write_bytes(data)
    print(f'PASS: {len(cases)} original SNS state programs/{sum(len(c["actions"]) for c in cases)} steps')


if __name__ == '__main__':
    main()
