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
        self.sdk_lookup = 0
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
            self.events.append('status')
            p = reg(2)
            uc.mem_write(p, bytes(128))
            self.wi(p + 4, 0xffffffff)
            for offset in (16, 20, 24, 28):
                uc.mem_write(p + offset, struct.pack('<f', -1.0))
            return ret(self.action['status_result'])
        if pc == 0x80303c:
            return ret(self.sdk_lookup)  # SDK handle lookup/lock boundary.
        if pc == 0xc11b80:
            return uc.reg_write(UC_ARM64_REG_PC, 0x8582ac)
        if pc == 0xc119d0:
            return ret(100000000)
        if pc in (0xc13290, 0xc118a0):
            return ret()  # SNP stats population / diagnostic output only.
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
        assert (0x800348 <= pc < 0x800960 or 0x800f94 <= pc < 0x801084 or
                0x806884 <= pc < 0x80695c or 0x8582ac <= pc < 0x858514), hex(pc)

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
    action = dict(now=100000000, info_ok=True, status_result=1, sdk_state=3)
    # Includes impossible/inconsistent input states deliberately; proves local
    # branch behavior, not that every combination is reachable on the wire.
    for state in range(5):
        for handle in (0, 1):
            for sdk in (-1, 0, 1, 2, 3, 4, 5, 6, 2147483647):
                for info_ok, status_result in ((True, 1), (False, 1), (True, 0), (True, 2), (True, 3), (True, 8), (True, 25), (True, 41)):
                    yield dict(name=f'matrix-{state}-{handle}-{sdk}-{int(info_ok)}-{status_result}',
                        initial=dict(state=state, handle=handle, last_check=90000000),
                        actions=[dict(action, sdk_state=sdk, info_ok=info_ok, status_result=status_result)])
    for elapsed in (-1000, 0, 999999, 1000000, 1000001):
        yield dict(name=f'throttle-{elapsed}',
            initial=dict(state=2, handle=1, last_check=action['now']-elapsed),
            actions=[dict(action, sdk_state=5), dict(action, now=action['now']+1000000, sdk_state=5)])
    # Original adds in 64 bits then compares a signed timestamp.
    yield dict(name='deadline-wrap',
        initial=dict(state=2, handle=1, last_check=(1 << 63)-500000), actions=[dict(action)])
    for failure in ('info_ok', 'status_result'):
        yield dict(name='detach-'+failure,
            initial=dict(state=1, handle=1, last_check=0),
            actions=[dict(action), dict(action, now=101000000, **{failure: False if failure == "info_ok" else 0}),
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
    # Confirm the slot is not a bool adapter: the actual SDK wrapper returns
    # 3 for a missing handle, and its real API body returns 8 for bad lanes.
    # Valid/null-output API still reaches the stats endpoint then returns 1.
    from unicorn import arm64_const as arm
    sdk_returns = []
    connection, level = 0x20090000, 0x20093000
    m.wq(0xc80888, level)
    m.wi(level, 0)
    for name, found, lanes, expected in (
            ('no-connection', False, 0, 3), ('invalid-lanes', True, 1, 8),
            ('ok-null-output', True, 0, 1)):
        m.sdk_lookup = connection if found else 0
        for n, value in ((2, 0), (3, lanes), (4, 0)):
            m.u.reg_write(getattr(arm, 'UC_ARM64_REG_X'+str(n)), value)
        m.call(0x806884, SDK, 1)
        returned = m.u.reg_read(UC_ARM64_REG_X0)
        assert returned == expected, (name, returned)
        sdk_returns.append(dict(name=name, result=returned))
    result = dict(schema=2, sample_sha256=base.SHA,
        scope='Original CheckConnection/SDR Close; SDK results, clock and diagnostics are controlled',
        sdk_returns=sdk_returns, cases=cases)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(result, indent=2) + '\n').encode()
    if args.output.suffix == '.gz':
        args.output.write_bytes(gzip.compress(data, mtime=0))
    else:
        args.output.write_bytes(data)
    print(f'PASS: {len(cases)} original SNS state programs/{sum(len(c["actions"]) for c in cases)} steps')


if __name__ == '__main__':
    main()
