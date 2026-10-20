#!/usr/bin/env python3
"""Execute the pinned client's address add/clear/get/comparator and complete sort.

Persistent-record lookup, preallocated vector storage, wall clock, strcmp and
bounded string-copy/printf are providers. Original IP equality, IPv4 extraction,
IPv6 formatting and all sort instructions execute. No wire parser, filesystem,
Qt scheduling or physical reachability is exercised. Offline executes the
original parsed type-2 branch with visible/cloud map and delegate providers;
it does not exercise the wire admission/parser or full manager Update.
"""
import argparse
import gzip
import hashlib
import importlib.util
import ipaddress
import itertools
import json
from pathlib import Path
import random
import struct

from unicorn import arm64_const as arm

spec = importlib.util.spec_from_file_location('sns_message_original',
    Path(__file__).with_name('audit-steam-sns-message.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
MANAGER, RECORD, MAP, ARRAY, INPUT, OUT, TLS = [0x20000000 + n * 0x10000 for n in range(7)]
CAPACITY = 1024


class Run(base.Machine):
    def __init__(self, binary):
        super().__init__(binary)
        self.u.reg_write(arm.UC_ARM64_REG_TPIDR_EL0, TLS)
        self.wq(TLS + 40, 0x12345678)
        self.wq(MANAGER + 1152, MAP)
        self.wq(MAP + 8, RECORD)
        self.wq(RECORD + 32, ARRAY)
        self.wi(RECORD + 40, CAPACITY)
        self.now = 100
        self.executed = set()
        self.offline = False

    def reg(self, n, value=None):
        reg = getattr(arm, 'UC_ARM64_REG_X' + str(n))
        if value is None:
            return self.u.reg_read(reg)
        self.u.reg_write(reg, value & ((1 << 64)-1))

    def string(self, p):
        return bytes(self.u.mem_read(p, 256)).split(b'\0')[0]

    def hook(self, u, pc, size, unused):
        self.executed.add(pc)
        def ret(v=0):
            self.reg(0, v)
            u.reg_write(arm.UC_ARM64_REG_PC, self.reg(30))
        redirects = {0xc0dc90: 0x7a24d8, 0xc0de80: 0x7a3140,
                     0xc0de90: 0x7a3260, 0xc0dc80: 0x8e78c8,
                     0xc0da00: 0x8e78b8, 0xc149e0: 0x8e5aec,
                     0xc14a20: 0x8e4cf8}
        if pc == base.STOP:
            return u.emu_stop()
        if self.offline:
            if pc == 0x79a1a4:
                u.reg_write(arm.UC_ARM64_REG_PC, base.STOP)
                return u.emu_stop()  # Branch is complete before protobuf/header destruction.
            if pc in (0xc0d4f0, 0xc0da60, 0xc0dbd0, base.STOP+0x100):
                if pc == 0xc0d4f0:
                    assert self.reg(0) == MANAGER+96 and self.q(self.reg(1)) == 123
                    return ret(0 if self.visible else 0xffffffff)
                if pc == 0xc0da60:
                    assert self.visible and self.q(self.reg(1)) == 123
                    self.visible = False
                    self.offline_events.append('remove_visible')
                elif pc == 0xc0dbd0:
                    assert self.reg(0) == MANAGER+192 and self.q(self.reg(1)) == 123
                    self.cloud = False
                    self.offline_events.append('remove_cloud_membership')
                else:
                    assert self.reg(1) == 123
                    self.offline_events.append('notify_removed')
                return ret()
        if pc in redirects:
            return u.reg_write(arm.UC_ARM64_REG_PC, redirects[pc])
        if pc == 0xc0d8b0:
            assert (self.reg(0), self.reg(1)) == (MANAGER, 123)
            return ret()
        if pc == 0xc0d950:
            assert self.q(self.reg(1)) == 123
            return ret(0)
        if pc == 0xc0a5b0:
            assert self.reg(0) == 0
            return ret(self.now)
        if pc == 0xc09fb0:
            a, b = self.string(self.reg(0)), self.string(self.reg(1))
            return ret((a > b)-(a < b))
        if pc == 0xc09f60:
            p, s, limit = self.reg(0), self.string(self.reg(1)), self.reg(2)
            assert limit > 0
            u.mem_write(p, s[:limit-1]+b'\0')
            return ret()
        if pc == 0xc09ff0:
            # IP formatting's only printf path here: four unsigned octets.
            p, limit, fmt = self.reg(0), self.reg(1), self.string(self.reg(2))
            assert fmt == b'%i.%i.%i.%i', fmt
            s = (fmt % tuple(self.reg(n) for n in range(3, 7)))
            u.mem_write(p, s[:limit-1]+b'\0')
            return ret(len(s))
        assert (0x79be58 <= pc < 0x79c308 or 0x7a24d8 <= pc < 0x7a38c4 or
                0x8e78b8 <= pc < 0x8e7954 or 0x8e5aec <= pc < 0x8e5ca8 or
                0x8e4cf8 <= pc < 0x8e4f5c or
                (self.offline and 0x79a03c <= pc < 0x79a0a8)), f'unmodeled instruction/provider {pc:#x}'

    def invoke(self, pc, *args):
        self.u.reg_write(arm.UC_ARM64_REG_SP, 0x300ff000)
        self.reg(30, base.STOP)
        for n, value in enumerate(args):
            self.reg(n, value)
        self.u.emu_start(pc, base.STOP + 4, count=1000000)
        assert self.u.reg_read(arm.UC_ARM64_REG_PC) == base.STOP, 'instruction budget exhausted'
        return self.reg(0)

    def set_ip(self, p, row):
        address = ipaddress.ip_address(row['ip'])
        raw = int(address).to_bytes(4, 'little') if address.version == 4 else address.packed
        self.u.mem_write(p, bytes(24))
        self.u.mem_write(p, raw)
        self.u.mem_write(p+20, struct.pack('<HH', 3 if address.version == 4 else 4, row['port']))

    def set_rows(self, rows):
        assert len(rows) <= CAPACITY
        self.u.mem_write(ARRAY, bytes(CAPACITY*40))
        self.wi(RECORD + 48, len(rows))
        for n, row in enumerate(rows):
            p = ARRAY + n*40
            self.u.mem_write(p, bytes((row['verified'], row['remote'])))
            self.wq(p+8, row['time'] & ((1 << 64)-1))
            self.set_ip(p+16, row)

    def ip(self, p):
        # Execute the original formatter too, rather than using host inet_ntop.
        self.invoke(0x8e78b8, p, OUT + 64, 48, 1)
        return dict(ip=self.string(OUT+64).decode(),
                    port=struct.unpack('<H', self.u.mem_read(p+22, 2))[0])

    def rows(self):
        result = []
        for n in range(self.i(RECORD+48)):
            p = ARRAY + n*40
            t = self.q(p+8)
            result.append(dict(verified=bool(self.u.mem_read(p, 1)[0]),
                remote=bool(self.u.mem_read(p+1, 1)[0]), time=t if t < 1 << 63 else t-(1 << 64),
                **self.ip(p+16)))
        return result

    def step(self, action):
        self.now = action.get('now', self.now)
        kind = action['kind']
        if kind == 'add':
            self.set_ip(INPUT, action)
            added = bool(self.invoke(0x79c040, MANAGER, 123, INPUT,
                                    action['verified'], action['remote']))
        elif kind == 'clear':
            self.invoke(0x79be58, MANAGER, 123)
            added = None
        elif kind == 'sort':
            count = self.i(RECORD+48)
            self.invoke(0x7a24d8, ARRAY, ARRAY+count*40, INPUT,
                        action.get('depth', 2*(count.bit_length()-1) if count else 0), 1)
            added = None
        else:
            raise ValueError(kind)
        self.reg(8, OUT)
        self.invoke(0x79c25c, MANAGER, 123)
        route = self.ip(OUT)
        return dict(added=added, rows=self.rows(), route=route)

    def offline_case(self, visible, cloud):
        self.set_rows([entry('10.0.0.1', verified=True, time=1), entry('10.0.0.2', time=99)])
        # Synthetic persistent-memory sentinel; this is not a recovered key
        # field/layout. No persistent-record lookup may occur in this branch.
        self.u.mem_write(RECORD+128, bytes(range(32)))
        before = bytes(self.u.mem_read(RECORD, 160)), bytes(self.u.mem_read(ARRAY, 80))
        self.visible, self.cloud, self.offline_events = visible, cloud, []
        self.wq(MANAGER+384, INPUT+128)
        self.wi(MANAGER+400, 1)
        self.wq(INPUT+128, INPUT+256)
        self.wq(INPUT+256, INPUT+384)
        self.wq(INPUT+384+40, base.STOP+0x100)
        self.offline = True
        self.reg(19, MANAGER)
        self.wq(0x300ff000+8, 123)
        self.invoke(0x79a03c)
        self.offline = False
        assert before == (bytes(self.u.mem_read(RECORD, 160)), bytes(self.u.mem_read(ARRAY, 80)))
        return dict(initial=dict(visible=visible, cloud=cloud), visible=self.visible,
                    cloud=self.cloud, retained_persistent_state=True, events=self.offline_events)


def entry(ip='10.0.0.1', *, verified=False, remote=False, time=0, port=27036):
    return dict(ip=ip, verified=verified, remote=remote, time=time, port=port)


def programs():
    def add(ip, now, verified=False, remote=False, port=27036):
        return dict(kind='add', ip=ip, now=now, verified=verified, remote=remote, port=port)
    yield dict(name='candidate-clock-and-duplicate', initial=[], actions=[
        add('10.0.0.1', 100), add('10.0.0.1', 200, port=1234),
        add('10.0.0.1', 201, remote=True, port=4321),
        add('10.0.0.1', 202, verified=True, port=1234),
        add('10.0.0.1', 203, verified=True, port=5678)])
    yield dict(name='clear-keeps-reachable-not-youngest', initial=[
        entry('10.0.0.1', verified=True, time=1), entry('10.0.0.2', time=100),
        entry('10.0.0.3', verified=True, time=2), entry('10.0.0.4', time=200),
        entry('10.0.0.5', verified=True, time=3)], actions=[dict(kind='clear', now=999999)])
    yield dict(name='old-direct-stays-selectable', initial=[
        entry('10.0.0.1', verified=True, time=1)], actions=[dict(kind='sort', now=999999)])
    yield dict(name='ipv6-ignore-port-match', initial=[], actions=[
        add('2001:db8::1', 100, verified=True, port=1234),
        add('2001:db8::1', 200, port=4321),
        add('2001:db8::1', 201, remote=True), dict(kind='clear')])
    # All input permutations of the known nontransitive triple: observe complete
    # original sort results, not just pairwise-comparator truth values.
    triple=[entry(f'0.0.0.{ip}', verified=True, time=t) for ip, t in [(3,104),(2,102),(1,100)]]
    for n, initial in enumerate(itertools.permutations(triple)):
        yield dict(name=f'nontransitive-{n}', initial=list(initial), actions=[dict(kind='sort')])
    rng = random.Random(20261020)
    for count in [0,1,2,3,4,5,6,8,16,23,24,25,31,32,63,64,127,128,129,255,256]:
        for mode in ['ascending','descending','shuffled','near-time','mixed']:
            rows=[]
            for n in range(count):
                v6 = mode == 'mixed' and n % 3 == 0
                rows.append(entry(str(ipaddress.ip_address((int(ipaddress.ip_address('2001:db8::')) if v6 else 0x0a000000)+n)),
                    verified=(n % 2 == 0) if mode == 'mixed' else True,
                    remote=(n % 4 == 0) if mode == 'mixed' else False,
                    time=100+rng.randrange(9) if mode == 'near-time' else 100))
            if mode == 'descending': rows.reverse()
            if mode in ('shuffled','near-time','mixed'): rng.shuffle(rows)
            yield dict(name=f'sort-{count}-{mode}', initial=rows, actions=[dict(kind='sort')])
    # Original literal comparisons add 3 in signed-64 space; preserve the
    # instruction semantics at wall-clock discontinuities as well.
    for t in [-100, 0, 1, 2, 3, 4, 99, 100, 101, 103, 104, (1<<63)-1]:
        yield dict(name=f'time-{t}', initial=[entry('10.0.0.2', verified=True, time=t),
            entry('10.0.0.1', verified=True, time=100)], actions=[dict(kind='sort')])
    yield dict(name='ipv6-original-format-order', initial=[entry(ip, verified=True, time=100)
        for ip in ['::', '::1', '::ffff:192.0.2.1', '2001:db8:0:1:0:0:1:1',
                   '2001:db8::2', '2001:db8::10', '2001:db8::a']], actions=[dict(kind='sort')])
    for count in [24, 32, 129]:
        rows=[entry(f'10.0.{n//256}.{n%256}', verified=True, time=100+rng.randrange(9))
              for n in range(count)]
        rng.shuffle(rows)
        yield dict(name=f'explicit-zero-depth-{count}', initial=rows,
                   actions=[dict(kind='sort', depth=0)])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--reference', type=Path, help='Require an identical frozen replay')
    args = p.parse_args()
    binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == base.SHA
    m, cases = Run(binary), []
    for program in programs():
        m.set_rows(program['initial'])
        program['results'] = [m.step(a) for a in program['actions']]
        cases.append(program)
    offline=[m.offline_case(visible, cloud) for visible in (False, True) for cloud in (False, True)]
    report=dict(schema=1, sample_sha256=base.SHA, scope=__doc__, cases=cases, offline=offline)
    raw=(json.dumps(report, sort_keys=True, separators=(',', ':'))+'\n').encode()
    if args.reference:
        stored = args.reference.read_bytes()
        assert raw == (gzip.decompress(stored) if args.reference.suffix == '.gz' else stored), 'reference changed'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(gzip.compress(raw, mtime=0) if args.output.suffix == '.gz' else raw)
    print(f'PASS: {len(cases)} original address-cache programs; {sum(len(c["actions"]) for c in cases)} steps; {len(offline)} Offline branches')


if __name__ == '__main__':
    main()
