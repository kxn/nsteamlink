#!/usr/bin/env python3
"""Execute original discovery wall-round boundaries and weak random stream.

Pinned Core and shell execute Update/Enable/Trigger/Disable, original protobuf
and wire serialization. Manager storage/empty hosts, OS returns and wall time
are controlled. Random programs execute ctor/SetSeed/Install/WeakRandomInt
(global+vtable)/RandomInt with time1000 and pid77. No whole manager constructor,
natural Qt/network, actual timing, production seed/entropy or random-quality
claim. Native port comparisons are separate.
"""
import argparse
import copy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
from collections import Counter
from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X30, UC_ARM64_REG_PC
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sender', ROOT / 'scripts/audit-steam-discovery-send.py')
sender = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sender)

class Random(sender.Sender):

    def hook(self, u, pc, size, data):
        name = self.plts.get(pc, '')
        if self.ready and name == 'getpid':
            self.trace.append(['controlled_getpid', 77])
            return self.ret(77)
        if self.ready and name == 'WeakRandomInt':
            return self.jump(self.symbols[name])
        return super().hook(u, pc, size, data)

class Nested(sender.Sender):
    """Opaque receive callback calls declared original operations during real Update.

    Nested Unicorn stop returns control at the exact original BProcess return
    PC. Resume that original outer instruction stream; no Source code patch.
    The nested call uses a separate mapped stack, then restores outer CPU state.
    """
    resume_pc = None
    actions = (('trigger', None), ('trigger', None))

    def call(self, entry, *params):
        try:
            return super().call(entry, *params)
        except AssertionError as error:
            if (str(error) != "instruction budget exceeded" or self.resume_pc is None or
                    self.u.reg_read(UC_ARM64_REG_PC) != self.resume_pc):
                raise
            self.trace.append(["resume_outer_after_nested_emulator_stop", self.resume_pc])
            self.u.emu_start(self.resume_pc, sender.config.STOP + 4, count=300000)
            assert self.u.reg_read(UC_ARM64_REG_PC) == sender.config.STOP
            self.resume_pc = None
            return self.r(0)

    def hook(self, u, pc, size, data):
        if (self.ready and self.plts.get(pc, '') ==
                '_ZN14CServerManager8BProcessEP10CIPAndPortP10CUtlBufferb'):
            saved = u.context_save()
            self.resume_pc = u.reg_read(UC_ARM64_REG_X30)
            tag = 'nested_trigger' if self.actions == Nested.actions else 'nested_operation'
            self.trace.append([tag + '_terminal_begin'])
            for operation, argument in self.actions:
                u.reg_write(UC_ARM64_REG_SP, 0x30080000)
                u.reg_write(UC_ARM64_REG_X0, self.manager)
                u.reg_write(UC_ARM64_REG_X30, sender.config.STOP)
                if argument is not None:
                    u.reg_write(UC_ARM64_REG_X1, argument)
                symbol = sender.FUNCTIONS.get(operation, operation)
                u.emu_start(self.symbols[symbol],
                            sender.config.STOP + 4, count=300000)
                assert u.reg_read(UC_ARM64_REG_PC) == sender.config.STOP
            u.context_restore(saved)
            self.trace.append([tag + '_terminal_end'])
            return self.ret(1)
        return super().hook(u, pc, size, data)

class Targets(sender.Sender):
    """Explicit preloaded cache/lookup adapters; not file loading/hash proof."""

    def __init__(self, binary):
        super().__init__(binary)
        ids = self.alloc(16)
        self.wq(ids, 123)
        self.wq(ids + 8, 456)
        self.wq(self.manager + 56, ids)
        self.wi(self.manager + 72, 0)
        table = self.alloc(48)
        self.wq(self.manager + 1152, table)
        for index, ips in enumerate(((2130706433, 2130706434), (2130706435,))):
            info = self.alloc(64)
            addresses = self.alloc(40 * len(ips))
            self.wq(table + index * 24 + 8, info)
            self.wq(info + 32, addresses)
            self.wi(info + 48, len(ips))
            for offset, ip in enumerate(ips):
                target = addresses + offset * 40 + 16
                self.u.mem_write(target, bytes(self.u.mem_read(self.peer, 24)))
                self.wi(target, ip)
                self.u.mem_write(target + 22, 7000 .to_bytes(2, 'little'))

    def hook(self, u, pc, size, data):
        name = self.plts.get(pc, '')
        if self.ready and name == '_ZN14CServerManager24LoadPersistentClientInfoEy':
            self.trace.append(['preloaded_persistent_info_terminal', self.r(1)])
            return self.ret()
        if self.ready and 'PersistentClientInfo_t' in name and ('4Find' in name):
            identity = self.q(self.r(1))
            assert identity in (123, 456)
            self.trace.append(['controlled_persistent_lookup', identity])
            return self.ret(0 if identity == 123 else 1)
        return super().hook(u, pc, size, data)

class NestedTargets(Nested, Targets):
    pass

def schedule(binary):
    cases = []

    def new():
        m = sender.started(binary, False)
        m.run('enable')
        return m

    def row(m):
        return dict(wall=m.wall_time, **m.snapshot())

    def update(m, t):
        m.wall_time = t
        m.run('update')
        return row(m)
    m = new()
    rows = [row(m), update(m, 999), update(m, 1000), update(m, 1001), update(m, 1001), update(m, 1005), update(m, 1012), update(m, 1013)]
    assert [len(r['sends']) for r in rows] == [1, 1, 1, 2, 2, 3, 3, 4]
    cases.append(dict(name='wall_backwards_same_tick_and_fast_cap', stages=rows))
    m = new()
    rows = [row(m), update(m, 1004), update(m, 1004), update(m, 1007), update(m, 1008)]
    assert [len(r['sends']) for r in rows] == [1, 2, 2, 2, 3]
    assert rows[1]['fast_status'] == 1008
    cases.append(dict(name='late_fast_is_single_and_reschedules_from_now', stages=rows))
    m = new()
    rows = [row(m), update(m, 1040), update(m, 1040), update(m, 1041)]
    assert [len(r['sends']) for r in rows] == [1, 2, 2, 3]
    assert rows[1]['next_status'] == 1053 and rows[1]['fast_status'] == 1041
    assert [r['sequence'] for r in rows] == [2, 3, 3, 3]
    cases.append(dict(name='full_priority_and_large_forward_jump_no_catchup', stages=rows))
    m = new()
    rows = [row(m)]
    m.run('trigger')
    rows.append(row(m))
    m.run('trigger')
    rows.append(row(m))
    assert [len(r['sends']) for r in rows] == [1, 2, 3] and [r['sequence'] for r in rows] == [2, 3, 4]
    assert all((r['broadcast_owners'] == 1 and r['status_tries'] == 1 for r in rows))
    cases.append(dict(name='same_tick_trigger_forces_full_without_owner_increment', stages=rows))
    m = sender.started(binary, False)
    m.run('trigger')
    rows = [row(m)]
    assert rows[0]['sequence'] == 2 and (not rows[0]['sends']) and (rows[0]['broadcast_owners'] == 0)
    m.run('enable')
    rows.append(row(m))
    assert len(rows[-1]['sends']) == 1 and rows[-1]['sequence'] == 3
    cases.append(dict(name='trigger_without_owner_updates_schedule_but_no_broadcast', stages=rows))
    m = new()
    m.run('enable')
    rows = [row(m)]
    disable = m.symbols['_ZN14CServerManager25DisableBroadcastDiscoveryEv']
    m.call(disable, m.manager)
    rows.append(row(m))
    rows.append(update(m, 1001))
    m.call(disable, m.manager)
    rows.append(row(m))
    rows.append(update(m, 1005))
    assert [r['broadcast_owners'] for r in rows] == [2, 1, 1, 0, 0] and [len(r['sends']) for r in rows] == [2, 2, 3, 3, 3]
    assert rows[-1]['status_tries'] == 3
    cases.append(dict(name='balanced_owner_disable_does_not_stop_wall_schedule', stages=rows))
    m = sender.started(binary, False)
    m.wi(m.manager + 44, 4294967295)
    m.run('enable')
    rows = [row(m), update(m, 1001), update(m, 1005), update(m, 1013)]
    assert [r['sequence'] for r in rows] == [0, 0, 0, 1]
    assert [x['wire'][-4:] for x in rows[-1]['sends']] == ['0800', '0800', '0800', '0801']
    cases.append(dict(name='sequence_wrap_only_on_full_round', stages=rows))
    m = sender.started(binary, False)
    m.socket_result = -1
    m.send_plan = [(-1, 5)] * 3
    m.run('enable')
    rows = [row(m), update(m, 1000)]
    assert len(rows[0]['sends']) == len(rows[1]['sends']) == 3 and rows[0]['status_tries'] == 1
    assert rows[1]['next_status'] == 1013 and rows[1]['fast_status'] == 1001
    cases.append(dict(name='failed_broadcast_does_not_force_extra_same_tick_round', stages=rows))
    m = Targets(binary)
    m.socket_result = 37
    m.socket_plan = [-1, 37]
    m.run('start')
    m.wi(m.manager + 72, 2)
    m.run('enable')
    rows = [row(m)]
    m.call(m.symbols['_ZN14CServerManager25DisableBroadcastDiscoveryEv'], m.manager)
    rows.append(row(m))
    rows.append(update(m, 1001))
    assert len(rows[0]['sends']) == 4 and len(rows[2]['sends']) == 8
    assert all((int.from_bytes(bytes.fromhex(x['sockaddr'])[2:4], 'big') == 27036 for x in rows[-1]['sends']))
    m.wi(m.manager + 72, 0)
    m.run('trigger')
    rows.append(row(m))
    assert len(rows[-1]['sends']) == 8
    cases.append(dict(name='targets', stages=rows, boundary='preloaded persistent address records and ID lookup adapters; original RequestStatus loops, port override, protobuf and full wire execute'))
    m = new()
    rows = [row(m)]
    m.run('trigger')
    m.run('trigger')
    rows.append(row(m))
    assert [len(r['sends']) for r in rows] == [1, 3]
    assert [r['sequence'] for r in rows] == [2, 4]
    cases.append(dict(name='independent_trigger_burst', stages=rows))
    m = Nested(binary)
    m.socket_result, m.socket_plan = 37, [-1, 37]
    m.run('start')
    m.run('enable')
    rows = [row(m)]
    m.receive_plan = [9, -1]
    m.run('update')
    rows.append(row(m))
    assert [len(r['sends']) for r in rows] == [1, 2]
    assert [r['sequence'] for r in rows] == [2, 3]
    assert rows[-1]['calls']['trigger'] == 2
    cases.append(dict(name='nested_receive_trigger', stages=rows,
        boundary='opaque BProcess callback; two real Trigger/Update calls execute reentry guard, then original outer Update continues; no valid Source wire admission'))
    m = new()
    rows = [row(m)]
    m.receive_plan = [9, -1]
    m.run('update')
    assert len(m.sends) == 1
    m.run('trigger')
    m.run('trigger')
    rows.append(row(m))
    assert [len(r['sends']) for r in rows] == [1, 3]
    assert [r['sequence'] for r in rows] == [2, 4]
    cases.append(dict(name='external_trigger_during_receive', stages=rows,
        boundary='Source completes one opaque receive Update before the independent UI calls; Native queues external actor calls during the callback and sends after RX, not reentry'))
    m = sender.started(binary, False)
    m.run('enable')
    m.call(m.symbols['_ZN14CServerManager25DisableBroadcastDiscoveryEv'], m.manager)
    final = row(m)
    assert final['sequence'] == 2 and final['broadcast_owners'] == 0 and len(final['sends']) == 1
    cases.append(dict(name='enable_disable_before_watch', stages=[final]))
    m = sender.started(binary, False)
    m.run('enable')
    m.call(m.symbols['_ZN14CServerManager25DisableBroadcastDiscoveryEv'], m.manager)
    m.run('trigger')
    m.run('enable')
    final = row(m)
    assert final['sequence'] == 4 and final['broadcast_owners'] == 1
    assert [x['wire'][-4:] for x in final['sends']] == ['0802', '0804']
    cases.append(dict(name='owner_flip_before_watch', stages=[final]))
    m = Targets(binary)
    m.socket_result, m.socket_plan = 37, [-1, 37]
    m.run('start')
    m.run('enable')
    m.call(m.symbols['_ZN14CServerManager18AddClientDiscoveryEy'], m.manager, 123)
    added = row(m)
    assert added['sequence'] == 2 and len(added['sends']) == 1 and added['next_status'] == 0
    m.run('update')
    final = row(m)
    assert final['sequence'] == 3 and len(final['sends']) == 4
    assert [x['wire'][-4:] for x in final['sends']] == ['0802', '0803', '0803', '0803']
    cases.append(dict(name='enable_targets_before_watch', stages=[final], after_add=added,
        boundary='original AddClientDiscovery appends ID and only clears full; actual next Update uses declared preloaded persistent lookup records'))
    for name, actions, disable_after in (
        ('first_receive_disables_owner', (('_ZN14CServerManager25DisableBroadcastDiscoveryEv', None),), False),
        ('first_receive_adds_targets', (('_ZN14CServerManager18AddClientDiscoveryEy', 123),), False),
        ('first_receive_triggers_before_queued_disable', (('trigger', None), ('trigger', None)), True),
    ):
        m = NestedTargets(binary)
        m.actions = actions
        m.socket_result, m.socket_plan = 37, [-1, 37]
        m.run('start')
        m.receive_plan = [9, -1]
        m.run('enable')
        if disable_after:
            m.call(m.symbols['_ZN14CServerManager25DisableBroadcastDiscoveryEv'], m.manager)
        final = row(m)
        assert final['sequence'] == 2
        assert final['broadcast_owners'] == (1 if name == 'first_receive_adds_targets' else 0)
        assert len(final['sends']) == (0 if name == 'first_receive_disables_owner' else
                                      3 if name == 'first_receive_adds_targets' else 1)
        cases.append(dict(name=name, stages=[final],
            boundary='opaque first BProcess invokes declared original operations during Enable Update; separate nested stack and strict outer continuation; target records/lookup explicit adapters'))
    return cases

def forced_random(binary):
    # Controlled valid generator states force acceptance/rejection at the exact
    # inclusive cutoff; ordinary seeded vectors almost never hit this branch.
    m = Random(binary)
    obj = m.alloc(256)
    m.call(m.symbols['_ZN20CUniformRandomStreamC1Ev'], obj)
    m.call(m.symbols['InstallUniformRandomStream'], obj)
    cases = []
    for high in (3, 5):
        limit = 0x7fffffff - (0x80000000 % high)
        for first in (limit, limit + 1):
            m.u.mem_write(obj + 8, bytes(136))
            m.wi(obj + 8, 1)
            m.wi(obj + 12, 1)
            m.wi(obj + 16, first)
            m.wi(obj + 16 + 31 * 4, 7)
            m.call(m.symbols['WeakRandomInt'], 1, high)
            row = dict(high=high, first=first, result=m.r(0), seed=m.i(obj + 8),
                       previous=m.i(obj + 12), table0=m.i(obj + 16),
                       table31=m.i(obj + 16 + 31 * 4))
            assert row['result'] == (first % high + 1 if first == limit else 7 % high + 1)
            assert row['seed'] == (16807 if first == limit else 282475249)
            cases.append(row)
    return cases

def random_stream(binary):
    m = Random(binary)
    obj = m.alloc(256)
    m.call(m.symbols['_ZN20CUniformRandomStreamC1Ev'], obj)
    ctor = {'seed_bits': m.i(obj + 8), 'state': m.i(obj + 12), 'trace': list(m.trace)}
    assert ctor['seed_bits'] == -(1000 ^ 77) & 4294967295 and ctor['state'] == 0
    m.call(m.symbols['InstallUniformRandomStream'], obj)
    cases = []
    for seed in (1, 17, 1234567, 0, -1, 2147483647, -2147483648):
        m.call(m.symbols['_ZN20CUniformRandomStream7SetSeedEi'], obj, seed & 4294967295)
        samples = []
        for low, high in [(1, 5), (1, 3), (4, 7)]:
            values = []
            for _ in range(128):
                m.call(m.symbols['WeakRandomInt'], low, high)
                values.append(m.r(0))
                assert low <= values[-1] <= high
            assert set(values) <= set(range(low, high + 1))
            samples.append({'range': [low, high], 'values': values,
                            'counts': {str(k): v for k, v in Counter(values).items()}})
        cases.append({'explicit_seed': seed, 'samples': samples})
    return dict(constructor=ctor, cases=cases, forced=forced_random(binary))

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--core-binary', required=True, type=Path)
    p.add_argument('--shell-binary', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--refresh-reference', action='store_true')
    args = p.parse_args()
    result = dict(scope=__doc__, binaries={}, helpers={})
    for identity, path in (('core', args.core_binary), ('shell', args.shell_binary)):
        binary = path.read_bytes()
        assert hashlib.sha256(binary).hexdigest() == sender.IDENTITIES[identity]
        result['binaries'][identity] = dict(sha256=sender.IDENTITIES[identity], schedules=schedule(binary), random=random_stream(binary))
    for name in (Path(__file__).name, 'audit-steam-discovery-send.py', 'audit-steam-client-config.py', 'audit-steam-client-fec-policy.py'):
        result['helpers'][name] = hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest()
    data = (json.dumps(result, indent=2) + '\n').encode()
    ref = ROOT / 'scripts/fixtures/steam-discovery-rounds-reference.json.gz'
    if args.refresh_reference:
        assert not ref.exists()
        ref.write_bytes(gzip.compress(data, mtime=0))
    else:
        assert result == json.loads(gzip.decompress(ref.read_bytes()))
    args.output.write_bytes(data)
    print('Original discovery rounds: 18 schedules, 7 seeded streams and 4 rejection boundaries per binary passed')
if __name__ == '__main__':
    main()
