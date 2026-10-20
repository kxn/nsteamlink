#!/usr/bin/env python3
"""Original discovery/launch due order and post-discovery reentry.

Pinned managers execute Update, RequestStatus/wire, recovery and nested original
operations. State5, launch deadline and saved-target lookup records are inputs.
Socket construction is constrained to IPv4, including reopen.
Launch producer is an explicit terminal: it advances its supplied deadline by
one wall second and may invoke declared nested operations. No original launch
payload/ticket, natural callback, real network or whole-manager claim.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X30, UC_ARM64_REG_PC
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('rounds', ROOT / 'scripts/audit-steam-discovery-rounds.py')
rounds = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rounds)
sender = rounds.sender
REFERENCE = ROOT / 'scripts/fixtures/steam-discovery-joint-reference.json.gz'

class Joint(rounds.NestedTargets):
    late_actions = ()
    late_done = False

    def hook(self, u, pc, size, data):
        if self.ready and self.plts.get(pc, '') == '_ZN14CServerManager25SendStartStreamingRequestEv':
            self.trace.append(['launch_retry_terminal', self.wall_time])
            self.wq(self.manager + 520, self.wall_time + 1)
            if self.late_actions and not self.late_done:
                self.late_done = True
                saved = u.context_save()
                self.resume_pc = u.reg_read(UC_ARM64_REG_X30)
                for operation, argument in self.late_actions:
                    u.reg_write(UC_ARM64_REG_SP, 0x30080000)
                    u.reg_write(UC_ARM64_REG_X0, self.manager)
                    u.reg_write(UC_ARM64_REG_X30, sender.config.STOP)
                    if argument is not None:
                        u.reg_write(UC_ARM64_REG_X1, argument)
                    symbol = sender.FUNCTIONS.get(operation, operation)
                    u.emu_start(self.symbols[symbol], sender.config.STOP + 4, count=300000)
                    assert u.reg_read(UC_ARM64_REG_PC) == sender.config.STOP
                u.context_restore(saved)
            return self.ret()
        return super().hook(u, pc, size, data)

def audit(binary):
    cases = []
    for name, actions in (
        ('joint_due', ()),
        ('joint_late_trigger', (('trigger', None), ('trigger', None))),
        ('joint_late_enable', (('enable', None),)),
        ('joint_late_disable', (('_ZN14CServerManager25DisableBroadcastDiscoveryEv', None),)),
        ('joint_late_targets', (('_ZN14CServerManager18AddClientDiscoveryEy', 123),)),
        ('joint_reopen_before_retry', ()),
    ):
        m = Joint(binary)
        m.socket_result, m.socket_plan = 37, [-1, 37]
        m.run('start')
        m.run('enable')
        m.wi(m.manager + 8, 5)
        m.wq(m.manager + 520, 1001)
        m.wall_time = 1001
        m.late_actions = actions
        if name == 'joint_reopen_before_retry':
            m.send_plan = [(-1, 5)]
            m.socket_plan = [-1, 37]  # Same IPv4-only capability on the reopen.
        before, sends = len(m.trace), len(m.sends)
        m.run('update')
        first = m.snapshot()
        first_order = [0 if x[0] == 'sendto' else 5 for x in m.trace[before:]
                       if x[0] in ('sendto', 'launch_retry_terminal')]
        first_sends = len(m.sends) - sends
        m.run('update')
        final = m.snapshot()
        trace = m.trace[before:]
        order = [0 if x[0] == 'sendto' else 5 for x in trace
                 if x[0] in ('sendto', 'launch_retry_terminal')]
        expected = [0, 5]
        if name in ('joint_late_trigger', 'joint_late_enable'):
            expected += [0]
        elif name == 'joint_late_targets':
            expected += [0, 0, 0]
        elif name == 'joint_reopen_before_retry':
            expected = [0, 0, 5]
        assert order == expected, (name, order)
        assert first['sequence'] == 2
        assert final['sequence'] == (3 if name in ('joint_late_trigger', 'joint_late_enable', 'joint_late_targets') else 2)
        if name == 'joint_late_trigger':
            assert first['next_status'] == 0 and final['next_status'] == 1014
            assert final['calls']['trigger'] == 2
        if name == 'joint_late_disable':
            assert final['broadcast_owners'] == 0
        if name == 'joint_late_enable':
            assert final['broadcast_owners'] == 2
        assert first_order == ([0, 0, 5] if name == 'joint_reopen_before_retry' else [0, 5])
        cases.append(dict(name=name, order=order, first_order=first_order, first_sends=first_sends, first=first, final=final,
            discovery_sends=m.sends[sends:], trace=trace))
    return cases

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
        result['binaries'][identity] = dict(sha256=sender.IDENTITIES[identity], cases=audit(binary))
    for name in (Path(__file__).name, 'audit-steam-discovery-rounds.py', 'audit-steam-discovery-send.py', 'audit-steam-client-config.py', 'audit-steam-client-fec-policy.py'):
        result['helpers'][name] = hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest()
    data = (json.dumps(result, indent=2) + '\n').encode()
    if args.refresh_reference:
        assert not REFERENCE.exists()
        REFERENCE.write_bytes(gzip.compress(data, mtime=0))
    else:
        assert result == json.loads(gzip.decompress(REFERENCE.read_bytes()))
    args.output.write_bytes(data)
    print('Original joint update: six programs per binary, post-discovery nested operations and reopen-before-retry passed')

if __name__ == '__main__':
    main()
