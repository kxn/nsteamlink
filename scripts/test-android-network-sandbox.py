#!/usr/bin/env python3
"""Check that partial setup and interrupted tests remove only their owned rules."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    'sandbox', Path(__file__).resolve().parents[1] / 'tools/android-network-sandbox.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FakeDevice(module.Sandbox):
    def __init__(self, output, fail_ipv6=False):
        super().__init__('emulator-5580', output, ['192.0.2.5', '2001:db8::5'])
        self.calls = []
        self.fail_ipv6 = fail_ipv6

    def command(self, *args):
        self.calls.append(args)
        if args == ('getprop', 'ro.kernel.qemu'):
            return '1'
        if args == ('id', '-u'):
            return '0'
        if args[0] == 'cmd':
            return 'package:com.valvesoftware.steamlink uid:10193'
        if self.fail_ipv6 and args[:5] == ('ip6tables', '-w', '2', '-I', 'OUTPUT'):
            raise RuntimeError('injected IPv6 attach failure')
        return '-A OUTPUT -j existing_android_chain'


class CleanupTests(unittest.TestCase):
    def test_cleanup_runs_on_test_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            sandbox = FakeDevice(Path(temp) / 'evidence')
            with self.assertRaisesRegex(RuntimeError, 'test failed'):
                with sandbox:
                    raise RuntimeError('test failed')
            self.assertFalse(sandbox.created)
            self.assertFalse(sandbox.attached)
            mutations = [args for args in sandbox.calls if args[0] in ('iptables', 'ip6tables')
                         and len(args) > 3 and args[3] in ('-I', '-D', '-F', '-X')]
            for args in mutations:
                if args[3] in ('-I', '-D'):
                    self.assertIn('--uid-owner', args)
                    self.assertIn('10193', args)
                else:
                    self.assertEqual(args[-1], sandbox.chain)
            # No flush/restore of global chains, which could destroy Android rules.
            self.assertNotIn(('iptables', '-F'), sandbox.calls)

    def test_partial_ipv6_failure_removes_ipv4_jump_and_both_chains(self):
        with tempfile.TemporaryDirectory() as temp:
            sandbox = FakeDevice(Path(temp) / 'evidence', fail_ipv6=True)
            with self.assertRaisesRegex(RuntimeError, 'IPv6 attach'):
                with sandbox:
                    self.fail('body must not run after setup failure')
            self.assertFalse(sandbox.created)
            self.assertFalse(sandbox.attached)
            self.assertIn(('iptables', '-w', '2', '-D', 'OUTPUT', '-m', 'owner',
                           '--uid-owner', '10193', '-j', sandbox.chain), sandbox.calls)
            for binary in ('iptables', 'ip6tables'):
                self.assertIn((binary, '-w', '2', '-X', sandbox.chain), sandbox.calls)

    def test_reject_real_devices_and_unbounded_loss(self):
        for serial, loss in [('10.10.10.50:5555', 0), ('emulator-5580', .9)]:
            with self.subTest(serial=serial), self.assertRaises(ValueError):
                module.Sandbox(serial, '/unused', [], loss)


if __name__ == '__main__':
    unittest.main()
