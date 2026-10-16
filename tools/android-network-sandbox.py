#!/usr/bin/env python3
"""Temporarily impair only Steam Link on an explicitly selected Android emulator.

Requires an already-rooted adb daemon. Never changes the development host firewall.
Peer addresses and raw firewall snapshots are written only to a private output directory.
"""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import secrets
import signal
import subprocess
import time


class Sandbox:
    def __init__(self, serial, output, addresses, udp_loss=0, adb='adb'):
        if not re.fullmatch(r'emulator-\d+', serial):
            raise ValueError('an explicit emulator serial is required')
        self.adb = [adb, '-s', serial, 'shell']
        self.output = Path(output)
        self.addresses = {ipaddress.ip_address(a) for a in addresses}
        if not 0 <= udp_loss <= .5:
            raise ValueError('outgoing UDP loss must be between 0 and 0.5')
        self.loss = udp_loss
        self.chain = 'NSL_WAN_' + secrets.token_hex(4)
        self.created = []
        self.attached = []

    def command(self, *args):
        return subprocess.check_output(self.adb + list(args), text=True,
                                       stderr=subprocess.PIPE, timeout=10).strip()

    def private(self, name, text):
        path = self.output / name
        path.write_text(text + '\n')
        path.chmod(0o600)

    def __enter__(self):
        self.output.mkdir(parents=True, mode=0o700, exist_ok=False)
        if self.command('getprop', 'ro.kernel.qemu') != '1':
            raise RuntimeError('selected device is not an Android emulator')
        if self.command('id', '-u') != '0':
            raise RuntimeError('adb daemon must already be root')
        package = self.command('cmd', 'package', 'list', 'packages', '-U',
                               'com.valvesoftware.steamlink')
        match = re.fullmatch(r'package:com\.valvesoftware\.steamlink uid:(\d+)', package)
        if not match or int(match[1]) < 10000:
            raise RuntimeError('could not resolve Steam Link application UID')
        self.uid = match[1]
        try:
            for family, binary in ((4, 'iptables'), (6, 'ip6tables')):
                self.private(f'{binary}-before.txt', self.command(binary, '-S'))
                self.command(binary, '-w', '2', '-N', self.chain)
                self.created.append(binary)
                for address in sorted(self.addresses, key=str):
                    if address.version == family:
                        self.command(binary, '-w', '2', '-A', self.chain,
                                     '-d', str(address), '-j', 'DROP')
                if self.loss:
                    self.command(binary, '-w', '2', '-A', self.chain, '-p', 'udp',
                                 '-m', 'statistic', '--mode', 'random',
                                 '--probability', str(self.loss), '-j', 'DROP')
                self.command(binary, '-w', '2', '-I', 'OUTPUT', '1', '-m', 'owner',
                             '--uid-owner', self.uid, '-j', self.chain)
                self.attached.append(binary)
            self.private('profile.json', json.dumps({'uid': int(self.uid),
                         'peer_addresses': sorted(str(a) for a in self.addresses),
                         'outgoing_udp_loss': self.loss, 'chain': self.chain}, indent=2))
        except BaseException:
            self.cleanup()
            raise
        print(json.dumps({'stage': 'firewall_applied', 'application': 'Steam Link',
                          'blocked_addresses': len(self.addresses),
                          'outgoing_udp_loss': self.loss}), flush=True)
        return self

    def cleanup(self):
        errors = []
        for binary in reversed(self.created):
            try:
                self.private(f'{binary}-counters.txt',
                             self.command(binary, '-L', self.chain, '-n', '-v', '-x'))
            except Exception as error:
                errors.append(type(error).__name__)
            if binary in self.attached:
                try:
                    self.command(binary, '-w', '2', '-D', 'OUTPUT', '-m', 'owner',
                                 '--uid-owner', self.uid, '-j', self.chain)
                    self.attached.remove(binary)
                except Exception as error:
                    errors.append(type(error).__name__)
                    continue
            try:
                self.command(binary, '-w', '2', '-F', self.chain)
                self.command(binary, '-w', '2', '-X', self.chain)
                self.created.remove(binary)
                self.private(f'{binary}-after.txt', self.command(binary, '-S'))
            except Exception as error:
                errors.append(type(error).__name__)
        result = {'stage': 'firewall_cleanup', 'removed': not self.created and not self.attached,
                  'errors': errors}
        self.private('cleanup.json', json.dumps(result))
        print(json.dumps(result), flush=True)
        if not result['removed']:
            raise RuntimeError('emulator firewall cleanup incomplete; see private snapshots')

    def __exit__(self, *exception):
        self.cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--peer-file', type=Path, help='JSON list of peer IPv4/IPv6 candidates')
    parser.add_argument('--udp-loss', type=float, default=0,
                        help='random loss of outgoing UDP; does not affect incoming packets')
    parser.add_argument('--seconds', type=float, default=30)
    parser.add_argument('--adb', default='adb')
    args = parser.parse_args()
    if not 0 < args.seconds <= 300:
        parser.error('seconds must be between 0 and 300')
    addresses = json.loads(args.peer_file.read_text()) if args.peer_file else []
    if not isinstance(addresses, list) or not all(isinstance(a, str) for a in addresses):
        parser.error('peer-file must contain a JSON string list')
    if not addresses and not args.udp_loss:
        parser.error('select peer blocking or outgoing UDP loss')
    def terminate(*unused):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, terminate)
    try:
        with Sandbox(args.serial, args.output, addresses, args.udp_loss, args.adb):
            time.sleep(args.seconds)
    except KeyboardInterrupt:
        pass  # The context manager has already removed this experiment's rules.


if __name__ == '__main__':
    main()
