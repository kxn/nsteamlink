#!/usr/bin/env python3
"""Observe the pinned official SDK during an Android Steam Link network test.

Requires a rooted emulator, running frida-server, adb forwarding to --remote,
and Steam Link already at Computer Settings. --tap must target Network Test.
Peer blocking must precede app startup when avoiding a cached LAN connection.
No desktop/game button is selected. Credentials and packet bodies are not read.
"""
import argparse
import importlib.util
import ipaddress
import json
from pathlib import Path
import queue
import re
import secrets
import signal
import subprocess
import time

PACKAGE = 'com.valvesoftware.steamlink'
SAMPLE_SHA256 = '195025601c2b17194a4d8b3debd674aca3377290fe3851986656c49bc973f907'


class RelayDrop:
    """Drop one UDP endpoint in this emulator, with a UID-scoped OUTPUT jump."""
    def __init__(self, command, output):
        self.command, self.output = command, output
        self.chains, self.jumps = [], []

    def apply(self, endpoint):
        ip = str(ipaddress.IPv4Address(endpoint['ip']))
        port = int(endpoint['port'])
        if not 0 < port <= 65535:
            raise ValueError('invalid relay port')
        package = self.command('cmd', 'package', 'list', 'packages', '-U', PACKAGE)
        match = re.fullmatch(r'package:com\.valvesoftware\.steamlink uid:(\d+)', package)
        if not match or int(match[1]) < 10000:
            raise RuntimeError('Steam Link UID missing')
        for direction, where, owner in [('o', 'OUTPUT', ['-m', 'owner', '--uid-owner', match[1]]),
                                         ('i', 'INPUT', [])]:
            chain = 'NSLR_' + secrets.token_hex(4) + direction
            self.command('iptables', '-w', '2', '-N', chain)
            self.chains.append(chain)
            self.command('iptables', '-w', '2', '-A', chain, '-p', 'udp',
                         '-d' if direction == 'o' else '-s', ip,
                         '--dport' if direction == 'o' else '--sport', str(port), '-j', 'DROP')
            self.command('iptables', '-w', '2', '-I', where, '1', *owner, '-j', chain)
            self.jumps.append([where, *owner, '-j', chain])

    def cleanup(self):
        errors = []
        for jump in reversed(self.jumps):
            try:
                self.command('iptables', '-w', '2', '-D', *jump)
            except Exception as error:
                errors.append(str(error))
        for chain in reversed(self.chains):
            try:
                private(self.output / (chain + '-counters.txt'),
                        self.command('iptables', '-L', chain, '-n', '-v', '-x'))
                self.command('iptables', '-w', '2', '-F', chain)
                self.command('iptables', '-w', '2', '-X', chain)
            except Exception as error:
                errors.append(str(error))
        return errors


def private(path, text):
    with path.open('w') as file:
        path.chmod(0o600)
        file.write(text + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--remote', default='127.0.0.1:27043')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--peer-file', type=Path, help='optional JSON peer IP list; emulator OUTPUT only')
    parser.add_argument('--force-sdr', action='store_true', help='set connection ICE config 104 to zero')
    parser.add_argument('--fault', action='store_true', help='drop the current primary after valid E2E + 3s')
    parser.add_argument('--hold-test-timeout', type=int, default=0,
                        help='hold only the network-test frame clock after injection, in seconds')
    parser.add_argument('--tap', type=int, nargs=2, help='coordinates of the Network Test button')
    parser.add_argument('--seconds', type=float, default=60)
    parser.add_argument('--stop-app', action='store_true', help='stop the emulator app before restoring rules')
    args = parser.parse_args()
    if not re.fullmatch(r'emulator-\d+', args.serial):
        parser.error('an explicit emulator serial is required')
    if not 0 < args.seconds <= 120 or not 0 <= args.hold_test_timeout <= 60:
        parser.error('seconds must be 1..120 and frame timeout hold 0..60')
    if args.fault and not args.force_sdr or args.hold_test_timeout and not args.fault:
        parser.error('fault requires --force-sdr; timeout hold requires --fault')
    if args.tap and any(value < 0 for value in args.tap):
        parser.error('tap coordinates must be nonnegative')
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    adb = ['adb', '-s', args.serial, 'shell']

    def command(*command_args):
        return subprocess.check_output(adb + list(command_args), text=True,
                                       stderr=subprocess.PIPE, timeout=10).strip()

    if command('getprop', 'ro.kernel.qemu') != '1' or command('id', '-u') != '0':
        raise RuntimeError('a rooted emulator is required')
    import frida
    events = queue.Queue()
    started = time.monotonic()
    log = (args.output / 'events.jsonl').open('w')
    (args.output / 'events.jsonl').chmod(0o600)

    def record(event):
        log.write(json.dumps({'elapsed': round(time.monotonic() - started, 3), **event}) + '\n')
        log.flush()

    def interrupt(*unused):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGINT, interrupt)
    script = session = sandbox = None
    drop = RelayDrop(command, args.output)
    primary = backup = None
    valid_since = fault_at = None
    dropped_pop = None
    ice_disabled = False
    sample_verified = False
    post_fault_e2e = errors = 0
    cleanup_errors = []
    try:
        if args.peer_file:
            spec = importlib.util.spec_from_file_location('sandbox',
                        Path(__file__).with_name('android-network-sandbox.py'))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            addresses = json.loads(args.peer_file.read_text())
            if not isinstance(addresses, list) or not all(isinstance(ip, str) for ip in addresses):
                raise ValueError('peer-file must contain a JSON list of IP addresses')
            sandbox = module.Sandbox(args.serial, args.output / 'peer-block', addresses)
            sandbox.__enter__()
        pid = int(command('pidof', PACKAGE))
        device = frida.get_device_manager().add_remote_device(args.remote)
        session = device.attach(pid)
        preflight = session.create_script("rpc.exports.metadata=()=>({arch:Process.arch,path:Process.getModuleByName('libshell_x86_64.so').path});")
        try:
            preflight.load()
            metadata = preflight.exports_sync.metadata()
            if metadata['arch'] != 'x64':
                raise RuntimeError('the pinned fixture requires an x86_64 process')
            sample = command('sha256sum', metadata['path']).split()[0]
        finally:
            preflight.unload()
        if sample != SAMPLE_SHA256:
            raise RuntimeError('unexpected official ELF; no hooks installed')
        sample_verified = True
        private(args.output / 'configuration.json', json.dumps({
            'sample_sha256': sample, 'force_sdr': args.force_sdr, 'fault': args.fault,
            'hold_test_timeout_seconds': args.hold_test_timeout, 'seconds': args.seconds}, indent=2))
        script = session.create_script(Path(__file__).with_suffix('.js').read_text())
        script.on('message', lambda message, data: events.put(message))
        script.load()
        script.exports_sync.configure(args.force_sdr, args.hold_test_timeout)
        tapped = False
        print(json.dumps({'output': str(args.output), 'sample_verified': True}), flush=True)
        while time.monotonic() - started < args.seconds:
            try:
                message = events.get(timeout=.1)
                event = message['payload'] if message.get('type') == 'send' else {
                    'kind': 'frida_error', 'message': message}
                record(event)
                kind = event.get('kind')
                if kind in ('frida_error', 'read_error', 'ice_override_failed'):
                    errors += 1
                elif kind == 'selection':
                    primary, backup = event.get('primary'), event.get('backup')
                elif kind == 'ice_disabled_config':
                    ice_disabled = event.get('actual') == 0
                elif kind == 'valid_e2e':
                    valid_since = valid_since or time.monotonic()
                    if fault_at and primary and event['relay']['pop'] == primary['pop'] != dropped_pop:
                        post_fault_e2e += 1
            except queue.Empty:
                pass
            if errors:
                break
            if args.tap and not tapped and time.monotonic() - started >= 2:
                command('input', 'tap', *map(str, args.tap))
                tapped = True
                record({'kind': 'network_test_button_tap', 'coordinates': args.tap})
            if (args.fault and not errors and ice_disabled and fault_at is None and
                    primary and backup and valid_since and time.monotonic() - valid_since >= 3):
                drop.apply(primary)
                fault_at, dropped_pop = time.monotonic(), primary['pop']
                record({'kind': 'fault_injected', 'endpoint': primary})
                script.exports_sync.armfault(primary['ip'], primary['port'])
    except KeyboardInterrupt:
        record({'kind': 'interrupted'})
    except Exception as error:
        errors += 1
        record({'kind': 'runner_error', 'error': str(error)})
    finally:
        if args.force_sdr and not ice_disabled:
            errors += 1
            record({'kind': 'force_sdr_not_observed'})
        if args.fault and fault_at is None:
            errors += 1
            record({'kind': 'fault_not_reached'})
        if args.stop_app:
            try:
                command('am', 'force-stop', PACKAGE)
            except Exception as error:
                cleanup_errors.append(str(error))
        cleanup_errors.extend(drop.cleanup())
        if script:
            try:
                script.unload()
            except frida.InvalidOperationError:
                pass
        if session:
            try:
                session.detach()
            except frida.InvalidOperationError:
                pass
        if sandbox:
            try:
                sandbox.__exit__(None, None, None)
            except Exception as error:
                cleanup_errors.append(str(error))
        result = {'sample_verified': sample_verified, 'force_sdr_applied': ice_disabled,
                  'injected': fault_at is not None, 'post_fault_e2e_samples': post_fault_e2e,
                  'script_errors': errors, 'cleanup_errors': cleanup_errors,
                  'recovery_asserted': False}
        record({'kind': 'complete', **result})
        private(args.output / 'result.json', json.dumps(result, indent=2))
        log.close()
        print(json.dumps(result), flush=True)
    return int(bool(errors or cleanup_errors))


if __name__ == '__main__':
    raise SystemExit(main())
