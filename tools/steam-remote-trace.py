#!/usr/bin/env python3
"""Collect bounded Frida control-channel evidence from an explicitly selected app."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import threading
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--remote', default='127.0.0.1:27042')
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--pid', type=int)
    target.add_argument('--spawn', help='Android package to launch under observation')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--seconds', type=float, default=30)
    parser.add_argument('--adb-serial', help='required when using automated UI actions')
    parser.add_argument('--tap', nargs=2, type=int, metavar=('X', 'Y'))
    parser.add_argument('--tap-after', type=float, default=3)
    parser.add_argument('--back-after', type=float)
    args = parser.parse_args()
    if not 0 < args.seconds <= 300:
        parser.error('seconds must be in (0, 300]')
    if (args.tap or args.back_after is not None) and not args.adb_serial:
        parser.error('UI actions require an explicit --adb-serial')
    if args.back_after is not None and not 0 < args.back_after < args.seconds:
        parser.error('back-after must be positive and shorter than capture duration')
    if args.tap and not 0 <= args.tap_after < args.seconds:
        parser.error('tap-after must be nonnegative and shorter than capture duration')
    import frida
    args.output.mkdir(parents=True, exist_ok=False)
    path = args.output / 'trace.jsonl'
    log = path.open('x')
    path.chmod(0o600)
    counter = 0
    lock = threading.Lock()
    errors = []

    def record(message, data=None):
        nonlocal counter
        with lock:
            entry = {'time': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                     'message': message}
            if message.get('type') == 'error':
                errors.append(message)
            if data is not None:
                counter += 1
                filename = f'{counter:03d}.bin'
                raw = args.output / filename
                with raw.open('xb') as file:
                    raw.chmod(0o600)
                    file.write(data)
                entry.update(file=filename, size=len(data),
                             sha256=hashlib.sha256(data).hexdigest())
            log.write(json.dumps(entry) + '\n')
            log.flush()
            print(json.dumps(entry), flush=True)

    device = frida.get_device_manager().add_remote_device(args.remote)
    session = None
    script = None
    spawned_pid = None
    resumed = False
    detached = threading.Event()

    def on_detached(reason, crash):
        detached.set()
        record({'type': 'detached', 'reason': reason, 'crash_present': crash is not None})

    try:
        if args.spawn:
            spawned_pid = device.spawn([args.spawn])
        session = device.attach(spawned_pid if spawned_pid is not None else args.pid)
        session.on('detached', on_detached)
        script = session.create_script(Path(__file__).with_suffix('.js').read_text())
        script.on('message', record)
        script.load()
        if spawned_pid is not None:
            device.resume(spawned_pid)
            resumed = True
        started = time.monotonic()
        back_sent = False
        tap_sent = False
        while time.monotonic() - started < args.seconds and not detached.is_set():
            if args.tap and not tap_sent and time.monotonic() - started >= args.tap_after:
                subprocess.run(['adb', '-s', args.adb_serial, 'shell', 'input', 'tap',
                                *map(str, args.tap)], check=True, timeout=10)
                tap_sent = True
                record({'type': 'action', 'action': 'tap', 'coordinates': args.tap})
            if (args.back_after is not None and not back_sent and
                    time.monotonic() - started >= args.back_after):
                subprocess.run(['adb', '-s', args.adb_serial, 'shell', 'input',
                                'keyevent', '4'], check=True, timeout=10)
                back_sent = True
                record({'type': 'action', 'action': 'back'})
            time.sleep(0.1)
    finally:
        try:
            if script is not None and not detached.is_set():
                script.unload()
        except frida.InvalidOperationError:
            record({'type': 'cleanup', 'script_already_destroyed': True})
        try:
            if session is not None and not detached.is_set():
                session.detach()
        finally:
            if spawned_pid is not None and not resumed:
                device.kill(spawned_pid)
        record({'type': 'complete', 'frames': counter, 'script_errors': len(errors)})
        log.close()
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
