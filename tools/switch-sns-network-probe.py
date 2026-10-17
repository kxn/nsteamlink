#!/usr/bin/env python3
"""Build/deploy a private network-only SNS NRO and receive encrypted key updates.

The user only prepares hbmenu netloader. Never publish the private build tree.
The return channel uses a fresh build-specific AES-GCM key, authenticates its
length header, and acknowledges only after validating and atomically persisting
the original device's profile. No key/profile bytes are written to the log.
"""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import threading
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parent.parent
MODES = {'ice': '--sns-test', 'sdr': '--sdr-only-test', 'loss': '--sdr-fault-test',
         'close': '--sdr-close-test', 'no-connection': '--sdr-no-connection-test'}
MEDIA_MODES = {'ice': '--sns-desktop', 'sdr': '--sdr-only-desktop', 'loss': '--sdr-fault-desktop',
               'loss-warm': '--sdr-warm-fault-desktop', 'pause': '--sdr-pause-desktop'}
LIMIT = 8+65536+8192+16

def profile_valid(data, original=None):
    if len(data) < 32 or data[:8] != b'NSLUI04\0':
        raise ValueError('unsupported private profile')
    version, size, checksum = struct.unpack_from('<III', data, 8)
    value = 2166136261
    for byte in data[24:]:
        value = ((value ^ byte)*16777619) & 0xffffffff
    if version != 4 or size != len(data) or checksum != value:
        raise ValueError('profile layout/checksum mismatch')
    if original is not None and (len(data) != len(original) or data[24:32] != original[24:32]):
        raise ValueError('profile belongs to another device/layout')

def write_private(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb', closefd=False) as out:
            out.write(data); out.flush(); os.fsync(out.fileno())
    finally:
        os.close(fd)

def receive_exact(stream, count):
    result = bytearray()
    while len(result) < count:
        part = stream.recv(count-len(result))
        if not part:
            raise EOFError('incomplete encrypted readback')
        result.extend(part)
    return bytes(result)

def verify_embedded(nro, profile, key):
    """Check the packaged root files, without displaying private contents.

    Layouts: libnx switch/nro.h and runtime/devices/romfs_dev.h.
    This fixture intentionally contains exactly two root files.
    """
    data = nro.read_bytes()
    if len(data) < 0x80 or data[0x10:0x14] != b'NRO0':
        raise ValueError('invalid private NRO header')
    asset = struct.unpack_from('<I', data, 0x18)[0]
    if asset+56 > len(data) or data[asset:asset+8] != b'ASET\0\0\0\0':
        raise ValueError('invalid private NRO assets')
    offset, size = struct.unpack_from('<QQ', data, asset+40)
    if size < 80 or asset+offset+size > len(data):
        raise ValueError('invalid private NRO RomFS bounds')
    romfs = memoryview(data)[asset+offset:asset+offset+size]
    header = struct.unpack_from('<10Q', romfs)
    table_offset, table_size, contents = header[7:10]
    if header[0] != 80 or table_offset+table_size > size or contents > size:
        raise ValueError('invalid private RomFS layout')
    files, cursor = {}, 0
    while cursor < table_size:
        if cursor+32 > table_size:
            raise ValueError('invalid private RomFS file entry')
        parent, sibling, start, length, next_hash, name_size = struct.unpack_from('<IIQQII', romfs, table_offset+cursor)
        if parent or cursor+32+name_size > table_size or contents+start+length > size:
            raise ValueError('invalid private RomFS file bounds')
        name = bytes(romfs[table_offset+cursor+32:table_offset+cursor+32+name_size])
        if name in files:
            raise ValueError('duplicate private RomFS file')
        files[name] = bytes(romfs[contents+start:contents+start+length])
        cursor += (32+name_size+3) & ~3
    if files != {b'profile.bin': profile, b'return.key': key}:
        raise ValueError('packaged private inputs do not match prepared fixture')

class Receiver:
    def __init__(self, key, profile, peer):
        self.key, self.profile, self.peer = key, profile, peer
        self.original = profile.read_bytes()
        profile_valid(self.original)
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(('0.0.0.0', 0)); self.server.listen(2); self.server.settimeout(0.25)
        self.port = self.server.getsockname()[1]
        self.stop = threading.Event(); self.received = False; self.error = None
        self.thread = threading.Thread(target=self.run, name='sns-private-readback')

    def handle(self, stream):
        stream.settimeout(5)
        header = receive_exact(stream, 8)
        magic, size = struct.unpack('<4sI', header)
        if magic != b'NSP1' or not 24 <= size <= LIMIT:
            raise ValueError('invalid encrypted readback size')
        nonce, cipher = receive_exact(stream, 12), receive_exact(stream, size)
        plain = AESGCM(self.key).decrypt(nonce, cipher, header)
        profile_size, error_size = struct.unpack_from('<II', plain)
        if not 0 < profile_size <= 65536 or error_size > 8192 or len(plain) != 8+profile_size+error_size:
            raise ValueError('invalid readback payload bounds')
        updated = plain[8:8+profile_size]
        profile_valid(updated, self.original)
        if self.profile.read_bytes() != self.original:
            raise ValueError('local profile changed during device test')
        if updated != self.original:
            backup = self.profile.with_name('profile.before-switch.private')
            write_private(backup, self.original)
        temporary = self.profile.with_name('profile.switch-return.tmp')
        write_private(temporary, updated)
        os.replace(temporary, self.profile)
        directory = os.open(self.profile.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
        error_file = self.profile.with_name('switch-sns-error.private')
        if error_size:
            write_private(error_file, plain[8+profile_size:])
        else:
            error_file.unlink(missing_ok=True)
        # Authenticated ACK follows durable storage. The NRO preserves its
        # private SD profile unless this exact transcript is acknowledged.
        ack = hmac.digest(self.key, b'NSP1-ACK'+header+nonce+cipher, 'sha256')
        stream.sendall(ack)
        self.received = True

    def run(self):
        deadline = time.monotonic()+120
        while not self.stop.is_set() and time.monotonic() < deadline and not self.received:
            try:
                stream, address = self.server.accept()
            except socket.timeout:
                continue
            with stream:
                if address[0] != self.peer:
                    continue
                try: self.handle(stream)
                except Exception as error:
                    self.error = type(error).__name__

    def close(self):
        self.stop.set(); self.thread.join(); self.server.close()

def prepare(build, profile, media=False):
    original = profile.read_bytes(); profile_valid(original)
    romfs = build / 'private-romfs'; romfs.mkdir(parents=True, exist_ok=True); os.chmod(romfs, 0o700)
    write_private(romfs / 'profile.bin', original)
    write_private(romfs / 'return.key', os.urandom(32))
    log = build / 'private-build.log'
    target = 'nsl-sns-media-private' if media else 'nsl-sns-network-private'
    with log.open('w') as output:
        subprocess.run(['cmake', '-S', str(ROOT), '-B', str(build),
            '-DCMAKE_TOOLCHAIN_FILE=/opt/devkitpro/cmake/Switch.cmake', '-DCMAKE_BUILD_TYPE=Release',
            '-DNSL_DIAGNOSTICS=ON', '-DNSL_BUILD_TOOLS=ON', '-DNSL_BUILD_SNS=ON', '-DNSL_ENABLE_SDR=ON',
            '-DNSL_PRIVATE_SNS_MEDIA='+('ON' if media else 'OFF'),
            '-DNSL_PRIVATE_SNS_ROMFS='+str(romfs)], stdout=output, stderr=subprocess.STDOUT, check=True)
        subprocess.run(['cmake', '--build', str(build), '--target', target+'_nro', '-j8'],
                       stdout=output, stderr=subprocess.STDOUT, check=True)
    nro = build / ('app/'+target+'.nro')
    for source in (romfs / 'profile.bin', romfs / 'return.key', nro.with_suffix('.elf')):
        if source.stat().st_mtime_ns > nro.stat().st_mtime_ns:
            raise ValueError('private NRO is stale')
    return nro

def main(media=False):
    description = 'Request a Steam desktop stream on Switch; loss mode requires fresh encoded frames after relay failure.' if media else __doc__
    parser = argparse.ArgumentParser(description=description)
    modes = MEDIA_MODES if media else MODES
    kind = 'media' if media else 'network'
    target = 'nsl-sns-'+kind+'-private'
    parser.add_argument('--address', required=True, help='explicit Switch IPv4 address')
    parser.add_argument('--profile', required=True, type=Path, help='our isolated paired test profile directory')
    parser.add_argument('--build', type=Path, default=ROOT / ('build/switch-sns-media-private' if media else 'build/switch-sns-private'))
    parser.add_argument('--mode', choices=modes, default='sdr')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--prepare-only', action='store_true')
    group.add_argument('--run-only', action='store_true')
    args = parser.parse_args()
    socket.inet_aton(args.address)
    build, profile = args.build.resolve(), args.profile.resolve() / 'profile.bin'
    if ROOT / 'build' not in build.parents:
        parser.error('private fixture builds must stay inside the ignored project build directory')
    build.mkdir(parents=True, exist_ok=True); os.chmod(build, 0o700)
    nro = build / ('app/'+target+'.nro') if args.run_only else prepare(build, profile, media)
    key_file, embedded = build / 'private-romfs/return.key', build / 'private-romfs/profile.bin'
    key = key_file.read_bytes()
    if len(key) != 32: raise ValueError('invalid private readback key')
    profile_valid(embedded.read_bytes(), profile.read_bytes())
    verify_embedded(nro, embedded.read_bytes(), key)
    digest = hashlib.sha256(nro.read_bytes()).hexdigest()
    if any(source.stat().st_mtime_ns > nro.stat().st_mtime_ns
           for source in (key_file, embedded, nro.with_suffix('.elf'))):
        raise ValueError('private NRO is stale; prepare it again')
    if args.prepare_only:
        print(json.dumps({'prepared': True, 'private_nro': str(nro), 'sha256': digest}))
        return
    receiver = Receiver(key, profile, args.address)
    receiver.thread.start()
    log = build / (kind+'-probe.private.log')
    exit_code, timed_out = None, False
    try:
        with log.open('w') as output:
            try:
                result = subprocess.run(['/opt/devkitpro/tools/bin/nxlink', '-a', args.address, '-s',
                    '-p', target+'.nro', '--args',
                    modes[args.mode]+' '+str(receiver.port), str(nro)], stdout=output, stderr=subprocess.STDOUT,
                    timeout=120)
                exit_code = result.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
    finally:
        receiver.close()
    text = log.read_text()
    passed = 'SWITCH_SNS_'+kind.upper()+'_RESULT=0' in text
    report = {'fixture': kind, 'mode': args.mode, 'nro_sha256': digest, 'nxlink_exit': exit_code, 'timed_out': timed_out,
        'profile_readback': receiver.received, 'readback_error': receiver.error,
        kind+'_result': passed,
        'private_upload_removed': 'PRIVATE_NRO_REMOVED=1' in text,
        'loader_return_verified': False,
        'events': [line for line in text.splitlines() if line.startswith(('CLOUD_', 'SNS_', 'SDR_',
            'SWITCH_SNS_', 'PROFILE_READBACK_', 'PREVIOUS_EXIT_', 'PRIVATE_NRO_', 'PRIVATE_FIXTURE_',
            'PRIVATE_EMBEDDED_', 'IHS_CONNECTED=', 'IHS_DISCONNECTED=', 'IHS_PAUSE_', 'IHS_RESUME_', 'PREVIOUS_MEDIA_EXIT_'))
            and 'SNS_ERROR_FILE' not in line]}
    (build / (kind+'-result.json')).write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))
    if timed_out or not passed or not receiver.received or not report['private_upload_removed']:
        raise SystemExit(1)

if __name__ == '__main__':
    main()
