import importlib.util
import io
from pathlib import Path
import hmac
import os
import struct
import tempfile
import unittest
from unittest import mock
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

spec = importlib.util.spec_from_file_location('sns_private', Path(__file__).parents[1] / 'switch-sns-network-probe.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

def profile(device=123, setting=1):
    data = bytearray(64); data[:8] = b'NSLUI04\0'
    struct.pack_into('<II', data, 8, 4, len(data)); struct.pack_into('<Q', data, 24, device)
    data[-1] = setting
    checksum = 2166136261
    for byte in data[24:]: checksum = ((checksum ^ byte)*16777619) & 0xffffffff
    struct.pack_into('<I', data, 16, checksum)
    return bytes(data)

class Stream:
    def __init__(self, data): self.input = io.BytesIO(data); self.ack = b''
    def settimeout(self, value): pass
    def recv(self, count): return self.input.read(min(count, 7))  # Exercise fragmented reads.
    def sendall(self, data): self.ack += data

class Readback(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'profile.bin'; self.original = profile()
        self.path.write_bytes(self.original); self.key = os.urandom(32)
        self.receiver = probe.Receiver(self.key, self.path, '127.0.0.1')
        self.addCleanup(self.receiver.server.close)

    def frame(self, updated, error=b''):
        plain = struct.pack('<II', len(updated), len(error))+updated+error
        header = b'NSP1'+struct.pack('<I', len(plain)+16); nonce = os.urandom(12)
        return header+nonce+AESGCM(self.key).encrypt(nonce, plain, header)

    def test_ack_after_valid_persistence_and_private_error(self):
        updated = profile(setting=2); frame = self.frame(updated, b'synthetic error')
        stream = Stream(frame); self.receiver.handle(stream)
        self.assertEqual(self.path.read_bytes(), updated)
        self.assertEqual(stream.ack, hmac.digest(self.key, b'NSP1-ACK'+frame, 'sha256'))
        self.assertEqual((self.path.parent / 'switch-sns-error.private').read_bytes(), b'synthetic error')
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_invalid_tag_never_changes_identity_or_acks(self):
        frame = bytearray(self.frame(profile(setting=2))); frame[-1] ^= 1
        stream = Stream(frame)
        with self.assertRaises(Exception): self.receiver.handle(stream)
        self.assertEqual(self.path.read_bytes(), self.original); self.assertFalse(stream.ack)

    def test_other_device_and_bad_checksum_rejected(self):
        for value in (profile(device=456), self.original[:-1]+b'\x02'):
            stream = Stream(self.frame(value))
            with self.assertRaises(ValueError): self.receiver.handle(stream)
            self.assertEqual(self.path.read_bytes(), self.original); self.assertFalse(stream.ack)

    def test_failed_save_cannot_ack(self):
        stream = Stream(self.frame(profile(setting=2)))
        with mock.patch.object(probe, 'write_private', side_effect=OSError('synthetic disk failure')):
            with self.assertRaises(OSError): self.receiver.handle(stream)
        self.assertEqual(self.path.read_bytes(), self.original); self.assertFalse(stream.ack)

    def test_bounds_and_concurrent_change(self):
        stream = Stream(b'NSP1'+struct.pack('<I', probe.LIMIT+1))
        with self.assertRaises(ValueError): self.receiver.handle(stream)
        changed = profile(setting=3); self.path.write_bytes(changed)
        stream = Stream(self.frame(profile(setting=2)))
        with self.assertRaises(ValueError): self.receiver.handle(stream)
        self.assertEqual(self.path.read_bytes(), changed); self.assertFalse(stream.ack)

if __name__ == '__main__': unittest.main()
