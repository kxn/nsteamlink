#!/usr/bin/env python3
"""Exercise signal authentication boundaries and interoperability-shaped framing."""
import hashlib
import hmac
import importlib.util
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location(
    'signaling', Path(__file__).resolve().parents[1] / 'tools/steam-remote-signaling.py')
signal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signal)


class SignalTests(unittest.TestCase):
    key = bytes(range(16))  # Synthetic key; no captured credentials in fixtures.

    def test_independent_known_shape_and_multiple_rendezvous_messages(self):
        payload = bytes.fromhex('1202380112025801')
        digest = hmac.new(self.key, payload, hashlib.sha256).digest()
        body = b'\x0a\x20' + digest + b'\x12\x08' + payload
        packet = signal.MAGIC + b'\x02\x00\x00\x00\x10\x0c' + struct.pack('<I', len(body)) + body
        self.assertEqual(signal.sdr_payload([b'\x38\x01', b'\x58\x01']), payload)
        self.assertEqual(signal.wrap(payload, self.key), packet)
        self.assertEqual(signal.unwrap(packet, self.key), payload)

    def test_reject_tampering_wrong_key_and_truncated_frame(self):
        packet = signal.wrap(signal.sdr_payload([b'\x38\x01']), self.key)
        for raw, key in [(packet, b'x' * 16), (packet[:-1], self.key),
                         (packet[:-1] + bytes([packet[-1] ^ 1]), self.key),
                         (packet + b'x', self.key)]:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                signal.unwrap(raw, key)

    def test_unauthenticated_inner_data_is_not_parsed(self):
        # Outer protobuf is valid; inner bytes are malformed and token is wrong.
        body = b'\x0a\x20' + b'x' * 32 + b'\x12\x01\x00'
        packet = signal.MAGIC + b'\x02\x00\x00\x00\x10\x0c' + struct.pack('<I', len(body)) + body
        with self.assertRaisesRegex(ValueError, 'HMAC mismatch'):
            signal.unwrap(packet, self.key)

    def test_reject_empty_keys_and_oversized_signals(self):
        with self.assertRaises(ValueError):
            signal.wrap(b'', b'')
        with self.assertRaises(ValueError):
            signal.unwrap(b'', b'')
        with self.assertRaises(ValueError):
            signal.wrap(signal.probe.bytes_field(2, b'x' * signal.probe.MAX_FRAME), self.key)


if __name__ == '__main__':
    unittest.main()
