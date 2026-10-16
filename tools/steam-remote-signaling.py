#!/usr/bin/env python3
"""Experimental Remote Play transport-signaling codec, without a media backend.

Evidence: STEAM_REMOTE_PLAY_NETWORKING.md. The key is the decrypted streaming
session key, not the long-lived pairing secret. Inner GNS messages remain opaque.
"""
import argparse
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import struct

spec = importlib.util.spec_from_file_location('probe', Path(__file__).with_name('steam-remote-probe.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
MAGIC = bytes.fromhex('ffffffff214c5fa0')


def sdr_payload(messages):
    """Pack opaque GNS rendezvous messages into CTransportSignalMsg.sdr."""
    payload = b''.join(probe.bytes_field(2, message) for message in messages)
    probe.fields(payload)
    return payload


def wrap(payload, session_key):
    if not session_key:
        raise ValueError('streaming session key is required')
    probe.fields(payload)
    token = hmac.new(session_key, payload, hashlib.sha256).digest()
    body = probe.bytes_field(1, token) + probe.bytes_field(2, payload)
    header = b'\x10\x0c'  # msg_type=12; official sender omits client_id here.
    packet = MAGIC + struct.pack('<I', len(header)) + header + struct.pack('<I', len(body)) + body
    if len(packet) > probe.MAX_FRAME:
        raise ValueError('signal exceeds research frame limit')
    return packet


def unwrap(packet, session_key):
    if not session_key:
        raise ValueError('streaming session key is required')
    kind, _, body = probe.discovery_packet(packet)
    if kind != 12:
        raise ValueError('expected transport signal')
    token = probe.scalar(body, 1, 2)
    payload = probe.scalar(body, 2, 2)
    if token is None or len(token) != 32 or payload is None:
        raise ValueError('missing payload or invalid token size')
    expected = hmac.new(session_key, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(token, expected):
        raise ValueError('transport signal HMAC mismatch')
    # Decode only the authenticated inner payload. The GNS wire version is left
    # to the selected backend, so unknown inner protobuf fields are preserved.
    probe.fields(payload)
    return payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--key-file', type=Path, required=True, help='private decrypted session key')
    parser.add_argument('--packet', type=Path, required=True, help='full discovery type-12 packet')
    args = parser.parse_args()
    payload = unwrap(args.packet.read_bytes(), args.key_file.read_bytes())
    print(json.dumps({'verified': True, 'payload_bytes': len(payload),
                      'sdr_messages': sum(n == 2 and w == 2 for n, w, _ in probe.fields(payload))}))


if __name__ == '__main__':
    main()
