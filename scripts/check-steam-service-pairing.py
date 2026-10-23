#!/usr/bin/env python3
"""Compare original state3 publication/crypto/Stop with the real IHS owner.

Full incoming frames use actual UDP/RX/deferred parsing. Time, identity, entropy,
selected credentials, metadata lookup and persistence endpoints are providers.
Outgoing calls are observed before final routing, matching the original audit's
SendMessage provider. RSA plaintext tickets, authorization publication fields,
current secret/cache, metadata operations, notifications and call ordering are
compared; original RSA ciphertext and final CM/UDP senders are not equated.
Production account list/file mutations are checked by the account receiver.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

if not __debug__:
    raise SystemExit('Original comparison requires assertions; do not use Python -O')
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('accounts', ROOT / 'scripts/check-steam-account-metadata.py')
accounts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(accounts)


def fields(hex_body):
    raw, pos, out = bytes.fromhex(hex_body), 0, {}

    def varint():
        nonlocal pos
        value = shift = 0
        while True:
            byte = raw[pos]
            pos += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value
            shift += 7
            assert shift < 70

    while pos < len(raw):
        tag = varint()
        kind = tag & 7
        if kind == 0:
            value = varint()
        elif kind in (1, 5):
            size = 8 if kind == 1 else 4
            value = int.from_bytes(raw[pos:pos + size], 'little')
            pos += size
        else:
            assert kind == 2
            size = varint()
            value = raw[pos:pos + size]
            pos += size
        out[tag >> 3] = value
    assert pos == len(raw)
    return out


def decrypt(token, secret):
    assert len(token) >= 32 and len(token) % 16 == 0
    key = bytes.fromhex(secret)
    decrypt = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    iv = decrypt.update(token[:16]) + decrypt.finalize()
    decrypt = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    plain = decrypt.update(token[16:]) + decrypt.finalize()
    count = plain[-1]
    assert 1 <= count <= 16 and plain[-count:] == bytes([count]) * count
    return plain[:-count]


def device_token(token, secret):
    assert decrypt(token, secret) == struct.pack('<Q', 0x1122334455667788)


def check(receiver, account_receiver, case):
    commands = [f'h 1000 {int(case["hint"])}']
    indices = [1]
    for event in case['inputs']:
        if event['command'] == 'prepare':
            suffix = '' if event['rid'] is None else ' ' + str(event['rid'])
            commands.append('a 1000 ' + event['pin'] + suffix)
        elif event['command'] == 'known':
            commands.append('k 1000')
            # The native oracle's first known request is 17; the original
            # trace enters StartStreaming/Unauthorized/Panel in this step.
            commands.append('p 1000 6 123 08111001')
        elif event['command'] == 'cancel':
            commands.append('z 1000')
        else:
            assert event['command'] == 'packet'
            commands.append('r 1000 ' + event['wire'])
        indices.append(len(commands))
    run = subprocess.run([str(receiver.resolve()), '0', '0', 'service'],
                         input='\n'.join(commands) + '\n', text=True,
                         capture_output=True, timeout=20)
    assert run.returncode == 0, (case['name'], case['hint'], run.returncode, run.stderr[-3000:])
    rows = [json.loads(line) for line in run.stdout.splitlines()]
    assert len(rows) == len(commands) + 1
    for index, (at, expected) in enumerate(zip(indices, case['steps'])):
        actual = rows[at]
        label = (case['name'], case['hint'], index)
        for key in ('state', 'rid', 'secret', 'cache', 'cached_result', 'derived', 'failures',
                    'send_states', 'persist_states', 'keypairs', 'saved_keys'):
            assert actual[key] == expected[key], (label, key, actual[key], expected[key])
        for key, source in (('metadata_ops', 'events'), ('service_draws', 'secret_draws'),
                            ('service_notifications', 'notifications'), ('ticket_wires', 'tickets')):
            assert actual[key] == expected[source], (label, key, actual[key], expected[source])
        assert len(actual['messages']) == len(expected['messages']), (label, actual, expected)
        count, save_order = 0, []
        for event in expected['events']:
            count += event['op'] == 'key'
            if event['op'] == 'send':
                save_order.append(count)
        pin_keys = {}
        for n, (a, e) in enumerate(zip(actual['messages'], expected['messages'])):
            assert a['tag'] == e['tag'] and a['saves'] == save_order[n], (label, a, e)
            if a['tag'] in (3, 5):
                ap, ep = fields(a['body']), fields(e['body'])
                selected = (2, 4, 5) if a['tag'] == 3 else (1, 12)
                assert all(ap.get(k) == ep.get(k) for k in selected), (label, ap, ep)
                secret = expected['send_states'][n]['secret']
                device_token(ap[1 if a['tag'] == 3 else 7], secret)
                device_token(ep[1 if a['tag'] == 3 else 7], secret)
                if a['tag'] == 5:
                    # Connect PIN is frozen at Start; authorization may have
                    # replaced current secret before a later same-ID send.
                    pin_secret = pin_keys.setdefault(ap[1], secret)
                    assert decrypt(ap[8], pin_secret) == decrypt(ep[8], pin_secret), label
            else:
                assert a['body'] == e['body'], (label, a, e)
        assert len(actual['publications']) == len(expected['publications'])
        # Source's caller-only final-send provider skips outer token/IV work.
        # Thus repeated mixed-path tokens need semantic AES checks, not an
        # assertion that Native consumed the same unmodelled outer IVs.
        tickets = [fields(t) for t in expected['tickets']]
        service_tickets = [t for t in tickets if t[1] != b'0042']
        assert len(service_tickets) == len(expected['publications'])
        for a, e, ticket in zip(actual['publications'], expected['publications'], service_tickets):
            ap, ep = fields(a), fields(e)
            assert set(ap) == set(ep) == {1, 2, 3, 4, 5}
            assert all(ap[k] == ep[k] for k in (2, 4, 5)), (label, ap, ep)
            assert len(ap[3]) == 256  # Actual pinned public RSA key, not Source's marker.
            device_token(ap[1], ticket[3].hex())
            device_token(ep[1], ticket[3].hex())
        # Compare the same metadata callbacks with the production list/file
        # implementation, including absent/zero accounts and paired-ID order.
        files = {}
        for client, ids in expected['accounts'].items():
            ops = [(2, e['steam']) for e in expected['events']
                   if e['op'] == 'identity' and str(e['client']) == client]
            changes = accounts.lists(account_receiver, accounts.INITIAL, ops)
            assert (changes[-1]['ids'] if changes else accounts.INITIAL) == ids, (label, client)
            if changes and changes[-1]['file'] is not None:
                namespace = int(client).to_bytes(8, 'little').hex()
                files[f'/fixture/{namespace}/steamid.txt'] = changes[-1]['file']
        paired = accounts.lists(account_receiver, [], [(1, e['steam']) for e in expected['events'] if e['op'] == 'key'])
        assert (paired[-1]['ids'] if paired else []) == expected['paired'], label
        if paired and paired[-1]['file'] is not None:
            files['/fixture/paired_steamid.txt'] = paired[-1]['file']
        assert files == expected['files'], (label, files, expected['files'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receiver', type=Path, required=True)
    parser.add_argument('--accounts', type=Path, required=True)
    parser.add_argument('--reference', type=Path, default=ROOT / 'scripts/fixtures/steam-service-pairing-reference.json.gz')
    args = parser.parse_args()
    reference = json.loads(gzip.decompress(args.reference.read_bytes()))
    assert reference['schema'] == 1
    assert reference['binary_sha256'] == '15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2'
    for name, sha in reference['helpers'].items():
        assert hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest() == sha, name
    assert len(reference['cases']) == 48
    for case in reference['cases']:
        check(args.receiver, args.accounts, case)
    print('PASS 48 original service publication/shared-cache/full-frame authorization/Stop traces; metadata file bytes and notification order')


if __name__ == '__main__':
    main()
