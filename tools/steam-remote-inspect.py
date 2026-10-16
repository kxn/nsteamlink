#!/usr/bin/env python3
"""Summarize a private control trace without printing IDs, PINs, tokens or key bytes."""
import argparse
import importlib.util
import json
from pathlib import Path


spec = importlib.util.spec_from_file_location('probe', Path(__file__).with_name('steam-remote-probe.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
CLIENT = {1: 'create_session_request', 2: 'start_pairing_request', 3: 'set_pairing_info_request',
          4: 'cancel_pairing_request', 5: 'register_status_update',
          6: 'unregister_status_update', 7: 'remote_packet'}
DISCOVERY = {0: 'discovery', 1: 'status', 2: 'offline', 3: 'authorization_request',
             4: 'authorization_response', 5: 'streaming_request', 6: 'streaming_response',
             7: 'proof_request', 8: 'proof_response', 9: 'authorization_cancel',
             10: 'streaming_cancel', 11: 'client_id_deconflict', 12: 'transport_signal',
             13: 'streaming_progress', 14: 'authorization_confirmed', 15: 'pairing_state',
             16: 'pairing_exclusivity'}


def blob_size(message, number):
    value = probe.scalar(message, number, 2)
    return None if value is None else len(value)


def authorization(message):
    return {'device_token_bytes': blob_size(message, 1), 'encrypted_request_bytes': blob_size(message, 3),
            'auth_key_bytes': blob_size(message, 4),
            'request_id_present': probe.scalar(message, 5, 0) is not None}


def rendezvous(raw):
    """Only field presence/lengths; never emit identities, ICE addresses or credentials.

    Field names follow Valve's public CMsgSteamNetworkingP2PRendezvous schema.
    Unknown fields are retained as numbers so version differences stay visible.
    """
    message = probe.fields(raw)
    candidates = []
    auth_fragments = 0
    for number, wire, value in message:
        if number != 13 or wire != 2:
            continue
        reliable = probe.fields(value)
        ice = probe.scalar(reliable, 1, 2)
        if ice is None:
            continue
        ice = probe.fields(ice)
        auth_fragments += probe.scalar(ice, 2, 2) is not None
        candidate = probe.scalar(ice, 1, 2)
        if candidate is not None:
            text = probe.scalar(probe.fields(candidate), 3, 2, b'').decode('ascii', errors='replace')
            words = text.split()
            kind = words[words.index('typ') + 1] if 'typ' in words[:-1] else 'unknown'
            candidates.append(kind if kind in ('host', 'srflx', 'prflx', 'relay') else 'unknown')
    return {'field_numbers': sorted({n for n, _, _ in message}),
            'ice_enabled': probe.scalar(message, 7, 0),
            'sdr_routes_bytes': blob_size(message, 2),
            'connect_request_present': probe.scalar(message, 4, 2) is not None,
            'connect_ok_present': probe.scalar(message, 5, 2) is not None,
            'ice_auth_messages': auth_fragments, 'ice_candidate_types': candidates}


def discovery(raw):
    kind, body_size, message = probe.discovery_packet(raw)
    result = {'kind': DISCOVERY.get(kind, f'unknown_{kind}'), 'body_bytes': body_size}
    if kind == 3:
        result.update(authorization(message))
    elif kind in (4, 14):
        result['authorization_result'] = probe.scalar(message, 1, 0)
        if kind == 4:
            result.update(auth_key_bytes=blob_size(message, 3), device_token_bytes=blob_size(message, 4))
    elif kind == 5:
        result['supported_transport'] = [value for number, wire, value in message
                                         if number == 14 and wire == 0]
        result['network_test'] = probe.scalar(message, 12, 0, 0)
    elif kind == 6:
        result.update(streaming_result=probe.scalar(message, 2, 0),
                      transport=probe.scalar(message, 6, 0, 1),
                      relay_server_bytes=blob_size(message, 7), cert_bytes=blob_size(message, 8))
    elif kind == 12:
        payload = probe.scalar(message, 2, 2, b'')
        signal = probe.fields(payload)
        result.update(token_bytes=blob_size(message, 1),
                      sdr_messages=sum(n == 2 and w == 2 for n, w, _ in signal),
                      webrtc_present=probe.scalar(signal, 1, 2) is not None)
        result['rendezvous'] = [rendezvous(raw) for n, w, raw in signal if n == 2 and w == 2]
    return result


def summarize_cm(raw, direction):
    message = probe.fields(raw)
    names = CLIENT if direction == 'out' else probe.KINDS
    bodies = [(n, w, value) for n, w, value in message if n in names]
    if len(bodies) != 1 or bodies[0][1] != 2:
        raise ValueError('expected one CM message')
    number, _, body = bodies[0]
    kind = names[number]
    fields = probe.fields(body)
    result = {'kind': kind, 'body_bytes': len(body)}
    if direction == 'in':
        result['service_result'] = probe.scalar(message, 1, 0)
    if kind == 'set_pairing_info_request':
        result['authorization'] = authorization(probe.fields(probe.scalar(fields, 3, 2, b'')))
    elif kind == 'register_status_update':
        result.update(steamid_present=probe.scalar(fields, 2, 1) is not None,
                      device_id_present=probe.scalar(fields, 3, 1) is not None,
                      disable_polling=probe.scalar(fields, 4, 0, 0))
    elif kind == 'remote_packet':
        result['packet'] = discovery(probe.scalar(fields, 4, 2, b''))
    elif kind == 'reply_packet':
        result['packets'] = [discovery(value) for n, w, value in fields if n == 1 and w == 2]
    return result


def inspect(directory):
    result = []
    for line in (directory / 'trace.jsonl').read_text().splitlines():
        entry = json.loads(line)
        metadata = entry.get('message', {}).get('payload', {})
        if metadata.get('kind') != 'wire':
            continue
        name = entry['file']
        if Path(name).name != name:
            raise ValueError('invalid frame filename')
        raw = (directory / name).read_bytes()
        record = {'file': name, 'channel': metadata['channel'], 'direction': metadata['direction'],
                  'bytes': len(raw)}
        try:
            if metadata['channel'] == 'cm':
                record.update(summarize_cm(raw, metadata['direction']))
            else:
                record['packet'] = discovery(raw)
        except ValueError as error:
            record['decode_error'] = str(error)
        result.append(record)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.directory), indent=2))


if __name__ == '__main__':
    main()
