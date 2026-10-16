#!/usr/bin/env python3
"""Research Steam's Remote Client WebSocket without a Steam login or media session.

Wire evidence: docs/STEAM_REMOTE_PLAY_NETWORKING.md. Requires aiohttp for live runs.
Raw frames stay in the selected evidence directory; console output omits PIN/session IDs.
"""
import argparse
import asyncio
import datetime
import hashlib
import json
from pathlib import Path
import struct


MAX_FRAME = 65536
DIRECTORY = ('https://api.steampowered.com/ISteamDirectory/'
             'GetCMListForConnect/v1/?cellid=0&cmtype=websockets')
KINDS = {2: 'create_session_response', 3: 'start_pairing_response',
         4: 'set_pairing_info_response', 5: 'cancel_pairing_response',
         6: 'reply_packet', 7: 'offline'}


def varint(value):
    if not 0 <= value < 1 << 64:
        raise ValueError('varint outside uint64')
    out = bytearray()
    while value > 127:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def read_varint(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise ValueError('truncated varint')
        byte = data[offset]
        offset += 1
        if shift == 63 and byte > 1:
            raise ValueError('varint overflow')
        value |= (byte & 127) << shift
        if not byte & 128:
            return value, offset
    raise ValueError('varint overflow')


def fields(data):
    """Bounded proto2 scalar decoder; groups are deliberately unsupported."""
    if len(data) > MAX_FRAME:
        raise ValueError('frame exceeds research limit')
    offset = 0
    out = []
    while offset < len(data):
        tag, offset = read_varint(data, offset)
        number, wire = tag >> 3, tag & 7
        if not 1 <= number < 1 << 29:
            raise ValueError('invalid field number')
        if wire == 0:
            value, offset = read_varint(data, offset)
        elif wire in (1, 2, 5):
            if wire == 2:
                size, offset = read_varint(data, offset)
            else:
                size = 8 if wire == 1 else 4
            if size > len(data) - offset:
                raise ValueError('truncated field')
            value = data[offset:offset + size]
            offset += size
            if wire != 2:
                value = int.from_bytes(value, 'little')
        else:
            raise ValueError('unsupported wire type')
        out.append((number, wire, value))
    return out


def scalar(message, number, wire, default=None):
    matches = [(w, v) for n, w, v in message if n == number]
    if len(matches) > 1:
        raise ValueError('duplicate research scalar')
    if not matches:
        return default
    actual, value = matches[0]
    if actual != wire:
        raise ValueError('incorrect scalar wire type')
    return value


def bytes_field(number, payload):
    return varint(number << 3 | 2) + varint(len(payload)) + payload


def request(kind, session_id=None):
    # CCMRemoteClient_ClientMessage: 1=create, 2=start pairing, 4=cancel pairing.
    if kind not in (1, 2, 4):
        raise ValueError('unsupported probe request')
    if kind != 1 and (session_id is None or not 0 < session_id < 1 << 64):
        raise ValueError('session required')
    body = b'' if kind == 1 else b'\x09' + struct.pack('<Q', session_id)
    return bytes_field(kind, body)


def response(data):
    message = fields(data)
    result = scalar(message, 1, 0)
    bodies = [(n, w, v) for n, w, v in message if n in KINDS]
    if len(bodies) != 1 or bodies[0][1] != 2:
        raise ValueError('expected one response body')
    number, _, body = bodies[0]
    return {'result': result, 'kind': KINDS[number], 'fields': fields(body)}


def registration_request(session_id, captured):
    """Reuse only the paired identity from one's own captured registration."""
    envelope = fields(captured)
    if len(envelope) != 1 or envelope[0][:2] != (5, 2):
        raise ValueError('expected captured register_status_update')
    source = fields(envelope[0][2])
    steam_id = scalar(source, 2, 1)
    device_id = scalar(source, 3, 1)
    if not steam_id or not device_id:
        raise ValueError('captured registration lacks paired identity')
    body = (b'\x09' + struct.pack('<Q', session_id) + b'\x11' + struct.pack('<Q', steam_id) +
            b'\x19' + struct.pack('<Q', device_id) + b'\x20\x01')
    return bytes_field(5, body)


def discovery_packet(raw):
    """Validate both length prefixes before interpreting a cloud-carried packet."""
    if len(raw) > MAX_FRAME or len(raw) < 16 or raw[:8] != bytes.fromhex('ffffffff214c5fa0'):
        raise ValueError('invalid discovery framing')
    header_size = struct.unpack_from('<I', raw, 8)[0]
    if header_size > len(raw) - 16:
        raise ValueError('truncated discovery header')
    header = fields(raw[12:12 + header_size])
    offset = 12 + header_size
    body_size = struct.unpack_from('<I', raw, offset)[0]
    if body_size != len(raw) - offset - 4:
        raise ValueError('discovery body size mismatch')
    body = fields(raw[offset + 4:])
    return scalar(header, 2, 0, 0), body_size, body


class Evidence:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=False)
        self.events = []
        self.frames = 0

    def private(self, name, data):
        path = self.directory / name
        with path.open('xb') as file:
            path.chmod(0o600)
            file.write(data)

    def event(self, stage, **values):
        entry = {'time': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                 'stage': stage, **values}
        self.events.append(entry)
        print(json.dumps(entry, ensure_ascii=False), flush=True)

    def frame(self, direction, data):
        self.frames += 1
        name = f'{self.frames:03d}-{direction}.bin'
        self.private(name, data)
        self.event('frame', direction=direction, file=name, size=len(data),
                   sha256=hashlib.sha256(data).hexdigest())

    def finish(self, result):
        self.private('result.json', (json.dumps({'result': result, 'events': self.events},
                                             indent=2) + '\n').encode())


async def exchange(ws, evidence, payload, expected, timeout):
    import aiohttp
    evidence.frame('sent', payload)
    await ws.send_bytes(payload)
    async with asyncio.timeout(timeout):
        for _ in range(32):
            packet = await ws.receive()
            if packet.type != aiohttp.WSMsgType.BINARY:
                raise RuntimeError(f'expected binary WebSocket message, got {packet.type.name}')
            evidence.frame('received', packet.data)
            decoded = response(packet.data)
            evidence.event('response', kind=decoded['kind'], result=decoded['result'])
            if decoded['result'] != 1:
                raise RuntimeError(f"service result {decoded['result']}")
            if decoded['kind'] == expected:
                return decoded['fields']
            # Hosts can send replies/offline notifications between RPC responses.
            if decoded['kind'] not in ('reply_packet', 'offline'):
                raise RuntimeError('unexpected RPC response')
        raise RuntimeError('response budget exceeded')


async def probe_connection(ws, evidence, start_pairing, timeout, captured_registration=None):
    created = await exchange(ws, evidence, request(1), 'create_session_response', timeout)
    session_id = scalar(created, 1, 1)
    if session_id is None or not 0 < session_id < 1 << 64:
        raise RuntimeError('missing or invalid session ID')
    evidence.event('session_created', universe=scalar(created, 2, 0))
    if captured_registration is not None:
        reply = await exchange(ws, evidence, registration_request(session_id, captured_registration),
                               'reply_packet', timeout)
        status_packets = 0
        for number, wire, raw in reply:
            if number != 1 or wire != 2:
                continue
            kind, _, _ = discovery_packet(raw)
            if kind == 1:
                status_packets += 1
        if not status_packets:
            raise RuntimeError('cloud reply did not contain host status')
        evidence.event('cloud_status_received', packets=status_packets)
        return
    if not start_pairing:
        return
    # A failed/malformed StartPairing response may still mean the server allocated
    # a pairing slot. Always attempt cancellation after sending that request.
    try:
        paired = await exchange(ws, evidence, request(2, session_id),
                                'start_pairing_response', timeout)
        pin = scalar(paired, 1, 0)
        if pin is None or not 0 <= pin <= 9999:
            raise RuntimeError('invalid pairing PIN')
        evidence.event('pairing_started', pin_present=True)
    finally:
        await exchange(ws, evidence, request(4, session_id), 'cancel_pairing_response', timeout)
        evidence.event('pairing_cancelled')


async def run_probe(args, evidence):
    import aiohttp
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=args.timeout),
                                     trust_env=True) as session:
        async with session.get(DIRECTORY) as reply:
            reply.raise_for_status()
            raw = await reply.content.read(MAX_FRAME + 1)
            if len(raw) > MAX_FRAME:
                raise RuntimeError('CM directory response too large')
            listing = json.loads(raw)
        evidence.private('directory.json', raw)
        candidates = [entry['endpoint'] for entry in listing['response']['serverlist']
                      if entry.get('type') == 'websockets' and
                      entry['endpoint'].endswith(':443')][:3]
        if not candidates:
            raise RuntimeError('no TLS CM endpoints')
        for endpoint in candidates:
            evidence.event('connecting', endpoint=endpoint)
            try:
                ws = await session.ws_connect('wss://' + endpoint + '/remoteplay/',
                                              max_msg_size=MAX_FRAME)
            except (aiohttp.ClientError, TimeoutError) as error:
                evidence.event('connection_failed', error_type=type(error).__name__)
                continue
            async with ws:
                captured = args.status_from.read_bytes() if args.status_from else None
                await probe_connection(ws, evidence, args.start_pairing, args.timeout, captured)
            evidence.event('websocket_closed', close_code=ws.close_code)
            return
        raise RuntimeError('CM connection attempts exhausted')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True,
                        help='new private evidence directory (must not already exist)')
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--start-pairing', action='store_true',
                        help='allocate a temporary cloud PIN, then immediately cancel it')
    action.add_argument('--status-from', type=Path,
                        help="reuse one's own captured registration identity to request host status")
    parser.add_argument('--timeout', type=float, default=10)
    args = parser.parse_args()
    if not 0 < args.timeout <= 60:
        parser.error('timeout must be in (0, 60] seconds')
    evidence = Evidence(args.output)
    result = 'FAIL'
    try:
        asyncio.run(run_probe(args, evidence))
        result = 'PASS'
    except (Exception, KeyboardInterrupt) as error:
        evidence.event('error', error_type=type(error).__name__, message=str(error))
    finally:
        evidence.event('complete', result=result, media_transport='unverified')
        evidence.finish(result)
    return 0 if result == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
