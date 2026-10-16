#!/usr/bin/env python3
"""Exercise real WebSocket sequencing and reject malformed external wire data."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest


spec = importlib.util.spec_from_file_location(
    'steam_remote_probe', Path(__file__).resolve().parents[1] / 'tools/steam-remote-probe.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
spec = importlib.util.spec_from_file_location(
    'steam_remote_inspect', Path(__file__).resolve().parents[1] / 'tools/steam-remote-inspect.py')
inspector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inspector)


def registration(session_id=9876):
    return probe.bytes_field(5, b'\x09' + struct.pack('<Q', session_id) +
                             b'\x11' + struct.pack('<Q', 4321) + b'\x19' + struct.pack('<Q', 6789))


def discovery(kind=1, body=b'\x08\x01'):
    header = b'\x10' + probe.varint(kind)
    return (bytes.fromhex('ffffffff214c5fa0') + struct.pack('<I', len(header)) + header +
            struct.pack('<I', len(body)) + body)


class WireTests(unittest.TestCase):
    def test_official_shape_with_synthetic_identifiers(self):
        raw = b'\x08\x01\x12\x0b\x09' + struct.pack('<Q', 12345) + b'\x10\x01'
        reply = probe.response(raw)
        self.assertEqual(reply['kind'], 'create_session_response')
        self.assertEqual(probe.scalar(reply['fields'], 1, 1), 12345)
        self.assertEqual(probe.request(2, 12345), b'\x12\x09\x09' + struct.pack('<Q', 12345))
        self.assertEqual(probe.request(4, 12345), b'\x22\x09\x09' + struct.pack('<Q', 12345))

    def test_malformed_wire_rejected(self):
        invalid = [b'\x00', b'\x0a\x80', b'\x0a\x02x', b'\x09xx', b'\x0dxx',
                   b'\x08' + b'\xff' * 9 + b'\x02', b'\x0b', b'x' * (probe.MAX_FRAME + 1)]
        for raw in invalid:
            with self.subTest(raw=raw[:12]), self.assertRaises(ValueError):
                probe.fields(raw)

    def test_ambiguous_rpc_and_wrong_types_rejected(self):
        for raw in [b'\x08\x01\x12\x00\x1a\x00', b'\x08\x01\x10\x00',
                    b'\x08\x01\x08\x01\x12\x00']:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                probe.response(raw)

    def test_uint64_limit(self):
        self.assertEqual(probe.read_varint(probe.varint((1 << 64) - 1), 0)[0], (1 << 64) - 1)
        with self.assertRaises(ValueError):
            probe.varint(1 << 64)

    def test_registration_uses_new_session_and_retains_identity(self):
        envelope = probe.fields(probe.registration_request(12345, registration()))
        body = probe.fields(envelope[0][2])
        self.assertEqual([probe.scalar(body, n, 1) for n in (1, 2, 3)], [12345, 4321, 6789])
        self.assertEqual(probe.scalar(body, 4, 0), 1)
        for captured in [probe.request(1), probe.bytes_field(5, b''),
                         registration() + registration()]:
            with self.subTest(captured=captured), self.assertRaises(ValueError):
                probe.registration_request(12345, captured)

    def test_discovery_requires_exact_body_length(self):
        self.assertEqual(probe.discovery_packet(discovery())[0], 1)
        for raw in [discovery()[:-1], discovery() + b'x', discovery()[:10],
                    bytes.fromhex('ffffffff214c5fa0ffffffff00000000')]:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                probe.discovery_packet(raw)

    def test_rendezvous_summary_redacts_peer_and_ice_credentials(self):
        ice = (probe.bytes_field(2, probe.bytes_field(1, b'private-password')) +
               probe.bytes_field(1, probe.bytes_field(3, b'candidate:1 1 UDP 123 192.0.2.99 1234 typ srflx')))
        raw = (probe.bytes_field(8, b'private-identity') + b'\x38\x01' +
               probe.bytes_field(13, probe.bytes_field(1, ice)))
        summary = inspector.rendezvous(raw)
        self.assertEqual(summary['ice_candidate_types'], ['srflx'])
        self.assertEqual(summary['ice_auth_messages'], 1)
        for secret in ('private-password', 'private-identity', '192.0.2.99'):
            self.assertNotIn(secret, str(summary))


class Recorder:
    def __init__(self):
        self.frames = []
        self.events = []

    def frame(self, direction, raw):
        self.frames.append((direction, raw))

    def event(self, stage, **values):
        self.events.append((stage, values))


class WebSocketTests(unittest.IsolatedAsyncioTestCase):
    async def run_server(self, mode):
        from aiohttp import ClientSession, web
        received = []

        async def handler(request):
            ws = web.WebSocketResponse()
            await ws.prepare(request)
            async for msg in ws:
                received.append(msg.data)
                field = probe.fields(msg.data)[0][0]
                if field == 1:
                    if mode == 'create_failure':
                        await ws.send_bytes(b'\x08\x02\x12\x00')
                    elif mode == 'missing_session':
                        await ws.send_bytes(b'\x08\x01\x12\x00')
                    else:
                        body = b'\x09' + struct.pack('<Q', 12345) + b'\x10\x01'
                        await ws.send_bytes(b'\x08\x01' + probe.bytes_field(2, body))
                elif field == 2:
                    if mode == 'wrong_rpc':
                        await ws.send_bytes(b'\x08\x01\x22\x00')
                    else:
                        if mode == 'notification':
                            await ws.send_bytes(b'\x08\x01\x32\x00')
                        body = b'\x08' + probe.varint(10000 if mode == 'bad_pin' else 1234)
                        await ws.send_bytes(b'\x08\x01' + probe.bytes_field(3, body))
                elif field == 4:
                    await ws.send_bytes(b'\x08\x01\x2a\x00')
                elif field == 5:
                    packet = discovery()
                    if mode == 'status_truncated':
                        packet = packet[:-1]
                    await ws.send_bytes(b'\x08\x01' + probe.bytes_field(6, probe.bytes_field(1, packet)))
            return ws

        app = web.Application()
        app.router.add_get('/remoteplay/', handler)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '127.0.0.1', 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        evidence = Recorder()
        error = None
        try:
            async with ClientSession() as client:
                async with client.ws_connect(f'http://127.0.0.1:{port}/remoteplay/') as ws:
                    try:
                        await probe.probe_connection(ws, evidence, not mode.startswith('status'), 2,
                                                     registration() if mode.startswith('status') else None)
                    except (RuntimeError, ValueError) as caught:
                        error = caught
        finally:
            await runner.cleanup()
        return received, evidence, error

    async def test_create_pair_cancel_over_websocket(self):
        received, evidence, error = await self.run_server('normal')
        self.assertIsNone(error)
        self.assertEqual(received, [probe.request(1), probe.request(2, 12345), probe.request(4, 12345)])
        self.assertIn(('pairing_cancelled', {}), evidence.events)

    async def test_create_failure_never_starts_pairing(self):
        for mode in ['create_failure', 'missing_session']:
            with self.subTest(mode=mode):
                received, _, error = await self.run_server(mode)
                self.assertIsNotNone(error)
                self.assertEqual(received, [probe.request(1)])

    async def test_pairing_failure_still_cancels(self):
        for mode in ['bad_pin', 'wrong_rpc']:
            with self.subTest(mode=mode):
                received, _, error = await self.run_server(mode)
                self.assertIsNotNone(error)
                self.assertEqual(received[-1], probe.request(4, 12345))

    async def test_unsolicited_notification_is_not_an_rpc_result(self):
        _, evidence, error = await self.run_server('notification')
        self.assertIsNone(error)
        self.assertIn(('response', {'kind': 'reply_packet', 'result': 1}), evidence.events)

    async def test_cloud_status_subscription_requires_valid_discovery(self):
        received, evidence, error = await self.run_server('status')
        self.assertIsNone(error)
        self.assertEqual(received, [probe.request(1), probe.registration_request(12345, registration())])
        self.assertIn(('cloud_status_received', {'packets': 1}), evidence.events)
        _, evidence, error = await self.run_server('status_truncated')
        self.assertIsInstance(error, ValueError)
        self.assertNotIn('cloud_status_received', [stage for stage, _ in evidence.events])


if __name__ == '__main__':
    unittest.main(argv=sys.argv)
