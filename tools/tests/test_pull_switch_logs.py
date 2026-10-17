import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import threading
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('pull_logs', Path(__file__).parents[1] / 'pull-switch-logs.py')
pull = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pull)
NAME = 'session-00000000001792241925-000001234-00000.log'


class Download(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name)
        self.body = bytes(range(256)) * 400
        self.ranges = []
        self.truncate_once = False
        self.after = False
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                if self.path.startswith('/logs?after='):
                    body = json.dumps({'files': [], 'next_after': ''}).encode()
                    self.send_response(200)
                elif self.path == '/logs':
                    page = {'version': 'test', 'commit': 'abc', 'storage_errno': 0,
                            'files': [{'name': NAME, 'bytes': len(owner.body), 'active': True}],
                            'next_after': NAME if owner.after else ''}
                    body = json.dumps(page).encode()
                    self.send_response(200)
                else:
                    assert self.path == '/logs/' + NAME
                    match = re.fullmatch(r'bytes=(\d+)-(\d+)', self.headers['Range'])
                    first, last = map(int, match.groups())
                    owner.ranges.append((first, last))
                    body = owner.body[first:last + 1]
                    self.send_response(206)
                    self.send_header('Content-Range', f'bytes {first}-{last}/{len(owner.body)}')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                if owner.truncate_once and self.path.startswith('/logs/'):
                    owner.truncate_once = False
                    body = body[:8]
                self.wfile.write(body)

        self.server = HTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.addCleanup(self.close)
        self.base = f'http://127.0.0.1:{self.server.server_port}'

    def close(self):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()

    def test_complete_capture_and_pagination(self):
        self.after = True
        meta, files = pull.index(self.base)
        result = pull.download(self.base, files[0], self.output)
        self.assertEqual(meta['commit'], 'abc')
        self.assertEqual((self.output / NAME).read_bytes(), self.body)
        self.assertEqual(result['sha256'], hashlib.sha256(self.body).hexdigest())
        self.assertTrue(all(last - first < pull.CHUNK for first, last in self.ranges))

    def test_resume_partial_and_retry_truncation(self):
        (self.output / (NAME + '.part')).write_bytes(self.body[:123])
        self.truncate_once = True
        _, files = pull.index(self.base)
        with mock.patch.object(pull.time, 'sleep'):
            pull.download(self.base, files[0], self.output)
        self.assertEqual(self.ranges[0], self.ranges[1])
        self.assertEqual(self.ranges[0][0], 123)
        self.assertEqual((self.output / NAME).read_bytes(), self.body)

    def test_active_snapshot_then_append(self):
        _, files = pull.index(self.base)
        before = self.body
        self.body += b'new events after the index snapshot\n'
        pull.download(self.base, files[0], self.output)
        self.assertEqual((self.output / NAME).read_bytes(), before)
        self.ranges.clear()
        _, files = pull.index(self.base)
        pull.download(self.base, files[0], self.output)
        self.assertEqual(self.ranges[0][0], len(before))
        self.assertEqual((self.output / NAME).read_bytes(), self.body)

    def test_invalid_path_and_shrinking_log_keep_evidence(self):
        with self.assertRaises(ValueError):
            pull.download(self.base, {'name': '../profile.bin', 'bytes': 1}, self.output)
        target = self.output / NAME
        target.write_bytes(self.body + b'keep me')
        with self.assertRaises(ValueError):
            pull.download(self.base, {'name': NAME, 'bytes': len(self.body)}, self.output)
        self.assertTrue(target.read_bytes().endswith(b'keep me'))
        self.assertFalse(self.ranges)


if __name__ == '__main__':
    unittest.main()
