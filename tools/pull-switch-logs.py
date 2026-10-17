#!/usr/bin/env python3
"""Download persistent debug logs from the running application; no netloader.

Each request fetches a bounded byte range. Interrupted downloads resume from the
local partial file. Active logs are captured at their indexed size and can be
extended on the next pull. Remote files are never removed or modified.
"""
import argparse
import datetime
import hashlib
from http.client import HTTPException
import json
from pathlib import Path
import re
import time
import urllib.request

NAME = re.compile(r'(?:session-[0-9p-]+|stream_diag(?:_prev|_older)?)\.log\Z')
CHUNK = 32768


def fetch(base, target, headers=None, limit=16384):
    error = None
    for attempt in range(5):
        try:
            request = urllib.request.Request(base + target, headers=headers or {})
            with urllib.request.urlopen(request, timeout=5) as response:
                data = response.read(limit + 1)
                if len(data) > limit:
                    raise ValueError('response exceeds requested bounds')
                length = response.headers.get('Content-Length')
                if length is not None and int(length) != len(data):
                    raise ValueError('incomplete response')
                return response.status, response.headers, data
        except (OSError, ValueError, HTTPException) as caught:
            error = caught
            if attempt < 4:
                time.sleep(.25 * (attempt + 1))
    raise RuntimeError(f'Cannot fetch {target}: {error}') from error


def index(base):
    files, cursor, metadata, seen = [], '', {}, set()
    for _ in range(1024):
        status, _, data = fetch(base, '/logs' + ('?after=' + cursor if cursor else ''))
        if status != 200:
            raise ValueError('unexpected index response')
        page = json.loads(data)
        if not metadata:
            metadata = {k: v for k, v in page.items() if k not in ('files', 'next_after')}
        for entry in page['files']:
            name, size = entry['name'], entry['bytes']
            if not NAME.fullmatch(name) or name in seen or type(size) is not int or size < 0:
                raise ValueError('invalid or duplicate log entry')
            seen.add(name)
            files.append(entry)
        next_cursor = page.get('next_after', '')
        if not next_cursor:
            return metadata, files
        if not NAME.fullmatch(next_cursor) or next_cursor <= cursor:
            raise ValueError('invalid log index cursor')
        cursor = next_cursor
    raise ValueError('log index did not terminate')


def download(base, entry, output):
    name, size = entry['name'], entry['bytes']
    if not NAME.fullmatch(name) or type(size) is not int or size < 0:
        raise ValueError('invalid log entry')
    target, partial = output / name, output / (name + '.part')
    if target.is_symlink() or partial.is_symlink():
        raise ValueError('log destination must not be a symbolic link')
    if target.exists():
        if target.stat().st_size > size:
            raise ValueError('remote log shrank; keeping the previous local capture')
        if not partial.exists() or target.stat().st_size >= partial.stat().st_size:
            target.replace(partial)
    offset = partial.stat().st_size if partial.exists() else 0
    if offset > size:
        raise ValueError('partial capture is larger than the remote snapshot')
    with partial.open('ab') as stream:
        while offset < size:
            end = min(offset + CHUNK, size) - 1
            status, headers, data = fetch(base, '/logs/' + name,
                                          {'Range': f'bytes={offset}-{end}'}, end - offset + 1)
            content_range = re.fullmatch(r'bytes (\d+)-(\d+)/(\d+)', headers.get('Content-Range', ''))
            if (status != 206 or not content_range or
                tuple(map(int, content_range.groups()[:2])) != (offset, end) or
                int(content_range[3]) < size or len(data) != end - offset + 1):
                raise ValueError('log range or response length mismatch')
            stream.write(data)
            stream.flush()
            offset += len(data)
    partial.replace(target)
    digest = hashlib.sha256()
    with target.open('rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            digest.update(block)
    return {**entry, 'downloaded_bytes': offset, 'sha256': digest.hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--address', required=True, help='current Switch address on the reachable LAN')
    parser.add_argument('--port', type=int, default=28773)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9.-]+', args.address) or not 0 < args.port < 65536:
        parser.error('invalid address or port')
    args.output.mkdir(parents=True, exist_ok=True)
    base = f'http://{args.address}:{args.port}'
    metadata, files = index(base)
    results = []
    for entry in files:
        result = download(base, entry, args.output)
        results.append(result)
        print(f"{entry['name']} {result['downloaded_bytes']} bytes", flush=True)
    report = {'captured_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'source': base, **metadata, 'files': results, 'remote_modified': False}
    (args.output / 'capture.json').write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
    if metadata.get('storage_errno'):
        raise SystemExit(f"Downloaded available logs; device reports storage errno {metadata['storage_errno']}")


if __name__ == '__main__':
    main()
