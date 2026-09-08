#!/usr/bin/env python3
"""Check release identity, embedded NRO assets and NSP container integrity.

NSP checks are structural; they cannot prove a supplied keyset or device launch.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_nsp(path):
    data = path.read_bytes()
    require(data[:4] == b'PFS0' and len(data) >= 16, 'Invalid NSP header')
    count, strings_size = struct.unpack_from('<II', data, 4)
    require(count == 3, 'Expected program, control and CNMT NCAs, not an ExeFS PFS0')
    strings_start = 16 + count * 24
    base = strings_start + strings_size
    require(base <= len(data), 'Truncated NSP table')
    ranges, names = [], []
    for i in range(count):
        offset, size, name_offset = struct.unpack_from('<QQI', data, 16 + i * 24)
        require(name_offset < strings_size, 'Invalid NSP filename offset')
        end = data.find(b'\0', strings_start + name_offset, base)
        require(end >= 0, 'Unterminated NSP filename')
        name = data[strings_start + name_offset:end].decode('ascii')
        require(re.fullmatch(r'[0-9a-f]{32}(?:\.cnmt)?\.nca', name), 'Unexpected NSP entry')
        require(size >= 0xc00 and base + offset + size <= len(data), 'Truncated NCA')
        content = data[base + offset:base + offset + size]
        require(hashlib.sha256(content).hexdigest()[:32] == name[:32], 'NCA content hash mismatch')
        ranges.append((offset, offset + size))
        names.append(name)
    require(len(set(names)) == count and sum('.cnmt.' in n for n in names) == 1, 'Invalid NCA set')
    ranges.sort()
    require(ranges[0][0] == 0 and all(a[1] == b[0] for a, b in zip(ranges, ranges[1:])), 'NSP gaps/overlap')
    require(base + ranges[-1][1] == len(data), 'Unexpected trailing NSP bytes')


def check_nro(path, identity, icon):
    data = path.read_bytes()
    require(data[0x10:0x14] == b'NRO0', 'Invalid NRO')
    asset = struct.unpack_from('<I', data, 0x18)[0]
    require(data[asset:asset + 4] == b'ASET', 'Missing NRO assets')
    io, size, no, ns = struct.unpack_from('<QQQQ', data, asset + 8)
    require(data[asset + io:asset + io + size] == icon.read_bytes(), 'Wrong embedded launcher icon')
    require(ns == 0x4000 and asset + no + ns <= len(data), 'Invalid embedded NACP')
    nacp = data[asset + no:asset + no + ns]
    require(nacp[:0x200].split(b'\0')[0] == b'NSteamLink', 'Wrong application name')
    require(nacp[0x3060:0x3070].split(b'\0')[0].decode() == identity['display_version'], 'NACP/UI version mismatch')
    require(identity['display_version'].encode() in data[:asset], 'Application identity missing from executable')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--identity', required=True, type=Path)
    p.add_argument('--nro', required=True, type=Path)
    p.add_argument('--icon', required=True, type=Path)
    p.add_argument('--nsp', type=Path)
    p.add_argument('--tag')
    p.add_argument('--require-clean', action='store_true')
    a = p.parse_args()
    identity = json.loads(a.identity.read_text())
    if a.require_clean or a.tag:
        require(not identity['dirty'], 'Release must use a clean checkout')
        require(re.fullmatch('[0-9a-f]{40}', identity['commit']), 'Release requires a full source commit')
    if a.tag:
        require(a.tag == 'v' + identity['version'], 'Release tag must match project version')
    check_nro(a.nro, identity, a.icon)
    if a.nsp:
        check_nsp(a.nsp)
    print('Verified ' + identity['display_version'] + (' NRO + NSP structure' if a.nsp else ' NRO'))


if __name__ == '__main__':
    main()
