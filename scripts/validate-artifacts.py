#!/usr/bin/env python3
"""Check release identity and embedded NRO assets.

These checks are structural; they cannot prove a device launch.
"""
import argparse
import json
from pathlib import Path
import re
import struct


def require(condition, message):
    if not condition:
        raise ValueError(message)


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
    print('Verified ' + identity['display_version'] + ' NRO')


if __name__ == '__main__':
    main()
