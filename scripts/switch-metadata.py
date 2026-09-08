#!/usr/bin/env python3
"""Create NACP using the same build identity as the application."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser()
p.add_argument('--identity', required=True, type=Path)
p.add_argument('--nacptool', required=True)
p.add_argument('--output', required=True, type=Path)
a = p.parse_args()
identity = json.loads(a.identity.read_text())
version = identity['display_version']
if len(version.encode('ascii')) > 15:
    p.error('NACP display_version exceeds 15 bytes; shorten semantic version/hash')
a.output.parent.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(dir=a.output.parent) as temporary:
    target = Path(temporary) / 'control.nacp'
    subprocess.run([a.nacptool, '--create', 'NSteamLink', 'kxn', version, str(target)], check=True)
    data = bytearray(target.read_bytes())
    # No Nintendo account/save-data slot is needed; app data lives on the SD card.
    data[0x3025] = 0  # NacpStruct.startup_user_account (libnx nacp.h)
    if not a.output.exists() or a.output.read_bytes() != data:
        a.output.write_bytes(data)
