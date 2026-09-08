#!/usr/bin/env python3
"""Collect only end-user artifacts, never build trees or keysets."""
import argparse
import json
from pathlib import Path
import shutil
p = argparse.ArgumentParser()
p.add_argument('--build', required=True, type=Path)
p.add_argument('--output', required=True, type=Path)
a = p.parse_args()
identity = json.loads((a.build / 'generated/build_identity.json').read_text())
a.output.mkdir(parents=True, exist_ok=True)
for suffix in ('nro', 'nsp'):
    source = a.build / f'app/nsteamlink.{suffix}'
    if source.exists():
        shutil.copyfile(source, a.output / f'NSteamLink-{identity["display_version"]}.{suffix}')
shutil.copyfile(a.build / 'generated/build_identity.json', a.output / 'build_identity.json')
