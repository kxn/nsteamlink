#!/usr/bin/env python3
"""Build an installable homebrew NSP; no default/downloaded keysets."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import importlib.util

spec = importlib.util.spec_from_file_location("validate_artifacts", Path(__file__).with_name("validate-artifacts.py"))
validate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validate)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--elf', required=True, type=Path)
    p.add_argument('--nacp', required=True, type=Path)
    p.add_argument('--icon', required=True, type=Path)
    p.add_argument('--config', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--keyset', default=os.environ.get('NSL_KEYSET', ''), type=str)
    p.add_argument('--hacbrewpack', default=os.environ.get('HACBREWPACK', 'hacbrewpack'))
    p.add_argument('--tools', default=str(Path(os.environ.get('DEVKITPRO', '/opt/devkitpro')) / 'tools/bin'), type=Path)
    a = p.parse_args()
    key_path = a.keyset or os.environ.get('NSL_KEYSET', '')
    keyset = Path(key_path).expanduser() if key_path else None
    if not keyset or not keyset.is_file():
        p.error('NSP requires --keyset / NSL_KEYSET pointing to an existing Switch keyset; NRO does not')
    # Check names and sizes without echoing any key values.
    values = dict(re.findall(r'^\s*([a-z0-9_]+)\s*=\s*([0-9a-fA-F]+)\s*$', keyset.read_text(), re.M))
    if len(values.get('header_key', '')) != 64 or len(values.get('key_area_key_application_00', '')) != 32:
        p.error('keyset must contain header_key (32 bytes) and key_area_key_application_00 (16 bytes)')
    tool = shutil.which(os.environ.get('HACBREWPACK', a.hacbrewpack) if a.hacbrewpack == 'hacbrewpack' else a.hacbrewpack)
    if not tool:
        p.error('hacbrewpack not found; run scripts/setup-switch-deps.sh --packager-only')
    title_id = json.loads(a.config.read_text())['program_id'].removeprefix('0x')
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='nsl-package-', dir=a.output.parent) as temp:
        root = Path(temp).resolve()
        for name in ('exefs', 'control', 'out'):
            (root / name).mkdir()
        subprocess.run([str(a.tools / 'elf2nso'), str(a.elf.resolve()), str(root / 'exefs/main')], check=True)
        subprocess.run([str(a.tools / 'npdmtool'), str(a.config.resolve()), str(root / 'exefs/main.npdm')], check=True)
        shutil.copyfile(a.nacp, root / 'control/control.nacp')
        shutil.copyfile(a.icon, root / 'control/icon_AmericanEnglish.dat')
        # Custom app icon/background are ours. Do not bundle Nintendo startup logos.
        result = subprocess.run([tool, '-k', str(keyset.resolve()), '--titleid', title_id,
                                 '--nspdir', str(root / 'out'), '--noromfs', '--nologo',
                                 '--keygeneration', '1'], cwd=root, capture_output=True, text=True)
        if result.returncode:
            # Upstream output is suppressed: no accidental keyset diagnostics in CI logs.
            raise SystemExit(f'hacbrewpack failed (exit {result.returncode}); check tool/keyset compatibility')
        output = root / 'out' / f'{title_id}.nsp'
        validate.check_nsp(output)
        os.replace(output, a.output)
    print(f'Built {a.output.name} (title ID {title_id})')


if __name__ == '__main__':
    main()
