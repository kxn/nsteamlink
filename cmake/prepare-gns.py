#!/usr/bin/env python3
"""Apply reviewed patches to a build copy; the pinned submodule stays pristine."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys

source, output, patches = map(Path, sys.argv[1:])
pin = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
if pin != 'd534c19aa760df3fb75fd20db13ba1932b8a5463':
    raise SystemExit('GNS patch baseline does not match the pinned SDK')
subprocess.run(['git', '-C', str(source), 'diff', '--exit-code', '--quiet'], check=True)
files = sorted(patches.glob('*.patch'))
digest = hashlib.sha256(pin.encode() + Path(__file__).read_bytes() +
                        b''.join(p.read_bytes() for p in files)).hexdigest()
stamp = output / '.nsl-patch-stamp'
if stamp.exists() and stamp.read_text() == digest:
    raise SystemExit(0)
if output.exists():
    shutil.rmtree(output)
shutil.copytree(source, output, ignore=shutil.ignore_patterns('.git', 'build'))
for patch in files:
    subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch.resolve())],
                   cwd=output, check=True)
stamp.write_text(digest)
