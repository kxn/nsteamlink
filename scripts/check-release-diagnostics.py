#!/usr/bin/env python3
"""Check diagnostic exclusion in a configured and built release tree."""
import argparse
import json
from pathlib import Path
import shlex
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('build', type=Path)
a = p.parse_args()
build = a.build.resolve()
cache = (build / 'CMakeCache.txt').read_text()
assert 'NSL_DIAGNOSTICS:BOOL=OFF' in cache, 'configure with -DNSL_DIAGNOSTICS=OFF'
commands = json.loads((build / 'compile_commands.json').read_text())
names = {'application.c', 'media.c', 'runtime.c', 'video_pipeline.c', 'gfx.c', 'frame_pacer.c', 'video_scheduler.c'}
checked = 0
for entry in commands:
    source = Path(entry['file'])
    if '/app/platforms/' not in str(source) or source.name not in names:
        continue
    argv = entry.get('arguments') or shlex.split(entry['command'])
    assert '-DNSL_DIAGNOSTICS=0' in argv, f'diagnostic macro missing: {source}'
    obj = Path(entry['directory']) / argv[argv.index('-o') + 1]
    data = obj.read_bytes()
    for marker in (b'render-rate-test', b'--adaptive-pacing', b'--no-adaptive-pacing', b'vq1 ', b'vq7 ', b'vq8 ', b'vq9 '):
        assert marker not in data, f'diagnostic string {marker!r} in {obj}'
    if source.name == 'gfx.c' and source.parent.name == 'switch':
        nm = Path(argv[0]).with_name('aarch64-none-elf-nm')
        symbols = subprocess.check_output([str(nm), '-u', str(obj)], text=True)
        assert 'dkCmdBufReportCounter' not in symbols, 'GPU diagnostic reports remain'
        assert 'dkTimestampToNs' not in symbols, 'GPU diagnostic conversion remains'
    if source.name == 'frame_pacer.c':
        # Check preprocessed source too: disabled counters must not merely rely
        # on the optimizer dropping unused updates or storage.
        pre = argv[:]
        del pre[pre.index('-o'):pre.index('-o') + 2]
        pre[pre.index('-c')] = '-E'
        expanded = subprocess.check_output(pre, cwd=entry['directory'], text=True)
        for field in ('diag_ready_us', 'diag_wait_us', 'diag_start_us',
                      'settled_presented', 'deferred', 'unobserved', 'holdovers'):
            assert field not in expanded, f'diagnostic field remains: {field}'
        for required in ('sl_pacer_wait', 'sl_pacer_publish', 'sl_pacer_submit'):
            assert required.encode() in data, f'product scheduler missing: {required}'
    checked += 1
assert checked == 7, f'expected seven relevant translation units, got {checked}'
if 'NSL_GFX_BACKEND:STRING=deko' in cache:
    link = (build / 'app/CMakeFiles/nsteamlink.dir/link.txt').read_text()
    assert 'libdeko3dd.a' not in link and 'libdeko3d.a' in link, 'wrong deko library'
print(f'PASS: {checked} units; diagnostic macros/strings and GPU reports excluded')
