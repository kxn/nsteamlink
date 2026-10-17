#!/usr/bin/env python3
"""Check diagnostic exclusion in a configured and built release tree."""
import argparse
import json
from pathlib import Path
import shlex
import subprocess
import re

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
    obj = Path(entry['directory']) / argv[argv.index('-o') + 1]
    # Some release-tree unit tests intentionally compile a diagnostic variant
    # of the same source. Inspect the product objects, not these test fixtures.
    if not re.search(r'CMakeFiles/nsl_(?:platform|ui|video_pipeline|gfx)\.dir/', str(obj)):
        continue
    assert '-DNSL_DIAGNOSTICS=0' in argv, f'diagnostic macro missing: {source}'
    data = obj.read_bytes()
    for marker in (b'render-rate-test', b'--adaptive-pacing', b'--no-adaptive-pacing', b'RUNTIME_FIXTURE_', b'vq1 ', b'vq7 ', b'vq8 ', b'vq9 '):
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
for entry in commands:
    if not entry['file'].endswith('/sns_backend.cpp'):
        continue
    argv = entry.get('arguments') or shlex.split(entry['command'])
    assert '-DNSL_SNS_PROBES=0' in argv, 'SNS probe API enabled in release product'
for entry in commands:
    if not entry['file'].endswith('/sdr_probe.cpp'):
        continue
    argv = entry.get('arguments') or shlex.split(entry['command'])
    assert '-DNSL_SNS_PROBES=0' in argv, 'relay fixture enabled in release product'
    compiler = Path(argv[0])
    nm = compiler.with_name(re.sub(r'(?:clang\+\+|g\+\+|c\+\+)$', 'nm', compiler.name))
    archive = build / 'third_party/GameNetworkingSockets/src/libGameNetworkingSockets_s.a'
    symbols = subprocess.check_output([str(nm), '--defined-only', str(archive)], text=True)
    for name in ('sl_gns_sdr_test_loss', 'sl_gns_sdr_test_terminal', 'sl_gns_sdr_test_migration', 'sl_gns_sdr_topology_fixture',
                 'sl_gns_sdr_transport_stats', 'sl_gns_sdr_probe_create'):
        assert name not in symbols, f'relay diagnostic API remains: {name}'
link = (build / 'app/CMakeFiles/nsteamlink.dir/link.txt').read_text()
assert 'runtime_fixture' not in link and 'runtime_probe' not in link, 'runtime fixture linked into product'
archive = build / 'app/libnsl_platform.a'
assert b'RUNTIME_FIXTURE_' not in archive.read_bytes(), 'runtime driver included in product platform'
manifest = json.loads((build / 'generated/graphics_manifest.json').read_text())
if any(e['file'].endswith('/platforms/switch/gfx.c') for e in commands):
    assert manifest['backend'] == 'deko', 'Switch must use deko'
    gfx_sources = [Path(e['file']) for e in commands if Path(e['file']).name == 'gfx.c']
    assert gfx_sources and all(p.parent.name == 'switch' for p in gfx_sources), 'SDL renderer in Switch build'
    link = (build / 'app/CMakeFiles/nsteamlink.dir/link.txt').read_text()
    assert 'libdeko3dd.a' not in link and 'libdeko3d.a' in link, 'wrong deko library'
print(f'PASS: {checked} units; diagnostic macros/strings and GPU reports excluded')
