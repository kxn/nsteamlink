#!/usr/bin/env python3
"""Record the exact graphics ABI/shader inputs alongside a diagnostic artifact."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
p = argparse.ArgumentParser()
p.add_argument('--root', required=True, type=Path)
p.add_argument('--build', required=True, type=Path)
p.add_argument('--backend', choices=['sdl', 'deko'], required=True)
p.add_argument('--sdk', type=Path, default=Path(os.environ.get('DEVKITPRO', '/opt/devkitpro')))
a = p.parse_args()
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
paths = [a.root / 'app/platforms/switch/video_surface.c', a.root / 'app/tests/fixtures/video/manifest.json']
if a.backend == 'deko':
    paths += [a.root / f'app/platforms/switch/shaders/quad.{s}' for s in ['vert', 'frag']]
    paths += [a.build / f'app/quad_{s}.dksh' for s in ['vert', 'frag']]
    paths += [a.sdk / x for x in ['tools/bin/uam', 'libnx/lib/libdeko3d.a',
        'libnx/lib/libnx.a', 'portlibs/switch/lib/libavcodec.a', 'portlibs/switch/lib/libavutil.a',
        'portlibs/switch/include/libavutil/hwcontext_nvtegra.h']]
manifest = {'backend': a.backend, 'hardware_validation': 'not established by a build',
            'sha256': {str(x.relative_to(a.root) if x.is_relative_to(a.root) else x): digest(x) for x in paths}}
for name, root in [('application', a.root), ('ihslib', a.root / 'third_party/ihslib')]:
    manifest[name] = {'commit': subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip(),
                      'dirty': bool(subprocess.check_output(['git', '-C', str(root), 'diff', 'HEAD'], text=True))}
output = a.build / 'generated/graphics_manifest.json'
output.parent.mkdir(parents=True, exist_ok=True)
text = json.dumps(manifest, indent=2) + '\n'
if not output.exists() or output.read_text() != text:
    output.write_text(text)
