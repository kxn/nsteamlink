#!/usr/bin/env python3
"""Regenerate the checked-in UI alpha atlas from its authored SVG (rsvg-convert + Pillow)."""
from pathlib import Path
import subprocess
import tempfile

from PIL import Image

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='nsl-icons-') as directory:
    output = Path(directory) / 'icons.png'
    subprocess.run(['rsvg-convert', str(root / 'assets/ui/connection-icons.svg'), '-o', str(output)], check=True)
    with Image.open(output) as image:
        if image.size != (128, 768):
            raise ValueError('Expected six 128×128 masks')
        (root / 'assets/ui/connection-icons.alpha').write_bytes(image.convert('RGBA').getchannel('A').tobytes())
