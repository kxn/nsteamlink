#!/usr/bin/env python3
"""Keep local startup independent from HTTPS failure, without persistent fixtures."""
import argparse
import subprocess
import tempfile
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--receiver', required=True)
a = p.parse_args()
with tempfile.TemporaryDirectory(prefix='nsl-http-failure-') as directory:
    subprocess.run([a.receiver, directory], check=True, timeout=25)
