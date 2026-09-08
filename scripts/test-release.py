#!/usr/bin/env python3
"""Regression checks for build provenance and release container rejection."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('artifacts', ROOT / 'scripts/validate-artifacts.py')
artifacts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifacts)


class ReleaseTests(unittest.TestCase):
    def test_identity_tracks_commits_and_dirty_without_reconfigure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            def run(*args):
                return subprocess.check_output(args, cwd=root, stderr=subprocess.DEVNULL, text=True).strip()
            run('git', 'init')
            run('git', 'config', 'user.email', 'test@example.invalid')
            run('git', 'config', 'user.name', 'Release Test')
            (root / 'source.c').write_text('first')
            run('git', 'add', 'source.c')
            run('git', 'commit', '-m', 'first')
            def identity():
                run('cmake', '-DSOURCE_DIR=' + str(root), '-DOUTPUT_DIR=' + str(root / 'generated'),
                    '-DAPP_VERSION=0.1.0', '-P', str(ROOT / 'cmake/BuildIdentity.cmake'))
                return json.loads((root / 'generated/build_identity.json').read_text())
            first = identity()
            self.assertFalse(first['dirty'])
            self.assertEqual(first['display_version'], '0.1.0+' + run('git', 'rev-parse', '--short=7', 'HEAD'))
            stamp = (root / 'generated/build_identity.h').stat().st_mtime_ns
            identity()
            self.assertEqual(stamp, (root / 'generated/build_identity.h').stat().st_mtime_ns)
            (root / 'source.c').write_text('second')
            self.assertTrue(identity()['dirty'])
            self.assertTrue(identity()['display_version'].endswith('.d'))
            run('git', 'commit', '-am', 'second')
            second = identity()
            self.assertFalse(second['dirty'])
            self.assertNotEqual(first['commit'], second['commit'])

    def test_exefs_is_not_installable_nsp(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / 'fake.nsp'
            p.write_bytes(b'PFS0' + bytes(60))
            with self.assertRaisesRegex(ValueError, 'program, control and CNMT'):
                artifacts.check_nsp(p)

    def test_keyset_required_without_leaking_values(self):
        result = subprocess.run(['python3', str(ROOT / 'scripts/package-switch.py'),
            '--elf', 'missing', '--nacp', 'missing', '--icon', 'missing', '--config', 'missing',
            '--output', 'missing', '--keyset', '/nonexistent/nsl-test-keyset'], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('NSP requires', result.stderr)


if __name__ == '__main__':
    unittest.main()
