#!/usr/bin/env python3
"""Ensure unattended runs cannot pass on stale logs or incomplete cleanup."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('runner', Path(__file__).with_name('test-switch-video.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
START = '[42 startup] PROBE_BEGIN build=abc\n'
CASE = '[42 cleanup-decoder] CASE_FINAL fixture=padding720 iteration=0 result=PASS failed_stage=none\n'
COUNTS = '[42 cleanup-sdl] SUITE cases_completed=1 cases_expected=1\n'
FINAL = '[42 complete] PROBE_FINAL result=PASS failed_stage=none\n'
CLEAN = '[42 complete] PROBE_CLEANUP resources=clean transport=closing\n'
LOG = START + CASE + COUNTS + FINAL + CLEAN


def parse(text, **overrides):
    result = runner.result_from_log(text)
    result.update(fixture='padding720', timed_out=False, nxlink_exit=0)
    result.update(overrides)
    return result


class Results(unittest.TestCase):
    def test_complete(self):
        self.assertTrue(runner.successful(parse(LOG)))

    def test_previous_log_is_not_result(self):
        old = ''.join('[42 startup] previous: ' + line for line in LOG.splitlines(True))
        self.assertFalse(runner.successful(parse(START + old)))

    def test_latest_run_wins(self):
        self.assertFalse(runner.successful(parse(LOG + '[43 startup] PROBE_BEGIN build=def\n')))

    def test_cleanup_required(self):
        self.assertFalse(runner.successful(parse(LOG.replace(CLEAN, ''))))

    def test_sdk_error_required(self):
        self.assertFalse(runner.successful(parse(LOG + '[42 complete] deko result=9 where=submit message=invalid fence type\n')))

    def test_timeout_or_deploy_failure(self):
        self.assertFalse(runner.successful(parse(LOG, timed_out=True)))
        self.assertFalse(runner.successful(parse(LOG, nxlink_exit=1)))

    def test_complete_case_matrix_required(self):
        self.assertFalse(runner.successful(parse(LOG, fixture='suite')))
        self.assertFalse(runner.successful(parse(LOG.replace(CASE, ''))))
        self.assertFalse(runner.successful(parse(LOG.replace('iteration=0 result=PASS', 'iteration=0 result=FAIL'))))

    def test_suite(self):
        fixtures = ['padding720', 'padding1080', 'sequential', 'reordered']
        cases = ''.join(CASE.replace('iteration=0', f'iteration={i}').replace('padding720', fixtures[i % 4]) for i in range(12))
        log = START + cases + COUNTS.replace('=1', '=12') + FINAL + CLEAN
        self.assertTrue(runner.successful(parse(log, fixture='suite')))
        self.assertFalse(runner.successful(parse(log.replace('iteration=1', 'iteration=0'), fixture='suite')))


if __name__ == '__main__':
    unittest.main()
