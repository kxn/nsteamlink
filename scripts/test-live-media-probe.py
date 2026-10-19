#!/usr/bin/env python3
"""A partial/stale real-host capture must never become a playback PASS."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "live_probe", Path(__file__).resolve().parents[1] / "tools/live-media-probe.py"
)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
BUILD = "a" * 40
LOG = f"""LIVE_BEGIN run=42 build={BUILD} host=192.0.2.1 seconds=30
LIVE_SETTINGS run=42 stored_fec=0 sound=1
LIVE_SUBMITTED run=42 existing_identity=1
LIVE_FIRST run=42 elapsed_ms=1000
LIVE_WIRE run=42 ordinary=500 fec=0 parity_enabled=0 parity_shards=0 fec_complete=0
LIVE_FLOW run=42 complete=200 recovery=0 feedback_sent=300 feedback_failed=0
LIVE_RESULT run=42 decoded=100 presented=90 audio=100 hardware=1 play_ms=30001 gap_ms=35 tail_ms=10
LIVE_FINAL run=42 result=PASS reason=none workers=joined media=destroyed
"""


def check(log):
    return probe.analyze(log, BUILD, "192.0.2.1", 30)


class Contract(unittest.TestCase):
    def test_complete(self):
        result = check(LOG)
        self.assertTrue(result["passed"])
        self.assertEqual(result["rs_reconstruction"], "unverified")
        self.assertEqual(result["loader_return"], "unverified")

    def test_every_required_record(self):
        for line in LOG.splitlines(True):
            with self.subTest(line=line):
                self.assertFalse(check(LOG.replace(line, ""))["passed"])

    def test_latest_run_and_prefixed_old_log(self):
        self.assertFalse(
            check(LOG + f"LIVE_BEGIN run=43 build={BUILD} host=192.0.2.1 seconds=30\n")[
                "passed"
            ]
        )
        self.assertFalse(check(LOG + "LIVE_BEGIN run=43\n")["passed"])
        self.assertFalse(
            check("".join("previous: " + line for line in LOG.splitlines(True)))[
                "passed"
            ]
        )

    def test_identity_timing_and_media(self):
        for before, after in [
            (BUILD, "b" * 40),
            ("192.0.2.1", "192.0.2.2"),
            ("play_ms=30001", "play_ms=29999"),
            ("presented=90", "presented=0"),
            ("decoded=100", "decoded=-1"),
            ("complete=200", "complete=0"),
            ("ordinary=500", "ordinary=0"),
            ("workers=joined", "workers=pending"),
            ("result=PASS", "result=FAIL"),
            ("hardware=1", "hardware=yes"),
            ("presented=90", "presented=1"),
            ("tail_ms=10", "tail_ms=2001"),
            ("gap_ms=35", "gap_ms=0"),
        ]:
            with self.subTest(before=before):
                self.assertFalse(check(LOG.replace(before, after))["passed"])

    def test_fec_observed_does_not_prove_reconstruction(self):
        log = LOG.replace(
            "fec=0 parity_enabled=0 parity_shards=0 fec_complete=0",
            "fec=100 parity_enabled=90 parity_shards=4 fec_complete=10",
        )
        result = check(log)
        self.assertTrue(result["passed"])
        self.assertEqual(result["wire"]["fec_complete"], 10)
        self.assertEqual(result["rs_reconstruction"], "unverified")
        self.assertFalse(
            check(log.replace("parity_shards=4", "parity_shards=91"))["passed"]
        )
        silent = check(LOG.replace("audio=100", "audio=0"))
        self.assertTrue(silent["passed"])
        self.assertFalse(silent["audio_decode_observed"])

    def test_malformed_duplicate_and_order(self):
        for log in [
            LOG.replace("ordinary=500", "ordinary=broken"),
            LOG.replace("ordinary=500", "ordinary=500 ordinary=600"),
            LOG.replace("ordinary=500", "ordinary"),
            LOG + LOG.splitlines(True)[-1],
            LOG.replace("LIVE_FIRST run=42 elapsed_ms=1000\n", "")
            + "LIVE_FIRST run=42 elapsed_ms=1000\n",
        ]:
            with self.subTest(log=log):
                self.assertFalse(check(log)["passed"])


if __name__ == "__main__":
    unittest.main()
