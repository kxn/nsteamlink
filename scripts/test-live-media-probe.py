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
LOG = f"""LIVE_BEGIN run=42 build={BUILD} host=192.0.2.1 seconds=30 observer=2
LIVE_SETTINGS run=42 stored_fec=0 sound=1
LIVE_SUBMITTED run=42 existing_identity=1
LIVE_FIRST run=42 elapsed_ms=1000
LIVE_VCHANNEL run=42 channel=9 ordinary=300 fec=0 retry=4
LIVE_VRECV run=42 complete=100 key=1 finish=100 last=1202590908417
LIVE_VWORK run=42 calls=99 key=1 finish=99 last=1202590908417
LIVE_VSUBMIT run=42 calls=100 returned=100 keys=1 errors=0 last=281474976776193
LIVE_VDECODE run=42 calls=0 accepted=0 reset=0 lost=0 disable=0
LIVE_VREQUEST run=42 requested=0 sent=0 failed=0
LIVE_WIRE run=42 ordinary=500 fec=0 parity_enabled=0 parity_shards=0 fec_complete=0
LIVE_FLOW run=42 complete=200 recovery=0 feedback_sent=300 feedback_failed=0
LIVE_RESULT run=42 decoded=100 presented=90 audio=100 hardware=1 play_ms=30001 gap_ms=35 tail_ms=10
LIVE_FINAL run=42 result=PASS reason=none workers=joined media=destroyed
"""


def check(log):
    return probe.analyze(log, BUILD, "192.0.2.1", 30)


def version3(mode="saved"):
    enabled = mode == "on"
    log = LOG.replace("observer=2", "observer=3 fec=" + mode).replace(
        "stored_fec=0 sound=1",
        f"original_known=1 original_has=0 stored_fec=0 effective_fec={int(enabled)} sound=1",
    )
    prefix = (
        f"LIVE_PREFS run=42 loads={0 if mode == 'saved' else 2} saves=0 profiles=0 errors=0\n"
        f"LIVE_NEGOTIATE run=42 type=4 calls=1 admitted=1 queued=1 sent=2 failed=1 fec={7 if enabled else 4 if mode == 'saved' else 6} sent_fec={8 if enabled else 1 if mode == 'saved' else 4}\n"
        "LIVE_NEGOTIATE run=42 type=99 calls=0 admitted=0 queued=0 sent=0 failed=0 fec=0 sent_fec=0\n"
        "LIVE_PEER run=42 config_accepted=1 overflow=0\n"
    )
    log = log.replace("LIVE_VCHANNEL", prefix + "LIVE_VCHANNEL")
    log = log.replace("retry=4\n", f"retry=4 fec_complete={10 if enabled else 0}\n")
    if enabled:
        log = log.replace(
            "channel=9 ordinary=300 fec=0", "channel=9 ordinary=300 fec=50"
        )
        log = log.replace(
            "fec=0 parity_enabled=0 parity_shards=0 fec_complete=0",
            "fec=100 parity_enabled=90 parity_shards=4 fec_complete=10",
        )
    return log


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

    def test_video_boundaries_and_failure_cleanup(self):
        for before, after in [
            ("observer=2", "observer=1"),
            ("channel=9", "channel=32"),
            ("retry=4", "retry=301"),
            ("complete=100", "complete=0"),
            ("calls=99", "calls=101"),
            ("returned=100", "returned=99"),
            ("errors=0", "errors=1"),
            ("last=1202590908417", "last=0"),
            ("last=281474976776193", "last=0"),
            ("key=1", "key=101"),
            ("accepted=0", "accepted=1"),
        ]:
            with self.subTest(before=before):
                self.assertFalse(check(LOG.replace(before, after))["passed"])
        failed = check(
            LOG.replace(
                "result=PASS reason=none", "result=FAIL reason=playback_stalled"
            )
        )
        self.assertIn("probe failed", failed["errors"])
        self.assertNotIn("cleanup incomplete", failed["errors"])
        self.assertEqual(failed["final"]["reason"], "playback_stalled")
        legacy = LOG.replace(" observer=2", "")
        self.assertFalse(check(legacy)["passed"])

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

    def test_negotiation_and_fec_modes(self):
        for mode in ("saved", "on", "off"):
            result = probe.analyze(version3(mode), BUILD, "192.0.2.1", 30, mode)
            self.assertTrue(result["passed"], result["errors"])
            self.assertEqual(result["rs_reconstruction"], "unverified")
            self.assertEqual(
                result["negotiation"]["video_type11_observed"], mode == "on"
            )
            self.assertEqual(result["negotiation"]["configs"][0]["sent"], 2)
        self.assertFalse(probe.analyze(LOG, BUILD, "192.0.2.1", 30, "on")["passed"])

    def test_negotiation_failure_boundaries(self):
        log = version3("on")
        for before, after in [
            ("sent=2", "sent=0"),
            ("admitted=1", "admitted=0"),
            ("queued=1", "queued=0"),
            ("fec=7", "fec=6"),
            ("sent_fec=8", "sent_fec=0"),
            ("sent_fec=8", "sent_fec=4"),
            ("sent_fec=8", "sent_fec=12"),
            ("fec=7 sent_fec=8", "fec=5 sent_fec=2"),
            ("config_accepted=1", "config_accepted=0"),
            ("overflow=0", "overflow=1"),
            ("loads=2", "loads=1"),
            ("errors=0\nLIVE_NEGOTIATE", "errors=1\nLIVE_NEGOTIATE"),
            ("original_known=1", "original_known=0"),
            ("effective_fec=1", "effective_fec=0"),
            ("effective_fec=1", "effective_fec=broken"),
            ("channel=9 ordinary=300 fec=50", "channel=9 ordinary=300 fec=0"),
            ("retry=4 fec_complete=10", "retry=4 fec_complete=0"),
            ("retry=4 fec_complete=10", "retry=4 fec_complete=11"),
        ]:
            with self.subTest(before=before):
                result = probe.analyze(
                    log.replace(before, after), BUILD, "192.0.2.1", 30, "on"
                )
                self.assertFalse(result["passed"], result)
        for line in log.splitlines(True):
            with self.subTest(removed=line):
                self.assertFalse(
                    probe.analyze(log.replace(line, ""), BUILD, "192.0.2.1", 30, "on")[
                        "passed"
                    ]
                )
        self.assertFalse(probe.analyze(log, BUILD, "192.0.2.1", 30, "saved")["passed"])


if __name__ == "__main__":
    unittest.main()
