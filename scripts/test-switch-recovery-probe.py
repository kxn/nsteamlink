#!/usr/bin/env python3
"""Parser-only synthetic logs: never evidence of a device run."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "probe", ROOT / "tools/switch-recovery-probe.py"
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
BUILD, FIXTURE = "a" * 40, "b" * 64


def records():
    messages = [
        f"PROBE_BEGIN build={BUILD} fixture=recovery output_height=720",
        f"RECOVERY_FIXTURE size=97067 sha256={FIXTURE} boundary=decoder",
    ]
    for padded in (False, True):
        for number in range(3):
            hardware = number != 0
            for stage in ("opened", "decoded"):
                messages.append(
                    "RECOVERY_RESOURCE "
                    + json.dumps(
                        dict(
                            padded=padded,
                            **{"pass": number},
                            stage=stage,
                            query_result=0,
                            heap_live_bytes=1,
                            process_used_bytes=2,
                        )
                    )
                )
            for index, fid in enumerate(m.IDS):
                messages.append(
                    "RECOVERY_ROW "
                    + json.dumps(
                        dict(
                            padded=padded,
                            **{"pass": number},
                            input=fid,
                            task=fid,
                            pixels=True,
                            pixel_input=fid,
                            bytes=65536 if padded else m.SIZES[index],
                            submit_result=1,
                            submit_us=1,
                            select_us=1,
                            render_verify_us=1,
                        )
                    )
                )
            messages.append(
                "RECOVERY_CASE "
                + json.dumps(
                    dict(
                        padded=padded,
                        **{"pass": number},
                        width=1280,
                        height=720,
                        hardware_requested=hardware,
                        hardware_context=hardware,
                        zero_copy=hardware,
                        inputs=7,
                        tasks=7,
                        pictures=7,
                        key_seen=True,
                        next_p_seen=True,
                        key_to_readback_us=2,
                        stopped=True,
                        passed=True,
                        failure="none",
                    )
                )
            )
        messages.append(
            "RECOVERY_MEMORY "
            + json.dumps(
                dict(
                    padded=padded,
                    query_result=0,
                    heap_live_bytes=1,
                    process_used_bytes=2,
                    cleanup_passed=True,
                )
            )
        )
    messages += [
        "SUITE cases_completed=2 cases_expected=2",
        "PROBE_FINAL result=PASS failed_stage=none",
        "PROBE_CLEANUP resources=clean transport=closing",
    ]
    return messages


def evaluate(messages):
    return m.analyze("\n".join("[123 recovery] " + v for v in messages), BUILD, FIXTURE)


class Tests(unittest.TestCase):
    def test_fixture_identity(self):
        self.assertEqual(
            m.fixture_identity(),
            m.sha(ROOT / "app/tests/fixtures/video/recovery720.h264"),
        )

    def test_complete_and_limits(self):
        r = evaluate(records())
        self.assertEqual(r["status"], "passed")
        self.assertEqual(r["hbmenu_return"], "unverified")
        self.assertEqual(r["physical_scanout"], "unverified")

    def test_truncation_is_failure(self):
        self.assertEqual(evaluate(records()[:-2])["status"], "failed")

    def test_hardware_fallback_is_failure(self):
        data = [
            s.replace('"hardware_context": true', '"hardware_context": false')
            for s in records()
        ]
        self.assertEqual(evaluate(data)["status"], "failed")

    def test_late_pixels_can_belong_to_older_input(self):
        # Two hardware tasks return placeholders, then older physical images.
        # Software golden rows stay complete. Task identity stays current.
        data = []
        offsets = {}
        for message in records():
            tag, _, payload = message.partition(" ")
            if tag in ("RECOVERY_ROW", "RECOVERY_CASE"):
                v = json.loads(payload)
                if v["pass"] in (1, 2):
                    if tag == "RECOVERY_ROW":
                        key = (v["padded"], v["pass"])
                        at = offsets.get(key, 0)
                        offsets[key] = at + 1
                        v["pixels"] = at >= 2
                        v["pixel_input"] = m.IDS[at - 2] if at >= 2 else 0
                    else:
                        v["pictures"] = 5
                    message = tag + " " + json.dumps(v)
            data.append(message)
        self.assertEqual(evaluate(data)["status"], "passed")

    def test_duplicate_physical_pixels_are_rejected(self):
        data = records()
        at = [i for i, s in enumerate(data) if s.startswith("RECOVERY_ROW ")][1:4]
        for j, pixel in zip(at, (100, 106, 107)):
            v = json.loads(data[j].split(" ", 1)[1])
            v["pixel_input"] = pixel
            data[j] = "RECOVERY_ROW " + json.dumps(v)
        # Duplicating already observed frame100 is invalid, independently of task IDs.
        self.assertEqual(evaluate(data)["status"], "failed")

    def test_corrupt_fields_fail_without_crashing(self):
        mutations = [
            ("RECOVERY_CASE", "padded", []),
            ("RECOVERY_CASE", "pass", {}),
            ("RECOVERY_CASE", "pass", True),
            ("RECOVERY_CASE", "pictures", 7.0),
            ("RECOVERY_ROW", "pixel_input", []),
            ("RECOVERY_ROW", "pixels", 1),
            ("RECOVERY_ROW", "submit_us", -1),
            ("RECOVERY_ROW", "submit_result", True),
            ("RECOVERY_RESOURCE", "heap_live_bytes", "0"),
            ("RECOVERY_MEMORY", "padded", {}),
        ]
        for tag, field, value in mutations:
            with self.subTest(tag=tag, field=field, value=value):
                data = records()
                index = next(i for i, s in enumerate(data) if s.startswith(tag + " "))
                record = json.loads(data[index].split(" ", 1)[1])
                record[field] = value
                data[index] = tag + " " + json.dumps(record)
                result = evaluate(data)
                self.assertEqual(result["status"], "failed")
                self.assertIn("malformed " + tag, result["errors"])
        for payload in ("{", "[]", "null"):
            self.assertEqual(
                evaluate(records() + ["RECOVERY_ROW " + payload])["status"], "failed"
            )

    def test_conflicting_final_or_late_records_are_rejected(self):
        for extra in ("PROBE_FINAL result=FAIL failed_stage=decode", records()[2]):
            self.assertEqual(evaluate(records() + [extra])["status"], "failed")

    def test_failed_resource_query_keeps_budget_unverified(self):
        data = [s.replace('"query_result": 0', '"query_result": 1') for s in records()]
        report = evaluate(data)
        self.assertEqual(report["status"], "passed")
        self.assertFalse(report["resource_queries_complete"])

    def test_gpu_sdk_error_rejects_otherwise_complete_result(self):
        data = records()
        data.insert(3, "deko result=7 where=queue message=device error")
        self.assertEqual(evaluate(data)["status"], "failed")

    def test_old_log_cannot_complete_current_run(self):
        old = "\n".join("[123 startup] previous: [1 recovery] " + v for v in records())
        r = m.analyze(
            old
            + f"\n[123 startup] PROBE_BEGIN build={BUILD} fixture=recovery output_height=720",
            BUILD,
            FIXTURE,
        )
        self.assertEqual(r["status"], "failed")

    def test_wrong_build_and_duplicate_row(self):
        self.assertEqual(
            m.analyze(
                "\n".join("[123 recovery] " + v for v in records()), "c" * 40, FIXTURE
            )["status"],
            "failed",
        )
        data = records()
        data.insert(3, next(s for s in data if s.startswith("RECOVERY_ROW ")))
        self.assertEqual(evaluate(data)["status"], "failed")


if __name__ == "__main__":
    unittest.main()
