#!/usr/bin/env python3
"""Synthetic log mutation tests only. Never evidence of a Switch run."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "probe", ROOT / "tools/switch-vcl-probe.py"
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
BUILD = "a" * 40
FIXTURES = m.fixtures()


def records():
    result = [
        f"VCL_BEGIN build={BUILD} limit=4194304 fixtures=2 sockets=1 transport=1",
        "STAGE=buffers",
        "STAGE=sdl-init",
    ]

    def row(tag, **fields):
        result.append(tag + " " + json.dumps(fields))

    for index, fixture in enumerate(FIXTURES):
        name = fixture["name"]
        result.append("STAGE=case-create")
        for number in range(2):
            result.append("STAGE=" + ("hardware-vcl" if number else "software-vcl"))
            for stage in ("opened", "decoded"):
                row(
                    "VCL_RESOURCE",
                    fixture=name,
                    **{"pass": number},
                    stage=stage,
                    heap_live_bytes=1,
                    process_used_bytes=2,
                    query_result=0,
                )
            if number:
                row(
                    "VCL_MAP",
                    fixture=name,
                    **{"pass": number},
                    index=index,
                    before=65536,
                    requested=4194304,
                    after=4194304,
                    align=256,
                    heap=1073741824,
                    flags=1,
                    result=0,
                )
            for n in range(2):
                row(
                    "VCL_ROW",
                    fixture=name,
                    **{"pass": number},
                    input=n + 1,
                    bytes=fixture["sizes"][n],
                    status=1,
                    taken=True,
                    task=n + 1,
                    pixel=n + 1,
                    submit_us=10,
                )
            row(
                "VCL_CASE",
                fixture=name,
                **{"pass": number},
                width=fixture["width"],
                height=fixture["height"],
                key_bytes=fixture["sizes"][0],
                vcl_bytes=fixture["vcl_bytes"],
                sha256=fixture["fixture_sha256"],
                hardware_requested=bool(number),
                hardware_context=bool(number),
                zero_copy=bool(number),
                inputs=2,
                pictures=2,
                stopped=True,
                passed=True,
                max_diff=0,
                failure="none",
            )
        result.append("STAGE=case-gfx-finish")
        row(
            "VCL_DRAIN",
            fixture=name,
            imported_bytes=0,
            pool_groups=0,
            busy_batches=0,
            maps=0,
        )
        result.append("STAGE=case-decoder-destroy")
        row(
            "VCL_RESOURCE",
            fixture=name,
            **{"pass": 2},
            stage="destroyed",
            heap_live_bytes=1,
            process_used_bytes=2,
            query_result=0,
        )
        row("VCL_CLEANUP", fixture=name, passed=True, failure="none")
    return result + [
        "STAGE=cleanup-sdl",
        "STAGE=complete",
        "VCL_FINAL result=PASS overflow=0",
        "VCL_TRANSPORT closing",
    ]


def evaluate(messages, build=BUILD):
    return m.analyze("\n".join("[123 probe] " + v for v in messages), build, FIXTURES)


def mutate(tag, key, value):
    data = records()
    index = next(n for n, message in enumerate(data) if message.startswith(tag + " "))
    row = json.loads(data[index].partition(" ")[2])
    row[key] = value
    data[index] = tag + " " + json.dumps(row)
    return data


class Tests(unittest.TestCase):
    def test_complete_scope(self):
        result = evaluate(records())
        self.assertEqual(result["status"], "passed", result["errors"])
        for key in (
            "hardware_maximum",
            "full_session_peak",
            "physical_scanout",
            "hbmenu_return",
            "socket_exit",
        ):
            self.assertEqual(result[key], "unverified")
        self.assertFalse(result["production_limit_changed"])

    def test_truncated_or_duplicate_or_late(self):
        data = records()
        for variant in (
            data[:-1],
            data + ["VCL_FINAL result=FAIL overflow=0"],
            data + [next(v for v in data if v.startswith("VCL_ROW "))],
            data + [next(v for v in data if v.startswith("VCL_CASE "))],
            [v for v in data if v != "STAGE=case-decoder-destroy"],
        ):
            self.assertEqual(evaluate(variant)["status"], "failed")

    def test_semantic_mismatches(self):
        for tag, field, value in (
            ("VCL_MAP", "after", 1024),
            ("VCL_MAP", "result", -12),
            ("VCL_MAP", "requested", 65536),
            ("VCL_MAP", "pass", 2),
            ("VCL_ROW", "pixel", 2),
            ("VCL_ROW", "taken", False),
            ("VCL_ROW", "bytes", 2097152),
            ("VCL_ROW", "status", 2),
            ("VCL_CASE", "sha256", "0" * 64),
            ("VCL_CASE", "max_diff", 4),
            ("VCL_DRAIN", "maps", 1),
            ("VCL_CLEANUP", "passed", False),
        ):
            with self.subTest(tag=tag, field=field):
                self.assertEqual(
                    evaluate(mutate(tag, field, value))["status"], "failed"
                )
        data = [
            v.replace('"hardware_context": true', '"hardware_context": false')
            for v in records()
        ]
        self.assertEqual(evaluate(data)["status"], "failed")
        self.assertEqual(evaluate(records(), "b" * 40)["status"], "failed")

    def test_corrupt_schema(self):
        for tag, field, value in (
            ("VCL_ROW", "pass", []),
            ("VCL_ROW", "bytes", True),
            ("VCL_ROW", "taken", 1),
            ("VCL_ROW", "input", {}),
            ("VCL_ROW", "submit_us", -1),
            ("VCL_CASE", "fixture", {}),
            ("VCL_CASE", "pictures", 2.0),
            ("VCL_MAP", "result", False),
            ("VCL_RESOURCE", "query_result", "0"),
        ):
            with self.subTest(tag=tag, field=field):
                result = evaluate(mutate(tag, field, value))
                self.assertEqual(result["status"], "failed")
                self.assertIn("malformed " + tag, result["errors"])
        for value in ("{", "[]", "null"):
            self.assertEqual(
                evaluate(records() + ["VCL_MAP " + value])["status"], "failed"
            )

    def test_samples_are_not_peak_or_required_for_decode(self):
        result = evaluate(
            [v.replace('"query_result": 0', '"query_result": 1') for v in records()]
        )
        self.assertEqual(result["status"], "passed")
        self.assertFalse(result["resource_queries_complete"])
        self.assertEqual(result["full_session_peak"], "unverified")

    def test_gpu_error_and_old_log(self):
        data = records()
        data.insert(4, "deko result=7 where=queue message=device error")
        self.assertEqual(evaluate(data)["status"], "failed")
        old = "\n".join("[123 old] previous: " + v for v in records())
        self.assertEqual(m.analyze(old, BUILD, FIXTURES)["status"], "failed")


if __name__ == "__main__":
    unittest.main()
