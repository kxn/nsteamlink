#!/usr/bin/env python3
"""Compare Native thread gates, CPU input and real media/SDK reports to Source.

72 selection cases use the production helper with explicit capability/default
metadata and real unopened contexts. Linux CPU-file terminals exercise the real
platform getter/cache. 54 full media cases use the actual H264 SDK, production
callback/actor and independent pixel MD5 before controlled receive results; full
message80/cache and pre-open fields match original client traces. Multi-thread
old-picture/map cleanup is a separate Native invariant, not official device proof.
"""

import argparse
import gzip
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "info_check", ROOT / "scripts/check-steam-decoder-info.py"
)
info = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(info)


def read(name):
    return json.loads(gzip.decompress((ROOT / "scripts/fixtures" / name).read_bytes()))


def verify(receiver):
    source = read("steam-client-decode-threads-reference.json.gz")
    commands = [
        f"J {c['processors']} {c['capabilities']} {c['default_count']} {c['default_type']}"
        for c in source["cases"]
    ]
    native = info.playback.execute(receiver, commands)
    assert len(native) == len(source["cases"])
    for c, got in zip(source["cases"], native, strict=True):
        assert got["thread_policy"] == [*c["at_open"], c["count_calls_at_open"]], (
            "production thread gates",
            c,
            got["thread_policy"],
        )
    representatives = {c["processors"]: c for c in source["cases"]}
    for count, c in representatives.items():
        got = info.playback.execute(receiver, [f"L {count} 0"])[-1]
        assert got["linux_cpu_probe"] == [c["source_cpu_byte"]] * 2 + [
            c["opens_after_cached_reads"]
        ], ("Linux CPU producer/cache", count, got["linux_cpu_probe"])
    got = info.playback.execute(receiver, ["L 3 1"])[-1]
    assert got["linux_cpu_probe"] == [1, 1, 1], (
        "Linux fopen-failure fallback",
        got["linux_cpu_probe"],
    )
    report = read("steam-client-thread-reports-reference.json.gz")
    for case in report["cases"]:
        native, positions = info.verify(
            receiver, case, case["cache_history"], prefix=[f"H {case['processors']}"]
        )
        rows = [native[3], *(native[position] for position in positions)]
        states = [case["initial"], *case["states"]]
        assert len(rows) == len(states)
        for got, state in zip(rows, states, strict=True):
            setup = state["thread_setups"][-1]
            assert got["thread_setup"][:2] == setup, (
                case["name"],
                "SDK pre-open",
                got["thread_setup"],
                setup,
            )
            assert got["cpu_queries"] == len(state["thread_setups"]), (
                case["name"],
                "actual CPU queries",
                got["cpu_queries"],
            )
            assert got["thread_result"][:2] == setup, (
                case["name"],
                "real SDK metadata",
                got["thread_result"],
                setup,
            )
            assert not got["thread_result"][2] & 1, (
                case["name"],
                "unexpected frame threading",
                got["thread_result"],
            )
    for count in (2, 3, 4):
        result = subprocess.run(
            [
                str(receiver),
                str(ROOT / "app/tests/fixtures/video/sequential.h264"),
                "--resources",
                str(count),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0 and result.stdout.strip().endswith(
            "Video timing resources passed"
        ), ("multithread resources", count, result.returncode, result.stderr[-2000:])
    print(
        "Native decode threads:",
        len(source["cases"]),
        "policy cases,",
        len(representatives) + 1,
        "Linux CPU cases,",
        len(report["cases"]),
        "media cases /",
        sum(len(c["states"]) for c in report["cases"]),
        "states; three multi-thread resource runs passed",
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    a = p.parse_args()
    verify(a.receiver.resolve())


if __name__ == "__main__":
    main()
