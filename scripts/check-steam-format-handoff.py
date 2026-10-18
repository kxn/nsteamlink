#!/usr/bin/env python3
"""Compare real Native actor/SDK handoff with captured original client processes.

normal/reset-ready/reset-pending compare single original API traces. Failed-open
compares a declared invalid SDK input; both run the real SDK error return. Cancellation
cases compare SDK/error/info/pixel projection; replacement composes cancel+decode,
not an observed original control replacement. Base-lock, frozen admission, initial
open's injected SDK callback are declared Native guard tests.
The C oracle runs production callbacks/control FIFO/actor and real OS worker/SDK,
checks original pixel MD5 across Stop, thread roles, cache and cancellation. No
actual host, hardware, Qt, complete stats or loader equivalence is claimed.
"""

import argparse
import gzip
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def projection(case):
    s = case["original_start"]
    return dict(
        infos=len(s.get("control", [])),
        pictures=sum(x["has_pixels"] for x in s.get("player_objects", [])),
        losses=sum(e[0] == "data_lost" for e in s["trace"]),
        sdk=[
            [4 if e[0] == "sdk_send_return" else 5, e[2]]
            for e in s["trace"]
            if e[0] in ("sdk_send_return", "sdk_receive_return")
        ],
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    p.add_argument("--source-report", type=Path)
    a = p.parse_args()
    if a.source_report:
        source = json.loads(a.source_report.read_text())
    else:
        source = json.loads(
            gzip.decompress(
                (
                    ROOT
                    / "scripts/fixtures/steam-client-format-handoff-reference.json.gz"
                ).read_bytes()
            )
        )
    cases = {
        c["original_start"]["mode"]: c
        for c in source["cases"]
        if c["original_start"]["client_bootstrap"] == "udp"
    }
    assert set(cases) == {
        "empty",
        "decode",
        "cancel",
        "restart",
        "reset_pending",
        "reset_ready",
        "reset_open_error",
    }
    for c in cases.values():
        assert (
            c["client_sha256"]
            == "95482ca6120f90bb90798b27206b7946ab732e079f008d7fc90ea58a8b0074e1"
        )
        assert len(c["source_functions"]) == 54 and c["original_process_exit_code"] == 0
        assert (
            c["sdk_sha256"]
            == "c53a7e3d32a986323ec6bedd28df73a6e5842c4753b67b1d2aa0d6e4f524472f"
        )
    compare = {
        "normal": ["decode"],
        "restart": ["reset_ready"],
        "config_pending": ["reset_ready"],  # Control/reset ordering projection.
        "reset_pending": ["reset_pending"],
        "reset_unavailable": ["reset_open_error"],
        "replace_pending": ["cancel", "decode"],
        "stop_pending": ["cancel"],
        "disconnect_pending": ["cancel"],
        "freeze_pending": ["cancel"],
    }
    for mode in [*compare, "base_cancel", "opening_guard"]:
        result = subprocess.run(
            [
                str(a.receiver.resolve()),
                str(ROOT / "app/tests/fixtures/video/sequential.h264"),
                "--formats",
                mode,
            ],
            text=True,
            capture_output=True,
            timeout=20,
        )
        assert result.returncode == 0, (mode, result.returncode, result.stderr[-4000:])
        native = json.loads(result.stdout)
        assert native["mode"] == mode and native["actor"]
        if mode in compare:
            expected = dict(infos=0, pictures=0, losses=0, sdk=[])
            for part in compare[mode]:
                values = projection(cases[part])
                for key in ("infos", "pictures", "losses"):
                    expected[key] += values[key]
                expected["sdk"] += values["sdk"]
            assert {k: native[k] for k in expected} == expected, (
                mode,
                native,
                expected,
            )
    print(
        "Native format handoff: 4 single-source traces (one invalid SDK input), 5 SDK projections/compositions, 2 guard cases passed"
    )


if __name__ == "__main__":
    main()
