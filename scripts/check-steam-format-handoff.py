#!/usr/bin/env python3
"""Compare real Native actor/SDK handoff with captured original client processes.

normal/reset-ready/reset-pending compare single original API traces. Failed-open
compares a declared invalid SDK input; both run the real SDK error return. Cancellation
cases compare SDK/error/info/pixel projection; normal/replacement/stop now use
original encrypted RX/FIFO handlers and factory, with parsed-carrier inputs. Base-lock, frozen admission, initial
open's injected SDK callback are declared Native guard tests.
The C oracle runs production callbacks/control FIFO/actor and real OS worker/SDK,
checks original pixel MD5 across Stop, thread roles, cache and cancellation. No
actual host, hardware, Qt, complete stats or loader equivalence is claimed.
"""

import argparse
import gzip
import hashlib
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
    p.add_argument("--control-source-report", type=Path)
    p.add_argument("--codec-source-report", type=Path)
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
        assert not c["source_assertions"]
        assert c["original_start"]["network_shutdown_before_main"]
        assert (
            c["client_sha256"]
            == "95482ca6120f90bb90798b27206b7946ab732e079f008d7fc90ea58a8b0074e1"
        )
        assert len(c["source_functions"]) == 54 and c["original_process_exit_code"] == 0
        assert (
            c["sdk_sha256"]
            == "c53a7e3d32a986323ec6bedd28df73a6e5842c4753b67b1d2aa0d6e4f524472f"
        )
    control_source = (
        json.loads(a.control_source_report.read_text())
        if a.control_source_report
        else json.loads(
            gzip.decompress(
                (
                    ROOT
                    / "scripts/fixtures/steam-client-control-start-reference.json.gz"
                ).read_bytes()
            )
        )
    )
    control_cases = {
        "control_" + c["original_start"]["mode"]: c for c in control_source["cases"]
    }
    assert set(control_cases) == {
        "control_decode",
        "control_replace_pending",
        "control_stop_pending",
    }
    for c in control_cases.values():
        assert c["client_sha256"] == cases["decode"]["client_sha256"]
        assert c["sdk_sha256"] == cases["decode"]["sdk_sha256"]
        assert c["original_process_exit_code"] == 0 and c["probe_cleanup_complete"]
        assert not c["source_assertions"]
        assert c["original_start"]["network_shutdown_before_main"]
        assert len(c["source_functions"]) == 54 and len(c["start_functions"]) == 20
        assert (
            not c["original_start"]["assertions"]
            and c["original_start"]["cleanup_complete"]
        )
    cases.update(control_cases)
    compare = {
        "normal": ["control_decode"],
        "restart": ["reset_ready"],
        "config_pending": ["reset_ready"],  # Control/reset ordering projection.
        "reset_pending": ["reset_pending"],
        "reset_unavailable": ["reset_open_error"],
        "replace_pending": ["control_replace_pending"],
        "stop_pending": ["control_stop_pending"],
        "disconnect_pending": ["cancel"],
        "freeze_pending": ["cancel"],
    }
    codec_source = (
        json.loads(a.codec_source_report.read_text())
        if a.codec_source_report
        else json.loads(
            gzip.decompress(
                (
                    ROOT / "scripts/fixtures/steam-client-codec-data-reference.json.gz"
                ).read_bytes()
            )
        )
    )
    codec_cases = {"codec_" + c["codec_case"]: c for c in codec_source["cases"]}
    media = (ROOT / "app/tests/fixtures/video/sequential.h264").read_bytes()[:2204]
    assert set(codec_cases) == {
        "codec_empty",
        "codec_opaque",
        "codec_truncated",
        "codec_annexb",
        "codec_avcc",
        "codec_avcc_reset",
    }
    for key, c in codec_cases.items():
        assert (
            c["client_sha256"] == cases["decode"]["client_sha256"]
            and c["sdk_sha256"] == cases["decode"]["sdk_sha256"]
        )
        assert (
            c["original_process_exit_code"] == 0
            and c["probe_cleanup_complete"]
            and not c["source_assertions"]
        )
        s = c["original_start"]
        assert not s["assertions"] and s["network_shutdown_before_main"]
        count = 2 if key == "codec_avcc_reset" else 1
        assert (
            s["codec_data_states"]
            == [dict(stored=s["codec_data_input"], sdk_size=0, sdk_has_pointer=False)]
            * count
        )
        assert (
            s["codec_packets"]
            == [
                dict(
                    size=len(media),
                    sha256=hashlib.sha256(media).hexdigest(),
                    sdk_size=0,
                )
            ]
            * count
        )
        assert s["cleanup_complete"]
        assert (
            c["fixture_sha256"]
            == hashlib.sha256(
                (ROOT / "app/tests/fixtures/video/sequential.h264").read_bytes()
            ).hexdigest()
        )
        assert (
            len(c["source_functions"]) == 54
            and len(c["start_functions"]) == 20
            and len(c["codec_data_functions"]) == 1
        )
        cases[key] = c
        compare[key] = [key]
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
        if mode in codec_cases:
            s = codec_cases[mode]["original_start"]
            assert native["codec_data"] == s["codec_data_input"], mode
            assert native["codec_sdk_sizes"] == [
                state["sdk_size"] for state in s["codec_data_states"]
            ], mode
            assert native["codec_packets"] == len(s["codec_packets"]), mode
    print(
        "Native format handoff: 12 single-source traces (6 codec_data, 3 full control chains; one invalid SDK input), 3 SDK/control projections, 2 guard cases passed"
    )


if __name__ == "__main__":
    main()
