#!/usr/bin/env python3
"""Exercise original client worker/SDK/main callback and frame ownership in-process.

Genuine pinned official Linux executable, bundled SDK and Valve-compatible Qt.
Already-parsed video Frame input and a configured partial client are explicit
boundaries. Original UDP transport/factory/Connection remain unopened and state3;
control80 is produced but rejected as unconnected. No authenticated Steam session,
full Client ctor/Qt consumer, rendering or hardware equivalence is claimed.

Each mode runs a separate original process and resumes its --version main after
probe resources retire. Source statuses are observed real SDK returns. Debugger
breakpoints record entries/returns and affect scheduling; no SDK status, code gate,
callback, async flag or original method body is replaced. Stable runtime invariants
are checked rather than freezing host CPU/Qt hashes, ASLR, PIDs or interleavings.
"""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "process", ROOT / "scripts/audit-steam-client-sdk-process.py"
)
process = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(process)


def verify(report):
    s = report["original_start"]
    mode, trace = s["mode"], s["trace"]
    bootstrap = s.get("client_bootstrap")
    names = [x[0] for x in trace]
    assert (
        report["original_process_exit_code"] == 0 and report["probe_cleanup_complete"]
    )
    assert s["threads_started"] > s["threads_before_start"]
    before = set(s["thread_ids_before_start"])
    assert set(s["thread_ids_after_stop"]) <= before
    assert set(s["thread_ids_after_resources"]) <= before
    assert s["context_cleared_after_stop"] and s["parser_cleared_after_stop"]
    assert ["decoder_pthread_join_completed", "main", 0] in trace
    if mode == "empty":
        assert not any(x in names for x in ("submit", "sdk_get_format", "decoder_info"))
        expected = (
            s["threads_before_start"] if bootstrap == "udp" else s["threads_before"]
        )
        assert s["threads_after_resources"] <= expected
        return
    if bootstrap == "udp":
        assert s["connection_state"] == 0 and s["transport_fd"] != 0xFFFFFFFF
    else:
        assert s["connection_state"] == 3 and s["transport_fd"] == 0xFFFFFFFF
    assert s["connection_retired"] and s["configured_decoder_owner_link"]
    assert "manager_destructor" in names
    shutdown = trace[names.index("manager_destructor") :]
    assert ["manager_pthread_join_enter", "main"] in shutdown
    assert ["manager_pthread_join_completed", "main", 0] in shutdown
    if not bootstrap:
        assert next(x[2] & 255 for x in shutdown if x[0] == "manager_join_return") == 1
    assert s["offered_formats"] and all(0 in f for f in s["offered_formats"])
    # The original process-global socket manager persists until its ELF dtor;
    # only the explicitly constructed connection/transport retire in the probe.
    # Baseline process services may terminate after the complete client dtor;
    # no new SDK/decoder thread may remain. Joins are observed separately.
    assert s["threads_after_resources"] <= s["threads_before_start"]
    assert (
        names.index("submit")
        < names.index("decode_frame")
        < names.index("final_decode")
    )
    for event in trace:
        if event[0] in (
            "decode_frame",
            "final_decode",
            "sdk_get_format",
            "sdk_send",
            "sdk_receive",
            "player_put",
        ):
            assert event[1].startswith("background"), event
        elif event[0] in (
            "submit",
            "public_start",
            "public_stop",
            "codec_stop",
            "main_format",
            "format_selector",
            "decoder_info",
        ):
            assert event[1] == "main", event
    if mode == "cancel":
        assert "main_format" not in names and "decoder_info" not in names
        assert ["sdk_get_format_return", "background1", -1] in trace
        assert ["sdk_send_return", "background1", -1094995529] in trace
        assert ["sdk_receive_return", "background1", -11] in trace
        assert (
            names.index("public_stop")
            < names.index("player_put")
            < names.index("codec_stop")
        )
        assert s["pending_after_cancel"] and s["cancel_cleared_codec"]
        assert s["reset_request_after_stop"] == 1
        assert s["player_objects"] == [
            {"id": 23, "shape": [0, 0, 0xFFFFFFFF], "has_pixels": False}
        ]
        return
    if mode == "reset_open_error":
        assert (
            s["sdk_open_input"]["original"] == 0
            and s["sdk_open_input"]["injected"] == -1
        )
        assert [e[2] for e in trace if e[0] == "sdk_open_return"] == [0, -22]
        assert s["failed_open_state"] == dict(
            codec_alive=True,
            parser_alive=False,
            active=True,
            guard=False,
            pending=False,
            threads=s["sdk_threads"],
        )
        assert s["after_actor_restart"] == dict(
            pending=True, request=0, codec_alive=True
        )
        assert s["request_before_think"] == 1 and s["request_after_reset_think"] == 0
        assert not s["pending_after_reset_think"] and s["reset_request_after_stop"] == 0
        assert s["control"] == [{"channel": 1, "type": 80}]
        assert s["player_objects"] == [
            {"id": 23, "shape": [0, 0, 0xFFFFFFFF], "has_pixels": False}
        ]
        for label, expected in (
            ("sdk_get_format_return", [-1]),
            ("sdk_send_return", [-1094995529]),
            ("sdk_receive_return", [-11]),
            ("frame_send_return", [3]),
            ("format_selector_return", [0]),
        ):
            assert [e[2] for e in trace if e[0] == label] == expected
        assert [e[1] for e in trace if e[0] == "data_lost"] == ["background1", "main"]
        ordered = [
            "reset_while_pending",
            "restart",
            "codec_stop",
            "public_start",
            "sdk_open_return",
            "actor_restart_completed",
            "network_poll",
            "control_dispatch",
            "main_format",
            "decoder_info",
        ]
        part = names[names.index("reset_while_pending") :]
        indexes = [part.index(label) for label in ordered]
        assert indexes == sorted(indexes)
        assert s["cached_info_after_stop"].startswith(
            "libavcodec software decoding with "
        )
        return
    if mode == "reset_pending":
        assert s["after_actor_restart"] == {
            "pending": True,
            "request": 0,
            "codec_alive": True,
        }
        assert s["request_before_think"] == 1 and s["request_after_reset_think"] == 0
        assert not s["pending_after_reset_think"]
        pic = s["picture"]
        assert pic["id"] == 24 and pic["timestamp"] == 1000000
        assert (
            pic["md5_before_stop"]
            == pic["md5_after_stop"]
            == report["contexts"][0]["pixel_md5"]
        )
        assert s["late_frame_returned_to_pool"] and s["reset_request_after_stop"] == 0
        assert s["control"] == [{"channel": 1, "type": 80}] * 2
        assert s["player_objects"] == [
            {"id": 23, "shape": [0, 0, 0xFFFFFFFF], "has_pixels": False},
            {"id": 24, "shape": [128, 72, 0], "has_pixels": True},
        ]
        assert [x[2] for x in trace if x[0] == "sdk_get_format_return"] == [-1, 0]
        assert [x[2] for x in trace if x[0] == "sdk_send_return"] == [-1094995529, 0]
        assert [x[2] for x in trace if x[0] == "sdk_receive_return"] == [-11, 0]
        assert [x[2] for x in trace if x[0] == "frame_send_return"] == [3, 3]
        assert [x[2] for x in trace if x[0] == "format_selector_return"] == [0, 0]
        assert [x[1] for x in trace if x[0] == "data_lost"] == [
            "background1",
            "main",
        ]
        stages = [
            "reset_while_pending",
            "client_think",
            "pending_resets",
            "restart",
            "public_stop",
            "decoder_pthread_join_enter",
            "sdk_get_format_return",
            "sdk_send_return",
            "sdk_receive_return",
            "player_put",
            "decoder_pthread_join_completed",
            "codec_stop",
            "public_start",
            "actor_restart_completed",
            "network_poll",
            "control_dispatch",
            "main_format",
            "decoder_info",
        ]
        # The first public_stop follows restart, not the final cleanup stop.
        start = names.index("reset_while_pending")
        part = names[start:]
        # Background failure signals DataLost before join; the reset handler
        # signals it again after Restart, before polling the network.
        actor = part.index("actor_restart_completed")
        assert part.index("data_lost", actor) < part.index("network_poll")
        order = [part.index(n) for n in stages]
        assert order == sorted(order)
        assert names.count("public_start") == 2 and names.count("restart") == 1
        return
    pictures = [s["picture"]]
    if mode in ("restart", "reset_ready"):
        assert not s["pending_after_restart"]
        pictures.append(s["picture_before_restart"])
        assert s["picture_before_restart"]["id"] == 23 and s["picture"]["id"] == 24
        assert names.count("restart") == 1 and names.count("public_start") == 2
    assert s["late_frame_returned_to_pool"]
    expected = report["contexts"][0]["pixel_md5"]
    for pic in pictures:
        assert pic["md5_before_stop"] == pic["md5_after_stop"] == expected
        assert pic["timestamp"] == 1000000
    assert s["control"] == [{"channel": 1, "type": 80}] * len(pictures)
    assert names.count("decoder_info") == len(pictures)
    assert names.count("player_put") == len(pictures)
    assert all(
        x["shape"] == [128, 72, 0] and x["has_pixels"] for x in s["player_objects"]
    )
    assert s["reset_request_after_stop"] == 0
    assert s["cached_info_after_stop"].startswith("libavcodec software decoding with ")
    # Inspect each actual submission rather than prescribing which side runs
    # immediately after main clears the callback flag. Tail-call finish BPs can
    # share a return PC and their relative observer order is not semantic order.
    begins = [i for i, x in enumerate(names) if x == "submit"]
    for i, begin in enumerate(begins):
        end = begins[i + 1] if i + 1 < len(begins) else len(trace)
        events = trace[begin:end]
        labels = [x[0] for x in events]
        order = [
            labels.index(x)
            for x in (
                "sdk_send",
                "sdk_get_format",
                "pending_observed",
                "main_format",
                "format_selector",
                "decoder_info",
                "frame_send",
                "sdk_send_return",
                "sdk_receive",
                "player_put",
            )
        ]
        assert order == sorted(order)
        assert next(x[2] for x in events if x[0] == "frame_send_return") == 3
        assert next(x[2] for x in events if x[0] == "sdk_get_format_return") == 0
        assert next(x[2] for x in events if x[0] == "sdk_send_return") == 0
        assert next(x[2] for x in events if x[0] == "sdk_receive_return") == 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--sdk-directory", type=Path, required=True)
    p.add_argument("--qt-library-directory", type=Path, action="append", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    cases = []
    for mode in ("empty", "decode", "cancel", "restart"):
        path = a.output.with_name(a.output.stem + "-" + mode + ".json")
        report = process.audit(
            a.binary.resolve(),
            a.sdk_directory.resolve(),
            [q.resolve() for q in a.qt_library_directory],
            path,
            worker_mode=mode,
        )
        path.write_text(json.dumps(report, indent=2) + "\n")
        verify(report)
        cases.append(report)
        s = report["original_start"]
        print(
            mode,
            "threads",
            s["threads_before_start"],
            s["threads_started"],
            s["threads_after_stop"],
            "trace entries",
            len(s["trace"]),
            flush=True,
        )
    a.output.write_text(json.dumps(dict(scope=__doc__, cases=cases), indent=2) + "\n")
    print(
        "Original worker process: four modes, real SDK callback/pixels/Stop/restart, normal exits"
    )


if __name__ == "__main__":
    main()
