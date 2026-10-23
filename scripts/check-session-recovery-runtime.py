#!/usr/bin/env python3
"""Check local runtime/worker/media/UI convergence, not Steam/Switch acceptance."""
import argparse
import json
from pathlib import Path
import subprocess


def require(value, reason):
    if not value:
        raise ValueError(reason)


def observe(receiver, video):
    result = subprocess.run([str(receiver.resolve()), str(video.resolve())],
                            capture_output=True, text=True, timeout=80)
    require(result.returncode == 0, "abnormal local recovery fixture: " + result.stderr[-4000:])
    return json.loads(result.stdout)


def verify(observed, application=False, manager=False):
    if manager:
        require(observed["control_discoveries"] > 0, "actual manager discovery must run")
        require(observed["control_requests"] >= 3 and observed["control_tokens"] == observed["control_requests"] and
                observed["manager_handoffs"] == observed["manager_ticket_phases"] == 3,
                "three actual manager requests, tickets and handoffs")
        require(observed["control_cancels"] == 0, "normal handoff must not send StreamingCancel")
        ids = observed["launch_ids"]
        require(len(ids) == 3 and all(ids) and len(set(ids)) == 3, "three fresh native launch IDs")
    if application:
        require(observed["application_exit"] == 0, "actual application run failed")
        require(observed["wrong_cleanup_owner"] is False, "replacement cleanup dismissed new connection")
        for field in ("overlay_closed_gate", "overlay_restored_gate", "peer_joined"):
            require(observed[field] is True, "application: " + field)
        require(observed["deferred_replacement"] is True, "real image pin did not defer replacement")
        require(observed["cleanup_generation"] == observed["first_generation"] < observed["replacement_generation"],
                "replacement cleanup must belong to the retiring request")
    rows = observed["rounds"]
    require(len(rows) == 3, "host stop, silent peer, then another playable session")
    for field in ("root_retained", "joins_clean", "final_clean"):
        require(observed[field] is True, "runtime/media root convergence: " + field)
    require(observed["audio_opens"] == observed["audio_closes"] == 3,
            "all three actual stream audio devices must retire")
    ids = [row["session_id"] for row in rows]
    require(all(isinstance(value, int) and value > 0 for value in ids) and len(set(ids)) == 3,
            "fresh session identity for each displayed stream")
    for index, row in enumerate(rows):
        for field in ("displayed", "audio", "stopped", "video_clean", "hid_unbound", "audio_closed", "returned_home"):
            require(row[field] is True, f"round {index+1}: " + field)
        require(row["callbacks"] == row["destroys"] == 1, "one disconnect and destruction per stream")
        silent = index == 1
        for field in ("unexpected", "ui_error", "timed_out"):
            require(row[field] is silent, f"round {index+1}: " + field)
        for field in ("host_stop", "ui_home"):
            require(row[field] is not silent, f"round {index+1}: " + field)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", required=True, type=Path)
    parser.add_argument("--video", required=True, type=Path)
    parser.add_argument("--application", action="store_true")
    parser.add_argument("--manager", action="store_true")
    args = parser.parse_args()
    observed = observe(args.receiver, args.video)
    print(json.dumps(observed, sort_keys=True))
    verify(observed, args.application, args.manager)
    print("Local runtime recovery: real UDP stop/silence/stop, three decoded streams and joined teardown")


if __name__ == "__main__":
    main()
