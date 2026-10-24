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


def verify(observed, application=False, manager=False, cloud=False, sdk_loopback=False, sdk_p2p=False):
    if sdk_p2p:
        require(observed["p2p_pairs"] == observed["p2p_closed"] == observed["p2p_connected"] == 3,
                "three actual P2P/ICE pairs must connect and close")
        require(observed["p2p_objects"] == observed["p2p_released"] == 6 and observed["p2p_accepted"] == 3,
                "all incoming P2P peers must accept and all signaling objects retire")
        require(observed["p2p_signals"] >= 6 and observed["p2p_delivered"] >= 6,
                "actual P2P rendezvous bytes must cross in all three sessions")
        require(observed["p2p_peer_forwarded"] > 0 and observed["p2p_client_delivered"] > 0,
                "actual SDK datagrams must cross both native ICE directions")
    if sdk_loopback:
        require(observed["network_loopback_pairs"] == observed["network_loopback_closed"] == 3,
                "three real SDK network loopback pairs must open and close")
        require(observed["network_peer_forwarded"] > 0 and observed["network_client_delivered"] > 0,
                "actual unreliable SDK messages must cross both loopback directions")
    if cloud:
        require(observed["cm_creates"] == 1 and observed["cm_subscriptions"] > 0, "real CM session/subscription producer")
        require(observed["cm_packets"] == observed["cm_outer_tokens"] == observed["control_requests"],
                "cloud control packets must carry paired outer tokens")
        require(observed["cm_notifications"] >= 4 and observed["cm_destroyed"] is True, "CM notification/close boundary")
        require(observed["sdk_creates"] == observed["sdk_starts"] == observed["sdk_destroys"] == 3,
                "three owned external datagram providers")
        require(observed["sdk_sent"] > 0 and observed["sdk_received"] > 0 and observed["sdk_joins_clean"] is True,
                "real provider data callbacks and join before destruction")
        require(observed["cloud_ui_hosts"] > 0 and observed["cloud_lan_hosts"] == observed["cloud_udp_requests"] == 0,
                "cloud-only host and control path")
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
    parser.add_argument("--cloud", action="store_true")
    parser.add_argument("--sdk-loopback", action="store_true")
    parser.add_argument("--sdk-p2p", action="store_true")
    args = parser.parse_args()
    observed = observe(args.receiver, args.video)
    print(json.dumps(observed, sort_keys=True))
    verify(observed, args.application, args.manager, args.cloud, args.sdk_loopback, args.sdk_p2p)
    print("Local runtime recovery: real UDP stop/silence/stop, three decoded streams and joined teardown")


if __name__ == "__main__":
    main()
