#!/usr/bin/env python3
"""Compare failed startup ownership with original BStart/idle/retrigger evidence.

Qt has no matching Native thread layout. The official vectors constrain inactive
failure and explicit retrigger, while Native resource faults check platform
ownership and the shared Session Connect false/finalize boundary. Real loopback
UDP is used after recovery; no natural network event, Steam host or Switch claim.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODES = """client_alloc base_mutex receive_cond timer_node timer_queue timer_mutex
timer_thread socket_alloc socket_fd socket_mutex rx_thread discovery_context
discovery_task""".split()


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def check(receiver, reference):
    source = json.loads(reference.read_text())
    require(source["binary_sha256"] == "15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2", "original binary identity")
    for name, digest in source["helpers"].items():
        require(hashlib.sha256((ROOT / "scripts" / name).read_bytes()).hexdigest() == digest, "source helper identity: " + name)
    cases = source["cases"]
    require([c["event"] for c in cases] == [-1, 0, 1, "explicit_start"], "all original startup triggers")
    for case in cases:
        failed, idle, restarted = (case[k] for k in ("failed", "idle", "restarted"))
        for stopped in (failed, idle):
            require(stopped["state"] == 0 and stopped["socket"] == 0, "original failed startup remains stopped")
            require(stopped["calls"]["start"] == 1 and stopped["calls"]["socket_destroy"] == 1, "original failed socket released without retry")
            require(not any(t[0] == "recvfrom" for t in stopped["trace"]), "original failure has no receive owner")
        require(idle["calls"]["timer_slot"] == 3 and idle["calls"]["update"] == 3, "three original idle timer dispatches")
        require(restarted["state"] == 1 and restarted["socket"] != 0 and restarted["calls"]["start"] == 2,
                "original explicit startup recovers")
        require(restarted["calls"]["socket_receive"] == 1, "original retrigger actually receives")
    results = []
    session_modes = MODES[:11] + ["send_mutex", "reliable_mutex", "send_queue", "pending_queue"]
    for mode in MODES + ["session_" + mode for mode in session_modes]:
        process = subprocess.run([str(receiver.resolve()), mode], text=True, capture_output=True, timeout=10)
        require(process.returncode == 0, f"{mode} exit {process.returncode}: {process.stderr}")
        result = json.loads(process.stdout)
        expected = dict(mode=mode, fault_hits=1, failure_clean=True, no_implicit_retry=True, final_clean=True)
        expected["explicit_retry_transport" if mode.startswith("session_") else "explicit_retry_status"] = True if mode.startswith("session_") else 1
        require(result == expected, "complete Native fault/retry/cleanup observations: " + mode)
        for line in process.stderr.splitlines():
            require(re.fullmatch(r"IHS_UDPSocketOpen: SO_RCVBUF capped at \d+ bytes \(wanted \d+\); raise net.core.rmem_max to avoid dropped video packets", line),
                    "unexpected Native stderr: " + mode + ": " + line)
        results.append(dict(observed=result, stderr=process.stderr))
    return dict(scope=__doc__, source_binary_sha256=source["binary_sha256"], original_plans=len(cases), cases=results)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", required=True, type=Path)
    parser.add_argument("--reference", type=Path, default=ROOT / "scripts/fixtures/steam-discovery-startup-reference.json")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = check(args.receiver, args.reference)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"Discovery startup: {result['original_plans']} original plans, {len(result['cases'])} actual Native fault/retry/cleanup cases passed")


if __name__ == "__main__":
    main()
