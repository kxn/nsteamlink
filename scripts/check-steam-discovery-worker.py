#!/usr/bin/env python3
"""Compare the real runtime worker's local startup/receive ownership with Steam.

Official receive batches and failed-startup records constrain this projection.
Native runs its public lifecycle and real outer pthread worker/timer clocks.
Cloud objects are real; their DNS/TLS pumping, debug UDP and outbound datagrams
are adapted. No real Steam, natural network switch or Switch proof is claimed.
"""
import argparse
import errno
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("polled", ROOT / "scripts/check-steam-discovery-polled.py")
polled = importlib.util.module_from_spec(spec)
spec.loader.exec_module(polled)
require = polled.require
SHA = "15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2"


def load_reference(name):
    source = json.loads((ROOT / "scripts/fixtures" / name).read_text())
    require(source["binary_sha256"] == SHA, "official binary identity")
    for name, digest in source["helpers"].items():
        require(hashlib.sha256((ROOT / "scripts" / name).read_bytes()).hexdigest() == digest,
                "official helper identity: " + name)
    return source


def plans():
    batches = load_reference("steam-discovery-cycles-reference.json")
    startup = load_reference("steam-discovery-startup-reference.json")
    manager = load_reference("steam-network-discovery-reference.json")
    failed = next(case for case in manager["cases"] if case["input"] ==
                  dict(kind="start", local=1, remote=1, socket_result=-1, remote_result=1))["observed"]
    require(failed["state"] == failed["socket"] == failed["remote"] == 0 and
            not any(row[0].startswith("remote_") for row in failed["trace"]),
            "official local failure returns before remote construction")
    for case in startup["cases"]:
        require(case["idle"]["state"] == 0 and case["idle"]["calls"]["start"] == 1 and
                case["idle"]["calls"]["timer_slot"] == 3, "official idle ticks do not restart")
        require(case["restarted"]["state"] == 1 and case["restarted"]["calls"]["start"] == 2,
                "official explicit retrigger")
    out = []
    for case in batches["cases"]:
        reads, callbacks = [], []
        require(case["timer_interval_ms"] == 100, "official timer argument")
        for index, cycle in enumerate(case["cycles"]):
            require(cycle["state"] == 1 and cycle["socket"] != 0 and cycle["tick_ms"] == index * 100,
                    "official continued receive owner")
            batch = cycle["input_reads"]
            require([row[-1] for row in cycle["trace"] if row[0] == "recvfrom"] == batch and
                    batch[-1] <= 0 and all(value > 0 for value in batch[:-1]), "official read batch")
            labels = [value for value in batch if value > 0]
            require([row[1] for row in cycle["trace"] if row[0] == "opaque_datagram"] == labels,
                    "official handoff labels")
            reads.extend(batch)
            callbacks.extend([index, label] for label in labels)
        for error in (errno.ENETDOWN, errno.EAGAIN):
            out.append(dict(mode="receive", error=error, name=case["name"], reads=reads, callbacks=callbacks))
    for name in polled.ERRORS:
        error = 0 if name == "NONE" else getattr(errno, name)
        out.append(dict(mode="receive", error=error, name="single_error" if error else "control",
                        reads=[-1, 9, -1] if error else [9, -1], callbacks=[[1, 9]] if error else [[0, 9]]))
    for mode in ("socket", "subscription"):
        out.append(dict(mode=mode, error=errno.ENETDOWN, name="negative_then_recovery",
                        reads=[-1,-1,-1,-1,-1,9,-1,7,0], callbacks=[[5,9],[6,7]]))
        out.append(dict(mode=mode + "-exit", error=errno.ENETDOWN, name="negative_then_recovery", reads=[], callbacks=[]))
    return out


def verify(receiver, plan):
    mode, error, name = (plan[key] for key in ("mode", "error", "name"))
    process = subprocess.run([str(receiver.resolve()), mode, str(error), name], capture_output=True,
                             text=True, timeout=10)
    require(process.returncode == 0, f"{mode}: abnormal receiver {process.returncode}: {process.stderr}")
    row = json.loads(process.stdout)
    require((row["mode"], row["errno"], row["program"]) == (mode, error, name), "actual worker input")
    require(row["reads"] == plan["reads"] and row["callbacks"] == plan["callbacks"], "actual worker batch/callback order")
    if mode != "receive":
        require(row["failure_attempts"] == 1 and row["failure_reads"] == 0, "failed startup implicitly restarted")
        require(row["failure_cloud"] == 0, mode + ": cloud constructed after failed local initialization")
    exiting = mode.endswith("-exit")
    require(row["cloud_creates"] == row["cloud_destroys"] == (0 if exiting else 1),
            mode + ": explicit startup did not construct exactly one cloud owner")
    require(row["early_cloud_creates"] == 0 and (row["cloud_pumps"] == 0 if exiting else row["cloud_pumps"] > 0),
            "cloud readiness/order observation")
    attempts = 1 if mode == "receive" or exiting else 2
    opens = 0 if mode == "socket-exit" else 2 if mode == "subscription" else 1
    require(row["attempts"] == attempts and row["opens"] == row["closes"] == opens and
            row["timer_joins"] == row["cond_creates"] == row["cond_destroys"] == attempts,
            "real local resources after worker teardown")
    require(row["runtime_joins"] == 1 and row["rx_workers"] == 0 and (row["host_events"] == 0 if exiting else row["host_events"] > 0),
            "actual outer worker join/polled/UI observations")
    if any(value <= 0 for value in plan["reads"][:-1]):
        require(row["min_read_gap_ns"] >= 90000000, "real outer-worker negative-read pacing")
    require(row["stop_ns"] < 1000000000, "outer worker stop/join exceeded desktop test bound")
    for line in process.stderr.splitlines():
        require(re.fullmatch(r"IHS_UDPSocketOpen: SO_RCVBUF capped at \d+ bytes \(wanted \d+\); raise net.core.rmem_max to avoid dropped video packets", line),
                "unexpected worker stderr: " + line)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    rows = [verify(args.receiver, plan) for plan in plans()]
    result = dict(scope=__doc__, source_binary_sha256=SHA,
                  receiver_sha256=hashlib.sha256(args.receiver.read_bytes()).hexdigest(),
                  source_sha256={str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                 for path in (ROOT / "app/platforms/common/runtime.c",
                                              ROOT / "app/tests/discovery_worker_runtime.c", Path(__file__))}, cases=rows)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"Discovery worker: {len(rows)} actual outer-worker startup/receive/retry/cleanup cases passed")


if __name__ == "__main__":
    main()
