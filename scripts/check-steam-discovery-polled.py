#!/usr/bin/env python3
"""Compare the product's polled discovery entry with original receive batches.

The real runtime start/update/stop functions, SDK polled receive and application
directory/UI publication execute. recvfrom, outgoing acceptance, protocol wall
and actor timestamps are fixtures. This is not the outer worker's real pacing,
Qt/Android scheduling, natural errors, Steam reachability or Switch lifetime.
"""
import argparse
import errno
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ERRORS = ("NONE", "EAGAIN", "ETIMEDOUT", "EINTR", "ECONNREFUSED", "ECONNRESET",
          "ENETUNREACH", "EHOSTUNREACH", "ENETDOWN", "EIO", "EINVAL", "EBADF", "ENOMEM", "ENOBUFS")


def require(value, reason):
    if not value:
        raise ValueError(reason)


def check(receiver, reference):
    source = json.loads(reference.read_text())
    require(source["binary_sha256"] == "15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2", "source binary identity")
    for name, expected in source["helpers"].items():
        require(hashlib.sha256((ROOT / "scripts" / name).read_bytes()).hexdigest() == expected,
                "source helper identity: " + name)
    programs = []
    require(len(source["cases"]) == 4, "four original programs")
    for case in source["cases"]:
        require(case["timer_interval_ms"] == 100, "original timer parameter")
        reads, callbacks = [], []
        socket = case["cycles"][0]["socket"]
        for i, cycle in enumerate(case["cycles"]):
            batch = cycle["input_reads"]
            require(cycle["tick_ms"] == i * 100 and cycle["state"] == 1 and cycle["socket"] == socket != 0,
                    "original retained manager/socket across timer dispatch")
            require(batch[-1] <= 0 and all(value > 0 for value in batch[:-1]), "original batch boundary")
            require([line[-1] for line in cycle["trace"] if line[0] == "recvfrom"] == batch,
                    "original actual reads")
            labels = [value for value in batch if value > 0]
            require([line[1] for line in cycle["trace"] if line[0] == "opaque_datagram"] == labels,
                    "original dispatch order")
            reads.extend(batch)
            callbacks.extend([i, label] for label in labels)
        for error in (errno.ENETDOWN, errno.EAGAIN):
            programs.append((case["name"], error, reads, callbacks))
    for name in ERRORS:
        error = 0 if name == "NONE" else getattr(errno, name)
        programs.append(("single_error" if error else "control", error,
                         [-1, 9, -1] if error else [9, -1], [[1, 9]] if error else [[0, 9]]))

    results = []
    for name, error, reads, callbacks in programs:
        process = subprocess.run([str(receiver.resolve()), str(error), name], text=True,
                                 capture_output=True, timeout=7)
        require(process.returncode == 0, f"{name}/{error}: receiver exit {process.returncode}: {process.stderr}")
        row = json.loads(process.stdout)
        require(row["errno"] == error and row["program"] == name and row["polled"] is True, "actual polled input")
        require(row["reads"] == reads and row["callbacks"] == callbacks, f"{name}/{error}: original read/callback order")
        cycles = sum(value <= 0 for value in reads)
        require(row["cycles"] == cycles and row["actor_pumps"] == 11 * cycles + 4 and
                row["early_pumps"] == 10 * cycles, "actual actor cadence observations")
        require(row["rx_workers"] == 0 and row["opens"] == row["closes"] ==
                row["timer_joins"] == row["cond_destroys"] == 1, "real owner cleanup counts")
        require(row["directory_visible"] == 1 and row["host_events"] > 0,
                "production directory/UI callback after error")
        require(all(row[key] is True for key in ("late_no_catchup", "stopped_no_receive", "final_clean")),
                "late actor/stopped/cleanup observations")
        for line in process.stderr.splitlines():
            require(re.fullmatch(r"IHS_UDPSocketOpen: SO_RCVBUF capped at \d+ bytes \(wanted \d+\); raise net.core.rmem_max to avoid dropped video packets", line),
                    "unexpected stderr: " + line)
        results.append(row)
    return dict(scope=__doc__, source_binary_sha256=source["binary_sha256"],
                receiver_sha256=hashlib.sha256(receiver.read_bytes()).hexdigest(),
                source_sha256={name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                               for name in ("app/platforms/common/runtime.c", "third_party/ihslib/src/client/client.c",
                                            "app/tests/discovery_polled_runtime.c", "scripts/check-steam-discovery-polled.py")},
                cases=results)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", type=Path, required=True)
    parser.add_argument("--reference", type=Path, default=ROOT / "scripts/fixtures/steam-discovery-cycles-reference.json")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = check(args.receiver, args.reference)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"Polled discovery: {len(result['cases'])} original-batch/errno cases with actual runtime entry and cleanup passed")


if __name__ == "__main__":
    main()
