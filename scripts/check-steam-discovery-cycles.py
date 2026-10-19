#!/usr/bin/env python3
"""Compare real Native receive batches with original discovery cycle programs.

Source positive labels 9/7 identify opaque read lengths; Native uses real valid
Status datagrams with timestamps 9/7 to observe callback order. This compares
receive-batch policy, not equal wire parsing (Source BProcess is a terminal).
Native timing/CPU use actual POSIX clocks/waits; three early wakes are adapters.
Persistent Stop uses a declared gate before forwarding the real cond wait,
then actual Stop/signal/join/destroy. No Switch/Qt physical timing claim.
"""
import argparse
import errno
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def run(receiver, *args):
    process = subprocess.run([str(receiver.resolve()), *map(str, args)],
                             text=True, capture_output=True, timeout=7)
    require(process.returncode == 0, f"fixture exit {process.returncode}: {process.stderr}")
    result = json.loads(process.stdout)
    require(result["joined_closed_destroyed"] is True and result["nonblocking"] is True,
            "live nonblocking socket and cleanup")
    require(result["signals"] == result["joins"] == result["destroys"] == 1,
            "actual signal -> join -> condition destroy")
    require(result["socket_live_before_stop"] is True, "socket retained before explicit Stop")
    require(result["min_read_gap_ns"] >= 90000000, "nonpositive reads paced, including early wake")
    require(result["stop_ns"] < 1000000000, "stop signal didn't release real wait")
    return result


def check(receiver, reference):
    source = json.loads(reference.read_text())
    require(source["binary_sha256"] == "15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2", "source identity")
    require({c["name"] for c in source["cases"]} == {
        "negative_then_recovery", "zero_then_recovery", "positive_before_error", "alternating"}, "source programs")
    rows = []
    for case in source["cases"]:
        require(case["timer_interval_ms"] == 100, "original timer parameter")
        expected = []
        sock = case["cycles"][0]["socket"]
        for index, cycle in enumerate(case["cycles"]):
            require(cycle["tick_ms"] == index * 100 and cycle["state"] == 1
                    and cycle["socket"] == sock != 0 and cycle["updating"] == 0, "source cycle continuation")
            reads = cycle["input_reads"]
            require(reads[-1] <= 0 and all(r > 0 for r in reads[:-1]), "source batch boundary")
            require([t[-1] for t in cycle["trace"] if t[0] == "recvfrom"] == reads, "actual original reads")
            positives = [r for r in reads if r > 0]
            require([t[1] for t in cycle["trace"] if t[0] == "opaque_datagram"] == positives, "actual source opaque handoffs")
            expected.extend([index, value] for value in positives)
        for error, early in ((errno.ENETDOWN, 0), (errno.EAGAIN, 3)):
            native = run(receiver, error, case["name"], early)
            require(native["callbacks"] == expected and native["delivered"] == len(expected), "callback batch/order")
            require(native["spurious"] == early, "early wake actually exercised")
            rows.append(dict(program=case["name"], errno=error, spurious=early, observed=native))
    for name in ("ENETDOWN", "EAGAIN", "EIO", "ZERO"):
        error = getattr(errno, name) if name != "ZERO" else 0
        native = run(receiver, error, "persistent")
        require(native["persistent"] is True and native["reads"] == 4 and native["delivered"] == 0,
                "four persistent failures then stop at actual wait")
        require(native["waits"] >= 4 and native["cpu_ns"] < 50000000,
                "actual waits and bounded desktop thread CPU")
        rows.append(dict(program="persistent_stop", errno=error, observed=native))
    process = subprocess.run([str(receiver.resolve()), "condfail"],
                             text=True, capture_output=True, timeout=7)
    require(process.returncode == 0, "condition allocation failure cleanup")
    require(json.loads(process.stdout) == dict(condition_failure=True, client_rejected=True),
            "condition allocation failure rejects owner")
    rows.append(dict(program="condition_failure", observed=json.loads(process.stdout)))
    return dict(scope=__doc__, source_binary_sha256=source["binary_sha256"], cases=rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", type=Path, required=True)
    parser.add_argument("--reference", type=Path, default=ROOT / "scripts/fixtures/steam-discovery-cycles-reference.json")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = check(args.receiver, args.reference)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print("Discovery cycles:", len(result["cases"]), "batch/spurious-wake/persistent-stop cases passed")


if __name__ == "__main__":
    main()
