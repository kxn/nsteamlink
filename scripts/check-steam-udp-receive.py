#!/usr/bin/env python3
"""Compare original UDP boundaries to actual native loopback and wait calls.

No normalization of missing/truncated original deliveries. Syscall error
continuation through session workers is separately gated by udp_error_worker.
Neither these fixtures nor the original syscall adapters prove Switch errors.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    fixture = json.loads(
        (ROOT / "scripts/fixtures/steam-udp-receive-reference.json").read_text()
    )
    assert (
        fixture["binary_sha256"]
        == "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"
    )
    for path, digest in fixture["helpers"].items():
        assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == digest, path
    rows, waits = [], []
    executable = str(args.receiver.resolve())
    for case in fixture["cases"]:
        want = case["observed"]
        if "wire" in case["input"]:
            run = subprocess.run(
                [executable, case["input"]["wire"]],
                capture_output=True,
                text=True,
                timeout=15,
            )
            assert run.returncode == 0, (
                case["input"]["name"],
                run.returncode,
                run.stderr,
            )
            got = json.loads(run.stdout)
            read, frames = want["reads"][0], want["cycles"][0]["delivered"]
            capacity_match = got["capacity"] == read["capacity"]
            bytes_match = (
                got["received_bytes"] == read["result"]
                and got["received_sha256"] == read["received_sha256"]
            )
            delivery_match = got["delivered"] == bool(frames)
            if frames:
                delivery_match &= (
                    got["body_bytes"] == frames[0]["bytes"]
                    and got["body_sha256"] == frames[0]["sha256"]
                )
            rows.append(
                dict(
                    name=case["input"]["name"],
                    source_read=read,
                    source_delivery=frames,
                    native=got,
                    capacity_match=capacity_match,
                    bytes_match=bytes_match,
                    delivery_match=delivery_match,
                    matched=capacity_match
                    and bytes_match
                    and delivery_match
                    and got["joined"],
                )
            )
        else:
            state, selected = want["cycles"][0], want["selects"][0]
            run = subprocess.run(
                [
                    executable,
                    "--wait",
                    str(selected["result"]),
                    str(int(selected["clear_sets"])),
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            assert run.returncode == 0, (case["input"]["name"], run.stderr)
            got = json.loads(run.stdout)
            waits.append(
                dict(
                    name=case["input"]["name"],
                    source=state["wait_ready"],
                    native=got,
                    matched=got["readable"] == state["wait_ready"]
                    and got["select_calls"] == 1,
                )
            )
    report = dict(
        scope=__doc__,
        cases=rows,
        waits=waits,
        capacities_matched=sum(v["capacity_match"] for v in rows),
        datagrams_matched=sum(v["bytes_match"] for v in rows),
        deliveries_matched=sum(v["delivery_match"] for v in rows),
        all_matched=all(v["matched"] for v in rows + waits),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"UDP receive: capacity {report['capacities_matched']}/{len(rows)}, actual datagrams {report['datagrams_matched']}/{len(rows)}, CRC/window deliveries {report['deliveries_matched']}/{len(rows)}, wait {sum(v['matched'] for v in waits)}/{len(waits)}"
    )
    return 0 if report["all_matched"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
