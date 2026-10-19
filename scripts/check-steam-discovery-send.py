#!/usr/bin/env python3
"""Compare actual Native local IPv4 broadcast behavior with original send policy.

The Native executable uses real client/UDP/protobuf/timers/cleanup. Explicit
sendto-error and loopback-destination adapters control transient/poisoned-fd
faults without sending to a LAN. Source IPv4 plans provide policy and full wire
bytes. Successful loopback reply/RX is separate Native evidence, not Source or
Steam network proof. Cadence checks relative sequence reuse, not startup's
absolute counter or a real Qt timer. Missing policies are reported as gaps and
exit nonzero; observation/cleanup success alone never means alignment.
"""
import argparse
import gzip
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IDENTITIES = dict(core="50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e",
                  shell="15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2")


def require(value, reason):
    if not value:
        raise ValueError(reason)


def sequence(wire):
    raw = bytes.fromhex(wire)
    require(raw[:8] == bytes.fromhex("ffffffff214c5fa0") and len(raw) >= 16, "discovery envelope")
    header_size = int.from_bytes(raw[8:12], "little")
    start = 12 + header_size
    require(start + 4 <= len(raw), "header/payload lengths")
    length = int.from_bytes(raw[start:start + 4], "little")
    body = raw[start + 4:]
    require(len(body) == length and len(body) == 2 and body[0] == 8 and body[1] < 128,
            "controlled single small discovery sequence")
    return body[1]


def policies(reference):
    source = json.loads(gzip.decompress(reference.read_bytes()))
    for name, digest in source["helpers"].items():
        require(hashlib.sha256((ROOT / "scripts" / name).read_bytes()).hexdigest() == digest,
                "source helper identity: " + name)
    result = []
    for identity, digest in IDENTITIES.items():
        binary = source["binaries"][identity]
        require(binary["binary_sha256"] == digest and len(binary["cases"]) == 27, "source identity/plans")
        cases = {case["name"]: case for case in binary["cases"]}
        expected = {}
        for mode in ("transient", "poisoned", "host"):
            case = cases["broadcast_ipv4_" + ("host_unreachable" if mode == "host" else "recover")]
            row = case["stages"][-1]
            expected[mode] = dict(result=bool(row["returns"][-1]),
                opens_before_cleanup=sum(t[0] == "socket" and t[2] >= 0 for t in row["trace"]),
                closes_before_cleanup=sum(t[0] == "close" for t in row["trace"]), attempts=len(row["sends"]),
                wire=row["sends"][-1]["wire"], owner_retained=True)
        low = cases["broadcast_schedule_lower"]["stages"][-1]["sends"][:3]
        high = cases["broadcast_schedule_upper"]["stages"][-1]["sends"][:3]
        relative = lambda rows: [sequence(row["wire"]) - sequence(rows[0]["wire"]) for row in rows]
        require(relative(low) == relative(high) == [0, 0, 0], "original fast retries reuse sequence")
        expected["cadence"] = dict(relative_sequences=relative(low))
        result.append(expected)
    require(result[0] == result[1], "independent official binary policy agreement")
    return result[0]


def compare(receiver, reference):
    expected = policies(reference)
    cases = []
    for mode, wanted in expected.items():
        process = subprocess.run([str(receiver.resolve()), mode], text=True, capture_output=True, timeout=20)
        require(process.returncode == 0, f"{mode} observation failed ({process.returncode}): {process.stderr}")
        observed = json.loads(process.stdout)
        require(observed["mode"] == mode and observed["cleanup"] is True, "completed Native observation/cleanup")
        for line in process.stderr.splitlines():
            require(re.fullmatch(r"IHS_UDPSocketOpen: SO_RCVBUF capped at \d+ bytes \(wanted \d+\); raise net.core.rmem_max to avoid dropped video packets", line),
                    "unexpected native stderr: " + line)
        if mode == "cadence":
            rows = observed["sends"]
            require(len(rows) == 3 and rows[0]["after_ns"] == 0 and
                    all(rows[i]["after_ns"] > rows[i - 1]["after_ns"] for i in (1, 2)), "actual ordered timer samples")
            values = [sequence(row["wire"]) for row in rows]
            projection = dict(relative_sequences=[value - values[0] for value in values])
        else:
            projection = {name: observed[name] for name in wanted}
        differences = {name: dict(expected=wanted[name], actual=projection[name]) for name in wanted
                       if wanted[name] != projection[name]}
        if mode in ("transient", "poisoned") and not observed["delivered"]:
            differences["native_loopback_status_after_recovery"] = dict(expected=1, actual=observed["delivered"])
        cases.append(dict(mode=mode, observed=observed, expected=wanted, differences=differences,
                          compatible=not differences, stderr=process.stderr))
    return dict(scope=__doc__, compatible=all(case["compatible"] for case in cases), cases=cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", required=True, type=Path)
    parser.add_argument("--reference", type=Path, default=ROOT / "scripts/fixtures/steam-discovery-send-reference.json.gz")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = compare(args.receiver, args.reference)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    gaps = [case["mode"] for case in result["cases"] if not case["compatible"]]
    print(f"Discovery send: {len(result['cases']) - len(gaps)}/{len(result['cases'])} compatible; gaps={','.join(gaps) or 'none'}")
    raise SystemExit(0 if result["compatible"] else 1)


if __name__ == "__main__":
    main()
