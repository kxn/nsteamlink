#!/usr/bin/env python3
"""Compare real Native UDP/authentication with fixed original client processes.

Both clients use real UDP/crypto/control workers against explicit loopback peer
inputs. Protocol bytes, phases, MTU and failure close/join are compared. This is
not a genuine Steam host, real pairing, complete negotiation or device proof.
"""

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", type=Path, required=True)
    parser.add_argument("--source-report", type=Path)
    args = parser.parse_args()
    report = (
        json.loads(args.source_report.read_text())
        if args.source_report
        else json.loads(
            gzip.decompress(
                (
                    ROOT / "scripts/fixtures/steam-client-auth-reference.json.gz"
                ).read_bytes()
            )
        )
    )
    assert (
        report["client_sha256"]
        == "95482ca6120f90bb90798b27206b7946ab732e079f008d7fc90ea58a8b0074e1"
    )
    assert len(report["source_functions"]) == 27 and len(report["cases"]) == 27
    for key, name in [
        ("helper_sha256", "steam-client-auth-gdb.py"),
        ("udp_helper_sha256", "steam-client-udp-gdb.py"),
        ("bootstrap_helper_sha256", "steam-client-sdk-gdb.py"),
    ]:
        assert (
            report[key]
            == hashlib.sha256((ROOT / "scripts" / name).read_bytes()).hexdigest()
        ), name
    for case in report["cases"]:
        source = case["process"]
        assert (
            source["cleanup_complete"]
            and source["exit_code"] == 0
            and not source["source_assertions"]
        )
        assert source["module_refs"] == [0, 0]
        wire_requests = [
            bytes.fromhex(p["data"])
            for p in case["received"]
            if bytes.fromhex(p["data"])[0] & 127 == 5
            and bytes.fromhex(p["data"])[13] == 1
        ]
        request = (
            (wire_requests[0][13:-4] if case["crc"] else wire_requests[0][13:]).hex()
            if wire_requests
            else ""
        )
        result = subprocess.run(
            [
                str(args.receiver.resolve()),
                str(int(case["crc"])),
                case["server"],
                case["response"] if case["response"] is not None else "-",
                str(int(case["finish_event"] == "server_handshake_return")),
            ],
            text=True,
            capture_output=True,
            timeout=10,
        )
        assert result.returncode == 0, (
            case["name"],
            result.returncode,
            result.stderr[-3000:],
        )
        native = json.loads(result.stdout)
        state = source["connected_state"]
        expected = dict(
            phase=state["client_phase"],
            mtu=state["mtu"],
            closed=state["client_phase"] == 0,
            goodbyes=int(state["client_phase"] == 0),
            requested=bool(source["authentication_frames"]),
            response_handled=case["response"] is not None,
            request=request,
        )
        assert {key: native[key] for key in expected} == expected, (
            case["name"],
            native,
            expected,
        )
        assert native["connects"] >= 1
    print(
        "Native/original real UDP authentication: 27 request/response/parser/lifecycle cases passed"
    )


if __name__ == "__main__":
    main()
