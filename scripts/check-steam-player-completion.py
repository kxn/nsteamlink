#!/usr/bin/env python3
"""Check persistent-frontend audio retirement against the full JNI exit boundary.

The original pre-JNI player-owner matrix remains separate and unchanged. The
frozen ARM64/DEX completion evidence requests process exit for all four global
flag combinations; the live Native frontend must release its stream resources
explicitly. This tests actual session/audio cleanup and reuse, not Android OS
exit/task restoration, real network disconnection, video or Switch lifecycle.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "tools/fixtures/steam-android-return-1.3.32.json"


def require(value, reason):
    if not value:
        raise ValueError(reason)


def source_contract():
    source = json.loads(REFERENCE.read_text())
    require(source["core_sha256"] == "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e" and
            source["dex_sha256"] == "a5c315d683eac7c7f8f73ec096bd414406d80f9ef68180a1ef469f052cd39e44",
            "original core/DEX identity")
    require(source["tool_sha256"] == hashlib.sha256((ROOT / "tools/steam-android-return-audit.py").read_bytes()).hexdigest(),
            "original completion producer identity")
    require(source["provider_sha256"] == hashlib.sha256((ROOT / "scripts/audit-steam-client-fec-policy.py").read_bytes()).hexdigest(),
            "original execution provider identity")
    cases = [case for case in source["cases"] if "background" in case]
    require({(c["background"], c["hard"]) for c in cases} == {(0,0),(0,1),(1,0),(1,1)}, "all original completion flags")
    for case in cases:
        require(case["exit_request"] == 0 and case["returned_to_native"] is False, "original exit request boundary")
        require([event["method"][1] for event in case["java"]] ==
                ["setLowLatencyAudio", "disableWiFiLock", "onStreamingResult", "exit"], "original callback order")
        require(case["java"][-1]["args"] == [0], "original zero exit status")
    return source


def verify(receiver, focus):
    process = subprocess.run([str(receiver.resolve()), str(int(focus))], text=True, capture_output=True, timeout=15)
    require(process.returncode == 0, f"abnormal completion fixture {process.returncode}: {process.stderr}")
    observed = json.loads(process.stdout)
    require(observed["final_clean"] is True and len(observed["rounds"]) == 2, "actual two-session/root cleanup")
    for row, expected in zip(observed["rounds"], (focus, not focus)):
        require(row["focus"] is expected, "focus is not an app-lifecycle alias")
        require(row["retained"] is False, "stream player survived completed session")
        require(row["completion_boundary"] is True, "missing full completion mapping")
        require(row["closed_after_owner"] is True and row["join_before_destroy_before_owner"] is True,
                "real join/destroy/player-close ordering")
    return observed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", type=Path, required=True)
    parser.add_argument("--focus", type=int, choices=(0,1), required=True)
    args = parser.parse_args()
    source_contract()
    observed = verify(args.receiver, bool(args.focus))
    print(json.dumps(observed))


if __name__ == "__main__":
    main()
