#!/usr/bin/env python3
"""Compare producer gating and nonterminal transport errors with official callers.

The native bool/result is queue admission; final Socket failures are driven
separately after real queueing/retention, not relabeled as synchronous Frame::Send.
Original channel/protobuf/encryption adapters do not prove whole wire equivalence.
"""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", type=Path, required=True)
    args = parser.parse_args()
    fixture = json.loads(
        (ROOT / "scripts/fixtures/steam-send-admission-reference.json").read_text()
    )

    def run(state, kind, value, code=0, present=True, fault=0):
        completed = subprocess.run(
            [
                str(args.receiver.resolve()),
                *map(str, (state, kind, value, code, int(present), fault)),
            ],
            text=True,
            capture_output=True,
            timeout=10,
        )
        assert completed.returncode == 0, completed.stderr
        return json.loads(completed.stdout)

    checked = 0
    for case in fixture["cases"]:
        group, inp, want = case["group"], case["input"], case["observed"]
        if group == "crypto_fault":
            continue  # explicit project protection, not an equivalent unsafe payload path
        frame = group == "frame_gate"
        kind = 0 if frame else 1
        value = int(inp["reliable"]) if frame else inp["message"]
        present = inp.get("connection", True)
        got = run(inp["state"], kind, value, inp["channel_result"], present)
        entered = any(a["action"] == "channel_send" for a in want["actions"])
        assert got["state"] == want["state"] and not got["interrupted"], (
            case["case"],
            got,
            want,
        )
        assert got["sequence"] == want["sequence"], (case["case"], got, want)
        assert got["encrypt_calls"] == int(
            not frame and inp["message"] not in (1, 2, 6, 7)
        )
        assert got["queued"] == int(entered), (case["case"], got, want)
        assert got["admission"] == (0 if entered else 3), (case["case"], got)
        assert got["attempts"] == int(entered)
        assert got["next_id"] == int(entered)  # rejection must consume no sequence ID
        if entered:
            assert got["socket_result"] == want["frame_result"], (
                case["case"],
                got,
                want,
            )
        else:
            assert got["socket_result"] == -1 and want["frame_result"] == 3
        assert got["pending"] == int(entered and (kind or value))
        checked += 1
    assert checked == 162
    # These are named project guards. Do not send the plaintext left by failed
    # crypto, or continue after a local retention failure creates an ID hole.
    for fault in (1, 2):
        got = run(1, 1, 106, fault=fault)
        assert got["queued"] == 0 and got["pending"] == 0 and got["interrupted"]
        assert got["sequence"] == 8 and got["state"] == 2
        assert got["next_id"] == int(fault == 2)
    print(
        f"Production send admission: {checked} official-reference projections + 2 local fault guards passed"
    )


if __name__ == "__main__":
    main()
