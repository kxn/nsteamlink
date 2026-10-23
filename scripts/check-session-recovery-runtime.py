#!/usr/bin/env python3
"""Check local runtime/worker/media/UI convergence, not Steam/Switch acceptance."""
import argparse
import json
from pathlib import Path
import subprocess


def require(value, reason):
    if not value:
        raise ValueError(reason)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", required=True, type=Path)
    parser.add_argument("--video", required=True, type=Path)
    args = parser.parse_args()
    result = subprocess.run([str(args.receiver.resolve()), str(args.video.resolve())],
                            capture_output=True, text=True, timeout=80)
    require(result.returncode == 0, "abnormal local recovery fixture: " + result.stderr[-4000:])
    observed = json.loads(result.stdout)
    print(json.dumps(observed, sort_keys=True))
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
    print("Local runtime recovery: real UDP stop/silence/stop, three decoded streams and joined teardown")


if __name__ == "__main__":
    main()
