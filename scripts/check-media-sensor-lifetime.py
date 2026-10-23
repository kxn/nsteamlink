#!/usr/bin/env python3
"""Check the real media owner's borrow across actual runtime session retirement.

Controlled platform sensor samples are used; this is a local lifetime regression,
not an official protocol oracle, physical IMU test or Steam transport acceptance.
"""
import argparse
import json
from pathlib import Path
import subprocess


def require(value, reason):
    if not value:
        raise ValueError(reason)


def observe(receiver):
    run = subprocess.run([str(receiver)], capture_output=True, text=True, timeout=15)
    require(run.returncode == 0, "abnormal lifetime fixture: " + run.stderr)
    result = json.loads(run.stdout)
    require(len(result["rounds"]) == 2, "two sessions on the retained media root")
    require(result["roots_retained"] is True, "frontend/controller root was replaced")
    require(result["final_clean"] is True, "media root did not shut down")
    for row in result["rounds"]:
        require(row["polls"] == 1, "controlled sensor call was not reached once")
        for field in ("retired", "poll_returned", "hid_worker_joined", "provider_unbound",
                      "session_detached", "initial_neutral"):
            require(row[field] is True, "incomplete lifetime fixture: " + field)
    return result


def verify(receiver):
    result = observe(receiver)
    for row in result["rounds"]:
        require(row["destroy_before_poll_return"] is False,
                "session destroyed during sensor borrow")
        require(row["injected_into_live_session"] is True,
                "sensor did not reach the live SDK HID device")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", required=True, type=Path)
    args = parser.parse_args()
    verify(args.receiver.resolve())
    print("Sensor lifetime: two live injections precede retirement; roots and workers converge")


if __name__ == "__main__":
    main()
