#!/usr/bin/env python3
"""Compare production POSIX deadlines to original event arithmetic, plus OS faults.

The primitive is not the event: zero/infinite/retained signal are event-layer
branches. Existing decoder_overlap covers that layer. Here only finite positive
deadline projections are compared; wake-result and cleanup are local invariants.
"""
import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def check(receiver):
    reference = json.loads(
        (ROOT / "scripts/fixtures/steam-wait-clock-reference.json").read_text()
    )
    data = json.loads(subprocess.check_output([str(receiver)], text=True, timeout=10))
    mono = data["monotonic"]
    assert mono != data["realtime"]
    assert data["creation"] == [
        [0, 1, 1, 1, 1, 1, mono],
        [1, 0, 1, 0, 0, 0, -1],
        [2, 0, 1, 1, 0, 0, -1],
        [3, 0, 1, 1, 1, 0, mono],
    ], data["creation"]
    deadlines = {}
    for c in reference["cases"]:
        attr = [t[1] for t in c["trace"] if t[0] == "pthread_condattr_setclock"]
        assert attr == [1]  # Android CLOCK_MONOTONIC; never a portable numeric ID.
        clocks = [t[1] for t in c["trace"] if t[0] == "clock_gettime"]
        waits = [t[1] for t in c["trace"] if t[0] == "pthread_cond_timedwait"]
        if waits:
            assert clocks == [1] and all(w == waits[0] for w in waits)
            deadlines[c["timeout"]] = waits[0]
    assert len(data["waits"]) == 40
    for wall, duration, result, success, clock, count, sec, nsec in data["waits"]:
        expected = deadlines[duration] if duration else [15, 999500000]
        assert [sec, nsec] == expected, (wall, duration, [sec, nsec], expected)
        assert clock == mono and count == 1 and success == (result < 2)
    assert data["clock_error"] == [0, 0], data["clock_error"]
    assert data["real_timeout"] == [1, mono, 1], data["real_timeout"]
    print(
        "POSIX clock: 4 creation paths, 40 waits, read error, real kernel timeout; official positive deadlines match"
    )
    return data


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", required=True, type=Path)
    a = p.parse_args()
    check(a.receiver)
