#!/usr/bin/env python3
"""Compare native audio control/start/stop/replay with the official client.

Golden data comes only from original Android instructions. Compare configured
metadata, decoder presence, channel/delay, full pending frames, receive metadata
and lifecycle order. Device format, embedded codec allocation, queue depth and
physical thread scheduling remain separate observations, not native equivalence
claims. Both original SetUseThreads branches project to the same callback API.
"""

import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def project(state, worker_failure=False):
    events = []
    codec = None
    for event in state["events"]:
        kind, *fields = event
        if kind == "request":
            channel, present, explicit, negotiated, rate, channels, data = fields
            codec = explicit if present else negotiated
            events.append(["configured", channel, codec, rate, channels, data])
        elif kind == "device_open" and codec in (1, 3):
            events.append(["start", codec, rate, channels, data])
        elif kind == "decoder_start":
            events.append(["ready"])
        elif kind == "decoder_stop":
            events.append(["stop"])
        elif kind in ("pending", "delay"):
            events.append(event)
        elif kind == "factory":
            # Actual selection must agree with the parsed presence/fallback
            # observation; a locally computed codec is never its only proof.
            assert fields == [codec, rate, channels]
    return dict(
        phase=state["phase"],
        paused=state["paused"],
        channel=state["channel"],
        decoder_ready=state["decoder"] is not None,
        pending=state["pending"],
        delays={k: v for k, v in state["delays"].items() if int(k) >= 3},
        events=events,
        received=[] if worker_failure else state["received"],
        queued=state["queued"] if worker_failure else [],
    )


def run(receiver, actions, fallback=3, fail_worker=False):
    command = [str(receiver.resolve()), str(fallback)]
    if fail_worker:
        command.append("fail-worker")
    lines = [" ".join(str(v) if v != "" else "-" for v in op) for op in actions]
    result = subprocess.run(
        command,
        input="\n".join(lines) + "\n",
        text=True,
        capture_output=True,
        timeout=15,
    )
    assert not result.returncode, (
        actions,
        result.returncode,
        result.stdout,
        result.stderr,
    )
    return [json.loads(line) for line in result.stdout.splitlines()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", type=Path, required=True)
    args = parser.parse_args()
    cases = json.loads(
        (ROOT / "scripts/fixtures/steam-audio-start-reference.json").read_text()
    )["cases"]
    states = count = 0
    for case in cases:
        inp = case["input"]
        if inp.get("source_only"):
            continue
        actual = run(
            args.receiver,
            inp["actions"],
            inp.get("fallback", 3),
            inp.get("worker_failure", False),
        )
        assert len(actual) == len(case["observed"])
        for index, (got, source) in enumerate(zip(actual, case["observed"])):
            want = project(source, inp.get("worker_failure", False))
            assert got == want, (
                inp["name"],
                inp["threads"],
                index,
                inp["actions"][index],
                {
                    k: (got.get(k), want.get(k))
                    for k in got.keys() | want.keys()
                    if got.get(k) != want.get(k)
                },
            )
            states += 1
        count += 1
    print(
        f"Audio startup: {count} official cases/{states} states including failed OS start passed"
    )


if __name__ == "__main__":
    main()
