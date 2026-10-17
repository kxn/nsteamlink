#!/usr/bin/env python3
"""Compare native focus/owner policy and actual audio cleanup with original gates.

Original caller loop/terminal order remains recorded source evidence; the native
policy projection compares teardown decisions, not SDL_main scheduling. Resource
runs use the actual app audio path; Android hard/background modes are explicit
policy inputs, while production Switch sessions use normal mode.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "audio", ROOT / "scripts/check-steam-audio-player.py"
)
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--policy", type=Path, required=True)
    p.add_argument("--player", type=Path, required=True)
    args = p.parse_args()
    source = json.loads(
        (ROOT / "scripts/fixtures/steam-player-owner-reference.json").read_text()
    )
    lines = []
    for case in source["cases"]:
        i = case["input"]
        lines.append(
            " ".join(
                map(
                    str,
                    [
                        i["flags"],
                        int(i["hard"]),
                        int(i["background"]),
                        len(i["events"]),
                        *map(int, i["events"]),
                    ],
                )
            )
        )
    run = subprocess.run(
        [str(args.policy.resolve())],
        input="\n".join(lines) + "\n",
        text=True,
        capture_output=True,
        timeout=15,
    )
    assert not run.returncode, (run.stdout[-1000:], run.stderr[-1000:])
    actual = [json.loads(line) for line in run.stdout.splitlines()]
    assert len(actual) == len(source["cases"])
    for got, case in zip(actual, source["cases"]):
        state = case["cleanup"]
        actions = state["events"]
        want = dict(
            focus=[x["focus"] for x in case["focus_states"]],
            quit="player_quit" in actions,
            destroy="destroy" in actions,
            background=state["background"],
        )
        assert got == want, (case["input"], got, want)
        # Executed caller order must place client retirement before any player
        # operation, and global network retirement after all player operations.
        start = actions.index("client_quit")
        end = actions.index("network_shutdown")
        assert start < end and actions[-1] == "datagram_kill"
        assert all(
            start < actions.index(x) < end
            for x in ("player_quit", "destroy")
            if x in actions
        )
    assert source["destructor_prefix"] == ["destructor_quit"]
    # Reproduce original audio-slice cases against the same production app
    # callback table, actual worker and SDL dummy devices as the audio audit.
    start = ["C", 50, "100318032880f7023002"]
    frame = ["M", 3, 1, 1100001, 1100011, 1100021, "f0fffe"]
    stop = ["C", 51, "-"]
    for case in source["resources"]:
        i = case["input"]
        op = ["O", int(i["focus"]), int(i["hard"]), int(i["background"])]
        actions = [start, frame, stop, op, ["X"]]
        r = subprocess.run(
            [str(args.player.resolve())],
            input="\n".join(" ".join(map(str, v)) for v in actions) + "\n",
            text=True,
            capture_output=True,
            timeout=15,
        )
        assert not r.returncode, (i, r.stdout[-2000:], r.stderr[-2000:])
        got = [json.loads(line) for line in r.stdout.splitlines()]
        assert got[0] == a.project(case["setup"][0], start)
        assert got[1] == a.project(case["setup"][1], frame)
        assert got[2] == a.project(case["before"], stop), (
            i,
            "before",
            got[2],
            a.project(case["before"], stop),
        )
        assert got[3] == a.project(case["after"], op), (
            i,
            "after",
            got[3],
            a.project(case["after"], op),
        )
    print(
        f"Official player owner: {len(source['cases'])} policy cases + {len(source['resources'])} real app audio cleanup cases passed"
    )


if __name__ == "__main__":
    main()
