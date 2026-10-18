#!/usr/bin/env python3
"""Compare the official audio control/PCM/player path with the live app backend.

Native runs control FIFO, pending/RX, actual decoder worker and app codec/jitter;
real SDL dummy devices are paused and their actual production callback is pulled
at controlled steps. Compare full float codec bytes/metadata, physical/logical
geometry, retained devices/rings, jitter scalars and all ring bytes, plus S16
output. SDL3 float partial-write -> SDL2 S16 zero-fill is the declared IO adapter.
Source base frame-completion cursor and SDL hints remain source observations,
not claims of a native/UI/whole-player memory image match.
"""

import argparse
import base64
import json
from pathlib import Path
import struct
import subprocess
import zlib

ROOT = Path(__file__).resolve().parents[1]


def project(state, action):
    output = b"".join(zlib.decompress(base64.b64decode(v)) for v in state["output"])
    values = struct.unpack("<" + "f" * (len(output) // 4), output)
    pcm = struct.pack(
        "<" + "h" * len(values),
        *(max(-32768, min(32767, round(v * 32768))) for v in values),
    )
    if action[0] == "A":
        size = action[1] * state["requested"][2] * 2
        assert len(pcm) <= size
        pcm += bytes(size - len(pcm))
    return dict(
        channel=state["channel"],
        pending=state["pending"],
        params=state["params"],
        decoder=state["decoder"] is not None,
        logical=state["logical_format"][1:3],
        requested=state["requested"][1:3],
        stream=state["stream"] or 0,
        running=state["stream"] is not None,
        pcm=[
            {**frame, "data": zlib.decompress(base64.b64decode(frame["data"])).hex()}
            for frame in state["pcm"]
        ],
        output=pcm.hex(),
        queued=state["queued"],
        ring_sha256=state["ring_sha256"],
        jitter_state=state["jitter_state"],
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    args = p.parse_args()
    source = json.loads(
        (ROOT / "scripts/fixtures/steam-audio-player-reference.json").read_text()
    )
    states = frames = 0
    for case in source["cases"]:
        inp = case["input"]
        actions = inp["actions"]
        run = subprocess.run(
            [str(args.receiver.resolve())],
            input="\n".join(
                " ".join(str(v) if v != "" else "-" for v in op) for op in actions
            )
            + "\n",
            text=True,
            capture_output=True,
            timeout=15,
        )
        assert not run.returncode, (
            inp["name"],
            run.returncode,
            run.stdout[-4000:],
            run.stderr[-4000:],
        )
        actual = [json.loads(v) for v in run.stdout.splitlines()]
        assert len(actual) == len(case["observed"])
        for i, (got, state, action) in enumerate(
            zip(actual, case["observed"], actions)
        ):
            want = project(state, action)
            assert got == want, (
                inp["name"],
                i,
                action[:2],
                {
                    k: (got.get(k), want.get(k))
                    for k in got.keys() | want.keys()
                    if got.get(k) != want.get(k)
                },
            )
            states += 1
            frames += len(state["pcm"])
    print(
        f"Official audio control/PCM/player path: {len(source['cases'])} cases/{states} states/{frames} full float PCM frames passed"
    )


if __name__ == "__main__":
    main()
