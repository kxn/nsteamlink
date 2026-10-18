#!/usr/bin/env python3
"""Historical Android/MediaCodec projection; not the AVCodec acceptance gate.

The product now follows the separately replayed Linux AVCodec caller (§91–93).
This retained helper documents the old Android projection and is not registered
as a product CTest; current FFmpeg acceptance is check-steam-video-avcodec.py.

Native runs actual control/parser/worker/FFmpeg/media/SDL and endpoint stages.
SDK output availability and Native suppression are declared backend inputs. The
comparison covers configured texture-mode input completion/16-17 and defined
buffer selections. NDK timeout/flush, Surface/platform failure, full startup/UI
cadence and physical device equivalence remain outside this projection.
"""

import argparse
import gzip
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(receiver, commands):
    result = subprocess.run(
        [str(receiver), str(ROOT / "app/tests/fixtures/video/sequential.h264")],
        input="\n".join(commands) + "\n",
        text=True,
        capture_output=True,
        timeout=20,
    )
    assert not result.returncode, result.stderr[-3000:]
    return [json.loads(line) for line in result.stdout.splitlines()]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    a = p.parse_args()
    receiver = a.receiver.resolve()
    fixture = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-video-present-reference.json.gz"
            ).read_bytes()
        )
    )
    count = states = 0
    for case in fixture["cases"]:
        inp = case["input"]
        if (
            inp.get("surface")
            or inp["shape"] in ("no_output", "release_failure")
            or inp.get("present_status") is False
        ):
            continue
        commands = ["B " + str(inp["budget"])]
        if inp["shape"] in ("future_output", "future_then_reuse", "future_chain"):
            commands += ["X 1"]
        mapping = []
        for n, action in enumerate(case["actions"]):
            if action[0] == "P":
                commands.append(" ".join(str(x) for x in action))
            elif action[0] == "D":
                commands.append("D " + str(action[1]))
                mapping.append((n, len(commands) - 1))
        native = run(receiver, commands)
        ids = {row[1] for row in case["states"][-1]["jobs"]}
        for src, dst in mapping:
            source, got = case["states"][src], native[dst]
            completed = [
                [fid, result]
                for typ, fid, result in source["complete_abi"]
                if typ == 1 and fid in ids and result in (1, 6)
            ]
            prep = [
                [fid, event]
                for _, fid, event, _ in source["events"]
                if event in (16, 17)
            ]
            assert got["completed"] == completed, (
                inp,
                src,
                "completion",
                got["completed"],
                completed,
            )
            assert [row[1:] for row in got["prep"]] == prep, (
                inp,
                src,
                "16/17",
                got["prep"],
                prep,
            )
            assert [row[1:] for row in got["codec_pts"]] == [
                row[1:] for row in source["input_pts"]
            ], (inp, src, "codec PTS")
            # BufferInfo-not-supplied domains retain their original caller
            # completion evidence, without claiming physical pixel selection.
            if not any(row[0] == src for row in source["unsupplied_info_reads"]):
                new_done = [
                    fid
                    for typ, fid, result in source["complete_abi"]
                    if typ == 1 and fid in ids and result == 1
                ]
                selected_here = next(
                    (row for row in got["selected"] if row[0] == dst), None
                )
                if selected_here and selected_here[1] is not None and new_done:
                    physical = next(
                        (row[1] for row in got["physical_selected"] if row[0] == dst),
                        None,
                    )
                    previous = None
                    for row in source["io"]:
                        if (
                            row[1] != "AMediaCodec_releaseOutputBuffer"
                            or not row[3]
                            or row[4]
                        ):
                            continue
                        stamp = next(
                            v[4]
                            for v in reversed(source["io"])
                            if v[1] == "dequeue" and v[0] == row[0] and v[3] == row[2]
                        )
                        previous = next(
                            v[1] for v in source["input_pts"] if v[3] == stamp
                        )
                    assert physical == previous, (
                        inp,
                        src,
                        "physical identity",
                        physical,
                        previous,
                    )
            states += 1
        count += 1
    # Independent SDK PTS generation vectors: original duplicate/regressive/
    # wrap/zero media timestamps and decoder input paths, all original cases.
    output = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-video-output-reference.json.gz"
            ).read_bytes()
        )
    )
    for case in output["cases"]:
        commands = [
            " ".join(str(v) for v in action)
            for action in case["actions"]
            if action[0] == "P"
        ]
        native = run(receiver, commands)
        assert native and [v[1:] for v in native[-1]["codec_pts"]] == [
            v[1:] for v in case["states"][-1]["input_pts"]
        ], (case["input"], "PTS generation")
    print(
        "Video presentation:",
        count,
        "official cases/",
        states,
        "presentation states;",
        len(output["cases"]),
        "SDK PTS vectors passed",
    )


if __name__ == "__main__":
    main()
