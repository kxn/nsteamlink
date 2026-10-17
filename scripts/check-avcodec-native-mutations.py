#!/usr/bin/env python3
"""Check AVCodec regression detection using isolated copies of production TUs.

Compile/link success is required before running a mutant. Policy mutants must
fail the official-client comparison without crashing the real Native oracle;
physical/task-identity mutation must fail the real reordered-pixel completion
invariant. No working source/golden edits or device operations are performed.
"""

import argparse
import json
from pathlib import Path
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--build", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    build = a.build.resolve()
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    entries = json.loads((build / "compile_commands.json").read_text())
    pipeline = ROOT / "app/platforms/common/video_pipeline.c"
    video = ROOT / "third_party/ihslib/src/session/channels/video/ch_data_video.c"
    oracle = ROOT / "app/tests/video_timing_oracle.c"
    mutations = [
        (
            "omit_again_first_result",
            pipeline,
            "if (result == AVERROR(EAGAIN)) dropped(ticket, IHS_VideoFrameResultDroppedReset);",
            "/* omit first result */",
            "oracle",
        ),
        (
            "omit_loss_before_put",
            pipeline,
            "if (feedback && (status & SL_VIDEO_SUBMIT_CORRUPT))",
            "if (false)",
            "oracle",
        ),
        (
            "premature_decode_end",
            pipeline,
            "    uint64_t output_seq;\n    bool valid_size, guard;",
            "    IHS_FrameTicketVideoDecodeStage(ticket,true);\n    uint64_t output_seq;\n    bool valid_size, guard;",
            "oracle",
        ),
        (
            "sdk_flush_on_mark",
            pipeline,
            "        /* Original Linux marked FlushPendingData",
            "        avcodec_flush_buffers(d->codec);\n        /* Original Linux marked FlushPendingData",
            "oracle",
        ),
        (
            "omit_real_reset_flag",
            video,
            "if (result & IHS_StreamVideoSubmitReset) atomic_store(&video->resetRequested, true);",
            "/* omit actual reset request */",
            "oracle",
        ),
        (
            "complete_physical_input",
            pipeline,
            "if (s->ticket) IHS_FrameTicketComplete(s->ticket,outcome);",
            "if (s->frame) IHS_FrameTicketComplete(s->frame->ticket,outcome);",
            "reordered",
        ),
    ]
    reports = []
    for name, source, before, after, kind in mutations:
        directory = out / name
        directory.mkdir(exist_ok=True)
        body = source.read_text()
        assert body.count(before) == 1, (name, body.count(before))
        body = body.replace(before, after)
        changed = directory / source.name
        changed.write_text(body)
        target = (
            "nsl-video-timing-oracle"
            if kind == "oracle"
            else "nsl-video-pipeline-tests"
        )
        link = shlex.split(
            (build / f"app/CMakeFiles/{target}.dir/link.txt").read_text()
        )
        objects = []

        def compile_file(original, path, label):
            e = next(e for e in entries if Path(e["file"]).resolve() == original)
            cmd = list(e.get("arguments") or shlex.split(e["command"]))
            obj = directory / (label + ".o")
            cmd[cmd.index("-o") + 1] = str(obj)
            cmd[cmd.index("-c") + 1] = str(path)
            cmd += ["-I" + str(original.parent)]
            with (directory / (label + "-compile.log")).open("w") as log:
                subprocess.run(
                    cmd,
                    cwd=e["directory"],
                    check=True,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                )
            return obj

        if kind == "oracle":
            text = oracle.read_text().replace(
                '#include "../platforms/common/',
                '#include "' + str(ROOT / "app/platforms/common") + "/",
            )
            if source == pipeline:
                text = text.replace(str(pipeline), str(changed))
            copied = directory / "oracle.c"
            copied.write_text(text)
            obj = compile_file(oracle, copied, "oracle")
            index = next(
                i for i, x in enumerate(link) if x.endswith("video_timing_oracle.c.o")
            )
            link[index] = str(obj)
            if source == video:
                objects.append(compile_file(video, changed, "video"))
        else:
            objects.append(compile_file(pipeline, changed, "pipeline"))
        first = next(i for i, x in enumerate(link) if x.endswith(".o"))
        link[first + 1 : first + 1] = list(map(str, objects))
        exe = directory / "mutant"
        link[link.index("-o") + 1] = str(exe)
        with (directory / "link.log").open("w") as log:
            subprocess.run(
                link,
                cwd=build / "app",
                check=True,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        if kind == "oracle":
            command = [
                "python3",
                str(ROOT / "scripts/check-steam-video-avcodec.py"),
                "--receiver",
                str(exe),
            ]
        else:
            command = [
                str(exe),
                str(ROOT / "app/tests/fixtures/video/reordered.h264"),
                str(ROOT / "app/tests/fixtures/video/sequential.h264"),
            ]
        r = subprocess.run(command, capture_output=True, text=True, timeout=60)
        (directory / "stdout.log").write_text(r.stdout)
        (directory / "stderr.log").write_text(r.stderr)
        assert r.returncode != 0, (name, "undetected")
        if kind == "oracle":
            assert (
                "AssertionError:" in r.stderr
                and "returncode" not in r.stderr
                and "StopIteration" not in r.stderr
            ), (name, r.stderr[-2000:])
            assert "(-6," not in r.stderr and "(-11," not in r.stderr, (
                name,
                "oracle crashed",
                r.stderr[-2000:],
            )
        else:
            assert "current[j].statsComplete" in r.stderr, (name, r.stderr[-2000:])
        reports.append(dict(name=name, returncode=r.returncode, detected=True))
    (out / "report.json").write_text(json.dumps(reports, indent=2) + "\n")
    print("AVCodec Native mutants:", len(reports), "detected")


if __name__ == "__main__":
    main()
