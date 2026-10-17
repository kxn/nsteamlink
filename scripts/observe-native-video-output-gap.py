#!/usr/bin/env python3
"""Observe actual native output gating against the official §88 availability case.

This is a research comparison, not a regression test requiring the old mismatch.
It builds an isolated observer from the existing runtime/pipeline oracle TU and
its actual configured compile/link commands. Production/golden files stay intact.
Both sides start with an explicit valid jitter budget of 10 ms. The real FFmpeg
first output is suppressed at the declared backend boundary; its second actual
output remains, matching the official SDK output availability input. Native
returned pixels retain the oracle's independent framemd5 check. This establishes
neither natural physical decoder failure nor the full player completion policy.
"""

import argparse
import gzip
import json
import shlex
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(text, before, after):
    assert text.count(before) == 1, ("observer API changed; re-audit adapter", before)
    return text.replace(before, after)


def observe(build, output):
    output.mkdir(parents=True, exist_ok=True)
    source = (ROOT / "app/tests/video_timing_oracle.c").read_text()
    for file in ("video_pipeline.c", "runtime.c"):
        source = replace_once(
            source,
            '"../platforms/common/' + file + '"',
            json.dumps(str(ROOT / "app/platforms/common" / file)),
        )
    source = replace_once(
        source,
        "uint64_t before = p->publish_seq;",
        "if (submitCount==1) { pthread_mutex_lock(&p->mailbox); "
        "p->timing.budget=10; pthread_mutex_unlock(&p->mailbox); } "
        "uint64_t before = p->publish_seq;",
    )
    source = replace_once(
        source,
        "assert(result == SL_VIDEO_SUBMIT_OK && p->publish_seq == before + (size != 0));\n"
        "    if (!size) return result;",
        "assert(result == SL_VIDEO_SUBMIT_OK);\n"
        "    if (!size || p->publish_seq==before) return result;",
    )
    source = replace_once(
        source,
        "int result=__real_avcodec_receive_frame(c,frame);\n"
        "    if (result>=0) clockTick+=outputTicks;",
        "int result=__real_avcodec_receive_frame(c,frame);\n"
        "    static bool firstMissing;\n"
        "    if (result>=0 && !firstMissing) {\n"
        "        packet_token *token=(packet_token *)frame->opaque_ref->data;\n"
        '        fprintf(stderr,"backend suppresses actual output %u\\n",'
        "IHS_FrameTicketIdentity(token->ticket).frameId);\n"
        "        firstMissing=true; av_frame_unref(frame); return AVERROR(EAGAIN);\n"
        "    }\n"
        "    if (result>=0) clockTick+=outputTicks;",
    )
    observer = output / "observer.c"
    observer.write_text(source)
    entries = json.loads((build / "compile_commands.json").read_text())
    entry = next(e for e in entries if e["file"].endswith("/video_timing_oracle.c"))
    command = entry.get("arguments") or shlex.split(entry["command"])
    command[command.index("-c") + 1] = str(observer)
    command[command.index("-o") + 1] = str(output / "observer.o")
    subprocess.run(command, cwd=entry["directory"], check=True)
    link = shlex.split(
        (build / "app/CMakeFiles/nsl-video-timing-oracle.dir/link.txt").read_text()
    )
    link = [arg for arg in link if not arg.startswith("-Wl,--dependency-file=")]
    link[link.index("-o") + 1] = str(output / "observer")
    link[
        link.index(
            "CMakeFiles/nsl-video-timing-oracle.dir/tests/video_timing_oracle.c.o"
        )
    ] = str(output / "observer.o")
    subprocess.run(link, cwd=build / "app", check=True)
    actions = (
        "P 1 1 24 998689 1000000 0 2204\n"
        "P 2 2 8 1001311 1000000 0 2204\n"
        "N 1000000\nN 1003000\n"
    )
    run = subprocess.run(
        [
            str(output / "observer"),
            str(ROOT / "app/tests/fixtures/video/sequential.h264"),
        ],
        input=actions,
        text=True,
        capture_output=True,
        timeout=20,
    )
    (output / "native-states.jsonl").write_text(run.stdout)
    (output / "native-stderr.log").write_text(run.stderr)
    assert not run.returncode, (run.returncode, run.stderr[-3000:])
    assert "backend suppresses actual output 1" in run.stderr
    native = [json.loads(line) for line in run.stdout.splitlines()]
    fixture = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-video-output-reference.json.gz"
            ).read_bytes()
        )
    )
    case = next(
        c
        for c in fixture["cases"]
        if c["input"]["shape"] == "future_output_for_ready_job"
    )
    final = case["states"][-1]
    rendered = [
        e[2]
        for e in final["io"]
        if e[1] == "AMediaCodec_releaseOutputBuffer" and e[3] == 1
    ]
    assert rendered == [7] and not final["unsupplied_info_reads"]
    sdk_stamp = next(e[4] for e in final["io"] if e[1] == "dequeue" and e[3] == 7)
    source_id = next(e[1] for e in final["input_pts"] if e[3] == sdk_stamp)
    selected = native[2]["selected"][-1][1]
    native_id = None if selected is None else selected[0]
    report = dict(
        boundary=__doc__,
        official_binary_sha256=fixture["binary_sha256"],
        source_held_job_id=final["held"][0][0],
        source_sdk_output_input_id=source_id,
        native_output_now=native_id,
        native_output_later=native[3]["selected"][-1][1],
        selection_matches=native_id == source_id,
    )
    (output / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    observe(args.build.resolve(), args.output.resolve())
