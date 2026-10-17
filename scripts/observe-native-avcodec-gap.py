#!/usr/bin/env python3
"""Observe the real native no-output path against official Linux AVCodec evidence.

Build an isolated observer from the actual runtime/parser/worker/FFmpeg/media
oracle and its configured compile/link commands. It reads real tracker records,
waiting owner and DataLost calls. The first actual decoded image is validated
against independent framemd5 then explicitly suppressed at the codec API boundary
as EAGAIN. This is controlled backend availability, not a natural Switch failure.
No product/golden source changes and no test requiring the gap to remain exist.
Source codec APIs are declared terminals in the pinned Linux audit. It does not
prove physical codec, timing, full stats/wire, complete startup or device parity.
"""

import argparse
import gzip
import json
from pathlib import Path
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def observe(build, output):
    output.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["cmake", "--build", str(build), "--target", "nsl-video-timing-oracle", "-j2"],
        check=True,
        stdout=(output / "build.log").open("w"),
        stderr=subprocess.STDOUT,
    )
    original = ROOT / "app/tests/video_timing_oracle.c"
    source = original.read_text()
    source = source.replace(
        '#include "../platforms/common/',
        '#include "' + str(ROOT / "app/platforms/common") + "/",
    )
    source = source.replace(
        "static void observe(void)", "static void observe(sl_runtime *r)"
    )
    source = source.replace("observe();++action", "observe(&r);++action")
    needle = '    puts("]}");'
    assert source.count(needle) == 1
    source = source.replace(
        needle,
        r"""    printf("],\"tracker\":[");
    IHS_TrackedFrame records[IHS_FRAME_TRACKER_CAPACITY];
    size_t count=IHS_FrameTrackerCopyStats(r->session->frameTracker,records,IHS_FRAME_TRACKER_CAPACITY);
    for(size_t n=0;n<count;++n) {
        IHS_TrackedFrame *f=&records[n];
        printf("%s{\"id\":%u,\"complete\":%s,\"result\":%d,\"decode_begin\":%s,\"decode_end\":%s}",
               n?",":"",f->identity.frameId,f->statsComplete?"true":"false",f->outcome.result,
               f->hasDecodeBegin?"true":"false",f->hasDecodeEnd?"true":"false");
    }
    printf("],\"loss_calls\":%u,\"waiting_id\":%u}\n",loss_calls,
           pipeline->waiting.ticket?IHS_FrameTicketIdentity(pipeline->waiting.ticket).frameId:0);""",
    )
    source = source.replace(
        "static unsigned action, pictureCount",
        "static unsigned loss_calls;\nstatic uint8_t golden[16];\nstatic unsigned action, pictureCount",
    )
    needle = "            av_frame_unref(frame);\n            return AVERROR(EAGAIN);"
    assert source.count(needle) == 1
    source = source.replace(
        needle,
        """            uint8_t bytes[128*72*3/2],digest[16];
            assert(av_image_copy_to_buffer(bytes,sizeof(bytes),(const uint8_t *const *)frame->data,
                   frame->linesize,AV_PIX_FMT_YUV420P,128,72,1)==sizeof(bytes));
            av_md5_sum(digest,bytes,sizeof(bytes));assert(!memcmp(digest,golden,16));
"""
        + needle,
    )
    source += """
void __real_IHS_SessionChannelDataLost(IHS_SessionChannel *);
void __wrap_IHS_SessionChannelDataLost(IHS_SessionChannel *ch) {
    if(recording) ++loss_calls;
    __real_IHS_SessionChannelDataLost(ch);
}
"""
    cpp = output / "observer.c"
    cpp.write_text(source)
    entries = json.loads((build / "compile_commands.json").read_text())
    entry = next(e for e in entries if Path(e["file"]).resolve() == original.resolve())
    cmd = list(entry.get("arguments") or shlex.split(entry["command"]))
    obj = output / "observer.o"
    cmd[cmd.index("-o") + 1] = str(obj)
    cmd[cmd.index("-c") + 1] = str(cpp)
    subprocess.run(cmd, cwd=entry["directory"], check=True)
    link = shlex.split(
        (build / "app/CMakeFiles/nsl-video-timing-oracle.dir/link.txt").read_text()
    )
    index = next(
        i for i, arg in enumerate(link) if arg.endswith("video_timing_oracle.c.o")
    )
    link[index] = str(obj)
    exe = output / "observer"
    link[link.index("-o") + 1] = str(exe)
    link += ["-Wl,--wrap=IHS_SessionChannelDataLost"]
    subprocess.run(link, cwd=build / "app", check=True)
    commands = "B 0\nX 1\nP 1 1 24 1000000 1000000 0 2204\nD 1000000\n"
    result = subprocess.run(
        [str(exe), str(ROOT / "app/tests/fixtures/video/sequential.h264")],
        input=commands,
        text=True,
        capture_output=True,
        timeout=20,
    )
    (output / "native-states.jsonl").write_text(result.stdout)
    (output / "native-stderr.log").write_text(result.stderr)
    assert result.returncode == 0, (result.returncode, result.stderr[-3000:])
    states = [json.loads(line) for line in result.stdout.splitlines()]
    source = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-client-avcodec-reference.json.gz"
            ).read_bytes()
        )
    )
    original = next(c for c in source["cases"] if c["name"] == "native_no_output")[
        "states"
    ][0]
    native = next(r for r in states[-1]["tracker"] if r["id"] == 1)
    report = dict(
        scope=__doc__,
        official_binary_sha256=source["binary_sha256"],
        native_head=subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        original=original,
        native=native,
        native_waiting_id=states[-1]["waiting_id"],
        native_loss_calls=states[-1]["loss_calls"],
        completion_matches=bool(
            native["complete"] and native["result"] == original["stats_result"]
        ),
    )
    # A second actual process observes a normal decoded/framemd5-checked image
    # with declared SDK elapsed ticks. Compare original OnThink's events, not
    # an Android-to-AVCodec timing formula.
    timing = subprocess.run(
        [str(exe), str(ROOT / "app/tests/fixtures/video/sequential.h264")],
        input="B 0\nQ 100 200\nP 23 23 24 1000000 1000000 0 2204\nD 1000300\n",
        text=True,
        capture_output=True,
        timeout=20,
    )
    (output / "native-timing-states.jsonl").write_text(timing.stdout)
    (output / "native-timing-stderr.log").write_text(timing.stderr)
    assert timing.returncode == 0, (timing.returncode, timing.stderr[-3000:])
    source_player = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-client-avcodec-player-reference.json.gz"
            ).read_bytes()
        )
    )
    official_timing = next(
        case for case in source_player["cases"] if case["name"] == "decoder_time"
    )["states"][0]
    native_timing = json.loads(timing.stdout.splitlines()[-1])
    expected_events = [
        row[1:] for row in official_timing["events"] if row[0] == "event"
    ]
    actual_events = [row[1:] for row in native_timing["decode_events"]]
    report["decoder_timing"] = dict(
        original_events=expected_events,
        native_events=actual_events,
        original_samples=[
            row[1:] for row in official_timing["events"] if row[0] == "sample"
        ],
        native_jitter=native_timing["jitter"],
        decode_events_match=actual_events == expected_events,
    )
    (output / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--build", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    observe(a.build.resolve(), a.output.resolve())
