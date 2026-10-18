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
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--build", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--only", action="append", help="Run a named mutation (repeatable)")
    a = p.parse_args()
    build = a.build.resolve()
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    entries = json.loads((build / "compile_commands.json").read_text())
    pipeline = ROOT / "app/platforms/common/video_pipeline.c"
    video = ROOT / "third_party/ihslib/src/session/channels/video/ch_data_video.c"
    config = ROOT / "third_party/ihslib/src/session/client_config.c"
    runtime = ROOT / "app/platforms/common/runtime.c"
    media = ROOT / "app/platforms/common/media.c"
    oracle = ROOT / "app/tests/video_timing_oracle.c"
    system = ROOT / "app/platforms/desktop/system.c"
    session = ROOT / "third_party/ihslib/src/session/session.c"
    mutations = [
        (
            "defer_codec_until_external_release",
            pipeline,
            "        codec = d->codec;\n        d->codec = NULL;\n        parser = d->parser;\n        d->parser = NULL;",
            "        /* leave codec/parser for final reap */",
            "resources",
        ),
        (
            "skip_retirement_after_codec_stop",
            pipeline,
            "        if (!retire)\n            continue;",
            "        if (!codec)\n            continue;",
            "resources",
        ),
        (
            "ignore_slice_capability",
            pipeline,
            "if (!(codec->capabilities & AV_CODEC_CAP_SLICE_THREADS) || !cpu_count)",
            "if (!cpu_count)",
            "threads",
        ),
        (
            "wrong_thread_limit",
            pipeline,
            "if (count > 4) count = 4;",
            "if (count > 3) count = 3;",
            "threads",
        ),
        (
            "overwrite_sdk_thread_defaults",
            pipeline,
            "if (count > 1) {",
            "if (true) {",
            "threads",
        ),
        (
            "select_frame_threads",
            pipeline,
            "context->thread_type = FF_THREAD_SLICE;",
            "context->thread_type = FF_THREAD_FRAME;",
            "threads",
        ),
        (
            "guess_cpu_count",
            pipeline,
            "unsigned count = cpu_count();",
            "unsigned count = 4;",
            "threads",
        ),
        (
            "omit_production_thread_setup",
            pipeline,
            "configure_threads(d->codec, codec, config->cpu_count);",
            "d->codec->thread_count = 1;",
            "threads",
        ),
        (
            "omit_media_cpu_input",
            media,
            ".cpu_count = sl_system_video_cpu_count,",
            ".cpu_count = NULL,",
            "threads",
        ),
        (
            "count_physical_cores",
            system,
            'strncasecmp(line, "processor", 9)',
            'strncasecmp(line, "core id", 7)',
            "threads",
        ),
        (
            "reread_cpu_count",
            system,
            "pthread_once(&video_cpu_once, read_video_cpu_count);",
            "read_video_cpu_count();",
            "threads",
        ),
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
        (
            "omit_eio_config",
            pipeline,
            "if (sent == AVERROR(EIO)) status |= SL_VIDEO_SUBMIT_DISABLE_HARDWARE;",
            "/* omit EIO-specific config mutation */",
            "recovery",
        ),
        (
            "invoke_config_setter",
            config,
            "s->clientConfig->enable_hardware_decoding = false;",
            "s->clientConfig->enable_hardware_decoding = false;\n        IHS_SessionClientConfigApply(s,s->clientConfig,true);",
            "recovery",
        ),
        (
            "omit_software_format",
            pipeline,
            "if (*formats == AV_PIX_FMT_YUV420P || *formats == AV_PIX_FMT_YUVJ420P)",
            "if (false)",
            "recovery",
        ),
        (
            "retry_missing_hardware_forever",
            pipeline,
            "        if (opened < 0) {\n            /* Original VAAPI factory",
            "        if (opened < 0) {\n            failure=SL_VIDEO_OPEN_UNAVAILABLE;goto fail;\n            /* Original VAAPI factory",
            "capability",
        ),
        (
            "omit_player_config_delegate",
            runtime,
            ".clientConfigChanged = client_config_changed",
            ".clientConfigChanged = NULL",
            "player",
        ),
        (
            "ignore_player_hardware_presence",
            runtime,
            "if (present && hardware != r->player_hardware_decoding)",
            "if (hardware != r->player_hardware_decoding)",
            "player",
        ),
        (
            "omit_player_config_reset",
            runtime,
            "IHS_SessionVideoRequestReset(session);",
            "/* omit config reset */",
            "player",
        ),
        (
            "omit_player_cache_update",
            runtime,
            "r->player_hardware_decoding = hardware;",
            "/* keep old cache */",
            "player",
        ),
        (
            "resync_player_cache_each_epoch",
            runtime,
            "int result = sl_media_video_start_tracked(s, epoch, c);",
            "int result = sl_media_video_start_tracked(s, epoch, c);\n    r->player_hardware_decoding = IHS_SessionVideoHardwareDecodingEnabled(s);",
            "player",
        ),
        (
            "omit_config_reset_atomic",
            video,
            "atomic_store(&((IHS_SessionChannelVideo *)ch)->resetRequested, true);",
            "/* omit actual config gate */",
            "player",
        ),
        (
            "omit_player_cache_initialization",
            runtime,
            "r->player_hardware_decoding = IHS_SessionVideoHardwareDecodingEnabled(session);",
            "/* omit active player init */",
            "player",
        ),
        (
            "restore_avcodec_start_info",
            video,
            "if (videoCh->tracked && callbacks->reportsDecoderInfo) return true;",
            "/* send generic startup info again */",
            "info",
        ),
        (
            "omit_runtime_info_flag",
            runtime,
            ".reportsDecoderInfo = true",
            ".reportsDecoderInfo = false",
            "info",
        ),
        (
            "omit_sdk_format_callback",
            pipeline,
            "d->codec->get_format = hardware_format;",
            "d->codec->get_format = avcodec_default_get_format;",
            "info",
        ),
        (
            "omit_actor_info_callback",
            pipeline,
            "if (info) info(context, description, (unsigned)threads);",
            "(void)info; (void)context;",
            "info",
        ),
        (
            "zero_decoder_info_threads",
            video,
            "PROTOBUF_C_SET_VALUE(message, threads, threads);",
            "PROTOBUF_C_SET_VALUE(message, threads, 0);",
            "info",
        ),
        (
            "reset_on_info_send_failure",
            media,
            "IHS_SessionVideoDecoderInfo(borrowed->session, borrowed->epoch, description, threads);",
            "if (!IHS_SessionVideoDecoderInfo(borrowed->session, borrowed->epoch, description, threads)) IHS_SessionVideoDecodeFeedback(borrowed->session, borrowed->epoch, IHS_StreamVideoSubmitReset);",
            "info",
        ),
        (
            "omit_owned_info_cache",
            video,
            "free(session->videoDecoderInfo);\n    session->videoDecoderInfo = copy;",
            "free(copy);",
            "info",
        ),
    ]
    # Full protocol/runtime/SDK format path, including actual actor scheduling.
    lock_begin = "    ++f->consumers;\n"
    lock_end = "    --f->consumers;\n"
    text = pipeline.read_text()
    assert text.count(lock_begin) == text.count(lock_end) == 1
    locked = text[text.index(lock_begin) : text.index(lock_end)]
    assert locked.count("pthread_mutex_unlock(&f->lock);") == 1
    assert locked.count("pthread_mutex_lock(&f->lock);") == 1
    holding = locked.replace(
        "    pthread_mutex_unlock(&f->lock);", "    /* hold format while sending */"
    )
    holding = holding.replace(
        "    pthread_mutex_lock(&f->lock);", "    /* already held */"
    )
    mutations += [
        (
            "worker_synchronous_format",
            media,
            ".deferred_formats = deferred_formats,",
            ".deferred_formats = false,",
            "formats",
        ),
        (
            "omit_actor_format_phase",
            session,
            "IHS_SessionVideoHandleFormatRequests(session);",
            "/* omit actor format phase */",
            "formats",
        ),
        (
            "drop_reset_format_values",
            pipeline,
            "if (!restarting && (same(f->backend, key) || same(f->request, key))) f->pending = false;",
            "if (same(f->backend, key) || same(f->request, key)) f->pending = false;",
            "formats",
        ),
        (
            "retain_replaced_format_values",
            pipeline,
            "if (!restarting && (same(f->backend, key) || same(f->request, key))) f->pending = false;",
            "/* incorrectly retain requests for a deleted decoder */",
            "formats",
        ),
        (
            "omit_prejoin_format_cancel",
            media,
            "if (video) sl_video_cancel_formats(video,\n        (sl_video_key){epoch->session_id, epoch->video_epoch}, restarting);",
            "(void)epoch; (void)restarting;",
            "formats",
        ),
        (
            "omit_initial_info_scope",
            video,
            "bool starting = session->videoStarting &&\n        session->videoStartingEpoch.session_id == epoch->session_id &&\n        session->videoStartingEpoch.video_epoch == epoch->video_epoch;",
            "bool starting = false;",
            "formats",
        ),
        (
            "retain_starting_info_scope",
            video,
            "session->videoStarting = false;",
            "/* leak initializing epoch */",
            "formats",
        ),
        (
            "discard_failed_open_metadata",
            pipeline,
            "    if (opened < 0) {\n        failure = opened == AVERROR(ENOMEM)",
            "    if (opened < 0) {\n        p->format.metadata_valid = false;\n        failure = opened == AVERROR(ENOMEM)",
            "formats",
        ),
        (
            "map_protocol_codec_data_to_sdk",
            media,
            "    sl_video_config decoder = {.width = config->width,\n                               .height = config->height,",
            "    sl_video_config decoder = {.width = config->width,\n                               .height = config->height,\n                               .extradata = config->codecData, .extradata_size = config->codecDataLen,",
            "formats",
        ),
        (
            "drop_protocol_codec_data",
            video,
            "    int started =\n        videoCh->tracked\n            ? callbacks->startTracked(session, &videoCh->epoch, &videoCh->config,",
            "    IHS_StreamVideoConfig misplaced = videoCh->config;\n    misplaced.codecData = NULL; misplaced.codecDataLen = 0;\n    int started =\n        videoCh->tracked\n            ? callbacks->startTracked(session, &videoCh->epoch, &misplaced,",
            "formats",
        ),
        ("format_lock_across_info", pipeline, locked, holding, "formats"),
    ]
    if a.only:
        assert set(a.only) <= {item[0] for item in mutations}, a.only
        mutations = [item for item in mutations if item[0] in a.only]
    reports = []
    for name, source, before, after, kind in mutations:
        directory = out / name
        directory.mkdir(exist_ok=True)
        body = source.read_text()
        assert body.count(before) == 1, (name, body.count(before))
        body = body.replace(before, after)
        changed = directory / source.name
        changed.write_text(body)
        codec_overlay = None
        if name == "map_protocol_codec_data_to_sdk":
            # Restore the prior SDK binding across its private configuration
            # ABI, media adapter and decoder TU. All three copies are isolated;
            # a compile failure is not accepted as regression detection.
            shutil.copytree(pipeline.parent, directory, dirs_exist_ok=True)
            changed.write_text(
                body
            )  # The isolated media mutation follows the copied tree.
            header = (pipeline.parent / "video_pipeline.h").read_text()
            header = header.replace(
                "    bool hardware;",
                "    bool hardware;\n    const unsigned char *extradata;\n    size_t extradata_size;",
                1,
            )
            (directory / "video_pipeline.h").write_text(header)
            decoder = pipeline.read_text()
            before_copy = "    d->codec->flags |= AV_CODEC_FLAG_COPY_OPAQUE;"
            assert decoder.count(before_copy) == 1
            decoder = decoder.replace(
                before_copy,
                before_copy
                + "\n    if(config->extradata_size) {\n        d->codec->extradata=av_mallocz(config->extradata_size+AV_INPUT_BUFFER_PADDING_SIZE);\n        if(!d->codec->extradata) goto fail;\n        memcpy(d->codec->extradata,config->extradata,config->extradata_size);\n        d->codec->extradata_size=config->extradata_size;\n    }",
                1,
            )
            codec_overlay = directory / "video_pipeline.c"
            codec_overlay.write_text(decoder)
        target = (
            "nsl-video-timing-oracle"
            if kind
            in (
                "oracle",
                "recovery",
                "player",
                "info",
                "threads",
                "resources",
                "formats",
            )
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

        if kind in (
            "oracle",
            "recovery",
            "player",
            "info",
            "threads",
            "resources",
            "formats",
        ):
            text = oracle.read_text().replace(
                '#include "../platforms/common/',
                '#include "' + str(ROOT / "app/platforms/common") + "/",
            )
            if codec_overlay:
                text = text.replace(str(pipeline.parent) + "/", str(directory) + "/")
            if source in (pipeline, runtime):
                text = text.replace(str(source), str(changed))
            copied = directory / "oracle.c"
            copied.write_text(text)
            obj = compile_file(oracle, copied, "oracle")
            index = next(
                i for i, x in enumerate(link) if x.endswith("video_timing_oracle.c.o")
            )
            link[index] = str(obj)
            if source in (video, config, media, system, session):
                objects.append(compile_file(source, changed, source.stem))
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
        if kind in ("oracle", "recovery", "player", "info", "threads", "formats"):
            command = [
                "python3",
                str(
                    ROOT
                    / {
                        "oracle": "scripts/check-steam-video-avcodec.py",
                        "recovery": "scripts/check-steam-video-recovery.py",
                        "player": "scripts/check-steam-player-config.py",
                        "info": "scripts/check-steam-decoder-info.py",
                        "threads": "scripts/check-steam-decode-threads.py",
                        "formats": "scripts/check-steam-format-handoff.py",
                    }[kind]
                ),
                "--receiver",
                str(exe),
            ]
        elif kind == "resources":
            command = [
                str(exe),
                str(ROOT / "app/tests/fixtures/video/sequential.h264"),
                "--resources",
                "3",
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
        if kind in ("oracle", "recovery", "player", "info", "threads"):
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
        elif kind == "formats":
            expected = {
                "worker_synchronous_format": (
                    "normal",
                    "atomic_load(&processed)<target",
                ),
                "omit_actor_format_phase": (
                    "normal",
                    "sl_video_formats_pending(pipeline)",
                ),
                "drop_reset_format_values": ("reset_pending", "infoCount=="),
                "map_protocol_codec_data_to_sdk": (
                    "codec_opaque",
                    "codecDataSdkSize==0",
                ),
                "drop_protocol_codec_data": (
                    "codec_opaque",
                    "config->codecDataLen==codecDataExpectedSize",
                ),
                "discard_failed_open_metadata": ("reset_unavailable", "infoCount==1"),
                "retain_replaced_format_values": ("replace_pending", "infoCount==0"),
                "omit_prejoin_format_cancel": ("reset_pending", "TimeoutExpired"),
                "omit_initial_info_scope": ("opening_guard", "infoCount==1"),
                "retain_starting_info_scope": ("normal", "videoStarting"),
                "format_lock_across_info": ("base_cancel", "TimeoutExpired"),
            }[name]
            assert all(value in r.stderr for value in expected), (
                name,
                r.stderr[-3000:],
            )
            assert "-11," not in r.stderr, (name, "unexpected segmentation fault")
        elif kind == "resources":
            expected = (
                "threadsWithOldFrame==threadBaseline"
                if name == "defer_codec_until_external_release"
                else "sl_media_video_clean()"
            )
            assert r.returncode == -6 and expected in r.stderr, (name, r.stderr[-2000:])
        elif kind == "reordered":
            assert "current[j].statsComplete" in r.stderr, (name, r.stderr[-2000:])
        else:
            assert (
                "opening_results" in r.stderr
                and "{1, 4}" in r.stderr
                and "SL_VIDEO_OPEN_READY" in r.stderr
            ), (name, r.stderr[-2000:])
        reports.append(dict(name=name, returncode=r.returncode, detected=True))
    (out / "report.json").write_text(json.dumps(reports, indent=2) + "\n")
    print("AVCodec Native mutants:", len(reports), "detected")


if __name__ == "__main__":
    main()
