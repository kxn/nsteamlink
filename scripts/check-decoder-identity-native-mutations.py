#!/usr/bin/env python3
"""Require real, normally exiting receivers to expose identity-policy regressions.

The fixtures and original-client reference are unchanged. Each isolated edit is
compiled/linked against the actual receiver; crashes/timeouts are not detections.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    build, output = args.build.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location(
        "identity_check", ROOT / "scripts/check-steam-decoder-identity.py"
    )
    check = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(check)
    reference = json.loads(
        (ROOT / "scripts/fixtures/steam-decoder-identity-reference.json").read_text()
    )
    directory = build / "third_party/ihslib/tests/session"
    baseline = directory / "ihs-video-identity-oracle"
    for case in reference["cases"]:
        check.verify(baseline, case)
    tracker = ROOT / "third_party/ihslib/src/session/frame_tracker.c"
    video = ROOT / "third_party/ihslib/src/session/channels/video/ch_data_video.c"
    fixtures = ROOT / "third_party/ihslib/tests/session"
    variants = [
        (
            "id_history_gates_input",
            tracker,
            "return begin_frame(t, epoch, frameId, receive, out, true);",
            "return begin_frame(t, epoch, frameId, receive, out, false);",
        ),
        (
            "pending_retirement_publishes_complete",
            tracker,
            "bool IHS_FrameTicketAbandonInput(IHS_FrameTicket *r) {",
            "bool IHS_FrameTicketAbandonInput(IHS_FrameTicket *r) {\n"
            "    IHS_FrameOutcome outcome = {.result=IHS_VideoFrameResultDroppedReset};\n"
            "    return IHS_FrameTicketComplete(r, &outcome);",
        ),
        (
            "missing_key_interval_cancellation",
            video,
            "IHS_FrameStatsRecordComplete(channel->session->frameStats, id,\n"
            "                                             IHS_VideoFrameResultDroppedReset);",
            "(void)id;",
        ),
    ]
    entries = json.loads((build / "compile_commands.json").read_text())
    reports = []
    for name, source, before, after in variants:
        work = output / name
        work.mkdir(exist_ok=True)
        original = source.read_text()
        assert original.count(before) == 1, (name, "anchor")
        copy = work / source.name
        copy.write_text(original.replace(before, after))
        source_entry = source
        if source == video:
            # This oracle includes the production video TU. Preserve every
            # test observer and redirect only that include to the isolated edit.
            for filename in (
                "video_identity_oracle.c",
                "video_pressure_oracle.c",
                "video_queue_oracle.c",
                "video_content_mode_oracle.c",
            ):
                value = (fixtures / filename).read_text()
                if filename == "video_content_mode_oracle.c":
                    value = value.replace(
                        '"../../src/session/channels/video/ch_data_video.c"',
                        json.dumps(str(copy)),
                    )
                (work / filename).write_text(value)
            source_entry = fixtures / "video_identity_oracle.c"
            copy = work / source_entry.name
        entry = next(e for e in entries if Path(e["file"]) == source_entry)
        obj = work / "mutant.o"
        command = [
            str(copy) if v == str(source_entry) else v
            for v in shlex.split(entry["command"])
        ]
        command[command.index("-o") + 1] = str(obj)
        command += ["-I", str(source.parent), "-I", str(fixtures)]
        compiled = subprocess.run(
            command, cwd=entry["directory"], text=True, capture_output=True
        )
        (work / "compile.log").write_text(compiled.stdout + compiled.stderr)
        assert compiled.returncode == 0, (name, "compile", compiled.stderr)
        link = shlex.split(
            (
                directory / "CMakeFiles/ihs-video-identity-oracle.dir/link.txt"
            ).read_text()
        )
        if source == tracker:
            link.insert(1, str(obj))
        else:
            old = next(v for v in link if v.endswith("video_identity_oracle.c.o"))
            link[link.index(old)] = str(obj)
        receiver = work / "receiver"
        link[link.index("-o") + 1] = str(receiver)
        link = [
            (
                "-Wl,--dependency-file=" + str(work / "link.d")
                if v.startswith("-Wl,--dependency-file=")
                else v
            )
            for v in link
        ]
        linked = subprocess.run(link, cwd=directory, text=True, capture_output=True)
        (work / "link.log").write_text(linked.stdout + linked.stderr)
        assert linked.returncode == 0, (name, "link", linked.stderr)
        mismatches, observations = [], []
        for case in reference["cases"]:
            rows = check.execute(receiver, case)
            observations.append(dict(name=case["name"], rows=rows))
            try:
                check.verify(receiver, case, rows)
            except AssertionError:
                mismatches.append(case["name"])
        assert mismatches, (name, "undetected")
        (work / "observed.json").write_text(json.dumps(observations, indent=2) + "\n")
        reports.append(
            dict(
                name=name,
                compiled=True,
                linked=True,
                normal_exit_cases=len(reference["cases"]),
                mismatches=mismatches,
            )
        )
    (output / "report.json").write_text(json.dumps(reports, indent=2) + "\n")
    print(
        "Decoder identity semantic regressions:",
        len(reports),
        "rejected after normal exit",
    )


if __name__ == "__main__":
    main()
