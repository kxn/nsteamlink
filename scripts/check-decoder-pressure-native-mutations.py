#!/usr/bin/env python3
"""Reject resource/collection regressions only after actual receivers exit normally.

Media state is checked against the original client, with two port guards explicit.
Completed-record reuse is an independent local resource invariant. Statistics
compare original slots, full serialized reports and completion order.
"""
import argparse
import gzip
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
        "pressure_check", ROOT / "scripts/check-steam-decoder-pressure.py"
    )
    check = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(check)
    reference = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-decoder-pressure-reference.json.gz"
            ).read_bytes()
        )
    )
    directory = build / "third_party/ihslib/tests/session"
    media_base, stats_base = (
        directory / "ihs-video-pressure-oracle",
        directory / "ihs-frame-stats-oracle",
    )
    for case in reference["cases"]:
        check.verify(media_base, case)
    for case in reference["stats_cases"]:
        check.verify_stats(stats_base, case)
    variants = [
        (
            "fixed_256_records",
            "frame_tracker.c",
            "IHS_FrameTicketBlock *block = calloc(1, sizeof(*block));",
            "IHS_FrameTicketBlock *block = NULL;",
            False,
        ),
        (
            "no_collected_reuse",
            "frame_tracker.c",
            "if (!freeRecord) freeRecord = collectedRecord;",
            "(void)collectedRecord;",
            True,
        ),
        (
            "collector_first_block_only",
            "frame_stats.c",
            "IHS_FrameTrackerCopyStats(tracker, frames, agg->trackedCapacity)",
            "IHS_FrameTrackerCopyStats(tracker, frames, IHS_FRAME_TRACKER_CAPACITY)",
            True,
        ),
        (
            "completion_order_is_storage_order",
            "frame_stats.c",
            "if (pending > 1) qsort(frames, pending, sizeof(*frames), compare_completions);",
            "(void)compare_completions;",
            True,
        ),
    ]
    entries = json.loads((build / "compile_commands.json").read_text())
    reports = []
    for name, filename, before, after, use_stats in variants:
        source = ROOT / "third_party/ihslib/src/session" / filename
        original = source.read_text()
        assert original.count(before) == 1, (name, "anchor")
        work = output / name
        work.mkdir(exist_ok=True)
        copy, obj = work / filename, work / "mutant.o"
        copy.write_text(original.replace(before, after))
        entry = next(e for e in entries if Path(e["file"]) == source)
        command = [
            str(copy) if v == str(source) else v for v in shlex.split(entry["command"])
        ]
        command[command.index("-o") + 1] = str(obj)
        command += ["-I", str(source.parent)]
        compiled = subprocess.run(
            command, cwd=entry["directory"], text=True, capture_output=True
        )
        (work / "compile.log").write_text(compiled.stdout + compiled.stderr)
        assert compiled.returncode == 0, (name, "compile", compiled.stderr)
        receivers = {}
        for kind, target in [
            ("media", "ihs-video-pressure-oracle"),
            *([("stats", "ihs-frame-stats-oracle")] if use_stats else []),
        ]:
            link = shlex.split(
                (directory / f"CMakeFiles/{target}.dir/link.txt").read_text()
            )
            receiver = work / kind
            link.insert(1, str(obj))
            link[link.index("-o") + 1] = str(receiver)
            link = [
                (
                    "-Wl,--dependency-file=" + str(work / (kind + ".d"))
                    if v.startswith("-Wl,--dependency-file=")
                    else v
                )
                for v in link
            ]
            linked = subprocess.run(link, cwd=directory, text=True, capture_output=True)
            (work / f"{kind}-link.log").write_text(linked.stdout + linked.stderr)
            assert linked.returncode == 0, (name, "link", linked.stderr)
            receivers[kind] = receiver
        mismatches = []
        for case in reference["cases"]:
            rows = check.execute(
                receivers["media"], case
            )  # Nonzero exit/timeout never counts.
            try:
                check.verify(receivers["media"], case, rows)
            except AssertionError:
                mismatches.append("media/" + case["name"])
        if use_stats:
            for case in reference["stats_cases"]:
                rows = check.execute_stats(receivers["stats"], case)
                try:
                    check.verify_stats(receivers["stats"], case, rows)
                except AssertionError:
                    mismatches.append("stats/full=" + str(case["full"]))
        assert mismatches, (name, "undetected")
        reports.append(
            dict(
                name=name,
                compiled=True,
                linked=True,
                normal_exit_media_cases=len(reference["cases"]),
                normal_exit_stats_cases=(
                    len(reference["stats_cases"]) if use_stats else 0
                ),
                mismatches=mismatches,
            )
        )
    (output / "report.json").write_text(json.dumps(reports, indent=2) + "\n")
    print(
        "Decoder pressure semantic regressions:",
        len(reports),
        "rejected after normal exit",
    )


if __name__ == "__main__":
    main()
