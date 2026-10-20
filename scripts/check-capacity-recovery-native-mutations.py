#!/usr/bin/env python3
"""Check normal-exit detection of missing recovery and key-induced extra recovery."""

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
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build, output = args.build.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location(
        "capacity", ROOT / "scripts/check-steam-capacity-recovery.py"
    )
    check = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(check)
    report = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-capacity-recovery-reference.json.gz"
            ).read_bytes()
        )
    )
    check.verify_reference(report)
    directory = build / "third_party/ihslib/tests/session"
    baseline = directory / "ihs-video-overlap-oracle"
    for case in report["cases"]:
        check.overlap.verify(baseline, case)
    source = ROOT / "third_party/ihslib/src/session/channels/video/ch_data_video.c"
    original = source.read_text()
    mutations = {
        "suppress_gap_request": (
            "if (!videoCh->states.syncingBacklog) {\n            IHS_SessionChannelDataLost(channel);",
            "if (!videoCh->states.syncingBacklog) {\n            (void)channel;",
        ),
        "request_before_key_resets_sequence": (
            "        videoCh->states.waitingKeyFrame = false;",
            "        if (vhead.sequence != videoCh->states.expectedSequence) IHS_SessionChannelDataLost(channel);\n        videoCh->states.waitingKeyFrame = false;",
        ),
    }
    fixtures = ROOT / "third_party/ihslib/tests/session"
    source_entry = fixtures / "video_overlap_oracle.c"
    entry = next(
        e
        for e in json.loads((build / "compile_commands.json").read_text())
        if Path(e["file"]) == source_entry
    )
    link_base = shlex.split(
        (directory / "CMakeFiles/ihs-video-overlap-oracle.dir/link.txt").read_text()
    )
    results = []
    for name, (before, after) in mutations.items():
        assert original.count(before) == 1, name
        folder = output / name
        folder.mkdir(exist_ok=True)
        copy, obj, receiver = [
            folder / p for p in ("ch_data_video.c", "mutant.o", "receiver")
        ]
        copy.write_text(original.replace(before, after))
        # The oracle includes the production video TU. Redirect only that
        # include in an isolated fixture chain, preserving all observers.
        for filename in (
            "video_overlap_oracle.c",
            "video_pressure_oracle.c",
            "video_queue_oracle.c",
            "video_content_mode_oracle.c",
        ):
            text = (fixtures / filename).read_text()
            if filename == "video_content_mode_oracle.c":
                text = text.replace(
                    '"../../src/session/channels/video/ch_data_video.c"',
                    json.dumps(str(copy)),
                )
            (folder / filename).write_text(text)
        command = [
            str(folder / "video_overlap_oracle.c") if p == str(source_entry) else p
            for p in shlex.split(entry["command"])
        ]
        command[command.index("-o") + 1] = str(obj)
        command += ["-I", str(source.parent), "-I", str(fixtures)]
        compiled = subprocess.run(
            command, cwd=entry["directory"], capture_output=True, text=True
        )
        (folder / "compile.log").write_text(compiled.stdout + compiled.stderr)
        assert compiled.returncode == 0, (name, "compile", compiled.stderr)
        link = list(link_base)
        old_object = next(p for p in link if p.endswith("video_overlap_oracle.c.o"))
        link[link.index(old_object)] = str(obj)
        link[link.index("-o") + 1] = str(receiver)
        link = [
            (
                "-Wl,--dependency-file=" + str(folder / "link.d")
                if p.startswith("-Wl,--dependency-file=")
                else p
            )
            for p in link
        ]
        linked = subprocess.run(link, cwd=directory, capture_output=True, text=True)
        (folder / "link.log").write_text(linked.stdout + linked.stderr)
        assert linked.returncode == 0, (name, "link", linked.stderr)
        rejected = []
        for case in report["cases"]:
            got = check.overlap.execute(receiver, case)  # Requires normal exit.
            try:
                check.overlap.verify(receiver, case, got)
            except AssertionError as error:
                rejected.append(case["name"])
                (folder / (case["name"] + ".difference.txt")).write_text(str(error))
        assert len(rejected) == 2, (name, rejected)
        results.append(dict(name=name, rejected=rejected, normal_exit_cases=2))
        print(name, "both normal-exit cases rejected", flush=True)
    (output / "report.json").write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
