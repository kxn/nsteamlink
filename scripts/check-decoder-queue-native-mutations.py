#!/usr/bin/env python3
"""Require normal-exit Native regressions to differ from official queue output.

Compile/link each isolated production edit against the unchanged baseline oracle
and fixtures. Crashes, build errors and hangs do not count as semantic detection.
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
    build, output = a.build.resolve(), a.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = ROOT / "third_party/ihslib/src/session/channels/ch_data.c"
    # Worker-level regressions deliberately retain the real video consumer.
    mutations = {
        "eager_per_input": (
            "            IHS_SessionPacketsWindowReleaseFrame(&frame);",
            "            IHS_SessionPacketsWindowReleaseFrame(&frame);\n"
            "            (void)IHS_SessionChannelDataThink(&channel->base);",
        ),
        "ignore_followup_timeout": (
            "uint32_t timeout = IHS_SessionChannelDataThink(&channel->base);",
            "uint32_t timeout = IHS_SessionChannelDataThink(&channel->base);\n"
            "        timeout = UINT32_MAX;",
        ),
    }
    checker = ROOT / "scripts/check-steam-decoder-queue.py"
    cases = json.loads(
        (ROOT / "scripts/fixtures/steam-decoder-queue-reference.json").read_text()
    )["cases"]
    directory = build / "third_party/ihslib/tests/session"
    baseline = directory / "ihs-video-queue-oracle"
    baseline_result = subprocess.run(
        ["python3", str(checker), "--receiver", str(baseline)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    (output / "baseline.log").write_text(
        baseline_result.stdout + baseline_result.stderr
    )
    assert baseline_result.returncode == 0
    entries = json.loads((build / "compile_commands.json").read_text())
    entry = next(e for e in entries if Path(e["file"]) == source)
    link_base = shlex.split(
        (directory / "CMakeFiles/ihs-video-queue-oracle.dir/link.txt").read_text()
    )
    reports = []
    original = source.read_text()
    for name, (before, after) in mutations.items():
        assert original.count(before) == 1
        work = output / name
        work.mkdir(exist_ok=True)
        copy, obj, receiver = (work / n for n in ("ch_data.c", "mutant.o", "receiver"))
        copy.write_text(original.replace(before, after))
        command = [
            str(copy) if v == str(source) else v for v in shlex.split(entry["command"])
        ]
        command[command.index("-o") + 1] = str(obj)
        command += ["-I", str(source.parent)]
        compiled = subprocess.run(
            command, cwd=entry["directory"], capture_output=True, text=True
        )
        (work / "compile.log").write_text(compiled.stdout + compiled.stderr)
        assert compiled.returncode == 0, (name, compiled.stderr)
        link = list(link_base)
        link.insert(1, str(obj))
        link[link.index("-o") + 1] = str(receiver)
        link = [
            (
                "-Wl,--dependency-file=" + str(work / "link.d")
                if v.startswith("-Wl,--dependency-file=")
                else v
            )
            for v in link
        ]
        linked = subprocess.run(link, cwd=directory, capture_output=True, text=True)
        (work / "link.log").write_text(linked.stdout + linked.stderr)
        assert linked.returncode == 0, (name, linked.stderr)
        rejected = []
        for case in cases:
            lines = []
            for batch in case["batches"]:
                lines.extend("F " + " ".join(map(str, f)) for f in batch)
                lines.append("B")
            result = subprocess.run(
                [str(receiver), str(ROOT / "app/tests/fixtures/video/sequential.h264")],
                input="\n".join(lines) + "\n",
                text=True,
                capture_output=True,
                timeout=15,
            )
            assert result.returncode == 0, (name, case["name"], result.stderr)
            got = [json.loads(line) for line in result.stdout.splitlines()]
            if got != case["states"]:
                rejected.append(case["name"])
        assert rejected, name
        reports.append(
            dict(
                name=name,
                compiled=True,
                linked=True,
                normal_exit_cases=len(cases),
                mismatches=rejected,
            )
        )
    (output / "report.json").write_text(json.dumps(reports, indent=2) + "\n")
    print(
        "Decoder queue semantic mutations:", len(reports), "rejected after normal exit"
    )


if __name__ == "__main__":
    main()
