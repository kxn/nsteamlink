#!/usr/bin/env python3
"""Require normal-exit Native regressions to differ from official overlap/event output.

Compile/link each isolated production edit against the unchanged baseline oracle
and fixtures. Crashes, build errors and hangs do not count as semantic detection.
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
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--build", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    build, output = a.build.resolve(), a.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = ROOT / "third_party/ihslib/src/session/channels/ch_data.c"
    mutations = {
        "forget_early_event": (
            "data->decoderWakePending = true;",
            "data->decoderWakePending = false;",
        ),
        "spurious_wake_runs_think": ("if (!woke) break;", "break;"),
        "renew_budget_on_spurious": (
            "uint64_t elapsed = IHS_TimerNow() - start;",
            "start = IHS_TimerNow(); uint64_t elapsed = 0;",
        ),
        "interrupt_is_timeout": (
            "return result == 0 || result == EINTR;",
            "return result == 0;",
        ),
    }
    spec = importlib.util.spec_from_file_location(
        "overlap_check", ROOT / "scripts/check-steam-decoder-overlap.py"
    )
    check = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(check)
    cases = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-decoder-overlap-reference.json.gz"
            ).read_bytes()
        )
    )["cases"]
    directory = build / "third_party/ihslib/tests/session"
    baseline = directory / "ihs-video-overlap-oracle"
    for case in cases:
        check.verify(baseline, case)
    check.verify_stop(baseline)
    check.verify_deadline(baseline)
    entries = json.loads((build / "compile_commands.json").read_text())
    link_base = shlex.split(
        (directory / "CMakeFiles/ihs-video-overlap-oracle.dir/link.txt").read_text()
    )
    reports = []
    for name, (before, after) in mutations.items():
        source = (
            ROOT
            / "third_party/ihslib/src"
            / (
                "platforms/ihs_thread_posix.c"
                if name == "interrupt_is_timeout"
                else "session/channels/ch_data.c"
            )
        )
        original = source.read_text()
        entry = next(e for e in entries if Path(e["file"]) == source)
        assert original.count(before) == 1
        work = output / name
        work.mkdir(exist_ok=True)
        copy, obj, receiver = (work / n for n in (source.name, "mutant.o", "receiver"))
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
        observations = []
        for case in cases:
            result = check.execute(receiver, case)
            observations.append(dict(name=case["name"], observed=result))
            try:
                check.verify(receiver, case, result)
            except AssertionError:
                rejected.append(case["name"])
        deadline = check.execute_deadline(receiver)
        try:
            check.verify_deadline(receiver, deadline)
        except AssertionError:
            rejected.append("local/deadline_budget")
        check.verify_stop(receiver)
        (work / "observed.json").write_text(json.dumps(observations, indent=2) + "\n")
        (work / "deadline.json").write_text(json.dumps(deadline, indent=2) + "\n")
        assert rejected, name
        reports.append(
            dict(
                name=name,
                compiled=True,
                linked=True,
                normal_exit_cases=len(cases),
                normal_exit_local_cases=2,
                mismatches=rejected,
            )
        )
    (output / "report.json").write_text(json.dumps(reports, indent=2) + "\n")
    print(
        "Decoder overlap semantic mutations:",
        len(reports),
        "rejected after normal exit",
    )


if __name__ == "__main__":
    main()
