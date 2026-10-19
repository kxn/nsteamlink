#!/usr/bin/env python3
"""Reject isolated disabled-input regressions, without changing real sources.

Each receiver must exit normally and produce every step before a difference
counts. Build failure, crash or timeout is not a semantic detection.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--build", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    build, output = args.build.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    sdk = ROOT / "third_party/ihslib"
    sdl = sdk / "src/hid/sdl/src/sdl_hid_event.c"
    control = sdk / "src/session/channels/control/control_hid.c"
    sdl_gate = (
        "    if (!IHS_SessionStreaming(session)) {\n        return false;\n    }\n"
    )
    variants = [
        (
            "skip_disabled_sdl_processing",
            sdl,
            sdl_gate,
            sdl_gate.replace(
                "!IHS_SessionStreaming(session)",
                "!IHS_SessionStreaming(session) || !IHS_SessionInputEnabled(session)",
            ),
        ),
        (
            "retain_disabled_batch",
            control,
            "if (!IHS_SessionStreaming(session)) return false;",
            "if (!IHS_SessionStreaming(session) || !IHS_SessionInputEnabled(session)) return false;",
        ),
        (
            "force_full_when_reenabled",
            sdl,
            sdl_gate,
            sdl_gate + "    static bool mutation_disabled_seen;\n"
            "    if (!IHS_SessionInputEnabled(session)) mutation_disabled_seen = true;\n"
            "    else if (mutation_disabled_seen) {\n"
            "        mutation_disabled_seen = false;\n"
            "        return IHS_HIDRefreshSDLGameControllers(session);\n"
            "    }\n",
        ),
    ]
    hashes = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in (sdl, control)}
    entries = json.loads((build / "compile_commands.json").read_text())
    directory = build / "third_party/ihslib/tests/session"
    link = shlex.split(
        (directory / "CMakeFiles/ihs-hid-disabled-oracle.dir/link.txt").read_text()
    )
    results = []
    for name, source, before, after in variants:
        work = output / name
        work.mkdir(exist_ok=True)
        original = source.read_text()
        assert original.count(before) == 1, (name, "anchor")
        copy, obj, receiver = work / source.name, work / "mutant.o", work / "receiver"
        copy.write_text(original.replace(before, after))
        entry = next(v for v in entries if Path(v["file"]) == source)
        command = [
            str(copy) if v == str(source) else v for v in shlex.split(entry["command"])
        ]
        command[command.index("-o") + 1] = str(obj)
        command += ["-I", str(source.parent)]
        linked = [link[0], str(obj), *link[1:]]
        linked[linked.index("-o") + 1] = str(receiver)
        linked = [
            (
                "-Wl,--dependency-file=" + str(work / "link.d")
                if v.startswith("-Wl,--dependency-file=")
                else v
            )
            for v in linked
        ]
        for label, argv, cwd in [
            ("compile", command, Path(entry["directory"])),
            ("link", linked, directory),
        ]:
            done = subprocess.run(
                argv, cwd=cwd, text=True, capture_output=True, timeout=60
            )
            (work / (label + ".log")).write_text(done.stdout + done.stderr)
            assert done.returncode == 0, (name, label, done.stderr)
        capture = work / "capture.json"
        done = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/check-steam-hid-disabled.py"),
                "--receiver",
                str(receiver),
                "--capture",
                str(capture),
            ],
            text=True,
            capture_output=True,
            timeout=60,
        )
        (work / "check.log").write_text(done.stdout + done.stderr)
        assert done.returncode == 1 and capture.exists(), (name, done.stderr)
        report = json.loads(capture.read_text())
        assert (
            len(report["cases"]) == 12
            and sum(len(c["actual"]) for c in report["cases"]) == 63
        )
        assert report["mismatches"], name
        results.append(
            dict(
                name=name,
                steps=63,
                mismatches=len(report["mismatches"]),
                receiver_sha256=report["receiver_sha256"],
            )
        )
    assert all(
        hashlib.sha256(p.read_bytes()).hexdigest() == digest
        for p, digest in hashes.items()
    )
    (output / "report.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
