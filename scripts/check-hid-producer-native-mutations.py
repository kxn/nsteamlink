#!/usr/bin/env python3
"""Require isolated production regressions to fail the original HID comparison.

Only copied translation units are edited. All 128 receivers must exit normally;
compile/link errors, crashes and timeouts do not count as detected semantics.
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
    control = sdk / "src/session/channels/ch_control.c"
    hid = sdk / "src/session/channels/control/control_hid.c"
    variants = [
        (
            "report_bypasses_admission",
            control,
            "    if (!IHS_SessionStreaming(channel->session) || !IHS_SessionInputEnabled(channel->session))\n        return false;\n",
            "",
        ),
        (
            "generic_omits_false_field",
            hid,
            "    wrapped.has_active_input = true;\n",
            "",
        ),
        (
            "batch_consumes_before_streaming",
            hid,
            "if (!IHS_SessionStreaming(session) || !IHS_SessionInputEnabled(session)) return false;",
            "if (!IHS_SessionInputEnabled(session)) return false;",
        ),
    ]
    hashes = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in (control, hid)}
    entries = json.loads((build / "compile_commands.json").read_text())
    directory = build / "third_party/ihslib/tests/session"
    link_command = shlex.split(
        (directory / "CMakeFiles/ihs-hid-producer-oracle.dir/link.txt").read_text()
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
        for label, command, cwd in (
            ("compile", command, Path(entry["directory"])),
            ("link", [link_command[0], str(obj), *link_command[1:]], directory),
        ):
            if label == "link":
                command[command.index("-o") + 1] = str(receiver)
                command = [
                    (
                        "-Wl,--dependency-file=" + str(work / "link.d")
                        if v.startswith("-Wl,--dependency-file=")
                        else v
                    )
                    for v in command
                ]
            done = subprocess.run(
                command, cwd=cwd, text=True, capture_output=True, timeout=60
            )
            (work / (label + ".log")).write_text(done.stdout + done.stderr)
            assert done.returncode == 0, (name, label, done.stderr)
        capture = work / "capture.json"
        done = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/check-steam-hid-producer.py"),
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
        assert len(report["cases"]) == 128 and report["mismatches"], name
        results.append(
            dict(
                name=name,
                cases=128,
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
