#!/usr/bin/env python3
"""Require UDP/audio comparisons to reject isolated production regressions.

Every mutant must compile/link, and the receiver must return normally. Only a
audio metadata/PCM mismatch against official output counts as detection. The working
production sources and references are never modified by this script.
"""
import argparse
import json
from pathlib import Path
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    if not __debug__:
        raise SystemExit("Assertions required")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--build", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    build, output = a.build.resolve(), a.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    directory = ROOT / "app/platforms/common"
    variants = [
        ("fec_disabled", "audio_recovery.c", ".fec = last", ".fec = false"),
        (
            "fec_without_packet",
            "audio_recovery.c",
            ".use_packet = last",
            ".use_packet = false",
        ),
        (
            "recovery_twenty_ms",
            "audio_recovery.c",
            ".max_samples = 480,",
            ".max_samples = 960,",
        ),
        (
            "recovery_wrong_timestamp",
            "audio_recovery.c",
            ".timestamp = timestamp,",
            ".timestamp = timestamp + 1u,",
        ),
        (
            "queue_silenced",
            "media.c",
            "sl_audio_jitter_push(&audio_jitter, pcm, playback_samples);",
            "for(int i=0;i<playback_samples*audio_channels;++i)((float *)pcm)[i]=0.0f;\n    sl_audio_jitter_push(&audio_jitter, pcm, playback_samples);",
        ),
    ]
    checker = ROOT / "scripts/check-steam-audio-process.py"
    link_dir = build / "app"
    link_base = shlex.split(
        (link_dir / "CMakeFiles/nsl-auth-udp-oracle.dir/link.txt").read_text()
    )
    entries = json.loads((build / "compile_commands.json").read_text())
    baseline = subprocess.run(
        [
            "python3",
            str(checker),
            "--receiver",
            str(link_dir / "nsl-auth-udp-oracle"),
            "--profile",
            "silk",
        ],
        text=True,
        capture_output=True,
        timeout=90,
    )
    (output / "baseline.log").write_text(baseline.stdout + baseline.stderr)
    assert baseline.returncode == 0, baseline.stderr
    reports = []
    for name, filename, before, after in variants:
        source = directory / filename
        text = source.read_text()
        assert text.count(before) == (2 if name == "recovery_wrong_timestamp" else 1), (
            name,
            "anchor",
        )
        work = output / name
        work.mkdir(exist_ok=True)
        copy, obj, receiver = (work / n for n in (filename, "mutant.o", "receiver"))
        copy.write_text(text.replace(before, after, 1))
        entry = next(e for e in entries if Path(e["file"]) == source)
        command = [
            str(copy) if v == str(source) else v for v in shlex.split(entry["command"])
        ]
        command[command.index("-o") + 1] = str(obj)
        command += ["-I", str(directory)]
        compiled = subprocess.run(
            command, cwd=entry["directory"], text=True, capture_output=True
        )
        (work / "compile.log").write_text(compiled.stdout + compiled.stderr)
        assert compiled.returncode == 0, (name, "compile")
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
        linked = subprocess.run(link, cwd=link_dir, text=True, capture_output=True)
        (work / "link.log").write_text(linked.stdout + linked.stderr)
        assert linked.returncode == 0, (name, "link", linked.stderr[-1000:])
        result = subprocess.run(
            ["python3", str(checker), "--receiver", str(receiver), "--profile", "silk"],
            text=True,
            capture_output=True,
            timeout=90,
        )
        (work / "check.log").write_text(result.stdout + result.stderr)
        assert (
            result.returncode == 1
            and "AssertionError" in result.stderr
            and "assert result.returncode" not in result.stderr
            and "TimeoutExpired" not in result.stderr
        ), (
            name,
            "must reject on official audio metadata/PCM mismatch",
            result.stderr[-2000:],
        )
        reports.append(
            dict(
                name=name,
                compile=compiled.returncode,
                link=linked.returncode,
                checker=result.returncode,
                reason=result.stderr.splitlines()[-1][:500],
            )
        )
        print(name, "normal receiver, official audio metadata/PCM mismatch", flush=True)
    (output / "report.json").write_text(json.dumps(reports, indent=2) + "\n")


if __name__ == "__main__":
    main()
