#!/usr/bin/env python3
"""Require RTT/environment cases to reject isolated production regressions.

Every mutant must compile/link, and the receiver must return normally. Only a
state/wire mismatch against official output counts as detection. The working
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
    p.add_argument("--capture-only", action="store_true")
    a = p.parse_args()
    build, output = a.build.resolve(), a.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    directory = ROOT / "third_party/ihslib/src/session"
    variants = [
        (
            "constant_retry",
            "clock.c",
            "return ticks + ticks / 4; /* SendReliablePackets 0x7f8b04..2c */",
            "return 81;",
        ),
        (
            "unbounded_retry",
            "clock.c",
            "if (ticks > 3276) ticks = 3276;",
            "/* regression: no upper clamp */",
        ),
        (
            "media_ignores_rtt",
            "clock.c",
            "return budget + (uint32_t)((uint64_t)extraMs * 65536 / 1000);",
            "return budget + 0u * extraMs;",
        ),
        (
            "constant_feedback",
            "clock.c",
            "return ticks < 65 ? 65 : ticks;",
            "return 65;",
        ),
        (
            "echo_guard_one_tick_early",
            "clock.c",
            "(echo - clock->lastEcho) < -130",
            "(echo - clock->lastEcho) < -129",
        ),
        ("zero_stamp_not_unsent", "retransmission.c", " || !p->lastSendTimestamp", ""),
        (
            "retry_at_equality",
            "retransmission.c",
            "(int32_t)(p->lastSendTimestamp + delay - nowTicks) < 0",
            "(int32_t)(p->lastSendTimestamp + delay - nowTicks) <= 0",
        ),
        (
            "keep_expired_present_slot",
            "window.c",
            "if ((int32_t)(newest - item->senderTimestamp) <= (int32_t)diff)",
            "if (FrameItemIsUsed(item) || (int32_t)(newest - item->senderTimestamp) <= (int32_t)diff)",
        ),
    ]
    checker = ROOT / "scripts/check-steam-network-cycle.py"
    baseline_flags = ["--adaptive-only"]
    if a.capture_only:
        variants = [
            v
            for v in variants
            if v[0] in ("media_ignores_rtt", "keep_expired_present_slot")
        ]
        checker = ROOT / "scripts/check-steam-rx-capture.py"
        baseline_flags = []
    link_dir = build / "third_party/ihslib/tests/session"
    link_base = shlex.split(
        (link_dir / "CMakeFiles/ihs-network-wire-oracle.dir/link.txt").read_text()
    )
    entries = json.loads((build / "compile_commands.json").read_text())
    baseline = subprocess.run(
        [
            "python3",
            str(checker),
            "--receiver",
            str(link_dir / "ihs-network-wire-oracle"),
            *baseline_flags,
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
        assert text.count(before) == 1, (name, "anchor")
        work = output / name
        work.mkdir(exist_ok=True)
        copy, obj, receiver = (work / n for n in (filename, "mutant.o", "receiver"))
        copy.write_text(text.replace(before, after))
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
            [
                "python3",
                str(checker),
                "--receiver",
                str(receiver),
                *(
                    []
                    if a.capture_only
                    else [
                        (
                            "--burst-only"
                            if name == "keep_expired_present_slot"
                            else "--adaptive-only"
                        )
                    ]
                ),
            ],
            text=True,
            capture_output=True,
            timeout=90,
        )
        (work / "check.log").write_text(result.stdout + result.stderr)
        assert (
            result.returncode == 1
            and (
                'assert actual == case["observed"]'
                if a.capture_only
                else "assert actual == want"
            )
            in result.stderr
        ), (
            name,
            "must reject on official state/wire mismatch",
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
        print(name, "normal receiver, official state/wire mismatch", flush=True)
    (output / "report.json").write_text(json.dumps(reports, indent=2) + "\n")


if __name__ == "__main__":
    main()
