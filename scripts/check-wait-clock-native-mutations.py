#!/usr/bin/env python3
"""Compile isolated real POSIX regressions; only normal-exit differences count."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "clock_check", ROOT / "scripts/check-steam-wait-clock.py"
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=True)
    sdk = ROOT / "third_party/ihslib"
    original = (sdk / "src/platforms/ihs_thread_posix.c").read_text()
    mutations = {
        "both_realtime": original.replace("CLOCK_MONOTONIC", "CLOCK_REALTIME"),
        "deadline_mismatch": original.replace(
            "clock_gettime(CLOCK_MONOTONIC", "clock_gettime(CLOCK_REALTIME"
        ),
        "missing_carry": original.replace(
            "until.tv_nsec >= 1000000000", "until.tv_nsec >= 2000000000"
        ),
        "ignore_setclock_failure": original.replace(
            "if (result == 0)\n        result = pthread_cond_init(&c->cond, &attr);",
            "result = pthread_cond_init(&c->cond, &attr);",
        ),
    }
    reports = []
    for name, source in {"baseline": original, **mutations}.items():
        assert source != original or name == "baseline"
        cfile, receiver = a.output / f"{name}.c", a.output / name
        cfile.write_text(source)
        command = [
            "cc",
            "-std=gnu11",
            "-UNDEBUG",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pthread",
            "-I",
            str(sdk / "src"),
            str(cfile),
            str(sdk / "tests/thread_clock_oracle.c"),
            "-o",
            str(receiver),
        ]
        command += [
            f"-Wl,--wrap={n}"
            for n in (
                "pthread_condattr_init",
                "pthread_condattr_setclock",
                "pthread_condattr_destroy",
                "pthread_cond_init",
                "pthread_cond_destroy",
                "clock_gettime",
                "pthread_cond_timedwait",
            )
        ]
        subprocess.run(command, check=True, capture_output=True, text=True)
        completed = subprocess.run(
            [str(receiver)], capture_output=True, text=True, timeout=10
        )
        assert completed.returncode == 0, (name, completed.returncode, completed.stderr)
        (a.output / f"{name}.json").write_text(completed.stdout)
        rejected = False
        try:
            m.check(receiver)
        except AssertionError:
            rejected = True
        assert rejected == (name != "baseline"), name
        reports.append(
            dict(name=name, compiled=True, exit=completed.returncode, rejected=rejected)
        )
    (a.output / "report.json").write_text(json.dumps(reports, indent=2) + "\n")
    print(
        "Clock regressions: baseline passes; 4 compiled normal-exit variants rejected"
    )


if __name__ == "__main__":
    main()
