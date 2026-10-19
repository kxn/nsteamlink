#!/usr/bin/env python3
"""Compare persistent Native SDL event/flush state with original generator.

Complete encrypted bodies, sequence and processed baseline are compared after
each input tick. Source device reads and Native SDL handle lookups are adapters;
this is not a real controller, worker scheduling, Switch or Steam session.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    p.add_argument("--capture", type=Path)
    args = p.parse_args()
    reference = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-hid-disabled-reference.json.gz"
            ).read_bytes()
        )
    )
    assert (
        reference["binary_sha256"]
        == "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"
    )
    assert len(reference["cases"]) == 12 and len(reference["functions"]) == 18
    for name, digest in reference["helpers"].items():
        assert (
            hashlib.sha256((ROOT / "scripts" / name).read_bytes()).hexdigest() == digest
        ), name
    cases, errors = [], []
    for case in reference["cases"]:
        commands = "".join(
            " ".join(str(v) for v in [int(s["enabled"]), s["buttons"], *s["axes"]])
            + "\n"
            for s in case["input"]
        )
        result = subprocess.run(
            [str(args.receiver.resolve())],
            input=commands,
            text=True,
            capture_output=True,
            check=True,
            timeout=15,
        )
        actual = [json.loads(line) for line in result.stdout.splitlines()]
        assert len(actual) == len(case["observed"]), (case["name"], result.stdout)
        diagnostic = 0
        for index, (a, e) in enumerate(zip(actual, case["observed"])):
            expected = {key: e[key] for key in ("bodies", "sequence", "baseline")}
            projection = {key: a[key] for key in expected}
            # Local diagnostic, independent of the Source generator baseline:
            # StartInputReports has no flush diagnostic; later enabled wire
            # submissions each advance it once, disabled processing never does.
            diagnostic += int(index > 0 and bool(e["bodies"]))
            if (
                projection != expected
                or a["pending_reports"] != 0
                or a["diagnostic_sequence"] != diagnostic
            ):
                errors.append(
                    dict(case=case["name"], step=index, expected=expected, actual=a)
                )
        cases.append(dict(name=case["name"], actual=actual))
    report = dict(
        source_binary_sha256=reference["binary_sha256"],
        receiver_sha256=hashlib.sha256(args.receiver.read_bytes()).hexdigest(),
        cases=cases,
        mismatches=errors,
        scope=__doc__,
    )
    if args.capture:
        args.capture.write_text(json.dumps(report, indent=2) + "\n")
    if errors:
        raise SystemExit(
            f"{len(errors)} HID disabled state mismatches; first {json.dumps(errors[0])}"
        )
    print(
        f"Verified 12 original/Native Generic sequences, {sum(len(c['actual']) for c in cases)} complete encrypted/baseline states"
    )


if __name__ == "__main__":
    main()
