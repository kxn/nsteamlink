#!/usr/bin/env python3
"""Compare real HID admission/sequence/encrypted bodies with original code.

The fixed Source channel-send terminal is compared with Native actual queued
bodies, not final socket return codes. No sender scheduling/UDP claim. Batch
buffer retirement while input is disabled is intentionally not projected:
the Source device collect is synthetic, while Native has a real local holder.
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
    ref = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-hid-producer-reference.json.gz"
            ).read_bytes()
        )
    )
    assert (
        ref["binary_sha256"]
        == "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"
    )
    assert len(ref["cases"]) == 128 and len(ref["functions"]) == 11
    for name, digest in ref["helpers"].items():
        assert (
            hashlib.sha256((ROOT / "scripts" / name).read_bytes()).hexdigest() == digest
        ), name
    cases, errors = [], []
    for case in ref["cases"]:
        inputs, expected = case["input"], case["observed"]
        result = subprocess.run(
            [
                str(args.receiver.resolve()),
                inputs["mode"],
                str(inputs["state"]),
                str(int(inputs["enabled"])),
                str(int(inputs["active"])),
                inputs["payload"],
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        actual = json.loads(result.stdout)
        projection = {"bodies": actual["bodies"], "sequence": actual["sequence"]}
        mismatch = projection != {key: expected[key] for key in projection}
        accepted = bool(expected["bodies"])
        mismatch |= actual["accepted"] is not accepted
        if inputs["mode"] != "generic":
            mismatch |= actual["submitted"] != int(accepted) or actual["sent"] != int(
                accepted
            )
        if inputs["mode"] == "batch" and inputs["state"] != 6:
            mismatch |= actual["pending_reports"] != 1
        if mismatch:
            errors.append(
                dict(
                    input=inputs,
                    expected={key: expected[key] for key in projection},
                    actual=actual,
                )
            )
        cases.append(dict(input=inputs, actual=actual))
    report = dict(
        source_binary_sha256=ref["binary_sha256"],
        receiver_sha256=hashlib.sha256(args.receiver.read_bytes()).hexdigest(),
        cases=cases,
        mismatches=errors,
        scope=__doc__,
    )
    if args.capture:
        args.capture.write_text(json.dumps(report, indent=2) + "\n")
    if errors:
        raise SystemExit(
            f"{len(errors)}/128 HID producer mismatches; first: {json.dumps(errors[0])}"
        )
    print(
        "Verified 128 HID producer gates, complete encrypted bodies, sequence and non-streaming holder admission"
    )


if __name__ == "__main__":
    main()
