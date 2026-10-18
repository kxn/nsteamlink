#!/usr/bin/env python3
"""Check real files and session reload against fixed official Android I/O bytes.

The two failed-parser cases intentionally preserve the old complete local value;
original Android leaves partial mutation. Both sides of that difference are
asserted. No Android filesystem or authenticated host is exercised.
"""
import argparse
import json
import runpy
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
fields = runpy.run_path(str(Path(__file__).with_name("check-steam-client-config.py")))[
    "fields"
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", type=Path, required=True)
    args = parser.parse_args()
    fixture = json.loads(
        (ROOT / "scripts/fixtures/steam-client-settings-io-reference.json").read_text()
    )
    count, guarded = 0, 0
    for case in fixture["cases"]:
        operation, inp, expected = case["operation"], case["input"], case["observed"]
        if (
            operation not in ("load", "save")
            or operation == "save"
            and not inp["filename"]
        ):
            continue  # Product uses a fixed filename in its configured data directory.
        with tempfile.TemporaryDirectory(prefix="nsl-settings-") as directory:
            path = Path(directory) / "streaming_settings.bin"
            initial = inp["initial"] if operation == "load" else inp["config"]
            if operation == "load" and inp["file"] is not None:
                path.write_bytes(bytes.fromhex(inp["file"]))
            if operation == "save" and not inp["write_success"]:
                path.write_bytes(b"previous-valid-file")
                (Path(directory) / "streaming_settings.tmp").mkdir()
            result = subprocess.run(
                [str(args.receiver.resolve()), directory, operation, initial or "-"],
                text=True,
                capture_output=True,
                timeout=10,
            )
            assert result.returncode == 0, (case["case"], result.stderr)
            actual = json.loads(result.stdout)
            if case["case"] in ("load_bad_tag", "load_partial_failure"):
                assert actual["status"] == -2
                assert fields(bytes.fromhex(actual["config"])) == fields(
                    bytes.fromhex(initial)
                )
                assert fields(bytes.fromhex(expected["config"])) != fields(
                    bytes.fromhex(initial)
                )
                guarded += 1
            else:
                assert fields(bytes.fromhex(actual["config"])) == fields(
                    bytes.fromhex(expected["config"])
                ), case["case"]
                if operation == "load":
                    assert actual["status"] == (1 if inp["file"] is None else 0)
                else:
                    assert (actual["status"] == 0) == inp["write_success"]
            if operation == "load" and inp["file"] is not None:
                assert path.read_bytes() == bytes.fromhex(
                    inp["file"]
                ), "load wrote the source file"
            elif operation == "save" and inp["write_success"]:
                written = next(
                    event["bytes"]
                    for event in expected["events"]
                    if "file_write" in event
                )
                assert fields(path.read_bytes()) == fields(bytes.fromhex(written))
            elif operation == "save":
                assert path.read_bytes() == b"previous-valid-file"
            count += 1
    print(
        f"Production settings I/O: {count} scenarios passed ({guarded} explicit malformed-load differences)"
    )


if __name__ == "__main__":
    main()
