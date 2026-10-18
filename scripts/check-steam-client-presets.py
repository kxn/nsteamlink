#!/usr/bin/env python3
"""Compare complete production presets, real files and session request limits.

Official factories take explicit config input. These checks do not manufacture
UI/Host triggers or treat Android preferred dimensions/codecs as Switch support.
"""
import argparse
import gzip
import json
from pathlib import Path
import runpy
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
fields = runpy.run_path(str(ROOT / "scripts/check-steam-client-config.py"))["fields"]
PRESERVED = {
    7,
    8,
    9,
    10,
    11,
    12,
    14,
    15,
    16,
    19,
    20,
    26,
    27,
    28,
    29,
    30,
    31,
    32,
    33,
    34,
}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    a = p.parse_args()
    reference = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-client-presets-reference.json.gz"
            ).read_bytes()
        )
    )
    assert (
        reference["binary_sha256"]
        == "15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2"
    )
    assert len(reference["cases"]) == 200
    assert reference["mutation"]["mutant"]["patch_hits"] == [
        reference["mutation"]["pc"]
    ]
    assert not reference["mutation"]["mutant"]["source_assertions"]
    assert (
        reference["mutation"]["mutant"]["output"]
        != reference["mutation"]["original"]["output"]
    )
    for c in reference["cases"]:
        assert not c["source_assertions"]
        original, expected = fields(bytes.fromhex(c["input"])), fields(
            bytes.fromhex(c["output"])
        )
        if c["preset"] == 0:
            assert original == expected
        else:
            for key in PRESERVED:
                assert original.get(key) == expected.get(key), (
                    c["name"],
                    c["preset"],
                    key,
                )
            allowed = PRESERVED | (
                {1, 13, 25}
                if c["preset"] == 4
                else {1, 6, 13, 22, 25} if c["preset"] in (2, 3) else set()
            )
            assert set(expected) <= allowed, (c["name"], c["preset"], expected)
        with tempfile.TemporaryDirectory(prefix="nsl-presets-") as directory:
            for limited in (False, True):
                cmd = [
                    str(a.receiver.resolve()),
                    directory,
                    "preset",
                    c["input"] or "-",
                    str(c["preset"]),
                ]
                if limited:
                    cmd.append("limits")
                result = subprocess.run(cmd, text=True, capture_output=True, timeout=10)
                assert result.returncode == 0, (
                    c["name"],
                    c["preset"],
                    result.returncode,
                    result.stderr[-1000:],
                )
                row = json.loads(result.stdout)
                assert row["status"] == 0, (c["name"], c["preset"], row)
                saved = (Path(directory) / "streaming_settings.bin").read_bytes()
                assert saved.hex() == c["output"], (c["name"], c["preset"], "file")
                actual = fields(bytes.fromhex(row["config"]))
                target = dict(expected)
                if limited:
                    # Same platform limiting contract used by the runtime.
                    if not target.get(2, [(0, 0)])[0][1] or target[2][0][1] > 1280:
                        target[2] = [(0, 1280)]
                    if not target.get(3, [(0, 0)])[0][1] or target[3][0][1] > 720:
                        target[3] = [(0, 720)]
                    num, den = (
                        target.get(4, [(0, 0)])[0][1],
                        target.get(5, [(0, 0)])[0][1],
                    )
                    if not num or not den or num > den * 60:
                        target[4], target[5] = [(0, 60)], [(0, 1)]
                    if target.get(13, [(0, 0)])[0][1]:
                        target[13] = [(0, 0)]
                assert actual == target, (
                    c["name"],
                    c["preset"],
                    limited,
                    actual,
                    target,
                )
    flow = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-network-test-fec-flow-reference.json.gz"
            ).read_bytes()
        )
    )
    policy_cases = flow["cases"] + reference["extra_policy"]
    assert len(policy_cases) == 73
    with tempfile.TemporaryDirectory(prefix="nsl-test-policy-") as directory:
        for c in policy_cases:
            states = c["observed"]["states"]
            first = states[0]
            result = next(s for s in states if s["label"] == "result_page")
            command = [
                str(a.receiver.resolve()),
                directory,
                "policy",
                c["initial"] or "-",
                str(result["previous_kbps"]),
                str(result["mode"]),
            ]
            p = subprocess.run(command, text=True, capture_output=True, timeout=10)
            assert p.returncode == 0, (c["input"], p.returncode, p.stderr[-1000:])
            assert json.loads(p.stdout) == dict(
                ok=True,
                mode=first["mode"],
                target=first["current_kbps"],
                recommendation=result["recommendation"],
            ), (c["input"], p.stdout, first, result)
    print(
        "Presets: 200 official full transformations, 200 exact files and 400 actual Session applications (200 with Switch request limits)"
    )


if __name__ == "__main__":
    main()
