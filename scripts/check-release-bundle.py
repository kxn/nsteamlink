#!/usr/bin/env python3
"""Verify a collected ordinary bundle before upload/publication.

The exclusion report binds the audited NRO bytes to this bundle. Trust in the
report comes from the build workflow, not from its filename or an assertion.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def check(bundle):
    identity = json.loads((bundle / "build_identity.json").read_text())
    report = json.loads((bundle / "diagnostic_exclusion.json").read_text())
    if identity["dirty"] or not re.fullmatch("[0-9a-f]{40}", identity["commit"]):
        raise ValueError("Bundle requires clean source identity")
    name = f'NSteamLink-{identity["display_version"]}.nro'
    required = {
        name,
        "build_identity.json",
        "diagnostic_exclusion.json",
        "opus-LICENSE.txt",
    }
    optional = {"devkitpro-packages.txt", "SHA256SUMS"}
    entries = {entry.name for entry in bundle.iterdir()}
    if not required <= entries or not entries <= required | optional:
        raise ValueError(
            "Unexpected/missing release files: " + str(sorted(entries ^ required))
        )
    if not all(
        entry.is_file() and not entry.is_symlink() for entry in bundle.iterdir()
    ):
        raise ValueError("Release files must be regular files")
    expected = {
        "CMAKE_BUILD_TYPE": "Release",
        "NSL_DIAGNOSTICS": "OFF",
        "NSL_BUILD_TOOLS": "OFF",
        "NSL_TEST_FORCE_1080": "OFF",
        "IHSLIB_DIAGNOSTICS": "OFF",
    }
    if (
        report.get("schema") != 1
        or report.get("status") != "passed"
        or report.get("configuration") != expected
    ):
        raise ValueError("Missing ordinary-build diagnostic exclusion proof")
    nro = bundle / name
    if report.get("nro_sha256") != hashlib.sha256(nro.read_bytes()).hexdigest():
        raise ValueError("NRO bytes do not match diagnostic exclusion report")
    spec = importlib.util.spec_from_file_location(
        "validate_artifacts", ROOT / "scripts/validate-artifacts.py"
    )
    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)
    validator.check_nro(nro, identity, ROOT / "assets/branding/icon.jpg")
    return name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()
    print("PASS: ordinary bundle " + check(args.bundle.resolve()))


if __name__ == "__main__":
    main()
