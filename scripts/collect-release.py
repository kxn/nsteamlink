#!/usr/bin/env python3
"""Collect ordinary end-user artifacts after auditing the actual build."""
import argparse
import importlib.util
import json
import re
from pathlib import Path
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load_script(name):
    spec = importlib.util.spec_from_file_location(
        name.replace("-", "_"), ROOT / "scripts" / (name + ".py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def collect(build, output):
    # Neither Release optimization nor a filename proves diagnostics are off.
    # Re-run the object/ELF/NRO gate here, so manual collection cannot bypass CI.
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError(
            "Release output must be empty; refuse stale or diagnostic files: "
            + str(output)
        )
    audit = load_script("check-release-diagnostics").check(build)
    identity = json.loads((build / "generated/build_identity.json").read_text())
    validator = load_script("validate-artifacts")
    validator.require(
        not identity["dirty"], "Ordinary release collection requires a clean checkout"
    )
    validator.require(
        re.fullmatch("[0-9a-f]{40}", identity["commit"]),
        "Ordinary release requires full source identity",
    )
    validator.check_nro(
        build / "app/nsteamlink.nro", identity, ROOT / "assets/branding/icon.jpg"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    # Prepare every owned file before exposing a bundle. Never copy build globs.
    with tempfile.TemporaryDirectory(prefix=".nsl-release-", dir=output.parent) as temp:
        stage = Path(temp)
        shutil.copyfile(
            build / "app/nsteamlink.nro",
            stage / f'NSteamLink-{identity["display_version"]}.nro',
        )
        shutil.copyfile(
            build / "generated/build_identity.json", stage / "build_identity.json"
        )
        shutil.copyfile(
            ROOT / "third_party/opus-LICENSE.txt", stage / "opus-LICENSE.txt"
        )
        (stage / "diagnostic_exclusion.json").write_text(
            json.dumps(audit, indent=2) + "\n"
        )
        output.mkdir(exist_ok=True)
        for source in stage.iterdir():
            shutil.copyfile(source, output / source.name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    collect(args.build.resolve(), args.output.resolve())


if __name__ == "__main__":
    main()
