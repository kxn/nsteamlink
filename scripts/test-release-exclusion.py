#!/usr/bin/env python3
"""Exercise release gates against actual OFF/ON artifacts and contaminated copies.

No build tree is edited: each counterexample uses a temporary overlay. Run after
both Switch builds; these checks do not launch either NRO on a device.
"""
import argparse
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def overlay(source, output):
    for name in (
        "CMakeCache.txt",
        "compile_commands.json",
        "generated/graphics_manifest.json",
        "generated/build_identity.json",
        "app/CMakeFiles/nsteamlink.dir/link.txt",
        "app/nsteamlink.elf",
        "app/nsteamlink.nro",
    ):
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(source / name)


def replace(path, data):
    path.unlink()
    path.write_bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", required=True, type=Path)
    parser.add_argument("--diagnostic-build", required=True, type=Path)
    args = parser.parse_args()
    ordinary, diagnostic = args.build.resolve(), args.diagnostic_build.resolve()
    checker = ROOT / "scripts/check-release-diagnostics.py"
    collector = ROOT / "scripts/collect-release.py"

    # -O is intentional: exclusion must survive disabled Python assertions.
    def run(arguments, expected=None):
        result = subprocess.run(
            [sys.executable, "-O", *map(str, arguments)], capture_output=True, text=True
        )
        if expected is None:
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
        elif result.returncode == 0 or expected not in result.stderr:
            raise RuntimeError(
                f"Counterexample did not fail for {expected!r}:\n"
                + result.stdout
                + result.stderr
            )

    run([checker, ordinary])
    run([checker, diagnostic], "NSL_DIAGNOSTICS must be OFF")
    checks = ["ordinary accepted under python -O", "actual diagnostic build rejected"]
    with tempfile.TemporaryDirectory(prefix="nsl-release-exclusion-") as temp:
        base = Path(temp)
        for option in (
            "NSL_DIAGNOSTICS",
            "NSL_BUILD_TOOLS",
            "NSL_TEST_FORCE_1080",
            "IHSLIB_DIAGNOSTICS",
        ):
            tree = base / option
            overlay(ordinary, tree)
            text = (tree / "CMakeCache.txt").read_text()
            changed, count = re.subn(
                r"^(" + option + r":[^=]+=)OFF$", r"\g<1>ON", text, flags=re.M
            )
            if count != 1:
                raise ValueError("Missing exact ordinary configuration: " + option)
            replace(tree / "CMakeCache.txt", changed.encode())
            run([checker, tree], option + " must be OFF")
            checks.append(option + " contamination rejected")
        # Keep the ordinary cache and commands, but replace the published NRO.
        tree = base / "swapped-nro"
        overlay(ordinary, tree)
        replace(
            tree / "app/nsteamlink.nro",
            (diagnostic / "app/nsteamlink.nro").read_bytes(),
        )
        run([checker, tree], "NRO/ELF")
        checks.append("actual diagnostic NRO under ordinary cache rejected")
        tree = base / "swapped-executable"
        overlay(ordinary, tree)
        replace(
            tree / "app/nsteamlink.elf",
            (diagnostic / "app/nsteamlink.elf").read_bytes(),
        )
        run([checker, tree], "diagnostic symbols")
        checks.append("actual diagnostic ELF under ordinary cache rejected")
        tree = base / "modified-nro"
        overlay(ordinary, tree)
        data = bytearray((tree / "app/nsteamlink.nro").read_bytes())
        data[0x100] ^= 1
        replace(tree / "app/nsteamlink.nro", data)
        run([checker, tree], "NRO/ELF executable segment mismatch")
        checks.append("post-link NRO mutation rejected")
        tree = base / "object-contamination"
        overlay(ordinary, tree)
        commands = json.loads((tree / "compile_commands.json").read_text())
        for entry in commands:
            if entry["file"].endswith("/platforms/switch/system.c"):
                argv = entry.get("arguments") or shlex.split(entry["command"])
                original = Path(entry["directory"]) / argv[argv.index("-o") + 1]
                target = (
                    tree / "app/CMakeFiles/nsl_platform.dir/platforms/switch/system.o"
                )
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(original.read_bytes() + b"\0stream_diag.log\0")
                argv[argv.index("-o") + 1] = str(target)
                entry["arguments"] = argv
                break
        else:
            raise ValueError("Missing real Switch system object")
        replace(tree / "compile_commands.json", json.dumps(commands).encode())
        run([checker, tree], "diagnostic marker b'stream_diag.log'")
        checks.append("compiled diagnostic marker under ordinary macro rejected")
        output = base / "contaminated-output"
        output.mkdir()
        (output / "switch-vcl-probe.nro").write_bytes(b"old private artifact")
        run(
            [collector, "--build", ordinary, "--output", output],
            "Release output must be empty",
        )
        checks.append("stale private artifact in output rejected")
        run(
            [collector, "--build", diagnostic, "--output", base / "diagnostic-output"],
            "NSL_DIAGNOSTICS must be OFF",
        )
        checks.append("collector rejects actual diagnostic build")
        bundle = base / "ordinary-bundle"
        run([collector, "--build", ordinary, "--output", bundle])
        bundle_checker = ROOT / "scripts/check-release-bundle.py"
        run([bundle_checker, bundle])
        checks.append(
            "collector and upload/publication bundle gate accept actual ordinary NRO"
        )
        extra = base / "extra-bundle"
        shutil.copytree(bundle, extra)
        (extra / "switch-video-probe.nro").write_bytes(b"private tool")
        run([bundle_checker, extra], "Unexpected/missing release files")
        checks.append("upload/publication gate rejects extra diagnostic artifact")
        modified = base / "modified-bundle"
        shutil.copytree(bundle, modified)
        nro = next(modified.glob("*.nro"))
        data = bytearray(nro.read_bytes())
        data[0x100] ^= 1
        nro.write_bytes(data)
        run(
            [bundle_checker, modified],
            "NRO bytes do not match diagnostic exclusion report",
        )
        checks.append("upload/publication gate rejects NRO changed after collection")
    print(json.dumps({"status": "passed", "checks": checks}, indent=2))


if __name__ == "__main__":
    main()
