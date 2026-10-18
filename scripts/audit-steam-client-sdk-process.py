#!/usr/bin/env python3
"""Probe the unchanged official client and bundled SDK inside its real process.

GDB pauses at original main after dynamic/static initialization. Explicit calls
exercise the original codec factory, real SDK decoding, and original base-player/
AVCodec constructors, Start, Stop and deleting destructors. The configured client
storage is not a full Client/Connection; original deferred get_format/FinalDecode,
Qt event-loop, network, hardware and physical display remain outside this probe.
The process must resume its original --version main and exit normally after
probe-owned resources and module references are released. No gate/name/token or
callback bypass is allowed. Qt runtime directories must supply Valve's controller
event patch; ordinary upstream Qt alone is not the client's runtime ABI.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "boundary", ROOT / "scripts/audit-steam-client-sdk-boundary.py"
)
boundary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boundary)
QT_PATCH = "https://raw.githubusercontent.com/flathub/com.valvesoftware.SteamLink/28b8ff1a858e2cc2e6b931e1918a6a105d886b58/patches/steamlink/qtbase.patch"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def audit(binary, sdk, qt, output):
    assert digest(binary) == boundary.codec.SHA
    assert binary.name == "steamlink" and binary.parent.name == "bin"
    assert digest(sdk / "libavcodec.so.61") == boundary.CODEC_SHA
    assert digest(sdk / "libavutil.so.59") == boundary.codec.SDK_SHA
    assert "STEAMVIDEOTOKEN" not in os.environ, "Run without a supplied video token."
    dependencies = {}
    for name in ("Core", "Gui", "Widgets", "Svg"):
        library = next(
            (
                directory / f"libQt6{name}.so.6"
                for directory in qt
                if (directory / f"libQt6{name}.so.6").is_file()
            ),
            None,
        )
        assert library, name
        dependencies[name] = digest(library)
    fixture = ROOT / "app/tests/fixtures/video/sequential.h264"
    helper = ROOT / "scripts/steam-client-sdk-gdb.py"
    env = dict(os.environ)
    env["QT_QPA_PLATFORM"] = "offscreen"
    env["LD_LIBRARY_PATH"] = ":".join(str(p) for p in [qt[0], sdk, *qt[1:]])
    with tempfile.TemporaryDirectory(prefix="official-sdk-process-") as directory:
        directory = Path(directory)
        config = directory / "config.json"
        result = directory / "result.json"
        config.write_text(
            json.dumps(
                dict(
                    binary=str(binary),
                    sdk_directory=str(sdk),
                    fixture=str(fixture),
                    result=str(result),
                )
            )
        )
        env["NSL_OFFICIAL_SDK_PROBE_CONFIG"] = str(config)
        commands = directory / "probe.gdb"
        commands.write_text(
            "\n".join(
                [
                    "set pagination off",
                    "set confirm off",
                    "set auto-load off",
                    "set debuginfod enabled off",
                    "set startup-with-shell off",
                    "set disable-randomization off",
                    "set breakpoint pending on",
                    "break __libc_start_main",
                    "run",
                    "set $source_main = $rdi",
                    "tbreak *$source_main",
                    "continue",
                    f"python exec(compile(open({str(helper)!r}).read(), {str(helper)!r}, 'exec'))",
                    "continue",
                    "",
                ]
            )
        )
        completed = subprocess.run(
            [
                "gdb",
                "--nx",
                "--batch",
                "--quiet",
                "-x",
                str(commands),
                "--args",
                str(binary),
                "--version",
            ],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        output.with_suffix(".gdb.log").write_bytes(completed.stdout)
        assert completed.returncode == 0, completed.stdout[-4000:].decode(
            errors="replace"
        )
        assert result.exists(), (
            "Probe did not finish and observe original process exit; inspect .gdb.log."
        )
        report = json.loads(result.read_text())
        assert report["original_process_exit_code"] == 0
        assert (
            b"1.3.32.316" in completed.stdout and b"exited normally" in completed.stdout
        )
        assert (
            report["probe_cleanup_complete"] and report["mapped_original_sdk_verified"]
        )
    report.update(
        archive_url="https://repo.steampowered.com/steamlink/1.3.32.316/steamlink-1.3.32.316.tgz",
        client_sha256=boundary.codec.SHA,
        sdk_sha256=boundary.CODEC_SHA,
        util_sha256=boundary.codec.SDK_SHA,
        fixture_sha256=digest(fixture),
        framemd5_sha256=digest(fixture.with_suffix(".framemd5")),
        helper_sha256=digest(helper),
        qt_dependency_sha256=dependencies,
        qt_required_controller_patch=QT_PATCH,
        source_functions=boundary.inventory(
            binary.read_bytes(),
            {
                0x173B10: "table_init",
                0x173C40: "table_release",
                0x1780C0: "codec_factory",
                0x2EE0F0: "base_player_constructor",
                0x2EE370: "base_player_deleting_destructor",
                0x324610: "avcodec_constructor",
                0x3246D0: "start_decoding",
                0x324840: "stop_decoding",
                0x323FC0: "avcodec_deleting_destructor",
                0x1A7350: "cpu_info",
                0x326BE0: "decode_thread_count",
            },
        ),
    )
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--sdk-directory", type=Path, required=True)
    p.add_argument("--qt-library-directory", type=Path, action="append", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    report = audit(
        a.binary.resolve(),
        a.sdk_directory.resolve(),
        [p.resolve() for p in a.qt_library_directory],
        a.output,
    )
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        "Original official process: factory,",
        len(report["contexts"]),
        "pixel-verified SDK contexts, original Start/Stop/destructors, balanced refs, normal exit.",
    )
    print(
        "CPU/thread observations:",
        report["cpu_info"],
        report["original_start"]["sdk_threads"],
    )


if __name__ == "__main__":
    main()
