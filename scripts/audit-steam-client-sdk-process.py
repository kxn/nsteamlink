#!/usr/bin/env python3
"""Probe the unchanged official client and bundled SDK inside its real process.

GDB pauses at original main after dynamic/static initialization. Explicit calls
exercise the original codec factory, real SDK decoding, and original base-player/
AVCodec constructors, Start, Stop and deleting destructors. The configured client
storage is not a full Client/Connection. The default excludes original deferred
get_format/FinalDecode; Qt event-loop, authenticated networking, hardware and
physical display remain outside all modes. An optional worker extension adds
original asynchronous submission, deferred format consumption and cancellation/
restart. Its client boundary can be partial storage, original construction or
original UDP Init against a receive-only loopback fixture; the default probe
retains the original direct Start/Stop scope. A separate control-start mode uses
the original player, encrypted packet callback/FIFO and video factory without
writing the decoder owner link. Its parsed-carrier/auth-token inputs are explicit.
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


def audit(
    binary,
    sdk,
    qt,
    output,
    worker_mode=None,
    client_bootstrap=None,
    endpoint=None,
    format_memory=False,
    start_mode=None,
    video_codec_data=None,
):
    assert start_mode in (
        None,
        "decode",
        "replace_pending",
        "stop_pending",
        "reset_ready",
    )
    assert video_codec_data is None or (
        start_mode and isinstance(video_codec_data, bytes)
    )
    assert not start_mode or (worker_mode is None and client_bootstrap == "udp")
    assert worker_mode in (
        None,
        "empty",
        "decode",
        "cancel",
        "restart",
        "reset_pending",
        "reset_ready",
        "reset_open_error",
    )
    assert (
        worker_mode not in ("reset_pending", "reset_ready", "reset_open_error")
        or client_bootstrap == "udp"
    )
    assert client_bootstrap in (None, "constructed", "udp")
    assert client_bootstrap is None or worker_mode is not None or start_mode is not None
    assert not format_memory or (
        client_bootstrap == "udp" and worker_mode == "reset_pending"
    )
    if client_bootstrap == "udp":
        assert (
            endpoint
            and endpoint.startswith("127.0.0.1:")
            and 0 < int(endpoint.split(":")[1]) < 65536
        )
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
                    worker_mode=worker_mode,
                    start_mode=start_mode,
                    video_codec_data_hex=video_codec_data.hex()
                    if video_codec_data is not None
                    else None,
                    start_helper=str(ROOT / "scripts/steam-client-start-gdb.py"),
                    client_bootstrap=client_bootstrap,
                    endpoint=endpoint,
                    format_memory=format_memory,
                    format_memory_helper=str(
                        ROOT / "scripts/steam-client-format-memory-gdb.py"
                    ),
                    worker_helper=str(ROOT / "scripts/steam-client-worker-gdb.py"),
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
                    "set python print-stack full",
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
        worker_helper_sha256=digest(ROOT / "scripts/steam-client-worker-gdb.py")
        if worker_mode
        else None,
        **(
            {
                "format_memory_helper_sha256": digest(
                    ROOT / "scripts/steam-client-format-memory-gdb.py"
                )
            }
            if format_memory
            else {}
        ),
        **(
            {"start_helper_sha256": digest(ROOT / "scripts/steam-client-start-gdb.py")}
            if start_mode
            else {}
        ),
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
                **(
                    {
                        0x31A6F0: "client_constructor",
                        0x31AAB0: "client_destructor",
                        0x31AC40: "client_deleting_destructor",
                        0x3181A0: "client_transport_init_connect",
                        0x3230A0: "client_on_think",
                        0x31F9D0: "handle_pending_resets",
                        0x2AED10: "address_parse",
                        0x2AEF30: "address_format",
                        0x1918A0: "message_channel_constructor",
                        0x191F90: "message_channel_poll",
                        0x1A3D10: "udp_transport_init",
                        0x31AA60: "client_cleanup",
                    }
                    if client_bootstrap
                    else {}
                ),
                **(
                    {
                        0x2ED830: "decoder_submit_frame",
                        0x2ED980: "public_decoder_start",
                        0x2EDBF0: "public_decoder_stop",
                        0x2EDB20: "decoder_join_purge",
                        0x2EDA20: "decoder_worker_loop",
                        0x2EDAF0: "decoder_worker_entry",
                        0x2EDC50: "decoder_restart",
                        0x3260D0: "decode_frame",
                        0x326F30: "decode_pending",
                        0x324190: "final_decode",
                        0x324C90: "format_dispatch",
                        0x324D00: "sdk_get_format",
                        0x324D10: "main_format_consumer",
                        0x324990: "format_selector",
                        0x31DD40: "decoder_info",
                        0x1947A0: "frame_send",
                        0x198AA0: "carrier_constructor",
                        0x1942F0: "frame_constructor",
                        0x194310: "frame_copy",
                        0x194540: "frame_destructor",
                        0x2EDF70: "player_put",
                        0x2EF250: "player_queue_pop",
                        0x323FF0: "output_release",
                        0x1A4210: "udp_transport_constructor",
                        0x19BD00: "connection_factory",
                        0x19BB80: "connection_constructor",
                        0x19A860: "connection_close",
                        0x1A0C10: "socket_manager_update",
                        0x1A00E0: "socket_manager_destructor",
                        0x19FFB0: "socket_manager_stop",
                        0x1AA260: "original_thread_join",
                    }
                    if worker_mode or start_mode
                    else {}
                ),
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
