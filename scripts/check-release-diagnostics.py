#!/usr/bin/env python3
"""Fail closed if an ordinary application build contains private diagnostics.

This audits configuration, application/SDK objects and the linked executable.
On Switch it also checks that the NRO's loadable segments came from that ELF.
It is an exclusion gate, not a general proof of network or memory safety.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import struct
import subprocess

MARKERS = (
    b"ERR supported: ping state stats perf cloud audio hid hidlog diag",
    b"GET required", b"storage_errno", b"session-%020",
    b"cloud_watch saved=", b"cloud_update stall_ms", b"media_rx ch=", b"udp_rx observer=",
    b"cloud_net event=", b"cloud_time total_ms=", b"cloud_subscription", b"cloud_addr local=",
    b"cloud_try stage=", b"cloud_dns event=", b"dns_query event=",
    b"control_tx phase=", b"control_rx phase=", b"control_identity account_present=",
    b"sns_config event=", b"sns_start failed_stage=",
    b"RUNTIME_FIXTURE_", b"CLOUD_FIXTURE_",
    b"render-rate-test",
    b"--adaptive-pacing",
    b"--no-adaptive-pacing",
    b"stream_diag.log",
    b"stream_diag_prev.log",
    b"stream_diag_older.log",
    b"ERR supported: ping state stats perf audio hid hidlog diag",
    b"runtime: debug UDP fd=",
    b"ERR diagnostic log unavailable",
    b"vq1 ",
    b"vq7 ",
    b"vq8 ",
    b"vq9 ",
    b"hidrep ms=",
    b"IHS_UDPSocketOpen: SO_RCVBUF capped",
    b"IHS_UDPSocketReceive:",
    b"Platform initialization failed",
    b"Media initialization failed",
    b"Font initialization failed:",
)
FORBIDDEN_SYMBOLS = {
    "sl_gns_sdr_test_loss", "sl_gns_sdr_test_terminal", "sl_gns_sdr_test_migration",
    "sl_gns_sdr_topology_fixture", "sl_gns_sdr_transport_stats", "sl_gns_sdr_probe_create",
    "sl_packet_diagnostics_begin", "sl_packet_diagnostics_read", "sl_packet_diagnostics_received",
    "udp_poll",
    "log_main",
    "log_queue",
    "log_tail_text",
    "log_previous_text",
    "nxlinkConnectToHost",
    "nxlinkStdio",
    "nxlinkConnectToHostRaw",
    "dkCmdBufReportCounter",
    "dkTimestampToNs",
    "IHS_ControlDiagnosticsInit",
    "IHS_ControlDiagnosticsQuit",
    "IHS_SessionChannelControlDrainPendingHIDReports",
    "IHS_SessionChannelControlGetRecentHIDReports",
    "HIDPendingPush",
    "hidPending",
    "hidReportRing",
    "hidDiagnostics",
    "hidReportLock",
    "hidPendingLock",
    "hidPendingDropped",
    "hidPendingCount",
    "hidPendingHead",
    "hidPendingTail",
    "hidReportRingHead",
    "hidReportRingCount",
}
CORE_UNITS = {
    "application.c",
    "media.c",
    "runtime.c",
    "video_pipeline.c",
    "gfx.c",
    "frame_pacer.c",
    "video_scheduler.c",
    "system.c",
    "ui_renderer.c",
    "ui_model.c",
    "input_router.c",
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cache_values(path):
    return dict(
        re.findall(r"^([A-Za-z_][A-Za-z_0-9]*):[^=\n]*=(.*)$", path.read_text(), re.M)
    )


def no_markers(data, label):
    for marker in MARKERS:
        require(marker not in data, f"diagnostic marker {marker!r} in {label}")


def symbols(nm, path):
    output = subprocess.check_output([str(nm), "-a", str(path)], text=True)
    return {line.split()[-1] for line in output.splitlines() if line.split()}


def no_symbols(names, label):
    forbidden = {n for n in names if n.split(".")[0] in FORBIDDEN_SYMBOLS}
    require(not forbidden, f"diagnostic symbols {sorted(forbidden)} in {label}")


def check_nro_elf(elf, nro):
    """Compare all PT_LOAD bytes, except the header elf2nro fills at 0x10..0x7f."""
    data, image = elf.read_bytes(), nro.read_bytes()
    require(data[:6] == b"\x7fELF\x02\x01", "expected little-endian ELF64")
    require(image[0x10:0x14] == b"NRO0", "expected NRO")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    loads = []
    for i in range(count):
        kind, flags, offset, address, _, filesz, memsz, align = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + i * size
        )
        if kind == 1:
            loads.append((offset, address, filesz, memsz))
    require(len(loads) == 3, "expected three loadable Switch ELF segments")
    for i, (offset, address, filesz, _) in enumerate(loads):
        start, padded = struct.unpack_from("<II", image, 0x20 + i * 8)
        require(
            start == address and padded == (filesz + 0xFFF) & ~0xFFF,
            f"NRO/ELF segment {i} layout mismatch",
        )
        require(start + padded <= len(image), "truncated NRO segment")
        expected = data[offset : offset + filesz] + bytes(padded - filesz)
        actual = image[start : start + padded]
        if i == 0:
            require(
                actual[:0x10] == expected[:0x10] and actual[0x80:] == expected[0x80:],
                "NRO/ELF executable segment mismatch",
            )
        else:
            require(actual == expected, f"NRO/ELF segment {i} mismatch")
    no_markers(image[: struct.unpack_from("<I", image, 0x18)[0]], nro)


def macro_off(argv, name, source):
    definitions = [
        arg
        for arg in argv
        if arg == "-U" + name or arg == "-D" + name or arg.startswith("-D" + name + "=")
    ]
    require(
        definitions == ["-D" + name + "=0"],
        f"{name} must be defined once as 0: {source}",
    )


def check(build):
    build = build.resolve()
    config = cache_values(build / "CMakeCache.txt")
    for option in (
        "NSL_DIAGNOSTICS",
        "NSL_BUILD_TOOLS",
        "NSL_TEST_FORCE_1080",
        "IHSLIB_DIAGNOSTICS",
    ):
        require(
            config.get(option) == "OFF", f"{option} must be OFF for ordinary artifacts"
        )
    require(
        config.get("CMAKE_BUILD_TYPE") == "Release",
        "ordinary artifacts require Release optimization",
    )
    commands = json.loads((build / "compile_commands.json").read_text())
    link_path = build / "app/CMakeFiles/nsteamlink.dir/link.txt"
    link = shlex.split(link_path.read_text())
    targets = {"nsteamlink"} | {
        re.search(r"lib(nsl_[^/]+)\.a$", item).group(1)
        for item in link
        if re.search(r"lib(nsl_[^/]+)\.a$", item)
    }
    require(
        {"nsl_platform", "nsl_ui", "nsl_gfx", "nsl_video_pipeline"} <= targets,
        "application product libraries missing from actual link",
    )
    nm = Path(config["CMAKE_NM"])
    product = []
    core = set()
    sdk = []
    for entry in commands:
        source = Path(entry["file"])
        argv = entry.get("arguments") or shlex.split(entry["command"])
        obj = Path(entry["directory"]) / argv[argv.index("-o") + 1]
        is_product = bool({t + ".dir" for t in targets}.intersection(obj.parts))
        is_sdk = (
            source.name in {"base.c", "ch_control.c", "ihs_udp_posix.c"}
            and "third_party" in source.parts
        )
        if source.name in {"sns_backend.cpp", "sdr_probe.cpp"}:
            macro_off(argv, "NSL_SNS_PROBES", source)
        if not is_product and not is_sdk:
            continue
        data = obj.read_bytes()
        if is_sdk:
            macro_off(argv, "IHSLIB_DIAGNOSTICS", source)
            no_markers(data, obj)
            no_symbols(symbols(nm, obj), obj)
            if source.name == "ihs_udp_posix.c":
                require(
                    not {"fprintf", "getsockopt"} & symbols(nm, obj),
                    "platform stderr/buffer diagnostics remain in UDP object",
                )
            sdk.append(
                {
                    "source": str(source),
                    "source_sha256": digest(source),
                    "object": str(obj),
                    "object_sha256": digest(obj),
                }
            )
        if not is_product:
            continue
        text = source.read_text()
        if "NSL_DIAGNOSTICS" in text:
            macro_off(argv, "NSL_DIAGNOSTICS", source)
        if any(arg.startswith("-DNSL_TEST_FORCE_1080") for arg in argv):
            macro_off(argv, "NSL_TEST_FORCE_1080", source)
        no_markers(data, obj)
        names = symbols(nm, obj)
        no_symbols(names, obj)
        if source.name == "application.c":
            require("fprintf" not in names, "application stderr diagnostics remain")
        if source.name == "runtime.c":
            require(
                not {"bind", "recvfrom", "sendto"} & names,
                "debug UDP transport remains in runtime object",
            )
        if source.name == "video_scheduler.c":
            require("sl_video_wait" in names, "official video timing gate missing")
            require(
                "sl_pacer_wait" not in names,
                "legacy publication wait still drives video",
            )
        if source.name == "frame_pacer.c":
            pre = argv[:]
            del pre[pre.index("-o") : pre.index("-o") + 2]
            pre[pre.index("-c")] = "-E"
            expanded = subprocess.check_output(pre, cwd=entry["directory"], text=True)
            for field in (
                "diag_ready_us",
                "diag_wait_us",
                "diag_start_us",
                "settled_presented",
                "deferred",
                "unobserved",
                "holdovers",
            ):
                require(field not in expanded, f"diagnostic field remains: {field}")
            for required in ("sl_pacer_wait", "sl_pacer_publish", "sl_pacer_submit"):
                require(required in names, f"product scheduler missing: {required}")
        if source.name in CORE_UNITS:
            core.add(source.name)
        product.append(
            {
                "source": str(source),
                "source_sha256": digest(source),
                "object": str(obj),
                "object_sha256": digest(obj),
            }
        )
    require(
        CORE_UNITS <= core,
        f"product audit coverage missing: {sorted(CORE_UNITS - core)}",
    )
    require(
        {"base.c", "ch_control.c", "ihs_udp_posix.c"}
        <= {Path(e["source"]).name for e in sdk},
        "SDK audit coverage missing",
    )
    switch = any("/platforms/switch/" in e["source"] for e in product)
    executable = build / ("app/nsteamlink.elf" if switch else "app/nsteamlink")
    no_symbols(symbols(nm, executable), executable)
    no_markers(executable.read_bytes(), executable)
    manifest = json.loads((build / "generated/graphics_manifest.json").read_text())
    result = {
        "schema": 1,
        "status": "passed",
        "scope": "diagnostic exclusion; not general network safety",
        "configuration": {
            k: config[k]
            for k in (
                "CMAKE_BUILD_TYPE",
                "NSL_DIAGNOSTICS",
                "NSL_BUILD_TOOLS",
                "NSL_TEST_FORCE_1080",
                "IHSLIB_DIAGNOSTICS",
            )
        },
        "product_units": product,
        "sdk_units": sdk,
        "executable_sha256": digest(executable),
    }
    if switch:
        require(manifest["backend"] == "deko", "Switch must use deko")
        require(
            "libdeko3dd.a" not in " ".join(link) and "libdeko3d.a" in " ".join(link),
            "wrong deko library",
        )
        nro = build / "app/nsteamlink.nro"
        check_nro_elf(executable, nro)
        result["nro_sha256"] = digest(nro)
    source_root = Path(config["CMAKE_HOME_DIRECTORY"])
    for unit in result["product_units"] + result["sdk_units"]:
        unit["source"] = str(Path(unit["source"]).relative_to(source_root))
        unit["object"] = str(Path(unit["object"]).relative_to(build))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = check(args.build)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(
        f'PASS: {len(result["product_units"])} product units, SDK objects and final executable; diagnostics excluded'
    )


if __name__ == "__main__":
    main()
