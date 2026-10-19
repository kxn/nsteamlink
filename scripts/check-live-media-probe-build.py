#!/usr/bin/env python3
"""Check actual Switch observer interposition and its exclusion from ordinary NROs.

This proves link/call structure and artifact identity, not a Steam session,
delivery of every config fragment, peer FEC acceptance or RS reconstruction.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import struct
import subprocess

WRAPPED = (
    "IHS_SessionChannelControlSend",
    "IHS_SessionQueuePacketResult",
    "IHS_SessionChannelControlOnNegotiation",
    "IHS_UDPSocketSend",
    "sl_stream_settings_load",
    "sl_stream_settings_save",
    "sl_auth_save",
)
EDGES = (
    ("OnNegotiationInit", "__wrap_IHS_SessionChannelControlSend"),
    ("IHS_SessionSendControlMessage", "__wrap_IHS_SessionChannelControlSend"),
    ("IHS_SessionChannelQueueFrameResult", "__wrap_IHS_SessionQueuePacketResult"),
    (
        "IHS_SessionChannelControlOnMessageReceived",
        "__wrap_IHS_SessionChannelControlOnNegotiation",
    ),
    ("IHS_BaseSend", "__wrap_IHS_UDPSocketSend"),
    ("worker_main", "__wrap_sl_stream_settings_load"),
    ("sync_stream_settings", "__wrap_sl_stream_settings_save"),
    ("worker_main", "__wrap_sl_auth_save"),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def same_loads(elf, nro):
    data, image = elf.read_bytes(), nro.read_bytes()
    require(
        data[:6] == b"\x7fELF\x02\x01" and image[0x10:0x14] == b"NRO0", "bad ELF/NRO"
    )
    offset = struct.unpack_from("<Q", data, 32)[0]
    stride, count = struct.unpack_from("<HH", data, 54)
    loads = []
    for index in range(count):
        kind, _, pos, address, _, size, _, _ = struct.unpack_from(
            "<IIQQQQQQ", data, offset + index * stride
        )
        if kind == 1:
            loads.append((pos, address, size))
    require(len(loads) == 3, "expected three Switch load segments")
    for index, (pos, address, size) in enumerate(loads):
        start, padded = struct.unpack_from("<II", image, 0x20 + index * 8)
        require(
            start == address and padded == (size + 4095) & ~4095,
            "NRO/ELF layout mismatch",
        )
        expected = data[pos : pos + size] + bytes(padded - size)
        actual = image[start : start + padded]
        if index == 0:
            expected, actual = (
                expected[:16] + expected[128:],
                actual[:16] + actual[128:],
            )
        require(actual == expected, "probe NRO differs from audited ELF")


def check(root, build, ordinary):
    root, build, ordinary = root.resolve(), build.resolve(), ordinary.resolve()
    spec = importlib.util.spec_from_file_location(
        "release_exclusion", root / "scripts/check-release-diagnostics.py"
    )
    exclusion = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(exclusion)
    ordinary_audit = exclusion.check(ordinary)
    cache = exclusion.cache_values(build / "CMakeCache.txt")
    for option in ("NSL_DIAGNOSTICS", "IHSLIB_DIAGNOSTICS"):
        require(cache.get(option) == "ON", option + " must be ON for this probe")
    require(
        cache.get("NSL_TEST_FORCE_1080") == "OFF",
        "forced resolution is not an ordinary session",
    )
    identity = json.loads((build / "generated/build_identity.json").read_text())
    ordinary_identity = json.loads(
        (ordinary / "generated/build_identity.json").read_text()
    )
    require(identity == ordinary_identity, "ordinary/probe build identities differ")
    app = build / "app"
    elf, nro = app / "nsl-live-media-probe.elf", app / "nsl-live-media-probe.nro"
    same_loads(elf, nro)
    require(
        identity["commit"].encode() in nro.read_bytes(), "probe source identity missing"
    )
    for marker in (
        b"observer=3 fec=",
        b"sent_fec=",
        b"original_known=",
        b"LIVE_%s run=",
    ):
        require(
            marker in nro.read_bytes(), "missing observer-v3 marker " + repr(marker)
        )
    link = shlex.split(
        (app / "CMakeFiles/nsl-live-media-probe.dir/link.txt").read_text()
    )
    for name in WRAPPED:
        require(
            link.count("-Wl,--wrap=" + name) == 1,
            "missing/duplicate wrap option " + name,
        )
    linkmap = (app / "nsl-live-media-probe.map").read_text()
    for library, source in (
        ("ihslib", "ch_control_negotiation"),
        ("ihslib", "channel"),
        ("ihslib", "base"),
        ("nsl_platform", "runtime"),
        ("nsl_stream_settings", "stream_settings"),
        ("nsl_ui", "auth_store"),
    ):
        require(
            re.search(r"lib" + library + r"\.a\(" + source + r"(?:\.c)?\.o\)", linkmap),
            "production provider missing: " + library + "/" + source,
        )
    symbol_text = subprocess.check_output(
        [cache["CMAKE_NM"], "-S", "--defined-only", str(elf)], text=True
    )
    names = {line.split()[-1] for line in symbol_text.splitlines() if line.split()}
    require("probe_config_sent_fec" in names, "per-sent-head FEC observation missing")
    ledger = [
        line.split()
        for line in symbol_text.splitlines()
        if line.endswith(" probe_config_entries")
    ]
    require(
        len(ledger) == 1 and int(ledger[0][1], 16) == 48128,
        "unexpected fixed observer ledger",
    )
    dump = subprocess.check_output([cache["CMAKE_OBJDUMP"], "-d", str(elf)], text=True)
    calls, function = set(), ""
    for line in dump.splitlines():
        header = re.match(r"^[0-9a-f]+ <([^>]+)>:", line)
        if header:
            function = header[1].split(".")[0]
        branch = re.search(r"\b(?:b|bl)\s+[0-9a-f]+\s+<([^>]+)>", line)
        if branch:
            calls.add((function, branch[1]))
    for source, destination in EDGES:
        require(
            (source, destination) in calls,
            "production call missing: " + source + " -> " + destination,
        )
    for name in WRAPPED:
        require(
            ("__wrap_" + name, name) in calls,
            "observer does not call original: " + name,
        )
    ordinary_elf = ordinary / "app/nsteamlink.elf"
    ordinary_names = exclusion.symbols(Path(cache["CMAKE_NM"]), ordinary_elf)
    for name in ["__wrap_" + name for name in WRAPPED] + [
        "probe_config_entries",
        "probe_config_sent_fec",
    ]:
        require(name not in ordinary_names, "probe remains in ordinary ELF: " + name)
    require(
        b"observer=3 fec=" not in (ordinary / "app/nsteamlink.nro").read_bytes(),
        "probe remains in ordinary NRO",
    )
    return {
        "status": "passed",
        "observer": 3,
        "identity": identity,
        "ledger_bytes": int(ledger[0][1], 16),
        "production_edges": [list(edge) for edge in EDGES],
        "original_delegation": list(WRAPPED),
        "probe_elf_sha256": sha(elf),
        "probe_nro_sha256": sha(nro),
        "ordinary_nro_sha256": sha(ordinary / "app/nsteamlink.nro"),
        "ordinary_exclusion": ordinary_audit["status"],
        "scope": "actual linked observers and ordinary exclusion; no device or RS claim",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--ordinary-build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = check(Path(__file__).resolve().parents[1], args.build, args.ordinary_build)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        "PASS: actual observer-v3 call paths, original delegation, fixed ledger and ordinary exclusion"
    )


if __name__ == "__main__":
    main()
