#!/usr/bin/env python3
"""Carry original shell test-result settings into original Linux UDP negotiation.

The shell instruction audit and Linux process are distinct pinned clients. The
interface is their identical complete protobuf settings file; no platform field
is silently changed. The Linux phase executes real file/UDP/crypto/stage/exit
code, against a controlled peer, not a genuine Steam host or FEC media producer.
"""

import argparse
import gzip
import importlib.util
import json
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "neg", ROOT / "scripts/audit-steam-client-negotiation-process.py"
)
neg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(neg)
_check_spec = importlib.util.spec_from_file_location(
    "check", ROOT / "scripts/check-steam-network-test-fec-flow.py"
)
check = importlib.util.module_from_spec(_check_spec)
_check_spec.loader.exec_module(check)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--sdk-directory", type=Path, required=True)
    p.add_argument("--qt-library-directory", type=Path, action="append", required=True)
    p.add_argument("--flow-report", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--snapshot", type=Path)
    args = p.parse_args()
    flow = json.loads(args.flow_report.read_text())
    check.verify_flow(flow)
    canonical = check.load("steam-network-test-fec-flow-reference.json.gz")
    assert flow == canonical
    configs = sorted({c["observed"]["final"] for c in flow["cases"]})
    binary, sdk, qt = (
        args.binary.resolve(),
        args.sdk_directory.resolve(),
        [d.resolve() for d in args.qt_library_directory],
    )
    digest = neg.udp.process.digest
    assert digest(binary) == neg.udp.process.boundary.codec.SHA
    assert digest(sdk / "libavcodec.so.61") == neg.udp.process.boundary.CODEC_SHA
    assert digest(sdk / "libavutil.so.59") == neg.udp.process.boundary.codec.SDK_SHA
    cases = []
    for index, config in enumerate(configs):
        for crc in (False, True):
            case = dict(
                name=f"result_{index:02d}_crc{int(crc)}",
                settings=config,
                reliable=False,
                crc=crc,
                bad_mac=False,
                server="070a0308c00b",
                response="0208001001",
                duplicate=False,
                bad_length=False,
            )
            with tempfile.TemporaryDirectory(
                prefix="official-test-result-settings-"
            ) as directory:
                settings = Path(directory) / "streaming_settings.bin"
                settings.write_bytes(bytes.fromhex(config))
                result = neg.udp.audit(
                    binary,
                    sdk,
                    qt,
                    args.output.with_name(
                        args.output.stem + "-" + case["name"] + ".json"
                    ),
                    case,
                    helper=ROOT / "scripts/steam-client-negotiation-gdb.py",
                    reactor=neg.Peer,
                    probe_config=dict(
                        udp_helper=str(ROOT / "scripts/steam-client-udp-gdb.py"),
                        settings_file=str(settings),
                    ),
                    validate=neg.verify,
                )
                assert settings.read_bytes() == bytes.fromhex(config)
                cases.append(result)
                print(
                    case["name"],
                    "exact complete result settings -> actual encrypted message4",
                    flush=True,
                )
    baseline = check.load("steam-client-negotiation-process-reference.json.gz")
    report = {
        key: baseline[key]
        for key in (
            "source_functions",
            "qt_dependency_sha256",
            "helper_sha256",
            "udp_helper_sha256",
            "bootstrap_helper_sha256",
        )
    }
    assert report["helper_sha256"] == digest(
        ROOT / "scripts/steam-client-negotiation-gdb.py"
    )
    assert report["udp_helper_sha256"] == digest(
        ROOT / "scripts/steam-client-udp-gdb.py"
    )
    assert report["bootstrap_helper_sha256"] == digest(
        ROOT / "scripts/steam-client-sdk-gdb.py"
    )
    assert report["source_functions"] == neg.udp.process.boundary.inventory(
        binary.read_bytes(), neg.FUNCTIONS
    )
    report["qt_dependency_sha256"] = {
        name: digest(
            next(
                d / f"libQt6{name}.so.6"
                for d in qt
                if (d / f"libQt6{name}.so.6").is_file()
            )
        )
        for name in ("Core", "Gui", "Widgets", "Svg")
    }
    assert report["qt_dependency_sha256"] == baseline["qt_dependency_sha256"]
    report.update(
        scope=__doc__,
        client_sha256=digest(binary),
        flow_report_sha256=digest(args.flow_report),
        cases=cases,
    )
    data = (json.dumps(report, indent=2) + "\n").encode()
    args.output.write_bytes(data)
    if args.snapshot:
        args.snapshot.write_bytes(gzip.compress(data, mtime=0))
    print(
        "Official shell results -> Linux real UDP: 24 complete-settings negotiations verified"
    )


if __name__ == "__main__":
    main()
