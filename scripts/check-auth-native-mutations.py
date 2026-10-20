#!/usr/bin/env python3
"""Compile isolated auth-policy regressions and run real Native UDP comparisons.

A compile/link error or crashing receiver is not detection. No working source,
reference fixture, SDK result or worker/crypto behavior is replaced.
"""

import argparse
import json
from pathlib import Path
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "6558b5276de2f4249524df46539429c548700e1c"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--negotiation",
        action="store_true",
        help="Check the independent legacy capability producer",
    )
    args = parser.parse_args()
    build, output = args.build.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = (
        ROOT / "third_party/ihslib/src/session/channels/ch_control_authentication.c"
    )
    if args.negotiation:
        source = (
            ROOT / "third_party/ihslib/src/session/channels/ch_control_negotiation.c"
        )
    body = source.read_text()
    historical = subprocess.check_output(
        ["git", "show", BASELINE + ":src/session/channels/ch_control_authentication.c"],
        cwd=ROOT / "third_party/ihslib",
        text=True,
    )
    entry = next(
        e
        for e in json.loads((build / "compile_commands.json").read_text())
        if Path(e["file"]) == source
    )
    compile_base = shlex.split(entry["command"])
    link_base = shlex.split(
        (build / "app/CMakeFiles/nsl-auth-udp-oracle.dir/link.txt").read_text()
    )
    changes = [
        ("old_policy", None, historical, "default_result"),
        (
            "no_version_gate",
            "!message->has_version || message->version != k_EStreamVersionCurrent ||",
            "",
            "version_missing",
        ),
        (
            "require_explicit_result",
            "if (!message->has_version ||",
            "if (!message->has_result || !message->has_version ||",
            "default_result",
        ),
        (
            "unknown_overwrites_known",
            "if (scalar <= 1)",
            "if (true)",
            "failed_then_unknown",
        ),
        (
            "leave_auth_waiting",
            "        IHS_SessionDisconnect(session);\n        IHS_SessionClientTransportClosed(session);",
            "        /* Keep the rejected authentication waiting. */",
            "failed",
        ),
        ("wrong_group_limit", "if (depth >= 100)", "if (depth >= 99)", "group_100"),
    ]
    if args.negotiation:
        changes = [
            (
                "infer_legacy_from_decoder",
                "if (caps->hasLegacyHevcCapability)\n        PROTOBUF_C_SET_VALUE(clientCaps, supports_video_hevc_obsolete, caps->legacyHevcCapability);",
                "if (hevcAvailable)\n        PROTOBUF_C_SET_VALUE(clientCaps, supports_video_hevc_obsolete, true);",
                "fec_absent_reliable0_crc0",
            ),
            (
                "infer_fec_from_unreliable",
                "    CNegotiationSetConfigMsg response = CNEGOTIATION_SET_CONFIG_MSG__INIT;",
                "    if (!message->reliable_data) PROTOBUF_C_SET_VALUE(clientConfig, enable_unreliable_fec, true);\n    CNegotiationSetConfigMsg response = CNEGOTIATION_SET_CONFIG_MSG__INIT;",
                "fec_absent_reliable0_crc0",
            ),
            (
                "discard_saved_fec_true",
                "    CNegotiationSetConfigMsg response = CNEGOTIATION_SET_CONFIG_MSG__INIT;",
                "    if (clientConfig.has_enable_unreliable_fec) clientConfig.enable_unreliable_fec = false;\n    CNegotiationSetConfigMsg response = CNEGOTIATION_SET_CONFIG_MSG__INIT;",
                "fec_c80101_reliable0_crc0",
            ),
        ]
    reports = []
    for name, before, after, expected in changes:
        directory = output / name
        directory.mkdir(exist_ok=True)
        if before is None:
            mutated = after
        else:
            assert body.count(before) == 1, (name, body.count(before))
            mutated = body.replace(before, after)
        copied, obj, executable = (
            directory / "auth.c",
            directory / "auth.o",
            directory / "receiver",
        )
        copied.write_text(mutated)
        command = [str(copied) if x == str(source) else x for x in compile_base]
        command[command.index("-o") + 1] = str(obj)
        command += ["-I", str(source.parent)]
        compiled = subprocess.run(
            command, cwd=entry["directory"], text=True, capture_output=True
        )
        (directory / "compile.log").write_text(compiled.stdout + compiled.stderr)
        assert compiled.returncode == 0, (name, "compile error")
        link = list(link_base)
        link.insert(1, str(obj))
        link[link.index("-o") + 1] = str(executable)
        link = [
            "-Wl,--dependency-file=" + str(directory / "link.d")
            if x.startswith("-Wl,--dependency-file=")
            else x
            for x in link
        ]
        linked = subprocess.run(link, cwd=build / "app", text=True, capture_output=True)
        (directory / "link.log").write_text(linked.stdout + linked.stderr)
        assert linked.returncode == 0, (name, "link error", linked.stderr)
        tested = subprocess.run(
            [
                "python3",
                str(
                    ROOT
                    / (
                        "scripts/check-steam-negotiation-process.py"
                        if args.negotiation
                        else "scripts/check-steam-auth-process.py"
                    )
                ),
                "--receiver",
                str(executable),
            ],
            text=True,
            capture_output=True,
            timeout=30,
        )
        diagnostic = tested.stdout + tested.stderr
        (directory / "test.log").write_text(diagnostic)
        assert tested.returncode == 1 and ("'" + expected + "'") in tested.stderr, (
            name,
            tested.returncode,
            tested.stderr,
        )
        assert (
            "AssertionError: (" in tested.stderr
            and "'native'" not in tested.stderr
            and "-6," not in tested.stderr
            and "-11," not in tested.stderr
        ), (name, "receiver crash is not detection")
        reports.append(
            dict(name=name, compiled=True, linked=True, detected=True, case=expected)
        )
        print(name, "detected by", expected, flush=True)
    (output / "report.json").write_text(json.dumps(reports, indent=2) + "\n")
    print(f"Native policy mutants: {len(reports)} compiled regressions detected")


if __name__ == "__main__":
    main()
