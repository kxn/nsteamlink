#!/usr/bin/env python3
"""Compile isolated streaming PIN regressions; require semantic checker rejection.

Every variant must compile/link, and its receiver must complete normally. A
compiler error, assertion in the receiver, crash or timeout is not detection.
"""
import argparse
import json
from pathlib import Path
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--build", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    build, out = a.build.resolve(), a.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    source = ROOT / "third_party/ihslib/src/client/streaming.c"
    body = source.read_text()
    entry = next(
        e
        for e in json.loads((build / "compile_commands.json").read_text())
        if Path(e["file"]) == source
    )
    compile_base = shlex.split(entry["command"])
    link_dir = build / "third_party/ihslib/tests/session"
    link_base = shlex.split(
        (link_dir / "CMakeFiles/ihs-streaming-pin-oracle.dir/link.txt").read_text()
    )
    variants = [
        (
            "plaintext_pin",
            "message.pin.len = state->encryptedPinLen;\n    message.pin.data = state->encryptedPin;",
            "message.pin.len = strnlen(request.pin, sizeof(request.pin));\n    message.pin.data = (uint8_t *)request.pin;",
            "9876",
        ),
        (
            "encrypt_each_retry",
            "    IHS_StreamingRequest request = state->request;",
            "    IHS_StreamingRequest request = state->request;\n    state->encryptedPinLen=sizeof(state->encryptedPin);\n    IHS_CryptoSymmetricEncrypt((const uint8_t *)request.pin,strnlen(request.pin,sizeof(request.pin)),client->base.secretKey,32,state->encryptedPin,&state->encryptedPinLen);",
            "9876",
        ),
        ("ignore_crypto_failure", "if (result != 0) {", "if (false) {", "False"),
    ]
    reports = []
    for name, before, after, expected in variants:
        if before is not None:
            assert body.count(before) == 1
        directory = out / name
        directory.mkdir(exist_ok=True)
        copied, obj, exe = (
            directory / "streaming.c",
            directory / "authorization.o",
            directory / "receiver",
        )
        mutant = body.replace(before, after)
        copied.write_text(mutant)
        command = [str(copied) if v == str(source) else v for v in compile_base]
        command[command.index("-o") + 1] = str(obj)
        command += ["-I", str(source.parent)]
        compiled = subprocess.run(
            command, cwd=entry["directory"], text=True, capture_output=True
        )
        (directory / "compile.log").write_text(compiled.stdout + compiled.stderr)
        assert compiled.returncode == 0, (name, "compile failed")
        link = list(link_base)
        link.insert(1, str(obj))
        link[link.index("-o") + 1] = str(exe)
        link = [
            (
                "-Wl,--dependency-file=" + str(directory / "link.d")
                if x.startswith("-Wl,--dependency-file=")
                else x
            )
            for x in link
        ]
        linked = subprocess.run(link, cwd=link_dir, text=True, capture_output=True)
        (directory / "link.log").write_text(linked.stdout + linked.stderr)
        assert linked.returncode == 0, (name, "link failed", linked.stderr)
        check = subprocess.run(
            [
                "python3",
                str(ROOT / "scripts/check-steam-streaming-pin.py"),
                "--receiver",
                str(exe),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        (directory / "test.log").write_text(check.stdout + check.stderr)
        assert check.returncode == 1 and "AssertionError" in check.stderr
        assert (
            "r.returncode == 0" not in check.stderr
            and "TimeoutExpired" not in check.stderr
        ), (name, "receiver failed", check.stderr)
        assert (
            expected in check.stderr
            or "assert rows[1:]" in check.stderr
            or "assert failed" in check.stderr
        ), (name, check.stderr)
        reports.append(
            dict(
                name=name,
                compiled=True,
                linked=True,
                checker_exit=1,
                receiver_normal=True,
                case=expected,
            )
        )
        print(name, "rejected by", expected, flush=True)
    (out / "report.json").write_text(json.dumps(reports, indent=2) + "\n")


if __name__ == "__main__":
    main()
