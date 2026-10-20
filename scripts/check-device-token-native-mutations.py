#!/usr/bin/env python3
"""Compile isolated token regressions; require normal receivers and semantic rejection."""
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
    source = ROOT / "third_party/ihslib/src/client/client.c"
    body = source.read_text()
    start = body.index("bool IHS_ClientCreateDeviceToken(")
    end = body.index("\nbool IHS_ClientSend(", start)
    helper = body[start:end]
    frozen = helper.replace(
        "    uint8_t id[8];",
        "    static bool saved; static uint8_t cached[32];\n    if (saved) { memcpy(token, cached, 32); return true; }\n    uint8_t id[8];",
    ).replace(
        "    return true;",
        "    memcpy(cached, token, 32); saved = true;\n    return true;",
    )
    discard = helper.replace(
        "    uint8_t id[8];",
        "    static bool saved; static uint8_t cached[32];\n    uint8_t id[8];",
    ).replace(
        "    return true;",
        "    if (saved) memcpy(token, cached, 32); else { memcpy(cached, token, 32); saved = true; }\n    return true;",
    )
    first_key = helper.replace(
        "    uint8_t id[8];",
        "    static bool saved; static uint8_t first[32];\n    if (!saved) { memcpy(first, secret, 32); saved = true; }\n    uint8_t id[8];",
    ).replace("sizeof(id), secret, 32,", "sizeof(id), first, 32,")
    variants = [
        (
            "freeze_token",
            source,
            body[:start] + frozen + body[end:],
            "fresh per-send encryption",
        ),
        (
            "discard_fresh_token",
            source,
            body[:start] + discard + body[end:],
            'assert row["token"]',
        ),
        (
            "big_endian_id",
            source,
            body.replace(
                "    IHS_WriteUInt64LE(id, client->base.deviceId);",
                "    for (unsigned n=0;n<8;++n) id[n]=(uint8_t)(client->base.deviceId>>(8*(7-n)));",
            ),
            'assert row["token"]',
        ),
        (
            "first_key_forever",
            source,
            body[:start] + first_key + body[end:],
            "reauthorize",
        ),
        (
            "aes128_token",
            source,
            body[:start]
            + helper.replace("sizeof(id), secret, 32,", "sizeof(id), secret, 16,")
            + body[end:],
            'assert row["token"]',
        ),
        (
            "ignore_encrypt_failure",
            source,
            body[:start]
            + helper.replace("if (result != 0 || count != 32)", "if (false)")
            + body[end:],
            "caller failure",
        ),
    ]
    for stem in ("authorization", "streaming"):
        path = source.parent / (stem + ".c")
        text = path.read_text()
        assert text.count("if (!tokenReady)") == 1
        variants.append(
            (
                stem + "_ignores_token_failure",
                path,
                text.replace("if (!tokenReady)", "if (false)"),
                "caller failure",
            )
        )
    entries = json.loads((build / "compile_commands.json").read_text())
    link_dir = build / "third_party/ihslib/tests/session"
    link_base = shlex.split(
        (link_dir / "CMakeFiles/ihs-device-token-oracle.dir/link.txt").read_text()
    )
    reports = []
    for name, src, mutant, expected in variants:
        assert mutant != src.read_text()
        directory = out / name
        directory.mkdir(exist_ok=True)
        copied, obj, receiver = (
            directory / src.name,
            directory / "mutant.o",
            directory / "receiver",
        )
        copied.write_text(mutant)
        entry = next(e for e in entries if Path(e["file"]) == src)
        command = [
            str(copied) if s == str(src) else s for s in shlex.split(entry["command"])
        ]
        command[command.index("-o") + 1] = str(obj)
        command += ["-I", str(src.parent)]
        compiled = subprocess.run(
            command, cwd=entry["directory"], capture_output=True, text=True
        )
        (directory / "compile.log").write_text(compiled.stdout + compiled.stderr)
        assert compiled.returncode == 0, (name, "compile failed")
        link = list(link_base)
        link.insert(1, str(obj))
        link[link.index("-o") + 1] = str(receiver)
        link = [
            (
                "-Wl,--dependency-file=" + str(directory / "link.d")
                if v.startswith("-Wl,--dependency-file=")
                else v
            )
            for v in link
        ]
        linked = subprocess.run(link, cwd=link_dir, capture_output=True, text=True)
        (directory / "link.log").write_text(linked.stdout + linked.stderr)
        assert linked.returncode == 0, (name, "link failed", linked.stderr)
        checked = subprocess.run(
            [
                "python3",
                str(ROOT / "scripts/check-steam-device-token.py"),
                "--receiver",
                str(receiver),
            ],
            text=True,
            capture_output=True,
            timeout=60,
        )
        (directory / "test.log").write_text(checked.stdout + checked.stderr)
        assert (
            checked.returncode == 1
            and "AssertionError" in checked.stderr
            and expected in checked.stderr
        ), (name, checked.stderr)
        assert (
            "run.returncode == 0" not in checked.stderr
            and "TimeoutExpired" not in checked.stderr
        ), (name, "receiver did not finish normally", checked.stderr)
        reports.append(
            dict(
                name=name,
                compiled=True,
                linked=True,
                checker_exit=1,
                receiver_normal=True,
                detected=expected,
            )
        )
        print(name, "semantic rejection", flush=True)
    (out / "report.json").write_text(json.dumps(reports, indent=2) + "\n")


if __name__ == "__main__":
    main()
