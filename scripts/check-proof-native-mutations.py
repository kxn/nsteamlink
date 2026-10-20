#!/usr/bin/env python3
"""Compile Proof regressions and require normal receiver semantic rejection."""
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
    directory = ROOT / "third_party/ihslib/src/client"
    stream = directory / "streaming.c"
    client = directory / "client.c"
    observer = """        if (client->callbacks.streaming && client->callbacks.streaming->persistProof)
            client->callbacks.streaming->persistProof(client, &state->host,
                                                      state->request.keySteamId, secret,
                                                      client->callbackContexts.streaming);
"""
    original = stream.read_text()
    late = original.replace(observer, "")
    mark = "    memset(secret, 0, sizeof(secret));\n    if (result == 0 && length <= capacity) {"
    assert late.count(mark) == 1
    late = late.replace(mark, observer + mark)
    variants = [
        (
            "rehash_duplicate",
            stream,
            "request->update_secret && !state->proofUpdated",
            "request->update_secret",
        ),
        ("skip_persist", stream, observer, ""),
        ("persist_after_encrypt", stream, original, late),
        (
            "echo_changed_instead_of_requested",
            stream,
            "response.updated_secret = request->update_secret;",
            "response.updated_secret = request->update_secret && !state->proofUpdated;",
        ),
        (
            "omit_absent_request_id",
            stream,
            "response.request_id = state->requestId;",
            "response.has_request_id = request->has_request_id; response.request_id = state->requestId;",
        ),
        (
            "ignore_request_id",
            stream,
            "if (request->has_request_id && request->request_id != state->requestId)",
            "if (false && request->has_request_id && request->request_id != state->requestId)",
        ),
        (
            "clear_flag_after_authorization",
            stream,
            "NotifyAuthorization(state, NULL, resp->steamid);",
            "state->proofUpdated = false; NotifyAuthorization(state, NULL, resp->steamid);",
        ),
        (
            "fixed_output_limit",
            stream,
            "(request->challenge.len / IHS_CRYPTO_AES_BLOCK_SIZE + 2) * IHS_CRYPTO_AES_BLOCK_SIZE;",
            "1024;",
        ),
        (
            "wrong_persistent_identity",
            stream,
            "state->request.keySteamId, secret,",
            "0, secret,",
        ),
        (
            "drop_foreign_reply",
            stream,
            "        SendEmptyProof(client, *incoming->address);",
            "        /* regression: ignore foreign */",
        ),
        (
            "admit_zero_identity",
            client,
            "if (!header->has_client_id || !header->client_id)",
            "if (false && (!header->has_client_id || !header->client_id))",
        ),
        (
            "admit_trailing_bytes",
            client,
            "if (payload_size != data->size)",
            "if (payload_size > data->size)",
        ),
    ]
    entries = json.loads((build / "compile_commands.json").read_text())
    link_dir = build / "third_party/ihslib/tests/session"
    link_base = shlex.split(
        (link_dir / "CMakeFiles/ihs-auto-authorization-oracle.dir/link.txt").read_text()
    )
    reports = []
    for name, path, before, after in variants:
        body = path.read_text()
        assert body.count(before) == 1, (name, "anchor")
        work = out / name
        work.mkdir(exist_ok=True)
        copy, obj, exe = (work / n for n in ("mutant.c", "mutant.o", "receiver"))
        copy.write_text(body.replace(before, after))
        entry = next(x for x in entries if Path(x["file"]) == path)
        command = [
            str(copy) if x == str(path) else x for x in shlex.split(entry["command"])
        ]
        command[command.index("-o") + 1] = str(obj)
        command += ["-I", str(directory)]
        compiled = subprocess.run(
            command, cwd=entry["directory"], text=True, capture_output=True
        )
        (work / "compile.log").write_text(compiled.stdout + compiled.stderr)
        assert compiled.returncode == 0, (name, "compile")
        link = list(link_base)
        link.insert(1, str(obj))
        link[link.index("-o") + 1] = str(exe)
        link = [
            (
                "-Wl,--dependency-file=" + str(work / "link.d")
                if x.startswith("-Wl,--dependency-file=")
                else x
            )
            for x in link
        ]
        linked = subprocess.run(link, cwd=link_dir, text=True, capture_output=True)
        (work / "link.log").write_text(linked.stdout + linked.stderr)
        assert linked.returncode == 0, (name, "link")
        result = subprocess.run(
            [
                "python3",
                str(ROOT / "scripts/check-steam-proof-transaction.py"),
                "--receiver",
                str(exe),
            ],
            text=True,
            capture_output=True,
            timeout=90,
        )
        (work / "check.log").write_text(result.stdout + result.stderr)
        assert result.returncode == 1 and "AssertionError" in result.stderr, (
            name,
            "checker must reject normally",
            result.stderr[-2000:],
        )
        assert (
            "run.returncode == 0" not in result.stderr
            and "run.returncode==0" not in result.stderr
        ), (name, "receiver crashed")
        reports.append(
            dict(
                name=name,
                compile=compiled.returncode,
                link=linked.returncode,
                checker=result.returncode,
            )
        )
        print(name, "normal receiver, semantic rejection", flush=True)
    (out / "report.json").write_text(json.dumps(reports, indent=2) + "\n")


if __name__ == "__main__":
    main()
