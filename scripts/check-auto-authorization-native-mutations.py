#!/usr/bin/env python3
"""Compile same-owner regressions and require normal receiver semantic rejection."""
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
    stream, auth = (directory / n for n in ("streaming.c", "authorization.c"))
    order = """    if (ok) {
        IHS_BaseSetSecretKey(&client->base, secretKey);
        if (client->callbacks.authorization && client->callbacks.authorization->persist)
            client->callbacks.authorization->persist(client, host, resp->steamid,
                secretKey, client->callbackContexts.authorization);
    }
    memset(secretKey, 0, sizeof(secretKey));
    IHS_ClientAuthorizationConfirm(client, host->address, cache->result);"""
    late = """    if (ok) IHS_BaseSetSecretKey(&client->base, secretKey);
    IHS_ClientAuthorizationConfirm(client, host->address, cache->result);
    if (ok && client->callbacks.authorization && client->callbacks.authorization->persist)
        client->callbacks.authorization->persist(client, host, resp->steamid, secretKey, client->callbackContexts.authorization);
    memset(secretKey, 0, sizeof(secretKey));"""
    variants = [
        (
            "new_id",
            stream,
            "            SetAuthorizing(state, true);",
            "            ++state->requestId;\n            SetAuthorizing(state, true);",
        ),
        (
            "new_keypair",
            stream,
            "            SetAuthorizing(state, true);",
            "            IHS_ClientAuthorizationFlowInit(&state->authorization, state->authorization.pin);\n            SetAuthorizing(state, true);",
        ),
        (
            "one_second_auth",
            stream,
            "state->authorizing ? 3u : 1u",
            "state->authorizing ? 1u : 1u",
        ),
        (
            "re_encrypt_pin",
            stream,
            "    IHS_StreamingRequest request = state->request;",
            "    IHS_StreamingRequest request = state->request;\n    state->encryptedPinLen=sizeof(state->encryptedPin);\n    IHS_CryptoSymmetricEncrypt((const uint8_t *)request.pin,strlen(request.pin),client->base.secretKey,32,state->encryptedPin,&state->encryptedPinLen);",
        ),
        (
            "cached_advances",
            auth,
            "return IHS_AuthorizationExchangeWaiting; /* Cache never advances twice. */",
            "return IHS_AuthorizationExchangeAccepted; /* regression */",
        ),
        ("persist_after_confirm", auth, order, late),
    ]
    variants.append(
        (
            "wrong_cancel_phase",
            stream,
            "                /* Invalid credentials stop the current protocol phase. */\n                if (state->authorizing) IHS_ClientAuthorizationSendCancel(client, &state->host);\n                else SendCancel(client, &state->host, state->requestId);",
            "                SendCancel(client, &state->host, state->requestId);",
        )
    )
    variants.append(
        (
            "retry_with_queued_response",
            directory / "client.c",
            "if (budget && drained && atomic_load_explicit",
            "if (budget && (drained || true) && atomic_load_explicit",
        )
    )
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
        # A fresh keypair keeps the same supplied PIN. Avoid aliasing init's output/input.
        if name == "new_keypair":
            after = "            char repeatedPin[16]; memcpy(repeatedPin,state->authorization.pin,16);\n            IHS_ClientAuthorizationFlowInit(&state->authorization, repeatedPin);\n            SetAuthorizing(state, true);"
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
                str(ROOT / "scripts/check-steam-auto-authorization.py"),
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
