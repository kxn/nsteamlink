#!/usr/bin/env python3
"""Compile isolated authorization regressions; require semantic checker rejection.

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
    source = ROOT / "third_party/ihslib/src/client/authorization.c"
    body = source.read_text()
    entry = next(
        e
        for e in json.loads((build / "compile_commands.json").read_text())
        if Path(e["file"]) == source
    )
    compile_base = shlex.split(entry["command"])
    link_dir = build / "third_party/ihslib/tests/session"
    link_base = shlex.split(
        (
            link_dir / "CMakeFiles/ihs-authorization-exchange-oracle.dir/link.txt"
        ).read_text()
    )
    variants = [
        (
            "ignore_result",
            "resp->result == k_ERemoteDeviceAuthorizationSuccess && resp->has_auth_key",
            "resp->has_auth_key",
            "result",
        ),
        (
            "ignore_cache",
            "bool cached = count == cache->keyLen &&",
            "bool cached = false && count == cache->keyLen &&",
            "cached_failure",
        ),
        (
            "fourth_key_allowed",
            "state->keyExchangeAttempts++ >= 3",
            "state->keyExchangeAttempts++ >= 99",
            "cache_alternation",
        ),
        (
            "one_second_retry",
            "(uint64_t)sentAt + 3",
            "(uint64_t)sentAt + 1",
            "wall_clock",
        ),
    ]
    variants.append(("monotonic_deadline", None, None, "wall_clock"))
    order = """    if (ok) {
        IHS_BaseSetSecretKey(&client->base, secretKey);
        if (client->callbacks.authorization && client->callbacks.authorization->persist)
            client->callbacks.authorization->persist(client, &state->host, resp->steamid,
                secretKey, client->callbackContexts.authorization);
    }
    memset(secretKey, 0, sizeof(secretKey));
    AuthorizationConfirm(client, state->host.address, cache->result);"""
    late = """    if (ok) IHS_BaseSetSecretKey(&client->base, secretKey);
    AuthorizationConfirm(client, state->host.address, cache->result);
    if (ok && client->callbacks.authorization && client->callbacks.authorization->persist)
        client->callbacks.authorization->persist(client, &state->host, resp->steamid,
            secretKey, client->callbackContexts.authorization);
    memset(secretKey, 0, sizeof(secretKey));"""
    variants.append(("persist_after_confirm", order, late, "persist_at_confirm"))
    variants.append(
        (
            "clear_cache_each_request",
            "    IHS_AuthorizationState *state = calloc(1, sizeof(IHS_AuthorizationState));",
            "    free(client->authorizationCache.key);\n    memset(&client->authorizationCache, 0, sizeof(client->authorizationCache));\n    client->authorizationCache.result = k_ERemoteDeviceAuthorizationFailed;\n    IHS_AuthorizationState *state = calloc(1, sizeof(IHS_AuthorizationState));",
            "reauthorizing",
        )
    )
    variants.append(
        (
            "per_host_cache",
            "    IHS_AuthorizationState *state = calloc(1, sizeof(IHS_AuthorizationState));",
            "    static uint64_t cacheHost;\n    if (cacheHost != host->clientId) { free(client->authorizationCache.key); memset(&client->authorizationCache, 0, sizeof(client->authorizationCache)); client->authorizationCache.result = k_ERemoteDeviceAuthorizationFailed; }\n    cacheHost = host->clientId;\n    IHS_AuthorizationState *state = calloc(1, sizeof(IHS_AuthorizationState));",
            "reauthorizing",
        )
    )
    variants.append(
        (
            "initial_cache_success",
            "    IHS_AuthorizationState *state = calloc(1, sizeof(IHS_AuthorizationState));",
            "    if (!client->authorizationCache.keyLen) client->authorizationCache.result = k_ERemoteDeviceAuthorizationSuccess;\n    IHS_AuthorizationState *state = calloc(1, sizeof(IHS_AuthorizationState));",
            "key_length",
        )
    )
    reports = []
    for name, before, after, expected in variants:
        if before is not None:
            assert body.count(before) == 1
        directory = out / name
        directory.mkdir(exist_ok=True)
        copied, obj, exe = (
            directory / "authorization.c",
            directory / "authorization.o",
            directory / "receiver",
        )
        if before is None:
            mutant = body.replace(
                "if (runCount && now < state->nextSendWallSecond) return 1;",
                "(void)now; (void)runCount;",
            )
            old = "    int64_t sentAt = (int64_t)time(NULL);\n    state->nextSendWallSecond = (int64_t)((uint64_t)sentAt + 3);\n    return 1;"
            assert old in mutant
            mutant = mutant.replace(old, "    return 3000;")
        else:
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
                str(
                    ROOT
                    / (
                        "scripts/check-steam-authorization-lifetime.py"
                        if name in ("clear_cache_each_request", "per_host_cache")
                        else "scripts/check-steam-authorization-exchange.py"
                    )
                ),
                "--receiver",
                str(exe),
                *(["--deferred"] if name == "persist_after_confirm" else []),
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
        if expected != "retry":
            assert expected in check.stderr, (name, check.stderr)
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
