#!/usr/bin/env python3
"""Compare manager-lived auth cache with repeated explicit Native LAN requests.

Original 5/10 streaming messages and UI ownership/foreign envelope cases remain
Source-only. Native requests are explicit calls, not automatic Unauthorized
resumption; each comparison anchors at the source authorization stage. Raw
response bytes and original crypto are shared with the fixed official reference.
"""
import argparse
import gzip
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "exchange", ROOT / "scripts/check-steam-authorization-exchange.py"
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def expected(step):
    messages = []
    for row in step["messages"]:
        if row["tag"] in (5, 10):
            continue
        messages.append(
            dict(
                tag=row["tag"],
                body=(
                    m.key_field(bytes.fromhex(row["body"]))
                    if row["tag"] == 3
                    else row["body"]
                ),
            )
        )
    saves = sum(x["op"] == "save_key" for x in step["timeline"])
    return dict(
        pending=step["state"] == 4,
        derived=step["derived"],
        success=saves,
        failed=len(step["errors"]),
        secret=step["secret"],
        cache=step["cache"],
        cached_result=step["cached_result"],
        keypairs=step["keypair_generations"],
        persist=saves,
        messages=messages,
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    p.add_argument("--deferred", action="store_true")
    a = p.parse_args()
    source = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-authorization-lifetime-reference.json.gz"
            ).read_bytes()
        )
    )
    assert len(source["cases"]) == 34
    compared = 0
    for case in source["cases"]:
        if case["input"]["path"] != "lifetime":
            continue
        prior = case["input"]["prior"]
        n = 4 if prior == "limit" else 1
        responses = case["responses"]
        args = ["lifetime_pump" if a.deferred else "lifetime"]
        args += [m.response(row) for row in responses[:n]]
        args += ["@" + str(case["input"]["host"])]
        args += [m.response(row) for row in responses[n:]]
        rows = m.execute(a.receiver, args)
        assert len(rows) == n + 5
        # Prior limit emits four responses; retain its final observed aggregate.
        observed = [rows[0], rows[n], *rows[n + 1 :]]
        steps = [case["steps"][i] for i in (0, 1, 2, 4, 5, 6)]
        for row, step in zip(observed, steps):
            target = expected(step)
            actual = {key: row[key] for key in target}
            assert actual == target, (case["input"], step["label"], actual, target)
        compared += 1
    assert compared == 12
    for negative in source["negative"]:
        assert negative["mutant"]["patch_hits"] == [negative["site"]]
        assert not negative["mutant"]["source_assertions"]
    print(
        f"Authorization lifetime: {compared} official/Native cache traces across successful, denied and exhausted requests, same/different hosts; explicit LAN projection, automatic streaming ownership remains separately scoped"
    )


if __name__ == "__main__":
    main()
