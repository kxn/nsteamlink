#!/usr/bin/env python3
"""Prepare/deploy once/inspect the self-contained large-VCL capability probe.

Never probe netloader TCP. --prepare is offline. --run is a single nxlink
attempt, used only after human readiness. Network/physical scanout/loader ABI
and full-session peak are not proved by decoder/GPU readback results.
"""
import argparse
import gzip
import hashlib
import importlib.util
import ipaddress
import json
import math
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
TAGS = ("VCL_ROW", "VCL_CASE", "VCL_MAP", "VCL_RESOURCE", "VCL_DRAIN", "VCL_CLEANUP")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixtures():
    base = ROOT / "app/tests/fixtures/video/vcl"
    rows = json.loads((base / "manifest.json").read_text())["cases"]
    if [v["name"] for v in rows] != ["pcm720", "pcm1080"]:
        raise ValueError("fixture identities")
    for row in rows:
        path = base / (row["name"] + ".h264.gz")
        raw = gzip.decompress(path.read_bytes())
        if (
            sha(path) != row["archive_sha256"]
            or hashlib.sha256(raw).hexdigest() != row["fixture_sha256"]
        ):
            raise ValueError("fixture digest")
    return rows


def valid(tag, row):
    if not isinstance(row, dict) or row.get("fixture") not in ("pcm720", "pcm1080"):
        return False
    integer, boolean, signed = [], [], []
    if tag not in ("VCL_DRAIN", "VCL_CLEANUP"):
        integer += ["pass"]
        if type(row.get("pass")) is not int or row["pass"] not in (0, 1, 2):
            return False
    if tag == "VCL_ROW":
        integer += ["input", "bytes", "status", "task", "pixel", "submit_us"]
        boolean = ["taken"]
    elif tag == "VCL_CASE":
        integer += [
            "width",
            "height",
            "key_bytes",
            "vcl_bytes",
            "inputs",
            "pictures",
            "max_diff",
        ]
        boolean = [
            "hardware_requested",
            "hardware_context",
            "zero_copy",
            "stopped",
            "passed",
        ]
        if not isinstance(row.get("sha256"), str):
            return False
    elif tag == "VCL_MAP":
        integer += ["index", "before", "requested", "after", "align"]
        signed = ["heap", "flags", "result"]
    elif tag == "VCL_RESOURCE":
        integer += ["heap_live_bytes", "process_used_bytes", "query_result"]
        if row.get("stage") not in ("opened", "decoded", "destroyed"):
            return False
    elif tag == "VCL_DRAIN":
        integer += ["imported_bytes", "pool_groups", "busy_batches", "maps"]
    else:
        boolean = ["passed"]
    if tag in ("VCL_CASE", "VCL_CLEANUP") and not isinstance(row.get("failure"), str):
        return False
    return (
        all(type(row.get(k)) is int and row[k] >= 0 for k in integer)
        and all(type(row.get(k)) is int for k in signed)
        and all(type(row.get(k)) is bool for k in boolean)
    )


def analyze(text, build, expected=None):
    expected = fixtures() if expected is None else expected
    messages, run_id = [], None
    for line in text.splitlines():
        match = re.search(r"\[(\d+) [^\]]+\] (.*)", line)
        if not match:
            continue
        rid, body = match.groups()
        if "previous:" in body:
            continue
        if body.startswith("VCL_BEGIN "):
            run_id, messages = rid, []
        if rid == run_id:
            messages.append(body)
    errors, records = [], {tag: [] for tag in TAGS}

    def require(condition, reason):
        if not condition:
            errors.append(reason)

    require(
        bool(messages)
        and messages[0].startswith(
            f"VCL_BEGIN build={build} limit=4194304 fixtures=2 "
        ),
        "build/limit/begin mismatch",
    )
    require(
        not any(re.match(r"deko result=[1-9]\d*\b", line) for line in messages),
        "GPU SDK error",
    )
    for message in messages:
        for tag in TAGS:
            if message.startswith(tag + " "):
                try:
                    row = json.loads(message[len(tag) + 1 :])
                    if not valid(tag, row):
                        raise ValueError("schema")
                    records[tag].append(row)
                except (ValueError, TypeError):
                    errors.append("malformed " + tag)
    cases, rows, maps, resources = (
        records[k] for k in ("VCL_CASE", "VCL_ROW", "VCL_MAP", "VCL_RESOURCE")
    )
    keys = [(f["name"], n) for f in expected for n in range(2)]
    require([(v["fixture"], v["pass"]) for v in cases] == keys, "case sequence")
    require(len(rows) == 8, "row count")
    require(len(resources) == 10, "resource count")
    for fixture in expected:
        name = fixture["name"]
        for number in range(2):
            key = (name, number)
            selected = lambda bank: [
                v for v in bank if (v["fixture"], v["pass"]) == key
            ]
            case_rows = selected(rows)
            require([v["input"] for v in case_rows] == [1, 2], f"input sequence {key}")
            for row in case_rows:
                index = row["input"] - 1
                require(
                    index in range(2)
                    and row["bytes"] == fixture["sizes"][min(max(index, 0), 1)],
                    f"input length {key}",
                )
                require(
                    row["status"] == 1
                    and row["taken"]
                    and row["task"] == row["pixel"] == row["input"],
                    f"input/task/pixels {key}",
                )
            for case in selected(cases):
                require(
                    all(
                        case[field] == fixture[field]
                        for field in ("width", "height", "vcl_bytes")
                    )
                    and case["key_bytes"] == fixture["sizes"][0]
                    and case["sha256"] == fixture["fixture_sha256"],
                    f"fixture identity {key}",
                )
                require(
                    case["passed"]
                    and case["failure"] == "none"
                    and case["stopped"]
                    and case["inputs"] == case["pictures"] == 2
                    and case["max_diff"] <= 3,
                    f"decode/result {key}",
                )
                require(
                    case["hardware_requested"] is bool(number),
                    f"hardware request {key}",
                )
                if number:
                    require(
                        case["hardware_context"] and case["zero_copy"],
                        f"hardware fallback/copy {key}",
                    )
            case_maps = selected(maps)
            if number:
                require(
                    any(
                        v["result"] == 0
                        and v["requested"] > v["before"]
                        and v["after"] >= max(v["requested"], fixture["vcl_bytes"])
                        for v in case_maps
                    ),
                    f"map growth {key}",
                )
            else:
                require(not case_maps, f"unexpected software map {key}")
            require(
                [v["stage"] for v in selected(resources)] == ["opened", "decoded"],
                f"resource stages {key}",
            )
        destroyed = [v for v in resources if v["fixture"] == name and v["pass"] == 2]
        require(
            len(destroyed) == 1 and destroyed[0]["stage"] == "destroyed",
            f"destroy sample {name}",
        )
    require(
        [v["index"] for v in maps] == list(range(len(maps))) and len(maps) <= 32,
        "map row sequence",
    )
    for row in maps:
        require((row["fixture"], row["pass"]) in keys, "map case")
        require(
            row["result"] == 0
            and row["requested"] <= row["after"]
            and row["align"] == 256
            and row["heap"] == 1073741824
            and row["flags"] == 1,
            "SDK map result/arguments",
        )
    for tag in ("VCL_DRAIN", "VCL_CLEANUP"):
        bank = records[tag]
        require(
            [v["fixture"] for v in bank] == [v["name"] for v in expected],
            tag + " sequence",
        )
        for row in bank:
            require(
                (
                    (row["passed"] and row["failure"] == "none")
                    if tag == "VCL_CLEANUP"
                    else all(
                        row[k] == 0
                        for k in (
                            "imported_bytes",
                            "pool_groups",
                            "busy_batches",
                            "maps",
                        )
                    )
                ),
                tag + " resources",
            )
    terminal = [v for v in messages if v.startswith(("VCL_FINAL ", "VCL_TRANSPORT "))]
    require(
        terminal == ["VCL_FINAL result=PASS overflow=0", "VCL_TRANSPORT closing"],
        "terminal records",
    )
    if terminal:
        end = next(
            n for n, message in enumerate(messages) if message.startswith("VCL_FINAL ")
        )
        require(
            not any(
                message.startswith(tuple(tag + " " for tag in TAGS))
                for message in messages[end:]
            ),
            "records after final",
        )
    stages = [message[6:] for message in messages if message.startswith("STAGE=")]
    require(
        stages
        == ["buffers", "sdl-init"]
        + [
            "case-create",
            "software-vcl",
            "hardware-vcl",
            "case-gfx-finish",
            "case-decoder-destroy",
        ]
        * 2
        + ["cleanup-sdl", "complete"],
        "cleanup stage order",
    )
    return dict(
        status="passed" if not errors else "failed",
        errors=errors,
        run_id=run_id,
        records=records,
        resource_queries_complete=len(resources) == 10
        and all(v["query_result"] == 0 for v in resources),
        last_stage=stages[-1] if stages else None,
        scope="synthetic I_PCM IDR/skip-P; SDK input map growth and GPU readback at 720p output",
        production_limit_changed=False,
        steam_network="not exercised",
        full_session_peak="unverified",
        hardware_maximum="unverified",
        physical_scanout="unverified",
        hbmenu_return="unverified",
        socket_exit="unverified",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--prepare", action="store_true")
    mode.add_argument("--run", action="store_true")
    mode.add_argument("--analyze-log", type=Path)
    parser.add_argument("--build", type=Path, default=ROOT / "build/switch-deko")
    parser.add_argument(
        "--ordinary", type=Path, default=ROOT / "build/switch/app/nsteamlink.nro"
    )
    parser.add_argument("--host", default="10.10.10.17")
    parser.add_argument("--expected-build")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=180)
    args = parser.parse_args()
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be finite and positive")
    if args.output.exists() and any(args.output.iterdir()):
        parser.error("choose a new empty output directory")
    args.output.mkdir(parents=True, exist_ok=True)
    package = None
    if not args.analyze_log:
        spec = importlib.util.spec_from_file_location(
            "build_check", ROOT / "scripts/check-vcl-probe-build.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        check = module.check(ROOT, args.build.resolve(), args.ordinary.resolve())
        identity = check["identity"]
        commit = subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True
        ).strip()
        dirty = subprocess.check_output(
            ["git", "-C", str(ROOT), "status", "--porcelain"], text=True
        ).strip()
        sdk_dirty = subprocess.check_output(
            ["git", "-C", str(ROOT / "third_party/ihslib"), "status", "--porcelain"],
            text=True,
        ).strip()
        if (
            dirty
            or sdk_dirty
            or identity.get("dirty") is not False
            or identity.get("commit") != commit
        ):
            parser.error(
                "prepare/deploy requires a rebuilt current clean checkout and SDK"
            )
        ipaddress.IPv4Address(args.host)
        nxlink = shutil.which("nxlink") or "/opt/devkitpro/tools/bin/nxlink"
        if not Path(nxlink).is_file():
            parser.error("nxlink not found")
        archived = args.output.resolve() / "nsl-vcl-probe.nro"
        shutil.copyfile(args.build / "app/nsl-vcl-probe.nro", archived)
        command = [nxlink, "-a", args.host, "-r", "1", "-s", str(archived)]
        package = dict(
            identity=identity,
            nro_sha256=sha(archived),
            command=command,
            build_check=check,
            source_sha256={
                str(p): sha(ROOT / p)
                for p in (
                    "app/tests/vcl_fixture_probe.h",
                    "app/tests/switch_vcl_probe.c",
                    "tools/switch-vcl-probe.py",
                    "scripts/prepare-vcl-probe.py",
                    "scripts/generate-vcl-fixtures.py",
                )
            },
        )
        (args.output / "package.json").write_text(json.dumps(package, indent=2) + "\n")
        if args.prepare:
            print(
                json.dumps(
                    dict(
                        identity=identity,
                        nro_sha256=package["nro_sha256"],
                        command=command,
                        device_execution=False,
                    ),
                    indent=2,
                )
            )
            return 0
        log = args.output / "nxlink.log"
        with log.open("wb") as output:
            process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
            try:
                rc = process.wait(timeout=args.timeout)
                timed_out = False
            except subprocess.TimeoutExpired:
                process.terminate()  # PC uploader only. Device state stays unknown.
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                rc, timed_out = process.returncode, True
        text, expected_build = log.read_text(errors="replace"), commit
    else:
        if not args.expected_build:
            parser.error("--analyze-log requires --expected-build")
        text = args.analyze_log.read_text(errors="replace")
        expected_build, rc, timed_out = args.expected_build, None, False
    report = analyze(text, expected_build)
    report.update(nxlink_returncode=rc, observation_timeout=timed_out)
    if package:
        report["package"] = package
        if rc != 0 or timed_out:
            report["status"] = "failed"
            report["errors"].append(
                "nxlink failed/timed out; device completion unverified"
            )
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {k: v for k, v in report.items() if k not in ("package", "records")},
            indent=2,
        )
    )
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
