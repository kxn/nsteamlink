#!/usr/bin/env python3
"""Prepare, deploy once, or inspect a self-contained decoder recovery probe.

Use nxlink directly; never probe netloader TCP. Complete machine records are
required. nxlink success is not proof of hbmenu return or physical scanout.
"""
import argparse
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
IDS = [100, 106, 107, 108, 109, 110, 111]
SIZES = [25334, 25334, 12307, 13619, 15358, 14251, 16198]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture_identity():
    directory = ROOT / "app/tests/fixtures/video"
    manifest = json.loads((directory / "recovery720.json").read_text())
    fixture = directory / "recovery720.h264"
    checks = {
        "fixture_sha256": sha(fixture),
        "source_sha256": sha(directory / "sequential.h264"),
        "frame_md5_sha256": sha(directory / "recovery720.framemd5"),
    }
    if any(manifest.get(key) != value for key, value in checks.items()):
        raise ValueError("recovery fixture/manifest hash mismatch")
    offset, packets = 0, []
    for size in SIZES[1:]:
        packets.append({"size": str(size), "pos": str(offset)})
        offset += size
    if (
        manifest.get("packets") != packets
        or fixture.stat().st_size != offset
        or manifest.get("width") != 1280
        or manifest.get("height") != 720
    ):
        raise ValueError("recovery fixture access-unit/dimension mismatch")
    return checks["fixture_sha256"]


def valid_record(tag, value):
    """Reject corrupt records before using any field as an index or set key."""
    if not isinstance(value, dict) or type(value.get("padded")) is not bool:
        return False
    if tag != "RECOVERY_MEMORY ":
        if type(value.get("pass")) is not int or value["pass"] not in range(3):
            return False
    integers, booleans = [], []
    if tag == "RECOVERY_ROW ":
        integers = [
            "input",
            "task",
            "pixel_input",
            "bytes",
            "submit_result",
            "submit_us",
            "select_us",
            "render_verify_us",
        ]
        booleans = ["pixels"]
    elif tag == "RECOVERY_CASE ":
        integers = [
            "width",
            "height",
            "inputs",
            "tasks",
            "pictures",
            "key_to_readback_us",
        ]
        booleans = [
            "hardware_requested",
            "hardware_context",
            "zero_copy",
            "key_seen",
            "next_p_seen",
            "stopped",
            "passed",
        ]
        if not isinstance(value.get("failure"), str):
            return False
    else:
        integers = ["heap_live_bytes", "process_used_bytes", "query_result"]
        if tag == "RECOVERY_MEMORY ":
            booleans = ["cleanup_passed"]
        elif value.get("stage") not in ("opened", "decoded"):
            return False
    return all(type(value.get(k)) is int and value[k] >= 0 for k in integers) and all(
        type(value.get(k)) is bool for k in booleans
    )


def analyze(log, expected_build, expected_fixture):
    run_id, messages = None, []
    for line in log.splitlines():
        match = re.search(r"\[(\d+) [^\]]+\] (.*)", line)
        if not match:
            continue
        rid, body = match.groups()
        if "previous:" in body or "PREVIOUS_LOG" in body:
            continue
        if body.startswith("PROBE_BEGIN "):
            run_id, messages = rid, []
        if rid == run_id:
            messages.append(body)
    errors, rows, cases, resources, memory = [], [], [], [], []

    def require(condition, reason):
        if not condition:
            errors.append(reason)

    require(bool(messages), "missing current PROBE_BEGIN")
    require(
        not any(re.match(r"deko result=[1-9]\d*\b", m) for m in messages),
        "GPU SDK diagnostic error",
    )
    require(
        bool(messages) and f"build={expected_build} fixture=recovery " in messages[0],
        "build or mode mismatch",
    )
    require(
        any(
            m
            == f"RECOVERY_FIXTURE size=97067 sha256={expected_fixture} boundary=decoder"
            for m in messages
        ),
        "fixture identity mismatch",
    )
    for message in messages:
        for tag, target in (
            ("RECOVERY_ROW ", rows),
            ("RECOVERY_CASE ", cases),
            ("RECOVERY_RESOURCE ", resources),
            ("RECOVERY_MEMORY ", memory),
        ):
            if message.startswith(tag):
                try:
                    value = json.loads(message[len(tag) :])
                    if not valid_record(tag, value):
                        raise ValueError("invalid record schema")
                    target.append(value)
                except (ValueError, TypeError):
                    errors.append("malformed " + tag.strip())
    expected = [(padded, number) for padded in (False, True) for number in range(3)]
    case_keys = [(v.get("padded"), v.get("pass")) for v in cases]
    require(case_keys == expected, "missing/duplicate/out-of-order case")
    for case in cases:
        key = (case.get("padded"), case.get("pass"))
        hardware = case.get("pass") in (1, 2)
        require(
            case.get("passed") is True and case.get("failure") == "none",
            f"case failed: {key} {case.get('failure')}",
        )
        require(
            case.get("width") == 1280 and case.get("height") == 720,
            f"dimensions: {key}",
        )
        require(case.get("hardware_requested") is hardware, f"hardware request: {key}")
        if hardware:
            require(
                case.get("hardware_context") is True and case.get("zero_copy") is True,
                f"hardware fallback/copy: {key}",
            )
        require(
            case.get("inputs") == 7 and case.get("tasks") == 7,
            f"input/task count: {key}",
        )
        require(
            case.get("stopped") is True
            and case.get("key_seen") is True
            and case.get("next_p_seen") is True,
            f"recovery/stop: {key}",
        )
        require(
            type(case.get("key_to_readback_us")) is int
            and case["key_to_readback_us"] >= 0,
            f"missing duration: {key}",
        )
        selected = [r for r in rows if (r.get("padded"), r.get("pass")) == key]
        require(
            [r.get("input") for r in selected] == IDS,
            f"missing/duplicate input row: {key}",
        )
        pixels = []
        for index, row in enumerate(selected):
            require(
                row.get("task") == row.get("input") and row.get("submit_result") == 1,
                f"task/result: {key}",
            )
            require(
                row.get("bytes")
                == (65536 if case.get("padded") else SIZES[min(index, 6)]),
                f"input size: {key}",
            )
            for field in ("submit_us", "select_us", "render_verify_us"):
                require(
                    type(row.get(field)) is int and row[field] >= 0,
                    f"duration {field}: {key}",
                )
            if row.get("pixels") is True:
                pixel = row.get("pixel_input")
                require(pixel in IDS[: index + 1], f"unknown/future pixel input: {key}")
                pixels.append(pixel)
            else:
                require(
                    row.get("pixel_input") == 0, f"placeholder pixel identity: {key}"
                )
        require(
            len(pixels) == len(set(pixels)) and 106 in pixels and 107 in pixels,
            f"pixel recovery: {key}",
        )
        require(case.get("pictures") == len(pixels), f"picture count: {key}")
        if not hardware:
            require(pixels == IDS, f"incomplete software reference: {key}")
        snapshots = [r for r in resources if (r.get("padded"), r.get("pass")) == key]
        require(
            [r.get("stage") for r in snapshots] == ["opened", "decoded"],
            f"resource observations: {key}",
        )
    require(len(rows) == 42 and len(resources) == 12, "unexpected row/resource count")
    require(
        len(memory) == 2 and {r.get("padded") for r in memory} == {False, True},
        "missing cleanup memory",
    )
    require(
        all(r.get("cleanup_passed") is True for r in memory), "profile cleanup failed"
    )
    terminal = [
        m
        for m in messages
        if m.startswith(("SUITE ", "PROBE_FINAL ", "PROBE_CLEANUP "))
    ]
    require(
        terminal
        == [
            "SUITE cases_completed=2 cases_expected=2",
            "PROBE_FINAL result=PASS failed_stage=none",
            "PROBE_CLEANUP resources=clean transport=closing",
        ],
        "missing, duplicate or inconsistent suite/final/cleanup records",
    )
    if terminal:
        end = next(
            (i for i, m in enumerate(messages) if m.startswith("SUITE ")), len(messages)
        )
        require(
            not any(m.startswith("RECOVERY_") for m in messages[end:]),
            "recovery records after suite end",
        )
    return dict(
        status="passed" if not errors else "failed",
        errors=errors,
        run_id=run_id,
        cases=cases,
        rows=rows,
        resources=resources,
        cleanup_memory=memory,
        resource_queries_complete=len(resources) == 12
        and all(v.get("query_result") == 0 for v in resources + memory),
        last_stage=next(
            (
                m
                for m in reversed(messages)
                if "STAGE=" in m or m.startswith("RECOVERY_STAGE")
            ),
            None,
        ),
        scope="decoder submission/selection/GPU readback; synthetic 720p input gap",
        steam_network="not exercised",
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
    parser.add_argument(
        "--nro", type=Path, default=ROOT / "build/switch-deko/app/nsl-video-probe.nro"
    )
    parser.add_argument("--host", default="10.10.10.17")
    parser.add_argument("--expected-build")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=180)
    args = parser.parse_args()
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be a finite positive number")
    if args.output.exists() and any(args.output.iterdir()):
        parser.error("output directory is not empty; choose a fresh output directory")
    args.output.mkdir(parents=True, exist_ok=True)
    fixture_sha = fixture_identity()
    package = None
    if not args.analyze_log:
        nro = args.nro.resolve()
        identity = json.loads(
            (nro.parent.parent / "generated/build_identity.json").read_text()
        )
        commit = subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True
        ).strip()
        dirty = subprocess.check_output(
            ["git", "-C", str(ROOT), "status", "--porcelain"], text=True
        ).strip()
        if (
            identity.get("dirty") is not False
            or dirty
            or identity.get("commit") != commit
        ):
            parser.error(
                "rebuild the probe from the current clean checkout before preparing/deploying"
            )
        executable = nro.read_bytes()
        fixture_bytes = (
            ROOT / "app/tests/fixtures/video/recovery720.h264"
        ).read_bytes()
        if (
            executable[0x10:0x14] != b"NRO0"
            or not re.fullmatch(r"[0-9a-f]{40}", commit)
            or commit.encode() not in executable
            or fixture_bytes not in executable
        ):
            parser.error("probe NRO does not contain the expected full commit/fixture")
        graphics = json.loads(
            (nro.parent.parent / "generated/graphics_manifest.json").read_text()
        )
        sdk_commit = subprocess.check_output(
            ["git", "-C", str(ROOT / "third_party/ihslib"), "rev-parse", "HEAD"],
            text=True,
        ).strip()
        if (
            graphics.get("backend") != "deko"
            or graphics.get("application") != {"commit": commit, "dirty": False}
            or graphics.get("ihslib") != {"commit": sdk_commit, "dirty": False}
        ):
            parser.error(
                "graphics manifest does not match the clean application/SDK checkout"
            )
        nxlink = shutil.which("nxlink")
        if not nxlink:
            candidate = Path("/opt/devkitpro/tools/bin/nxlink")
            nxlink = str(candidate) if candidate.is_file() else None
        if not nxlink:
            parser.error("nxlink not found")
        ipaddress.IPv4Address(args.host)
        archived_nro = args.output.resolve() / "nsl-video-probe.nro"
        shutil.copyfile(nro, archived_nro)
        command = [
            nxlink,
            "-a",
            args.host,
            "-r",
            "1",
            "-s",
            "--args",
            "recovery",
            str(archived_nro),
        ]
        package = dict(
            nro=str(nro),
            archived_nro=str(archived_nro),
            nro_sha256=sha(nro),
            identity=identity,
            graphics_manifest=graphics,
            fixture_sha256=fixture_sha,
            command=command,
            source_sha256={
                p: sha(ROOT / p)
                for p in (
                    "app/tests/video_recovery_probe.h",
                    "app/tests/switch_video_probe.c",
                    "tools/switch-recovery-probe.py",
                    "app/tests/fixtures/video/recovery720.json",
                )
            },
        )
        (args.output / "package.json").write_text(json.dumps(package, indent=2) + "\n")
        if args.prepare:
            print(json.dumps(package, indent=2))
            return 0
        logfile = args.output / "nxlink.log"
        if logfile.exists():
            parser.error("nxlink.log already exists; choose a fresh output directory")
        with logfile.open("wb") as output:
            process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
            try:
                rc = process.wait(timeout=args.timeout)
                timeout = False
            except subprocess.TimeoutExpired:
                process.terminate()  # PC uploader/listener only; device state stays unknown.
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                rc, timeout = process.returncode, True
        text = logfile.read_text(errors="replace")
        expected_build = identity["commit"]
    else:
        if not args.expected_build:
            parser.error("--analyze-log requires --expected-build")
        text = args.analyze_log.read_text(errors="replace")
        expected_build, rc, timeout = args.expected_build, None, False
    report = analyze(text, expected_build, fixture_sha)
    report.update(nxlink_returncode=rc, observation_timeout=timeout)
    if package:
        report["package"] = package
        if rc != 0 or timeout:
            report["status"] = "failed"
            report["errors"].append(
                "nxlink process failed/timed out; device completion unverified"
            )
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                k: v
                for k, v in report.items()
                if k not in ("rows", "resources", "package")
            },
            indent=2,
        )
    )
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
