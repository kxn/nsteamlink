#!/usr/bin/env python3
"""Prepare/run one real-host probe, or validate a captured machine record.

Only --run deploys; use it after the user prepares netloader. Never probe TCP
28280 or retry a launch. PASS covers a playback smoke test, not adverse-network
equivalence, physical scanout, hbmenu return or RS reconstruction proof.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def analyze(log, build, steam, seconds):
    records, run = [], None
    for line in log.splitlines():
        match = re.fullmatch(r"LIVE_([A-Z]+) run=(\d+) (.+)", line)
        if not match:
            if line.startswith("LIVE_"):
                return {"passed": False, "errors": ["truncated/malformed record"]}
            continue
        tag, rid, payload = match.groups()
        if tag == "BEGIN":
            run, records = rid, []
        if rid == run:
            pairs = [item.split("=", 1) for item in payload.split()]
            if any(len(item) != 2 for item in pairs):
                return {"passed": False, "errors": ["malformed record"]}
            values = dict(pairs)
            if len(values) != len(pairs):
                return {"passed": False, "errors": ["duplicate record field"]}
            records.append((tag, values))
    errors = []

    def require(test, reason):
        if not test:
            errors.append(reason)

    def one(tag):
        found = [value for kind, value in records if kind == tag]
        require(len(found) == 1, "missing/duplicate " + tag)
        return found[0] if len(found) == 1 else {}

    def number(value, key):
        text = value.get(key, "")
        valid = bool(re.fullmatch(r"[0-9]{1,20}", text))
        parsed = int(text) if valid else -1
        valid = valid and parsed <= (1 << 64) - 1
        require(valid, "invalid numeric " + key)
        return parsed if valid else -1

    begin, settings, submitted, first, result, final = (
        one(tag)
        for tag in ("BEGIN", "SETTINGS", "SUBMITTED", "FIRST", "RESULT", "FINAL")
    )
    require(
        begin == {"build": build, "host": steam, "seconds": str(seconds)},
        "identity mismatch",
    )
    require(settings.get("stored_fec") in ("0", "1"), "missing FEC preference")
    require(settings.get("sound") in ("0", "1"), "missing sound preference")
    require(submitted == {"existing_identity": "1"}, "no existing identity submission")
    number(first, "elapsed_ms")
    require(
        final
        == {
            "result": "PASS",
            "reason": "none",
            "workers": "joined",
            "media": "destroyed",
        },
        "probe failed or cleanup incomplete",
    )
    tags = [tag for tag, _ in records]
    require(
        tags[-4:] == ["WIRE", "FLOW", "RESULT", "FINAL"], "missing final counter group"
    )
    require(
        bool(tags) and tags[0] == "BEGIN" and tags[-1] == "FINAL", "record boundaries"
    )
    if all(tag in tags for tag in ("FIRST", "SUBMITTED", "RESULT")):
        require(
            tags.index("SUBMITTED") < tags.index("FIRST") < tags.index("RESULT"),
            "stage order",
        )
    require(number(result, "decoded") > 0, "no decoded frame")
    require(number(result, "presented") > 1, "no continuing presentation")
    audio = number(result, "audio")
    require(result.get("hardware") in ("0", "1"), "missing hardware fact")
    require(number(result, "play_ms") >= seconds * 1000, "short playback")
    tail = number(result, "tail_ms")
    require(0 <= tail <= 2000, "presentation stopped before end of smoke")
    require(number(result, "gap_ms") >= tail, "invalid presentation gap")
    wire = records[-4][1] if tags[-4:] == ["WIRE", "FLOW", "RESULT", "FINAL"] else {}
    flow = records[-3][1] if tags[-4:] == ["WIRE", "FLOW", "RESULT", "FINAL"] else {}
    wire = {
        key: number(wire, key)
        for key in (
            "ordinary",
            "fec",
            "parity_enabled",
            "parity_shards",
            "fec_complete",
        )
    }
    flow = {
        key: number(flow, key)
        for key in ("complete", "recovery", "feedback_sent", "feedback_failed")
    }
    require(
        wire["ordinary"] + wire["fec"] > 0 and flow["complete"] > 0,
        "no real media ingress",
    )
    require(
        0 <= wire["parity_shards"] <= wire["parity_enabled"] <= wire["fec"],
        "FEC counts",
    )
    require(0 <= wire["fec_complete"] <= flow["complete"], "completion counts")
    return {
        "passed": not errors,
        "errors": errors,
        "run": run,
        "wire": wire,
        "flow": flow,
        "media": result,
        "scope": "real-host video playback smoke; audio counters observed; no loss injected",
        "audio_decode_observed": audio > 0,
        "rs_reconstruction": "unverified",
        "physical_scanout": "unverified",
        "loader_return": "unverified",
    }


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def capture(command, path, timeout):
    with path.open("wb") as log:
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        timed_out = False
        try:
            deadline = time.monotonic() + timeout
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    if time.monotonic() >= deadline:
                        timed_out = True
                        break
                    for key, _ in selector.select(timeout=1):
                        data = os.read(key.fileobj.fileno(), 8192)
                        if data:
                            log.write(data)
                            log.flush()
                        else:
                            selector.unregister(key.fileobj)
            if timed_out:
                process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdout.close()
    return process.returncode, timed_out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--steam", required=True, type=lambda x: str(ipaddress.IPv4Address(x))
    )
    parser.add_argument(
        "--seconds", type=int, default=30, choices=range(5, 121), metavar="5..120"
    )
    parser.add_argument(
        "--switch", default="10.10.10.17", type=lambda x: str(ipaddress.IPv4Address(x))
    )
    parser.add_argument("--build-dir", type=Path, default=ROOT / "build/switch-deko")
    parser.add_argument("--output", required=True, type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--run", action="store_true")
    modes.add_argument("--analyze-log", type=Path)
    parser.add_argument(
        "--expected-build", help="full commit for offline log validation"
    )
    args = parser.parse_args()
    if args.analyze_log:
        if not args.expected_build or not re.fullmatch(
            r"[0-9a-f]{40}", args.expected_build
        ):
            parser.error("offline analysis requires --expected-build (40 hex)")
        report = analyze(
            args.analyze_log.read_text(), args.expected_build, args.steam, args.seconds
        )
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        return 0 if report["passed"] else 1
    dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)
    if dirty:
        parser.error("prepare/run requires a clean checkout")
    identity = json.loads(
        (args.build_dir / "generated/build_identity.json").read_text()
    )
    head = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    source = args.build_dir / "app/nsl-live-media-probe.nro"
    if (
        identity.get("commit") != head
        or identity.get("dirty") is not False
        or head.encode() not in source.read_bytes()
    ):
        parser.error("NRO/build identity does not match clean HEAD")
    args.output.mkdir(parents=True, exist_ok=False)
    nro = args.output / source.name
    shutil.copyfile(source, nro)
    shutil.copyfile(
        args.build_dir / "generated/build_identity.json",
        args.output / "build_identity.json",
    )
    shutil.copyfile(
        args.build_dir / "generated/graphics_manifest.json",
        args.output / "graphics_manifest.json",
    )
    command = [
        shutil.which("nxlink") or "/opt/devkitpro/tools/bin/nxlink",
        "-a",
        args.switch,
        "-r",
        "3",
        "-s",
        str(nro.resolve()),
        "--args",
        f"{args.steam} {args.seconds}",
    ]
    package = {
        "build": head,
        "nro_sha256": sha(nro),
        "steam": args.steam,
        "switch": args.switch,
        "seconds": args.seconds,
        "command": command,
        "scope": "existing paired identity; saved preferences; no loss injection",
    }
    (args.output / "package.json").write_text(json.dumps(package, indent=2) + "\n")
    if not args.run:
        print("Prepared " + str(args.output.resolve()))
        return 0
    code, timeout = capture(command, args.output / "nxlink.log", 240)
    report = analyze(
        (args.output / "nxlink.log").read_text(errors="replace"),
        head,
        args.steam,
        args.seconds,
    )
    report.update(nxlink_exit=code, timed_out=timeout, nro_sha256=sha(nro))
    report["passed"] = report["passed"] and code == 0 and not timeout
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
