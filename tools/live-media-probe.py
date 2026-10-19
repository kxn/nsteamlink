#!/usr/bin/env python3
"""Prepare/run one real-host probe, or validate a captured machine record.

Only --run deploys; use it after the user prepares netloader. Never probe TCP
28280 or retry a launch. PASS covers a playback smoke test, not adverse-network
equivalence, physical scanout, hbmenu return or RS reconstruction proof.
"""
import argparse
import hashlib
import importlib.util
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


def analyze(log, build, steam, seconds, fec_mode="saved"):
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
    version = begin.get("observer")
    require(fec_mode in ("saved", "on", "off"), "invalid FEC test mode")
    expected_begin = {"build": build, "host": steam, "seconds": str(seconds)}
    expected_begin["observer"] = version
    if version == "3":
        expected_begin["fec"] = fec_mode
    require(
        begin == expected_begin
        and version in ("2", "3")
        and (version == "3" or fec_mode == "saved"),
        "identity mismatch",
    )
    require(settings.get("stored_fec") in ("0", "1"), "missing FEC preference")
    require(settings.get("sound") in ("0", "1"), "missing sound preference")
    if version == "3":
        require(
            set(settings)
            == {
                "original_known",
                "original_has",
                "stored_fec",
                "effective_fec",
                "sound",
            }
            and all(value in ("0", "1") for value in settings.values()),
            "invalid SETTINGS fields",
        )
        effective = settings.get("effective_fec")
        require(
            effective
            == (
                settings.get("stored_fec")
                if fec_mode == "saved"
                else str(int(fec_mode == "on"))
            ),
            "FEC test input mismatch",
        )
        if fec_mode != "saved":
            require(
                settings.get("original_known") == "1", "saved FEC preference unknown"
            )
    require(submitted == {"existing_identity": "1"}, "no existing identity submission")
    number(first, "elapsed_ms")
    require(
        final.get("result") == "PASS" and final.get("reason") == "none", "probe failed"
    )
    require(
        final.get("workers") == "joined" and final.get("media") == "destroyed",
        "cleanup incomplete",
    )
    require(
        set(final) == {"result", "reason", "workers", "media"}, "invalid FINAL fields"
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
    detail_tags = ["VCHANNEL", "VRECV", "VWORK", "VSUBMIT", "VDECODE", "VREQUEST"]
    require(
        tags[-10:] == detail_tags + ["WIRE", "FLOW", "RESULT", "FINAL"],
        "missing final video counter group",
    )
    details = dict(records[-10:-4]) if tags[-10:-4] == detail_tags else {}
    schemas = {
        "VCHANNEL": "channel ordinary fec retry"
        + (" fec_complete" if version == "3" else ""),
        "VRECV": "complete key finish last",
        "VWORK": "calls key finish last",
        "VSUBMIT": "calls returned keys errors last",
        "VDECODE": "calls accepted reset lost disable",
        "VREQUEST": "requested sent failed",
    }
    video = {}
    for tag, schema in schemas.items():
        value = details.get(tag, {})
        require(set(value) == set(schema.split()), "invalid " + tag + " fields")
        video[tag] = {key: number(value, key) for key in schema.split()}
    channel, rx, worker, submit, fb, requests = (video[tag] for tag in detail_tags)
    require(3 <= channel["channel"] < 32, "missing video channel role")
    require(
        0 <= channel["retry"] <= channel["ordinary"] <= wire["ordinary"]
        and 0 <= channel["fec"] <= wire["fec"],
        "video wire counts",
    )
    require(
        0 < rx["complete"] <= flow["complete"]
        and 0 < worker["calls"] <= rx["complete"],
        "video receive/worker missing",
    )
    for value, count in ((rx, "complete"), (worker, "calls")):
        require(
            0 <= value["key"] <= value[count] and 0 <= value["finish"] <= value[count],
            "video header counts",
        )
        packed = value["last"]
        require((1 << 40) <= packed < (1 << 41), "missing video header identity")
        value["last_header"] = {
            "id": packed & 65535,
            "sequence": (packed >> 16) & 65535,
            "flags": (packed >> 32) & 255,
        }
    require(
        0 < submit["calls"] == submit["returned"]
        and submit["errors"] == 0
        and 0 <= submit["keys"] <= submit["calls"],
        "video submit failed/incomplete",
    )
    require((1 << 48) <= submit["last"] < (1 << 49), "missing submitted identity")
    require(
        0 <= fb["accepted"] <= fb["calls"]
        and all(0 <= fb[key] <= fb["calls"] for key in ("reset", "lost", "disable"))
        and all(requests[key] >= 0 for key in ("requested", "sent", "failed")),
        "video feedback counts",
    )
    negotiation = {"scope": "unverified in observer v2"}
    if version == "3":
        require(
            tags[-14:]
            == ["PREFS", "NEGOTIATE", "NEGOTIATE", "PEER"]
            + detail_tags
            + ["WIRE", "FLOW", "RESULT", "FINAL"],
            "missing final negotiation group",
        )
        group = records[-13:-10] if len(records) >= 14 else []
        configs = []
        for i in range(2):
            value = group[i][1] if len(group) == 3 else {}
            schema = "type calls admitted queued sent failed fec sent_fec".split()
            require(set(value) == set(schema), "invalid NEGOTIATE fields")
            config = {key: number(value, key) for key in schema}
            require(
                config["type"] == (4 if i == 0 else 99), "config message type/order"
            )
            require(
                0 <= config["admitted"] <= config["queued"] <= config["calls"]
                and config["sent"] >= 0
                and config["failed"] >= 0,
                "config producer/socket counters",
            )
            require(
                (config["sent"] == 0 and config["sent_fec"] == 0)
                or (config["sent"] > 0 and 1 <= config["sent_fec"] <= 15),
                "config socket FEC observations",
            )
            if config["calls"]:
                require(4 <= config["fec"] <= 7, "missing config FEC observation")
            else:
                require(
                    all(config[key] == 0 for key in schema if key != "type"),
                    "empty config counters",
                )
            config["fec_present"] = bool(config["fec"] & 2)
            config["fec_value"] = bool(config["fec"] & 1)
            configs.append(config)
        initial = configs[0]
        require(
            min(initial[key] for key in ("calls", "admitted", "queued", "sent")) > 0,
            "initial config not admitted/queued/sent",
        )
        require(
            int(initial["fec_value"]) == number(settings, "effective_fec"),
            "negotiation config FEC differs from test input",
        )
        require(
            initial["sent_fec"] == 1 << (initial["fec"] & 3),
            "sent config heads differ from observed FEC input",
        )
        if fec_mode != "saved":
            require(initial["fec_present"], "explicit FEC field missing from config")
        peer = group[2][1] if len(group) == 3 else {}
        require(set(peer) == {"config_accepted", "overflow"}, "invalid PEER fields")
        accepted, overflow = number(peer, "config_accepted"), number(peer, "overflow")
        require(accepted > 0, "no accepted peer negotiation")
        require(overflow == 0, "config observation ledger overflow")
        prefs = one("PREFS")
        require(
            set(prefs) == {"loads", "saves", "profiles", "errors"},
            "invalid PREFS fields",
        )
        prefs = {
            key: number(prefs, key) for key in ("loads", "saves", "profiles", "errors")
        }
        require(prefs["errors"] == 0, "preference I/O failed")
        if fec_mode == "saved":
            require(
                all(v == 0 for v in prefs.values()), "unexpected preference override"
            )
        else:
            require(prefs["loads"] >= 2, "initial FEC override path missing")
        if fec_mode == "on":
            require(channel["fec"] > 0, "no video type11 received after FEC request")
            require(channel["fec_complete"] > 0, "no completed video FEC group")
        elif fec_mode == "off":
            require(channel["fec"] == 0, "video type11 received after explicit FEC off")
        require(
            0 <= channel["fec_complete"] <= wire["fec_complete"],
            "video FEC completion counts",
        )
        negotiation = {
            "requested_mode": fec_mode,
            "configs": configs,
            "peer_config_accepted": accepted,
            "video_type11_observed": channel["fec"] > 0,
            "video_fec_completion_observed": channel["fec_complete"] > 0,
            "preferences": prefs,
            "scope": "producer inputs/admission and exact encrypted head socket attempts; peer config is not a FEC ACK; received type11 does not prove RS reconstruction",
        }
    return {
        "passed": not errors,
        "errors": errors,
        "run": run,
        "wire": wire,
        "flow": flow,
        "media": result,
        "video": video,
        "negotiation": negotiation,
        "final": final,
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
    parser.add_argument(
        "--fec-request",
        choices=("saved", "on", "off"),
        default="saved",
        help="diagnostic initial config input; preserve the saved FEC preference on normal saves",
    )
    parser.add_argument(
        "--ordinary-build-dir",
        type=Path,
        default=ROOT / "build/switch",
        help="ordinary build from the same source identity, used for probe exclusion checks",
    )
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
            args.analyze_log.read_text(),
            args.expected_build,
            args.steam,
            args.seconds,
            args.fec_request,
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
    spec = importlib.util.spec_from_file_location(
        "live_probe_build", ROOT / "scripts/check-live-media-probe-build.py"
    )
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    observer_build = checker.check(ROOT, args.build_dir, args.ordinary_build_dir)
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
        f"{args.steam} {args.seconds} {args.fec_request}",
    ]
    package = {
        "build": head,
        "nro_sha256": sha(nro),
        "steam": args.steam,
        "switch": args.switch,
        "seconds": args.seconds,
        "fec_request": args.fec_request,
        "command": command,
        "scope": "existing paired identity; diagnostic initial FEC input; saved FEC preference preserved on normal saves; no loss injection",
    }
    (args.output / "observer_build.json").write_text(
        json.dumps(observer_build, indent=2) + "\n"
    )
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
        args.fec_request,
    )
    report.update(nxlink_exit=code, timed_out=timeout, nro_sha256=sha(nro))
    report["passed"] = report["passed"] and code == 0 and not timeout
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
