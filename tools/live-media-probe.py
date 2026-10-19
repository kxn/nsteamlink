#!/usr/bin/env python3
"""Prepare/run one real-host probe, or validate a captured machine record.

Only --run deploys; use it after the user prepares netloader. Never probe TCP
28280 or retry a launch. Optional drop-one requires a missing-systematic byte
witness; drop-group requires an actual scoped request/send, later key/submit and
continued playback. Temporal order does not prove host causal/GOP policy. These
modes do not prove adverse-network equivalence, decoded pixel identity, physical
scanout or hbmenu/loader ABI.
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


def analyze(log, build, steam, seconds, fec_mode="saved", loss_mode="none"):
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
    if version in ("3", "4", "5"):
        expected_begin["fec"] = fec_mode
    if version in ("4", "5"):
        expected_begin["loss"] = loss_mode
    require(
        loss_mode in ("none", "drop-one", "drop-group")
        and (loss_mode == "none" or (fec_mode == "on" and version in ("4", "5"))),
        "invalid erasure mode/version",
    )
    require(loss_mode != "drop-group" or version == "5", "group loss needs observer5")
    require(
        begin == expected_begin
        and version in ("2", "3", "4", "5")
        and (version != "2" or fec_mode == "saved"),
        "identity mismatch",
    )
    require(settings.get("stored_fec") in ("0", "1"), "missing FEC preference")
    require(settings.get("sound") in ("0", "1"), "missing sound preference")
    if version in ("3", "4", "5"):
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
        + (" fec_complete" if version in ("3", "4", "5") else ""),
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
    stopping = {"scope": "unverified in captures without STOPPING"}
    if "STOPPING" in tags:
        value = one("STOPPING")
        require(
            set(value) == {"submit_calls", "submit_errors"}, "invalid STOPPING fields"
        )
        calls, stop_errors = number(value, "submit_calls"), number(
            value, "submit_errors"
        )
        require(
            0 <= calls <= submit["calls"] and 0 <= stop_errors <= submit["errors"],
            "invalid pre-cleanup submit counts",
        )
        require(tags.index("STOPPING") < len(tags) - 4, "STOPPING after final counters")
        stopping = {
            "submit_calls": calls,
            "submit_errors": stop_errors,
            "scope": "main-thread snapshot before local close/exit; not a causal error classification",
        }
    negotiation = {"scope": "unverified in observer v2"}
    if version in ("3", "4", "5"):
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
    erasure = {"mode": loss_mode, "scope": "no diagnostic erasure"}
    repair_proved = False
    key_recovery = {"verified": False, "scope": "not tested"}
    if version in ("4", "5"):
        witness, shape, after = (
            one(tag) for tag in ("FECLOSS", "FECSHAPE", "FECAFTER")
        )
        schemas = (
            (witness, "selected blocked complete matched conflict replaced"),
            (shape, "channel group index bytes length k m data parity"),
            (after, "decoded presented"),
        )
        parsed = []
        for values, schema in schemas:
            require(set(values) == set(schema.split()), "invalid erasure fields")
            parsed.append({key: number(values, key) for key in schema.split()})
        witness, shape, after = parsed
        require(
            tags[-17:-14] == ["FECLOSS", "FECSHAPE", "FECAFTER"],
            "missing final erasure group",
        )
        if loss_mode == "none":
            require(
                all(value == 0 for group in parsed for value in group.values()),
                "unexpected diagnostic erasure",
            )
        elif loss_mode == "drop-one":
            require(
                witness["selected"] == witness["complete"] == witness["matched"] == 1
                and witness["blocked"] >= 1
                and witness["blocked"] <= channel["fec"]
                and witness["conflict"] == witness["replaced"] == 0,
                "no exact erasure reconstruction witness",
            )
            require(
                shape["channel"] == channel["channel"]
                and 0 <= shape["group"] <= 65535
                and shape["index"] == 0
                and 1 <= shape["bytes"] <= 1472
                and 2 <= shape["k"] < 255
                and 1 <= shape["m"] <= 255 - shape["k"]
                and (shape["k"] - 1) * shape["bytes"]
                < shape["length"]
                <= shape["k"] * shape["bytes"]
                and 0 <= shape["data"] < shape["k"]
                and 1 <= shape["parity"] <= shape["m"]
                and shape["k"]
                <= shape["data"] + shape["parity"]
                <= channel["fec"] - witness["blocked"]
                and channel["fec_complete"] >= 1,
                "invalid missing-systematic/parity witness",
            )
            require(
                10 <= after["decoded"] <= number(result, "decoded")
                and 10 <= after["presented"] <= number(result, "presented"),
                "no continued playback after reconstruction",
            )
            repair_proved = not errors
        erasure = {
            "mode": loss_mode,
            "witness": witness,
            "shape": shape,
            "after": after,
            "scope": "one withheld systematic shard, including all its duplicates; exact useful-byte comparison in production receiver output; not decoded pixel identity or physical scanout",
        }
    if version == "5":
        gap_tags = ["GROUPDROP", "GAPFLOW", "GAPKEY", "GAPTIME"]
        schemas = (
            "unique loss",
            "calls unscoped sent failed producer",
            "header submitted lost_submits",
            "loss producer sent key submit",
        )
        groups = []
        for tag, schema in zip(gap_tags, schemas):
            value = one(tag)
            require(set(value) == set(schema.split()), "invalid " + tag + " fields")
            groups.append({key: number(value, key) for key in schema.split()})
        require(tags[-21:-17] == gap_tags, "missing final group recovery records")
        dropped, gap, key, times = groups
        if loss_mode != "drop-group":
            require(
                all(v == 0 for group in groups for v in group.values()),
                "unexpected group recovery observation",
            )
        else:
            witness, shape, after = (
                erasure.get(k, {}) for k in ("witness", "shape", "after")
            )
            require(
                witness.get("selected") == 1
                and witness.get("blocked", -1) >= dropped["unique"]
                and dropped["unique"] >= 1
                and witness.get("blocked", -1) <= channel["fec"]
                and all(
                    witness.get(k) == 0
                    for k in ("complete", "matched", "conflict", "replaced")
                ),
                "group erasure not witnessed",
            )
            require(
                shape.get("channel") == channel["channel"]
                and 0 <= shape.get("group", -1) <= 65535
                and shape.get("index") == 0
                and 20 <= shape.get("bytes", -1) <= 1472
                and 1 <= shape.get("k", -1) <= 255
                and 0 <= shape.get("m", -1)
                and shape.get("k", -1) + shape.get("m", -1) == dropped["unique"] <= 255
                and (shape.get("k", -1) - 1) * shape.get("bytes", -1)
                < shape.get("length", -1)
                <= shape.get("k", -1) * shape.get("bytes", -1)
                and shape.get("length", -1) >= 20
                and shape.get("data") == shape.get("parity") == 0,
                "not all group shards withheld",
            )

            def header(value):
                require((1 << 48) <= value < (1 << 49), "invalid recovery header")
                parsed = dict(
                    channel=(value >> 40) & 255,
                    flags=(value >> 32) & 255,
                    sequence=(value >> 16) & 65535,
                    id=value & 65535,
                )
                require(
                    parsed["channel"] == channel["channel"], "recovery channel mismatch"
                )
                return parsed

            loss_header, producer, key_header = (
                header(x) for x in (dropped["loss"], gap["producer"], key["header"])
            )
            for newer, older in ((producer, loss_header), (key_header, producer)):
                require(
                    all(
                        0 < (newer[k] - older[k]) & 65535 < 32768
                        for k in ("id", "sequence")
                    ),
                    "recovery header order",
                )
            require(
                loss_header["flags"] & 8
                and not loss_header["flags"] & (16 | 32)
                and not producer["flags"] & 16
                and key_header["flags"] & 16
                and key_header["flags"] & 8,
                "not P loss to key recovery",
            )
            require(
                gap["calls"] > 0
                and gap["unscoped"] == gap["failed"] == 0
                and gap["sent"]
                == gap["calls"]
                == requests["requested"]
                == requests["sent"]
                and requests["failed"] == 0
                and key["submitted"] == 1
                and key["lost_submits"] == 0,
                "missing scoped successful recovery send/submit",
            )
            ordered = [times[k] for k in ("loss", "producer", "sent", "key", "submit")]
            require(
                ordered[0] >= int(run or 0) > 0 and ordered == sorted(ordered),
                "invalid recovery timeline",
            )
            require(
                10 <= after.get("decoded", -1) <= number(result, "decoded")
                and 10 <= after.get("presented", -1) <= number(result, "presented"),
                "no playback after recovery key submit",
            )
            key_recovery = dict(
                verified=not errors,
                loss=loss_header,
                producer=producer,
                key=key_header,
                requests=gap,
                times_ms=times,
                loss_to_send_ms=times["sent"] - times["loss"],
                send_to_key_ms=times["key"] - times["sent"],
                loss_to_submit_ms=times["submit"] - times["loss"],
                scope="one whole post-CRC non-key group withheld; actual scoped producer/send, later key and submit, continuing playback; temporal order does not establish host causal/GOP policy",
            )
            erasure["scope"] = (
                "all observed shards of one non-key group withheld, including duplicates; no RS reconstruction expected"
            )
    return {
        "passed": not errors,
        "errors": errors,
        "run": run,
        "wire": wire,
        "flow": flow,
        "media": result,
        "video": video,
        "negotiation": negotiation,
        "stopping": stopping,
        "erasure": erasure,
        "keyframe_recovery": key_recovery,
        "final": final,
        "scope": "real-host video playback smoke; audio counters observed; "
        + (
            "one diagnostic FEC data erasure"
            if loss_mode == "drop-one"
            else (
                "one whole non-key FEC group erased"
                if loss_mode == "drop-group"
                else "no loss injected"
            )
        ),
        "audio_decode_observed": audio > 0,
        "rs_reconstruction": (
            "one diagnostic erasure byte-verified" if repair_proved else "unverified"
        ),
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
        "--fec-loss",
        choices=("none", "drop-one", "drop-group"),
        default="none",
        help="isolated diagnostic shard/group erasure; requires --fec-request on",
    )
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
    if args.fec_loss != "none" and args.fec_request != "on":
        parser.error("--fec-loss requires --fec-request on")
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
            args.fec_loss,
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
        f"{args.steam} {args.seconds} {args.fec_request} {args.fec_loss}",
    ]
    package = {
        "build": head,
        "nro_sha256": sha(nro),
        "steam": args.steam,
        "switch": args.switch,
        "seconds": args.seconds,
        "fec_request": args.fec_request,
        "fec_loss": args.fec_loss,
        "command": command,
        "scope": "existing paired identity; saved FEC preference preserved on normal saves; "
        + (
            "one diagnostic data-shard erasure"
            if args.fec_loss == "drop-one"
            else (
                "one whole non-key group erasure"
                if args.fec_loss == "drop-group"
                else "no loss injection"
            )
        ),
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
        args.fec_loss,
    )
    report.update(nxlink_exit=code, timed_out=timeout, nro_sha256=sha(nro))
    report["passed"] = report["passed"] and code == 0 and not timeout
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
