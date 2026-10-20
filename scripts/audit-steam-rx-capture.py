#!/usr/bin/env python3
"""Capture real CLIENT/Native receive batches and replay the measured environment.

Linux original constructors, OS UDP/CRC/crypto/50-51, workers, Opus/SDL and natural
shutdown execute. GDB observes Socket boundaries, HandleMessage, timestamp
samples and the actual computed receive budget. Native observers are bounded
forwarding wrappers; they never change scheduling with a barrier or replace IO.
Peer handshake/media and the existing initial decoded-seed/NACK/Stop conditions
are controlled. A burst has no per-frame continuation barrier. Capture RTT and
batching vary; the explicit independent Android network replay boundary supplies
one ACK for the real Connected clock input, an outgoing seed and initial shaper
deadline. It proves this receive projection, not natural timing equivalence,
global backlog/high bitrate, host retransmission/FEC policy or real Steam/Switch.
"""
import argparse
import copy
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


base = module("audio", "audit-steam-client-audio-process.py")
check = module("capture_check", "check-steam-rx-capture.py")
network = module("capture_network", "audit-steam-network-cycle.py")


class BurstPeer(base.Peer):
    def media(self, pid, retry=0):
        for n in (range(3, len(self.case["ids"])) if pid == 3 else [pid]):
            super().media(n, retry)


def verify(case):
    # This is an observation count, not the oracle. Independent original
    # network replay below must predict these exact actual callbacks.
    case["expected_frames"] = len(case["process"]["audio_frame_returns"])
    base.verify(case)
    r = case["process"]
    assert len(r["rx_clock"]) == 1
    assert all(b["result"] == 1 for b in r["rx_batches"])


def linux_capture(case):
    r = case["process"]
    clock = r["rx_clock"]
    assert len(clock) == 1
    row = clock[0]
    tick = (row["now"] - row["echo"]) & 0xFFFFFFFF
    assert row["after"]["minimum"] == row["after"]["smooth"] == tick
    return dict(
        clock=[{k: row[k] for k in ("echo", "peer", "now")}],
        batches=[
            dict(
                tick=b["tick"],
                mean=b["clock"]["mean"],
                budgets=b["budgets"],
                packets=b["packets"],
            )
            for b in r["rx_batches"]
        ],
    )


def native_capture(case, receiver):
    stages = [[], [], []]
    for i, row in enumerate(case["sent"]):
        raw = bytes.fromhex(row["data"])
        if raw[4] == 3:
            stages[
                (
                    0
                    if i < case["after_seed_sent_index"]
                    else 1 if i < case["recovery_sent_index"] else 2
                )
            ].append(raw)
    assert [len(s) for s in stages] == [1, 1, 15]
    with tempfile.TemporaryDirectory(prefix="native-rx-capture-") as d:
        p = Path(d)
        (p / "streaming_settings.bin").write_bytes(bytes.fromhex(case["settings"]))
        (p / "media.bin").write_bytes(
            bytes(4).join(
                b"".join(struct.pack("<I", len(w)) + w for w in rows) for rows in stages
            )
        )
        result = subprocess.run(
            [
                str(receiver),
                "--audio",
                str(int(case["crc"])),
                d,
                "080010031804",
                "0",
                str(p / "media.bin"),
                "0",
                "18",
                "burst",
                check.norm.normalize(bytes.fromhex(case["gap_feedback"])).hex(),
            ],
            capture_output=True,
            text=True,
            timeout=12,
            env=dict(
                os.environ,
                SDL_VIDEODRIVER="dummy",
                SDL_AUDIODRIVER="dummy",
                SDL_RENDER_DRIVER="software",
            ),
        )
        assert result.returncode == 0, (case["name"], result.returncode, result.stderr)
        original = json.loads(result.stdout)
        assert (p / "streaming_settings.bin").read_bytes() == bytes.fromhex(
            case["settings"]
        )
    capture = dict(
        clock=original["rx_clock"],
        batches=[
            dict(
                tick=b["tick"],
                mean=b["mean"],
                budgets=[b["budget"]],
                packets=b["packets"],
            )
            for b in original["rx_batches"]
        ],
    )
    return capture, original


def fixed_frames(binary, frames):
    r = base.arm.Opus(binary, 2)
    r.start()
    observed = []
    for f in frames:
        r.feed(f["id"], f["timestamp"], bytes.fromhex(f["payload"]))
        observed.append(r.snapshot())
    r.call(0x7B16FC, r.decoder)
    assert not r.q(r.decoder + 400)
    return dict(
        binary_sha256=base.arm.c.SHA,
        decoder_config=r.decoder_config,
        frames=frames,
        observed=observed,
    )


def main():
    if not __debug__:
        raise SystemExit("Assertions required")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--android-binary", type=Path, required=True)
    p.add_argument("--sdk-directory", type=Path, required=True)
    p.add_argument("--qt-library-directory", type=Path, action="append", required=True)
    p.add_argument("--native-receiver", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--snapshot", type=Path)
    a = p.parse_args()
    binary, sdk, qt, native = (
        a.binary.resolve(),
        a.sdk_directory.resolve(),
        [d.resolve() for d in a.qt_library_directory],
        a.native_receiver.resolve(),
    )
    arm = a.android_binary.read_bytes()
    digest = base.neg.udp.process.digest
    assert (
        digest(binary) == check.audio.CLIENT_SHA
        and hashlib.sha256(arm).hexdigest() == check.audio.ANDROID_SHA
    )
    cases = []
    os.environ["SDL_AUDIODRIVER"] = "dummy"
    for plan in base.plans():
        if plan["profile"] != "drop":
            continue
        case = dict(
            plan,
            settings="3800c80101",
            bad_mac=False,
            server="070a0308c00b",
            response="0208001001",
            duplicate=False,
            bad_length=False,
        )
        with tempfile.TemporaryDirectory(prefix="official-rx-capture-") as d:
            settings = Path(d) / "streaming_settings.bin"
            settings.write_bytes(bytes.fromhex(case["settings"]))
            case["stage_file"] = str(Path(d) / "stage")
            result = base.neg.udp.audit(
                binary,
                sdk,
                qt,
                a.output.with_name(a.output.stem + "-" + case["name"] + ".json"),
                case,
                helper=ROOT / "scripts/steam-client-rx-gdb.py",
                reactor=BurstPeer,
                probe_config=dict(
                    udp_helper=str(ROOT / "scripts/steam-client-udp-gdb.py"),
                    negotiation_helper=str(
                        ROOT / "scripts/steam-client-negotiation-gdb.py"
                    ),
                    audio_helper=str(ROOT / "scripts/steam-client-audio-gdb.py"),
                    settings_file=str(settings),
                    stage_file=case["stage_file"],
                    blocked=False,
                    drop=False,
                    expected_calls=18,
                    expected_frames=1,
                    require_output=True,
                ),
                validate=verify,
            )
            assert settings.read_bytes() == bytes.fromhex(case["settings"])
        result["fixed_reference"] = base.fixed_reference(result, arm)
        name = f"linux_crc{int(case['crc'])}"
        cases.append(
            dict(
                name=name,
                kind="linux",
                crc=case["crc"],
                capture=linux_capture(result),
                original=result,
                decoder_reference=result["fixed_reference"],
            )
        )
        capture, original = native_capture(result, native)
        cases.append(
            dict(
                name=f"native_crc{int(case['crc'])}",
                kind="native",
                crc=case["crc"],
                capture=capture,
                original=original,
                control_projection=result["native_projection"],
            )
        )
        print(
            name,
            "actual Socket batches and Native captured; original clean exit",
            flush=True,
        )
    inputs = [check.make_input(c["capture"], c["crc"], c["name"]) for c in cases]
    old = network.schedules
    try:
        network.schedules = lambda: inputs
        observed = network.audit(arm)
    finally:
        network.schedules = old
    for case, oracle in zip(cases, observed, strict=True):
        case.update(oracle)
        frames = []
        for state in case["observed"]:
            for value in state["delivered"]:
                body = bytes.fromhex(value)
                frames.append(
                    dict(
                        id=struct.unpack_from("<H", body, 1)[0],
                        timestamp=struct.unpack_from("<I", body, 3)[0],
                        payload=body[13:].hex(),
                    )
                )
        if case["kind"] == "native":
            case["decoder_reference"] = fixed_frames(arm, frames)
        assert frames == case["decoder_reference"]["frames"]
        check.check_projection(case)
        print(
            case["name"],
            "original instructions predicted frames",
            [f["id"] for f in frames],
            flush=True,
        )
    counterinputs = []
    for case in cases:
        if case["kind"] != "linux":
            continue
        other = next(
            c for c in cases if c["kind"] == "native" and c["crc"] == case["crc"]
        )
        sample = other["capture"]["clock"][0]
        delta = (sample["now"] - sample["echo"]) & 0xFFFFFFFF
        inp = copy.deepcopy(case["input"])
        changed = (inp["cycles"][1]["tick"] - delta) & 0xFFFFFFFF
        inp["name"] = "low_rtt_" + case["name"]
        inp["constructor_tick"] = inp["initial_deadline"] = inp["seeds"][0][0] = inp[
            "cycles"
        ][0]["tick"] = changed
        inp["cycles"][1]["rows"][0][6] = struct.pack("<I", changed).hex()
        counterinputs.append(inp)
    try:
        network.schedules = lambda: counterinputs
        counterfactuals = network.audit(arm)
    finally:
        network.schedules = old
    for c in counterfactuals:
        ids = [
            struct.unpack_from("<H", bytes.fromhex(v), 1)[0]
            for state in c["observed"]
            for v in state["delivered"]
        ]
        original = next(
            x for x in cases if "low_rtt_" + x["name"] == c["input"]["name"]
        )
        assert ids != [f["id"] for f in original["decoder_reference"]["frames"]], (
            c["input"]["name"],
            ids,
        )
    functions = dict(base.neg.FUNCTIONS)
    functions.update(
        {
            0x3252A0: "opus_start",
            0x3253A0: "opus_stop",
            0x3253E0: "opus_decode",
            0x1A0760: "socket_update",
            0x1A0500: "socket_handle",
            0x19B0A0: "process_timestamp",
            0x19C010: "unreliable_update",
            0x1997E0: "receive_rtt_budget",
        }
    )
    report = dict(
        scope=__doc__,
        client_sha256=digest(binary),
        android_sha256=hashlib.sha256(arm).hexdigest(),
        native_receiver_sha256=digest(native),
        source_functions=base.neg.udp.process.boundary.inventory(
            binary.read_bytes(), functions
        ),
        android_functions=network.function_manifest(arm),
        qt_dependency_sha256={
            name: digest(
                next(
                    d / f"libQt6{name}.so.6"
                    for d in qt
                    if (d / f"libQt6{name}.so.6").is_file()
                )
            )
            for name in ("Core", "Gui", "Widgets", "Svg")
        },
        qt_required_controller_patch=base.neg.udp.process.QT_PATCH,
        codec_sha256=digest(sdk / "libavcodec.so.61"),
        util_sha256=digest(sdk / "libavutil.so.59"),
        helpers={
            name: digest(ROOT / "scripts" / name)
            for name in (
                "steam-client-rx-gdb.py",
                "steam-client-audio-gdb.py",
                "steam-client-negotiation-gdb.py",
                "steam-client-udp-gdb.py",
                "steam-client-sdk-gdb.py",
                "audit-steam-rx-capture.py",
                "audit-steam-client-audio-process.py",
                "audit-steam-opus-recovery.py",
                "check-steam-rx-capture.py",
                "audit-steam-network-cycle.py",
                "audit-steam-receive-cycle.py",
                "audit-steam-network-loss.py",
            )
        },
        cases=cases,
        counterfactuals=counterfactuals,
    )
    data = (json.dumps(report, indent=2) + "\n").encode()
    a.output.write_bytes(data)
    if a.snapshot:
        a.snapshot.write_bytes(gzip.compress(data, mtime=0))
    print(
        "Actual RX capture: 4 measured-environment projections matched official instructions",
        flush=True,
    )


if __name__ == "__main__":
    main()
