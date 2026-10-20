#!/usr/bin/env python3
"""Compare original UDP audio recovery with the actual app media backend.

Linux float Opus and Android fixed Opus are distinct recorded boundaries. Exact
fixed PCM is compared with Android; SDL3 push/SDL2 pull only prove device API
activity separately, not identical cadence or physical playback. Controlled peer
stages wait for real decoded seed/feedback. No parsed frames are injected.
"""
import argparse
import base64
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


norm = module("norm", "check-steam-retry-process.py")
platform = module("platform", "check-steam-negotiation.py")
CLIENT_SHA = "95482ca6120f90bb90798b27206b7946ab732e079f008d7fc90ea58a8b0074e1"
ANDROID_SHA = "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"


def projection(case):
    original = case["outputs"]
    assert original[1] == dict(sequence=1, plain="05") and original[0]["sequence"] == 0
    config = next(
        v
        for n, k, v, _ in platform.fields(bytes.fromhex(original[0]["plain"])[1:])
        if n == 2 and k == 2
    )
    assert config == bytes.fromhex(case["settings"])
    expected = case["native_projection"]
    assert expected[0]["plain"] == platform.platform_frame(original[0]["plain"])
    assert expected[1]["plain"] == "05"
    assert [r["sequence"] for r in expected] == [0, 1]
    return expected


def verify_source(case):
    r = case["process"]
    assert r["exit_code"] == 0 and r["cleanup_complete"] and not r["source_assertions"]
    assert {
        k: v for k, v in r["audio_final"].items() if k != "feedback_updates"
    } == dict(phase=6, rx=4, tx=2, owner_cleared=True)
    assert r["audio_before_stop"] == dict(
        frames=case["expected_frames"],
        calls=case["expected_calls"],
        feedback_updates=30 if case["profile"] == "blocked" else 0,
    )
    assert [e["name"] for e in r["audio_events"]].count("start") == 1
    assert [e["name"] for e in r["audio_events"]].count("stop") == 1
    assert len(r["audio_frame_returns"]) == case["expected_frames"]
    assert len(r["audio_decodes"]) == case["expected_calls"]
    assert r["audio_create"] == dict(
        rate=48000,
        channels=2,
        streams=1,
        coupled=1,
        mapping=[0, 1],
        created=True,
        error=0,
    )
    assert r["audio_spec"] == dict(format=0x8120, channels=2, rate=48000)
    if case["profile"] != "blocked":
        assert any(w.get("accepted") and w["bytes"] > 0 for w in r["audio_writes"])
    assert r["module_refs"] == [0, 5]
    assert [
        (e["value"], e["phase"]) for e in r["module_events"] if "force" in e["name"]
    ] == [(5, "original_exit"), (0, "original_exit")]
    assert not {
        p for p, state in r["tasks_after_shutdown"].items() if state not in ("X", "Z")
    } - set(r["tasks_before"])
    assert any(e[0] == "join_completed" and e[2] == 0 for e in r["trace"])


def check_case(case, receiver):
    verify_source(case)
    fixed = case["fixed_reference"]
    assert fixed["binary_sha256"] == ANDROID_SHA
    frames = fixed["frames"]
    observed = fixed["observed"]
    assert len(frames) == len(observed) == case["expected_frames"]
    for row, event, state in zip(
        frames,
        [e for e in case["process"]["audio_events"] if e["name"] == "frame"],
        case["process"]["audio_frame_returns"],
        strict=True,
    ):
        assert row["id"] == event["id"]
        assert row["timestamp"] == (event["timestamp"] + event["offset"]) & 0xFFFFFFFF
        assert any(
            row["id"] == struct.unpack_from("<H", w, 14)[0]
            and row["timestamp"] == struct.unpack_from("<I", w, 16)[0]
            and row["payload"] == w[26:].hex()
            for w in (norm.without_crc(bytes.fromhex(r["data"])) for r in case["sent"])
            if w[4] == 3 and len(w) >= 26
        )
    assert [{k: row[k] for k in ("first", "next")} for row in observed] == [
        dict(first=bool(row["first"]), next=row["next"])
        for row in case["process"]["audio_frame_returns"]
    ]
    linux = []
    for row in case["process"]["audio_decodes"]:
        value = {
            k: row[k]
            for k in ("id", "timestamp", "payload", "max_samples", "fec", "result")
        }
        value["timestamp"] = (row["timestamp"] + row["offset"]) & 0xFFFFFFFF
        linux.append(value)
    decodes = [d for row in observed for d in row["decodes"]]
    assert decodes == linux
    stages = [[]]
    seed = case["after_seed_sent_index"]
    recovery = case.get("recovery_sent_index")
    continuation = case.get("continuation_sent_index")
    for i, row in enumerate(case["sent"]):
        raw = bytes.fromhex(row["data"])
        if raw[4] != 3:
            continue
        stage = 0 if i < seed else 1 if recovery is None or i < recovery else 2
        if continuation is not None and i >= continuation:
            stage = 3
        while len(stages) <= stage:
            stages.append([])
        stages[stage].append(raw)
        wire = norm.without_crc(raw)
        pid = struct.unpack_from("<H", wire, 7)[0]
        assert wire[0] & 127 == (5 if case["reliable"] else 3)
        assert bool(wire[0] & 128) == case["crc"] and wire[2] == 7
        assert wire[13] == 1 and struct.unpack_from("<h", wire, 5)[0] == 0
        assert struct.unpack_from("<H", wire, 14)[0] == case["ids"][pid]
    assert [len(s) for s in stages][:1] == [1]
    gap = case["profile"] in ("repair", "drop", "blocked")
    assert len(stages) == (
        4 if case["profile"] == "drop" else 3 if case["profile"] == "repair" else 2
    )
    if case["profile"] == "drop":
        assert len(stages[2]) == 1 and struct.unpack_from("<H", stages[2][0], 7)[0] == 3
    feedback = norm.normalize(bytes.fromhex(case["gap_feedback"])) if gap else None
    if gap:
        assert any(row["data"] == case["gap_feedback"] for row in case["received"])
        assert len(stages[1]) == 1 and struct.unpack_from("<H", stages[1][0], 7)[0] == 2
    with tempfile.TemporaryDirectory(prefix="native-udp-audio-") as directory:
        path = Path(directory)
        (path / "streaming_settings.bin").write_bytes(bytes.fromhex(case["settings"]))
        (path / "media.bin").write_bytes(
            bytes(4).join(
                b"".join(struct.pack("<I", len(w)) + w for w in stage)
                for stage in stages
            )
        )
        result = subprocess.run(
            [
                str(receiver),
                "--audio",
                str(int(case["crc"])),
                directory,
                "080110031804" if case["reliable"] else "080010031804",
                "0",
                str(path / "media.bin"),
                str(case["expected_frames"]),
                str(case["expected_calls"]),
                case["profile"],
                feedback.hex() if feedback else "-",
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
        assert result.returncode == 0, (
            case["name"],
            result.returncode,
            result.stderr[-4000:],
            result.stdout[-1000:],
        )
        native = json.loads(result.stdout)
        assert (path / "streaming_settings.bin").read_bytes() == bytes.fromhex(
            case["settings"]
        )
    expected = dict(
        phase=6,
        closed=False,
        mtu=1472,
        goodbyes=0,
        receive_sequence=4,
        send_sequence=2,
        frames=projection(case),
    )
    assert {k: native[k] for k in expected} == expected, (
        case["name"],
        native,
        expected,
    )
    if feedback:
        assert norm.normalize(bytes.fromhex(native["audio_feedback"])) == feedback
    got = native["audio"]
    assert got["config"] == fixed["decoder_config"]
    assert got["backend"].endswith("-fixed")
    assert got["starts"] == got["stops"] == 1
    if case["profile"] != "blocked":
        assert got["played"] > 0
    expected_frames = [
        dict(id=f["id"], timestamp=f["timestamp"], first=s["first"], next=s["next"])
        for f, s in zip(frames, observed, strict=True)
    ]
    assert got["frames"] == expected_frames, (
        case["name"],
        got["frames"],
        expected_frames,
    )
    actual_decodes = [
        {k: v for k, v in d.items() if k != "pcm"} for d in got["decodes"]
    ]
    assert actual_decodes == decodes, (case["name"], actual_decodes, decodes)
    valid = [s for row in observed for s in row["submitted"] if "s16_zlib_base64" in s]
    assert len(valid) == len(got["decodes"])
    assert got["queued"] == [d["pcm"] for d in got["decodes"]]
    for want, d in zip(valid, got["decodes"], strict=True):
        pcm = zlib.decompress(base64.b64decode(want["s16_zlib_base64"]))
        assert hashlib.sha256(pcm).hexdigest() == want["s16_sha256"]
        assert pcm == bytes.fromhex(d["pcm"]), (case["name"], d["id"], "PCM mismatch")
    return len(decodes)


def main():
    if not __debug__:
        raise SystemExit("Assertions required")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    p.add_argument("--source-report", type=Path)
    p.add_argument("--profile", action="append")
    a = p.parse_args()
    report = (
        json.loads(a.source_report.read_text())
        if a.source_report
        else json.loads(
            gzip.decompress(
                (
                    ROOT
                    / "scripts/fixtures/steam-client-audio-process-reference.json.gz"
                ).read_bytes()
            )
        )
    )
    assert report["client_sha256"] == CLIENT_SHA
    assert len(report["cases"]) == 18
    assert {(c["profile"], c["crc"]) for c in report["cases"]} == {
        (p, crc)
        for p in (
            "continuous",
            "gap1",
            "gap3",
            "old",
            "wrap",
            "repair",
            "drop",
            "blocked",
            "silk",
        )
        for crc in (False, True)
    }
    assert len(report["source_functions"]) == 38
    previous = json.loads(
        gzip.decompress(
            (
                ROOT
                / "scripts/fixtures/steam-client-negotiation-process-reference.json.gz"
            ).read_bytes()
        )
    )
    assert {
        k: report["source_functions"][k] for k in previous["source_functions"]
    } == previous["source_functions"]
    assert report["qt_dependency_sha256"] == previous["qt_dependency_sha256"]
    assert (
        report["qt_required_controller_patch"]
        == previous["qt_required_controller_patch"]
    )
    assert (
        report["codec_sha256"]
        == "c53a7e3d32a986323ec6bedd28df73a6e5842c4753b67b1d2aa0d6e4f524472f"
    )
    assert (
        report["util_sha256"]
        == "6df6556b6026144eb545dd95c0e2cc8c4568f462c9bd7e036531207d4172db34"
    )
    assert (
        report["opus_stimulus_sha256"]
        == hashlib.sha256(
            (ROOT / "scripts/fixtures/steam-opus-recovery-reference.json").read_bytes()
        ).hexdigest()
    )
    for name, address, size, sha in (
        (
            "opus_start",
            0x3252A0,
            250,
            "82282054c71cf880c7613dafa00ad10bf47e66d04f65f0146cb2fff4ef49b6d2",
        ),
        (
            "opus_stop",
            0x3253A0,
            57,
            "f5b11a3ea2919a77c575d078c8c20cf7c7259ac09e287a730f57fe2de0e02812",
        ),
        (
            "opus_decode",
            0x3253E0,
            657,
            "e94359d532117bec1a3f638a35c6834d94bd913c8afec97988e67290966fd7e4",
        ),
    ):
        assert report["source_functions"][name] == dict(
            address=address, size=size, sha256=sha
        )
    assert len(report["helpers"]) == 6
    for name, sha in report["helpers"].items():
        assert hashlib.sha256((ROOT / "scripts" / name).read_bytes()).hexdigest() == sha
    for case in report["cases"]:
        assert case["process"]["audio_library"] == dict(
            path="/usr/lib/x86_64-linux-gnu/libopus.so.0.10.1",
            sha256="621e97f23655dbf2727873b7717e3b65ae8c734f84a0848f88c21edb95202357",
            version="libopus 1.5.2",
        )
    count = 0
    cases = [c for c in report["cases"] if not a.profile or c["profile"] in a.profile]
    for case in cases:
        count += check_case(case, a.receiver.resolve())
        print(case["name"], "UDP/codec/PCM/SDL/Stop matched", flush=True)
    print(
        f"Audio UDP: {len(cases)} source/native processes, {count} exact fixed PCM decodes"
    )


if __name__ == "__main__":
    main()
