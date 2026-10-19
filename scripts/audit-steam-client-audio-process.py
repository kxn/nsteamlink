#!/usr/bin/env python3
"""Official Linux UDP/audio/Opus/SDL execution plus independent Android PCM.

Linux constructors, real socket/CRC/crypto/OnThink/worker, codec and SDL3 dummy
stream run. Only peer bytes/input barriers and platform audio init/quit are
provided. No parsed Frame, phase, original method or SDK return is replaced.
The actual external Linux Opus is recorded, not called an Android fixed build.
Android decoder entry is a separate explicit component boundary, using the
actual Linux-decoded input frames; its valid S16 outputs serve the fixed-point
Switch backend. Natural SDL timing, physical acoustics/Steam/Switch and host
retransmission/GOP/FEC policy are not proved by this controlled peer.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


neg = module("neg", "audit-steam-client-negotiation-process.py")
arm = module("arm", "audit-steam-opus-recovery.py")


def plans():
    result = []
    for crc in (False, True):
        for profile, ids in (
            ("continuous", list(range(10, 26))),
            ("gap1", [10, *range(12, 28)]),
            ("gap3", [10, *range(14, 30)]),
            ("old", [10, 10, 9, *range(11, 27)]),
            ("wrap", [65534, 0, 65535, *range(1, 17)]),
            ("repair", list(range(10, 28))),
            ("drop", list(range(10, 28))),
            ("blocked", [10, 11, 12]),
            ("silk", [0, 1, 2, 4, 5, *range(6, 18)]),
        ):
            reliable = profile in ("repair", "blocked")
            # Scheduling bounds only; observations are independently checked.
            frames = (
                1
                if profile == "blocked"
                else len(ids) - (2 if profile == "drop" else 0)
            )
            calls = 1 if profile == "blocked" else (ids[-1] - ids[0] + 1) & 65535
            result.append(
                dict(
                    name=f"audio_{profile}_crc{int(crc)}",
                    profile=profile,
                    crc=crc,
                    reliable=reliable,
                    channels=2,
                    ids=ids,
                    expected_frames=frames,
                    expected_calls=calls,
                )
            )
    return result


def packet(case, pid, retry=0):
    timestamp = 1000000 + pid * 655
    if case["profile"] == "drop" and pid >= 3:
        timestamp += 20000
    if case["profile"] == "silk" and pid < 5:
        stimulus = json.loads(
            (ROOT / "scripts/fixtures/steam-opus-recovery-reference.json").read_text()
        )
        payload = next(c for c in stimulus["cases"] if c["name"] == "silk_fec_gap1_2")[
            "actions"
        ][pid][3]
    else:
        payload = "f0fffe"
    body = struct.pack("<BHIHI", 1, case["ids"][pid], timestamp, 0, 0) + bytes.fromhex(
        payload
    )
    raw = (
        struct.pack(
            "<BBBBBhHI", 5 if case["reliable"] else 3, retry, 7, 0, 3, 0, pid, timestamp
        )
        + body
    )
    return raw


class Peer(neg.Peer):
    def __init__(self, *args):
        super().__init__(*args)
        self.started = self.seeded = self.recovered = self.stopped = self.continued = (
            False
        )
        self.address = None
        self.local = 0

    def media(self, pid, retry=0):
        raw = bytearray(packet(self.case, pid, retry))
        raw[3] = self.local
        self.send(raw, self.address)

    def __call__(self, raw, address):
        self.on_idle()
        super().__call__(raw, address)
        data = neg.udp.without_crc(raw)
        if data[0] & 127 == 5 and data[4] == 1 and data[13] == 5 and not self.started:
            self.started = True
            self.address, self.local = address, raw[2]
            start = bytes.fromhex("100318032880f7023002")
            self.send(
                bytearray(
                    struct.pack("<BBBBBhHI", 5, 0, 7, self.local, 1, 0, 4, 1000000)
                    + bytes([50])
                    + neg.encrypted(start, 2)
                ),
                address,
            )
            self.media(0)
        if (
            self.seeded
            and not self.recovered
            and self.case["profile"] in ("repair", "drop", "blocked")
            and data[4] == 3
            and data[0] & 127 == (8 if self.case["reliable"] else 10)
            and struct.unpack_from("<H", data, 7)[0] == 2
            and len(data) == 20
            and data[17:] == b"\0\0\x01"
        ):
            self.recovered = True
            self.case["gap_feedback"] = raw.hex()
            Path(self.case["stage_file"] + ".feedback").write_text(raw.hex())
            self.case["recovery_sent_index"] = len(self.sent)
            if self.case["profile"] == "repair":
                self.media(1, 1)
            if self.case["profile"] != "blocked":
                for pid in (
                    range(3, 4)
                    if self.case["profile"] == "drop"
                    else range(3, len(self.case["ids"]))
                ):
                    self.media(pid)

    def on_idle(self):
        path = Path(self.case["stage_file"])
        stage = path.read_text() if path.exists() else ""
        if stage == "continuation" and not self.continued:
            assert self.case["profile"] == "drop" and self.recovered
            self.continued = True
            self.case["continuation_sent_index"] = len(self.sent)
            for pid in range(4, len(self.case["ids"])):
                self.media(pid)
        if stage == "seed" and self.started and not self.seeded:
            self.seeded = True
            self.case["after_seed_sent_index"] = len(self.sent)
            if self.case["profile"] in ("repair", "drop", "blocked"):
                self.media(2)
            else:
                for pid in range(1, len(self.case["ids"])):
                    self.media(pid)
        if stage == "stop" and not self.stopped and self.started:
            self.stopped = True
            self.send(
                bytearray(
                    struct.pack("<BBBBBhHI", 5, 0, 7, self.local, 1, 0, 5, 1000000)
                    + bytes([51])
                    + neg.encrypted(b"", 3)
                ),
                self.address,
            )


def verify(case):
    r = case["process"]
    assert r["exit_code"] == 0 and r["cleanup_complete"] and not r["source_assertions"]
    final = dict(r["audio_final"])
    updates = final.pop("feedback_updates")
    assert final == dict(
        phase=6,
        rx=4,
        tx=2,
        owner_cleared=True,
    )
    assert updates >= 30 if case["profile"] == "blocked" else updates == 0
    assert r["audio_before_stop"] == dict(
        frames=case["expected_frames"],
        calls=case["expected_calls"],
        feedback_updates=30 if case["profile"] == "blocked" else 0,
    )
    assert [e["name"] for e in r["audio_events"]].count("start") == 1
    assert [e["name"] for e in r["audio_events"]].count("stop") == 1
    assert len(r["audio_frame_returns"]) == case["expected_frames"]
    assert len(r["audio_decodes"]) == case["expected_calls"]
    assert all(x["result"] == 480 for x in r["audio_decodes"])
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
        assert any(x.get("accepted") and x["bytes"] > 0 for x in r["audio_writes"])
    assert r["module_refs"] == [0, 5]
    assert [
        (e["value"], e["phase"]) for e in r["module_events"] if "force" in e["name"]
    ] == [(5, "original_exit"), (0, "original_exit")]
    assert not {
        p for p, state in r["tasks_after_shutdown"].items() if state not in ("X", "Z")
    } - set(r["tasks_before"])
    assert any(e[0] == "join_completed" and e[2] == 0 for e in r["trace"])
    outputs = {}
    for item in case["received"]:
        raw = neg.udp.without_crc(bytes.fromhex(item["data"]))
        if raw[0] & 127 != 5 or raw[4] != 1 or raw[13] not in (4, 5):
            continue
        sequence, body = neg.decrypted(raw[14:])
        value = dict(sequence=sequence, plain=(raw[13:14] + body).hex())
        if raw[13] in outputs:
            assert outputs[raw[13]] == value
        outputs[raw[13]] = value
    assert outputs[5] == dict(sequence=1, plain="05") and outputs[4]["sequence"] == 0
    config = next(
        v
        for n, k, v in neg.fields(bytes.fromhex(outputs[4]["plain"])[1:])
        if n == 2 and k == 2
    )
    assert config == bytes.fromhex(case["settings"])
    case["outputs"] = [outputs[4], outputs[5]]
    projected = bytes.fromhex(neg.projection.platform_frame(outputs[4]["plain"]))
    case["native_projection"] = [
        dict(
            sequence=0,
            plain=projected.hex(),
            cipher=(bytes([4]) + neg.encrypted(projected[1:], 0)).hex(),
        ),
        dict(sequence=1, plain="05", cipher=(bytes([5]) + neg.encrypted(b"", 1)).hex()),
    ]


def fixed_reference(case, binary):
    """Run separate original Android codec, never replace Linux's library."""
    decoder = arm.Opus(binary, case["channels"])
    decoder.start()
    frames, observed = [], []
    decoded = []
    for event in case["process"]["audio_events"]:
        if event["name"] != "frame":
            continue
        timestamp = (event["timestamp"] + event["offset"]) & 0xFFFFFFFF
        matching = [
            pid
            for pid in range(len(case["ids"]))
            if struct.unpack_from("<I", packet(case, pid), 16)[0] == timestamp
        ]
        assert len(matching) == 1, (event, matching)
        raw = packet(case, matching[0])
        assert struct.unpack_from("<H", raw, 14)[0] == event["id"]
        payload = raw[26:]
        frames.append(dict(id=event["id"], timestamp=timestamp, payload=payload.hex()))
        decoder.feed(event["id"], timestamp, payload)
        row = decoder.snapshot()
        observed.append(row)
        decoded.extend(row["decodes"])
    linux = [
        {
            k: r[k]
            for k in ("id", "timestamp", "payload", "max_samples", "fec", "result")
        }
        for r in case["process"]["audio_decodes"]
    ]
    for r, original in zip(linux, case["process"]["audio_decodes"], strict=True):
        r["timestamp"] = (r["timestamp"] + original["offset"]) & 0xFFFFFFFF
    assert decoded == linux, (case["name"], decoded, linux)
    assert [{k: r[k] for k in ("first", "next")} for r in observed] == [
        {"first": bool(r["first"]), "next": r["next"]}
        for r in case["process"]["audio_frame_returns"]
    ]
    decoder.call(0x7B16FC, decoder.decoder)
    assert not decoder.q(decoder.decoder + 400)
    return dict(
        binary_sha256=arm.c.SHA,
        decoder_config=decoder.decoder_config,
        frames=frames,
        observed=observed,
    )


def main():
    if not __debug__:
        raise SystemExit("Assertions required")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--sdk-directory", type=Path, required=True)
    p.add_argument("--qt-library-directory", type=Path, action="append", required=True)
    p.add_argument("--android-binary", type=Path)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--snapshot", type=Path)
    p.add_argument("--only", action="append")
    a = p.parse_args()
    binary, sdk, qt = (
        a.binary.resolve(),
        a.sdk_directory.resolve(),
        [d.resolve() for d in a.qt_library_directory],
    )
    assert neg.udp.process.digest(binary) == neg.udp.process.boundary.codec.SHA
    android = a.android_binary.read_bytes() if a.android_binary else None
    if android:
        assert hashlib.sha256(android).hexdigest() == arm.c.SHA
    os.environ["SDL_AUDIODRIVER"] = "dummy"
    cases = []
    for plan in plans():
        if a.only and plan["profile"] not in a.only:
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
        with tempfile.TemporaryDirectory(prefix="source-udp-audio-") as d:
            settings = Path(d) / "streaming_settings.bin"
            settings.write_bytes(bytes.fromhex(case["settings"]))
            case["stage_file"] = str(Path(d) / "stage")
            result = neg.udp.audit(
                binary,
                sdk,
                qt,
                a.output.with_name(a.output.stem + "-" + case["name"] + ".json"),
                case,
                helper=ROOT / "scripts/steam-client-audio-gdb.py",
                reactor=Peer,
                probe_config=dict(
                    udp_helper=str(ROOT / "scripts/steam-client-udp-gdb.py"),
                    negotiation_helper=str(
                        ROOT / "scripts/steam-client-negotiation-gdb.py"
                    ),
                    settings_file=str(settings),
                    stage_file=case["stage_file"],
                    blocked=case["profile"] == "blocked",
                    expected_calls=case["expected_calls"],
                    expected_frames=case["expected_frames"],
                    require_output=case["profile"] != "blocked",
                    drop=case["profile"] == "drop",
                ),
                validate=verify,
            )
            assert settings.read_bytes() == bytes.fromhex(case["settings"])
        cases.append(result)
        if android:
            result["fixed_reference"] = fixed_reference(result, android)
        print(
            case["name"],
            len(result["process"]["audio_decodes"]),
            "codec calls, original UDP/SDL/Stop verified",
            flush=True,
        )
    functions = neg.udp.process.boundary.inventory(binary.read_bytes(), neg.FUNCTIONS)
    functions.update(
        neg.udp.process.boundary.inventory(
            binary.read_bytes(),
            {0x3252A0: "opus_start", 0x3253A0: "opus_stop", 0x3253E0: "opus_decode"},
        )
    )
    report = dict(
        scope=__doc__,
        client_sha256=neg.udp.process.digest(binary),
        archive_url="https://repo.steampowered.com/steamlink/1.3.32.316/steamlink-1.3.32.316.tgz",
        codec_sha256=neg.udp.process.digest(sdk / "libavcodec.so.61"),
        util_sha256=neg.udp.process.digest(sdk / "libavutil.so.59"),
        qt_dependency_sha256={
            name: neg.udp.process.digest(
                next(
                    d / f"libQt6{name}.so.6"
                    for d in qt
                    if (d / f"libQt6{name}.so.6").is_file()
                )
            )
            for name in ("Core", "Gui", "Widgets", "Svg")
        },
        qt_required_controller_patch=neg.udp.process.QT_PATCH,
        opus_stimulus_sha256=neg.udp.process.digest(
            ROOT / "scripts/fixtures/steam-opus-recovery-reference.json"
        ),
        source_functions=functions,
        helpers={
            name: neg.udp.process.digest(ROOT / "scripts" / name)
            for name in (
                "steam-client-audio-gdb.py",
                "steam-client-negotiation-gdb.py",
                "steam-client-udp-gdb.py",
                "steam-client-sdk-gdb.py",
                "audit-steam-client-audio-process.py",
                "audit-steam-opus-recovery.py",
            )
        },
        cases=cases,
    )
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    if a.snapshot:
        a.snapshot.write_bytes(gzip.compress(a.output.read_bytes(), mtime=0))


if __name__ == "__main__":
    main()
