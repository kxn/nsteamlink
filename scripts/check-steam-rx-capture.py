#!/usr/bin/env python3
"""Replay captured OS batches/actual clock inputs against official projections.

Linux GDB and Native bounded observers change scheduling. The captured batches
and measured RTT are inputs, never a natural timing equivalence assertion. The
network replay boundary uses one real ACK for the observed Connected timestamp
sample, with an explicit outgoing seed/constructor deadline. It is not another
handshake, OS playback, host FEC policy or Switch test.
"""
import argparse
import base64
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import zlib

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


norm = module("norm", "check-steam-retry-process.py")
audio = module("audio_check", "check-steam-audio-process.py")


def budget(mean):
    return 6553 + int((mean + 2.0) * 0.5) * 65536 // 1000


def make_input(capture, crc, name):
    assert len(capture["clock"]) == 1
    sample = capture["clock"][0]
    echo, now, peer = (sample[k] for k in ("echo", "now", "peer"))
    mean = struct.unpack(
        "<f", struct.pack("<f", ((now - echo) & 0xFFFFFFFF) * (1000.0 / 65536))
    )[0]

    def batch(tick, rows=(), ready=True):
        return dict(
            tick=tick,
            rows=list(rows),
            eof=0,
            ready=ready,
            result=0,
            blocked=False,
            write_cost=0,
        )

    ack = [7, 4, 0, 0, 0, peer, struct.pack("<I", echo).hex(), 0, 0]
    cycles = [batch(echo, ready=False), batch(now, [ack])]
    ids = []
    for b in capture["batches"]:
        rows = []
        packets = [p for p in b["packets"] if bytes.fromhex(p["wire"])[4] == 3]
        if not packets:
            continue
        assert struct.pack("<f", b["mean"]) == struct.pack("<f", mean)
        for want in b.get("budgets", []):
            assert want == budget(mean)
        for i, p in enumerate(packets):
            raw = norm.without_crc(bytes.fromhex(p["wire"]))
            assert (
                bool(raw[0] & 128) == crc
                and raw[0] & 127 == 3
                and raw[4] == 3
                and len(raw) == 29
            )
            pid = struct.unpack_from("<H", raw, 7)[0]
            ids.append(pid)
            assert struct.unpack_from("<H", raw, 14)[0] == 10 + pid
            assert (
                struct.unpack_from("<I", raw, 16)[0]
                == struct.unpack_from("<I", raw, 9)[0]
            )
            assert raw[26:] == bytes.fromhex("f0fffe")
            nxt = packets[i + 1]["tick"] if i + 1 < len(packets) else b["tick"]
            work = (nxt - p["tick"]) & 0xFFFFFFFF
            assert work < 65536
            rows.append(
                [
                    3,
                    3,
                    pid,
                    raw[1],
                    0,
                    struct.unpack_from("<I", raw, 9)[0],
                    raw[13:].hex(),
                    0,
                    work,
                ]
            )
        cycles.append(batch(packets[0]["tick"], rows))
    assert ids == [0, 2, *range(3, 18)]
    return dict(
        name=name,
        crc=crc,
        constructor_tick=echo,
        seeds=[[echo, 5, 4, "aabb", 0]],
        initial_deadline=echo,
        cycles=cycles,
    )


def network_text(inp):
    lines = [f"D {inp['initial_deadline']}"]
    lines.extend("A " + " ".join(map(str, row)) for row in inp["seeds"])
    for b in inp["cycles"]:
        lines.append(
            f"B {b['tick']} {int(b['ready'])} 0 {b['eof']} {len(b['rows'])} 0 0"
        )
        lines.extend("P " + " ".join(map(str, row)) for row in b["rows"])
    return "\n".join(lines) + "\n"


def check_projection(case):
    inp = make_input(case["capture"], case["crc"], case["name"])
    assert inp == case["input"]
    delivered = [raw for state in case["observed"] for raw in state["delivered"]]
    frames = [
        dict(
            id=struct.unpack_from("<H", bytes.fromhex(raw), 1)[0],
            timestamp=struct.unpack_from("<I", bytes.fromhex(raw), 3)[0],
            payload=bytes.fromhex(raw)[13:].hex(),
        )
        for raw in delivered
    ]
    assert frames == case["decoder_reference"]["frames"]
    if case["kind"] == "linux":
        original = case["original"]
        audio.verify_source(original)
        actual = original["fixed_reference"]
        assert actual == case["decoder_reference"]
    else:
        n = case["original"]
        expected = dict(
            phase=6,
            closed=False,
            mtu=1472,
            goodbyes=0,
            receive_sequence=4,
            send_sequence=2,
            frames=case["control_projection"],
        )
        assert {k: n[k] for k in expected} == expected
        got = n["audio"]
        ref = case["decoder_reference"]
        observed = ref["observed"]
        assert got["config"] == ref["decoder_config"] and got["backend"].endswith(
            "-fixed"
        )
        assert got["frames"] == [
            dict(id=f["id"], timestamp=f["timestamp"], first=o["first"], next=o["next"])
            for f, o in zip(frames, observed, strict=True)
        ]
        assert [{k: v for k, v in d.items() if k != "pcm"} for d in got["decodes"]] == [
            d for o in observed for d in o["decodes"]
        ]
        assert got["queued"] == [d["pcm"] for d in got["decodes"]]
        valid = [s for o in observed for s in o["submitted"] if "s16_zlib_base64" in s]
        assert len(valid) == len(got["decodes"]) == 18
        for s, d in zip(valid, got["decodes"], strict=True):
            pcm = zlib.decompress(base64.b64decode(s["s16_zlib_base64"]))
            assert hashlib.sha256(pcm).hexdigest() == s[
                "s16_sha256"
            ] and pcm == bytes.fromhex(d["pcm"])
        assert got["starts"] == got["stops"] == 1 and got["played"] > 0
    return len(frames)


def main():
    if not __debug__:
        raise SystemExit("Assertions required")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    p.add_argument("--source-report", type=Path)
    a = p.parse_args()
    report = (
        json.loads(a.source_report.read_text())
        if a.source_report
        else json.loads(
            gzip.decompress(
                (
                    ROOT / "scripts/fixtures/steam-rx-capture-reference.json.gz"
                ).read_bytes()
            )
        )
    )
    assert (
        report["client_sha256"] == audio.CLIENT_SHA
        and report["android_sha256"] == audio.ANDROID_SHA
    )
    assert {(c["kind"], c["crc"]) for c in report["cases"]} == {
        (kind, crc) for kind in ("linux", "native") for crc in (False, True)
    } and len(report["cases"]) == 4
    for name, sha in report["helpers"].items():
        assert hashlib.sha256((ROOT / "scripts" / name).read_bytes()).hexdigest() == sha
    previous = json.loads(
        (ROOT / "scripts/fixtures/steam-network-cycle-reference.json").read_text()
    )
    assert report["android_functions"] == previous["functions"]
    process = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-client-audio-process-reference.json.gz"
            ).read_bytes()
        )
    )
    assert len(report["source_functions"]) == 43 and len(report["helpers"]) == 12
    for name, address, size, sha in (
        (
            "socket_update",
            0x1A0760,
            361,
            "ee9f948d128fb5553199e4357d86b3838b19e6af66c2612233da9354db92998c",
        ),
        (
            "socket_handle",
            0x1A0500,
            604,
            "613dbfbb9044c77a8a2b65348e8281aef8190dd76ab1a2d47e77aa595ab51dc8",
        ),
        (
            "process_timestamp",
            0x19B0A0,
            389,
            "18ed42a04dea648b9f5b69c693c7fc1be23df5b405c4ac5334a4562bab31a04a",
        ),
        (
            "unreliable_update",
            0x19C010,
            2382,
            "13c19d9323ffdfed2f29a9d2055a1f6795edadf1404974856eb47aabc6830340",
        ),
        (
            "receive_rtt_budget",
            0x1997E0,
            21,
            "c53c9c07abf1d50a0e85da66fc0c46c6fba1ae81a56e8d4bc67eab2d254839fb",
        ),
    ):
        assert report["source_functions"][name] == dict(
            address=address, size=size, sha256=sha
        )
    assert {
        k: report["source_functions"][k] for k in process["source_functions"]
    } == process["source_functions"]
    for key in (
        "codec_sha256",
        "util_sha256",
        "qt_dependency_sha256",
        "qt_required_controller_patch",
    ):
        assert report[key] == process[key]
    assert len(report["counterfactuals"]) == 2
    for c in report["counterfactuals"]:
        assert not c["source_assertions"]
        ids = [
            struct.unpack_from("<H", bytes.fromhex(v), 1)[0]
            for state in c["observed"]
            for v in state["delivered"]
        ]
        original = next(
            x for x in report["cases"] if "low_rtt_" + x["name"] == c["input"]["name"]
        )
        assert ids != [f["id"] for f in original["decoder_reference"]["frames"]]
    frames = 0
    for case in report["cases"] + [
        {**c, "name": c["input"]["name"], "crc": c["input"]["crc"]}
        for c in report["counterfactuals"]
    ]:
        if "capture" in case:
            frames += check_projection(case)
        r = subprocess.run(
            [
                str(a.receiver.resolve()),
                str(int(case["crc"])),
                "1",
                "-1",
                "34",
                "network",
            ],
            input=network_text(case["input"]),
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert r.returncode == 0, (case["name"], r.returncode, r.stderr)
        actual = [json.loads(row) for row in r.stdout.splitlines()]
        assert actual == case["observed"], (
            case["name"],
            [
                (
                    i,
                    {
                        k: (x.get(k), y.get(k))
                        for k in set(x) | set(y)
                        if x.get(k) != y.get(k)
                    },
                )
                for i, (x, y) in enumerate(zip(actual, case["observed"]))
                if x != y
            ],
        )
    print(
        f"Captured actual UDP: 4 clock/batch projections, {frames} frames, full Native network replay matched"
    )


if __name__ == "__main__":
    main()
