#!/usr/bin/env python3
"""Compare native float jitter state/ring/output against original ARM64 evidence.

The oracle calls the native module directly, with serialized operations and the
same host libm boundary. Source 'play' actions additionally execute original
CStreamPlayer::PlayAudio at volume 1; native device wiring is not proved here.
"""

import argparse
import base64
import hashlib
import struct
import zlib
import gzip
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def check(receiver, source):
    steps = 0
    for case in source["cases"]:
        result = subprocess.run(
            [str(receiver.resolve()), str(case["frequency"]), str(case["channels"])],
            input="\n".join(" ".join(map(str, a)) for a in case["actions"]) + "\n",
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert not result.returncode, (case["name"], result.stderr[-2000:])
        got = json.loads(result.stdout)
        assert got["params"] == case["params"], (
            case["name"],
            got["params"],
            case["params"],
        )
        assert got["table_sha256"] == case["table"]["sha256"], case["name"]
        assert len(got["observed"]) == len(case["observed"])
        for index, (want, actual) in enumerate(
            zip(case["observed"], got["observed"], strict=True)
        ):
            label = (case["name"], index, case["actions"][index])
            assert actual["result"] == want["result"], (
                label,
                actual["result"],
                want["result"],
            )
            for key, value in actual["state"].items():
                assert value == want["state"][key], (
                    label,
                    key,
                    value,
                    want["state"][key],
                )
            assert actual["output_sha256"] == want["output"]["sha256"], (
                label,
                "PCM mismatch",
            )
            steps += 1
    print(
        f"official audio jitter: {len(source['cases'])} cases/{steps} steps; "
        "exact scalar/float bits, ring and output; serialized host-libm boundary"
    )


def playback(receiver, source):
    count, steps = 0, 0
    for case in source["cases"]:
        if case["frequency"] == 44100 or case["channels"] > 2:
            continue  # Existing production rate admission is a separate contract.
        result = subprocess.run(
            [str(receiver.resolve()), str(case["frequency"]), str(case["channels"])],
            input="\n".join(" ".join(map(str, a)) for a in case["actions"]) + "\n",
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert not result.returncode, (case["name"], result.stderr[-2000:])
        rows = json.loads(result.stdout)
        assert len(rows) == len(case["actions"])
        for index, (action, want, got) in enumerate(
            zip(case["actions"], case["observed"], rows, strict=True)
        ):
            raw = zlib.decompress(base64.b64decode(want["output"]["zlib_base64"]))
            values = struct.unpack("<" + "f" * (len(raw) // 4), raw)
            pcm = struct.pack(
                "<" + "h" * len(values),
                *(max(-32768, min(32767, round(v * 32768))) for v in values),
            )
            if action[0] != "push":
                pcm += bytes(action[1] * case["channels"] * 2 - len(pcm))
            expected = dict(
                queued=want["state"]["queued"] * case["channels"] * 2,
                dropped=want["state"]["dropped"],
                pcm_sha256=hashlib.sha256(pcm).hexdigest(),
            )
            assert got == expected, (case["name"], index, action, got, expected)
            steps += 1
        count += 1
    result = subprocess.run(
        [str(receiver.resolve()), "48000", "2", "live"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert not result.returncode, result.stderr[-2000:]
    live = json.loads(result.stdout)
    assert live["launches"] == 3 and live["callbacks"] >= 9
    print(
        f"production SDL callback: {count} official schedules/{steps} steps exact S16/zero tail and occupancy; "
        f"3 live dummy start-stop cycles/{live['callbacks']} callbacks joined"
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    p.add_argument(
        "--reference",
        type=Path,
        default=ROOT / "scripts/fixtures/steam-audio-jitter-reference.json.gz",
    )
    p.add_argument("--playback", action="store_true")
    a = p.parse_args()
    opener = gzip.open if a.reference.suffix == ".gz" else open
    with opener(a.reference, "rt") as f:
        (playback if a.playback else check)(a.receiver, json.load(f))


if __name__ == "__main__":
    main()
