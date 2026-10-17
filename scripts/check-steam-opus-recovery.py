#!/usr/bin/env python3
"""Compare real audio worker/app decoder/SDL output with official Opus policy.

The native complete-frame dispatcher and FIFO carry IDs/local timestamps into
the new callback. Wrappers record actual recovery steps and real libopus calls.
Negative codec output is deliberately discarded instead of copying the source
client's unsafe submit/Resize. Valid PCM is compared after float->S16 observation
conversion, requiring exact S16 bytes with the project's fixed-point codec. This does
not claim jitter-buffer, transport or device output equivalence.
"""

import argparse
import base64
import json
from pathlib import Path
import struct
import subprocess
import zlib

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    a = p.parse_args()
    source = json.loads(
        (ROOT / "scripts/fixtures/steam-opus-recovery-reference.json").read_text()
    )
    count, callbacks, decodes, pcm_count, peak_error = 0, 0, 0, 0, 0
    for case in source["cases"]:
        if case.get("source_only"):
            continue
        text = "\n".join(" ".join(map(str, row)) for row in case["actions"]) + "\n"
        r = subprocess.run(
            [str(a.receiver.resolve()), str(case["channels"])],
            input=text,
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert not r.returncode, (case["name"], r.stdout[-1000:], r.stderr[-1000:])
        states = json.loads(r.stdout)
        assert len(states) == len(case["observed"])
        for action, want, got in zip(
            case["actions"], case["observed"], states, strict=True
        ):
            assert got["config"] == case["decoder_config"]
            assert got["backend"].endswith("-fixed"), got["backend"]
            assert (want["first"], want["next"]) == (got["first"], got["next"])
            assert want["decodes"] == got["decodes"], (
                case["name"],
                action,
                want["decodes"],
                got["decodes"],
            )
            decodes += len(got["decodes"])
            if action[0] == "F":
                assert got["info"] == action[1:3], (case["name"], action, got["info"])
                callbacks += 1
            valid = [v for v in want["submitted"] if "s16_zlib_base64" in v]
            assert len(valid) == len(got["submitted"]), (
                case["name"],
                action,
                want,
                got,
            )
            for expected, actual in zip(valid, got["submitted"], strict=True):
                assert [expected[k] for k in ("id", "timestamp")] == [
                    actual[k] for k in ("id", "timestamp")
                ]
                raw = zlib.decompress(base64.b64decode(expected["s16_zlib_base64"]))
                pcm = bytes.fromhex(actual["pcm"])
                assert len(pcm) * 2 == expected["size"] and len(raw) == len(pcm)
                lhs = struct.unpack("<" + "h" * (len(raw) // 2), raw)
                rhs = struct.unpack("<" + "h" * (len(pcm) // 2), pcm)
                error = max(
                    (abs(x - y) for x, y in zip(lhs, rhs, strict=True)), default=0
                )
                assert raw == pcm, (case["name"], action, error)
                peak_error = max(peak_error, error)
                pcm_count += 1
        count += 1
    # Legacy source callers still receive encoded payloads through submit only.
    r = subprocess.run(
        [str(a.receiver.resolve()), "2", "legacy"],
        input="F 10 1100000 f0fffe\nF 12 1101000 f0fffe\n",
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert not r.returncode, (r.stdout, r.stderr)
    old = json.loads(r.stdout)
    assert all(len(s["decodes"]) == 1 and not s["decodes"][0]["fec"] for s in old)
    r = subprocess.run(
        [str(a.receiver.resolve()), "2"],
        input="F 10 1100000 ff\n",
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert not r.returncode, (r.stdout, r.stderr)
    invalid = json.loads(r.stdout)[0]
    original = next(c for c in source["cases"] if c["name"] == "invalid")["observed"][0]
    assert invalid["decodes"] == original["decodes"] and not invalid["submitted"]
    r = subprocess.run(
        [str(a.receiver.resolve()), "2", "guard"],
        input="F 0 1100000 f0fffe\nF 100 1101000 f0fffe\n",
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert not r.returncode, (r.stdout, r.stderr)
    bounded = json.loads(r.stdout)
    assert bounded["frames"] == 101 and not bounded["errors"] and bounded["drops"] > 0
    assert bounded["queued"] <= 48000 * 2 * 2 * 300 // 1000 + 5760 * 2 * 2
    print(
        f"Production Opus: {count} source schedules, {callbacks} metadata callbacks, {decodes} exact codec calls, {pcm_count} PCM outputs, max S16 error={peak_error}; legacy/invalid-output/local queue-bound processes passed"
    )


if __name__ == "__main__":
    main()
