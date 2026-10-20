#!/usr/bin/env python3
"""Compare actual complete-frame RX shared mark effects with the official client.

Native runs dispatcher/RX preparation, mark creation, independent media slots,
video completion/report/protobuf/admission. Terminal decoder enqueue and clock
are controlled; neither OS decoder workers nor physical input producers run.
"""

import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def slot(value):
    if value is None:
        return None
    return {
        **{k: v for k, v in value.items() if k != "extra"},
        "deltas": value["extra"][:16],
    }


def check(receiver, source):
    states, bodies, coverage = 0, 0, set()
    for case in source["cases"]:
        r = subprocess.run(
            [
                str(receiver.resolve()),
                str(int(case["full"])),
                str(case["offset"]),
                *map(str, case["ids"]),
            ],
            input="\n".join(" ".join(map(str, a)) for a in case["actions"]) + "\n",
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert not r.returncode, (case["name"], r.stdout[-2000:], r.stderr[-2000:])
        rows = [json.loads(line) for line in r.stdout.splitlines()]
        assert len(rows) == len(case["observed"])
        for index, (want, got) in enumerate(zip(case["observed"], rows, strict=True)):
            assert not want["assertions"], (case["name"], index, want["assertions"])
            expected = dict(
                audio_slots=[slot(v) for v in want["audio_slots"]],
                video={
                    **want["video"],
                    "slots": [slot(v) for v in want["video"]["slots"]],
                },
                marks=want["marks"],
                frames=want["frames"],
                video_samples=want["pcs"].get("video_network_sample", 0),
                admitted=want["pcs"].get("rx_prepared", 0),
            )
            assert got == expected, (
                case["name"],
                index,
                case["actions"][index],
                {
                    k: (got.get(k), expected.get(k))
                    for k in got.keys() | expected.keys()
                    if got.get(k) != expected.get(k)
                },
            )
            coverage.update(want["pcs"])
            states += 1
            bodies += len(want["frames"])
    assert {
        "new_slot",
        "same_id",
        "bind_mark",
        "consume_mark",
        "video_network_sample",
    } <= coverage
    print(
        f"Official shared media input: {len(source['cases'])} cases/{states} RX/stat states, "
        f"{bodies} complete report bodies; independent slots/shared marks and actual video sampler calls exact"
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    p.add_argument(
        "--reference",
        type=Path,
        default=ROOT / "scripts/fixtures/steam-media-input-reference.json",
    )
    a = p.parse_args()
    check(a.receiver, json.loads(a.reference.read_text()))


if __name__ == "__main__":
    main()
