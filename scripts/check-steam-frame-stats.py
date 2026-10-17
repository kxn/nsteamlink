#!/usr/bin/env python3
"""Compare native video ring and detail Save with original-client execution.

Each R/E/C/S entry compares the full visible slot and cursor state. Full reports
also compare each CFrameStats row byte-for-byte with original C++ serialization.
The source's accumulator/network rows, packet send, OnThink cadence, tracked
ticket path and audio report suppression are NOT claimed by this harness.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "wire", ROOT / "scripts/check-steam-negotiation.py"
)
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    a = p.parse_args()
    fixture = json.loads(
        (ROOT / "scripts/fixtures/steam-frame-stats-reference.json").read_text()
    )
    checked = stages = details = audio = 0
    for index, case in enumerate(fixture["cases"]):
        inp = case["input"]
        if inp.get("type", 1) == 0:
            audio += 1
            continue
        commands = []
        for action in inp["actions"]:
            if action[0] in ("R", "P"):
                args = dict(
                    fid=0,
                    frame_start=900000,
                    sent=901000,
                    received=902000,
                    size=100,
                    input_mark=0,
                    input_received=0,
                )
                if isinstance(action[1], dict):
                    args.update(action[1])
                else:
                    args.update(
                        zip(
                            ("fid", "frame_start", "sent", "received", "size"),
                            action[1:],
                        )
                    )
                if action[0] == "P":
                    for key in ("frame_start", "sent", "input_received"):
                        if key != "input_received" or args[key]:
                            args[key] = (args[key] - inp["offset"]) & 0xFFFFFFFF
                commands.append("R " + " ".join(map(str, args.values())))
            else:
                commands.append(" ".join(map(str, action)))
        r = subprocess.run(
            [
                str(a.receiver.resolve()),
                str(int(inp["full"])),
                str(inp["offset"]),
                str(inp.get("watermark", 0)),
                *map(str, inp["ids"]),
            ],
            input="\n".join(commands) + "\n",
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert r.returncode == 0, (index, inp, r.stdout, r.stderr)
        actual = [json.loads(line) for line in r.stdout.splitlines()]
        assert len(actual) == len(case["observed"])
        for n, (got, original) in enumerate(zip(actual, case["observed"])):
            want = {
                key: original[key]
                for key in (
                    "last_frame",
                    "last_display",
                    "displayed",
                    "reported",
                    "slots",
                )
            }
            want["slots"] = [
                None
                if s is None
                else {
                    **{k: v for k, v in s.items() if k != "extra"},
                    "deltas": s["extra"][:16],
                }
                for s in want["slots"]
            ]
            want["details"] = []
            for frame in original["frames"]:
                raw = bytes.fromhex(frame)
                assert raw[0] == 1
                want["details"] += [
                    v.hex() for k, t, v, _ in wire.fields(raw[1:]) if k == 2 and t == 2
                ]
            assert got == want, (index, inp["case"], n, inp["actions"][n], got, want)
            details += len(want["details"])
            stages += 1
        checked += 1
    print(
        f"Video ring/detail Save: {checked} original-client cases, {stages} states, {details} rows passed; {audio} audio case source-only"
    )


if __name__ == "__main__":
    main()
