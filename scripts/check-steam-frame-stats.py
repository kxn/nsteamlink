#!/usr/bin/env python3
"""Compare native ring and complete frame-stat producer body with original client.

Each R/E/C/S entry compares the full visible slot and cursor state. Full reports
also compare each CFrameStats row byte-for-byte with original C++ serialization.
The actual native report consumer, float accumulator, protobuf and StatsSend
run to frame admission. Network collector scalars and final admission results
are controlled, matching the source adapters. Tracked modes exercise real ticket
stages/completion/collection; batched mode checks only flush boundaries without
intermediate observational collection. OnThink cadence, decoder/GPU, metric
collector windows, Socket and audio suppression are excluded.
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


def signed(value):
    return (value + 2**31) % 2**32 - 2**31


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    p.add_argument("--tracked", action="store_true")
    p.add_argument("--batched", action="store_true")
    a = p.parse_args()
    a.tracked = a.tracked or a.batched
    fixture = json.loads(
        (ROOT / "scripts/fixtures/steam-frame-stats-reference.json").read_text()
    )
    checked = stages = details = reports = audio = pending_only = 0
    for index, case in enumerate(fixture["cases"]):
        inp = case["input"]
        if inp.get("type", 1) == 0:
            audio += 1
            continue
        if a.tracked and any(x[0] == "C" and x[2] == 0 for x in inp["actions"]):
            pending_only += 1  # Only direct primitive accepts result Pending; ticket API rejects it.
            continue
        commands = []
        if "network" in inp:
            n = inp["network"]
            commands.append(
                "N "
                + " ".join(
                    map(
                        str,
                        (
                            n["ping"],
                            n["server"],
                            n["client"],
                            n["link"],
                            signed(n["total"]),
                            signed(n["lost"]),
                        ),
                    )
                )
            )
        commands.append("F " + str(int(inp.get("send_result", 0) != 0)))
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
                *(["tracked-batched" if a.batched else "tracked"] if a.tracked else []),
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
            if a.batched and inp["actions"][n][0] != "S":
                continue  # Inspect only flush boundaries; no observational intermediate collection.
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
            want["frames"] = original["frames"]
            for frame in original["frames"]:
                raw = bytes.fromhex(frame)
                assert raw[0] == 1
                want["details"] += [
                    v.hex() for k, t, v, _ in wire.fields(raw[1:]) if k == 2 and t == 2
                ]
            assert got == want, (index, inp["case"], n, inp["actions"][n], got, want)
            details += len(want["details"])
            reports += len(want["frames"])
            stages += 1
        checked += 1
    print(
        f"Production {'batched tracked' if a.batched else 'tracked' if a.tracked else 'legacy'} frame stats: {checked} original-client cases, {stages} states, {reports} complete bodies, {details} detail rows passed; {audio} audio source-only; {pending_only} Pending-primitive cases excluded from ticket path"
    )


if __name__ == "__main__":
    main()
