#!/usr/bin/env python3
"""Compare real native RX/stage/sender with the original client negotiation chain.

The 39 OnThink cases compare phase, full copied config, control frames, encryption
sequence, connected notification, priority-setter results and KeepAlive timestamp.
Network/transport adapters, log/lock calls, stats internals and frame-event timing
are explicit exclusions, not normalized into successful comparisons. The peer
entry's 22 state4 cases also compare before stage advancement; its direct state5/6
cases are not replayed as admissible messages (the real dispatcher rejects them).
Encrypted frame producer bodies are always compared; wire output is additionally
checked where synthetic tick jumps do not exceed the signed half-domain. Source
Connection/shaper/Socket internals are adapters in these particular references.
"""

import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def run(receiver, state, crc, initial, commands, tick=1000000):
    r = subprocess.run(
        [str(receiver.resolve()), str(state), str(crc), initial, str(tick)],
        input="\n".join(commands) + "\n",
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert r.returncode == 0, (state, crc, commands, r.stdout, r.stderr)
    return [json.loads(line) for line in r.stdout.splitlines()]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    a = p.parse_args()
    loop = json.loads(
        (ROOT / "scripts/fixtures/steam-negotiation-loop-reference.json").read_text()
    )
    peer = json.loads(
        (ROOT / "scripts/fixtures/steam-peer-negotiation-reference.json").read_text()
    )
    count = 0
    for crc in (0, 1):
        for c in loop["cases"]:
            i = c["input"]
            commands = ["RX " + (body or "-") for body in i["packets"]]
            commands += [f"UPDATE {s['tick']}" for s in c["observed"]]
            actual = run(
                a.receiver,
                i["state"],
                crc,
                "080110031804",
                commands,
                tick=c["observed"][0]["tick"],
            )
            assert len(actual) == len(c["observed"])
            prior = c["observed"][0]["tick"]
            for n, (got, want) in enumerate(zip(actual, c["observed"])):
                # At synthetic half-domain jumps the shaper can block UDP.
                # Source captures Connection::Send entry, not its shaper/Socket.
                if ((want["tick"] - prior) & 0xFFFFFFFF) < 0x80000000:
                    assert got["wire_frames"] == got["frames"], (count, n, got)
                prior = want["tick"]
                for key in ("state", "config", "frames", "sequence", "keepalive_time"):
                    assert got[key] == want[key], (count, n, key, got, want)
                assert got["connected"] == want["events"].count("player_started"), (
                    count,
                    n,
                    got,
                    want,
                )
                assert got["client_config"] == ""
                if any(isinstance(e, dict) and "priority" in e for e in want["events"]):
                    assert got["priorities"] == [2, -1], (count, n, got)
            count += 1
        for c in peer["cases"]:
            i = c["input"]
            if i["state"] != 4:
                continue
            actual = run(
                a.receiver,
                4,
                crc,
                "08011003180428013001",
                ["RX " + (i["body"] or "-"), "DRAIN", "UPDATE 123456"],
                tick=123456,
            )
            assert len(actual) == 2
            assert all(got["wire_frames"] == got["frames"] for got in actual)
            got, want = actual[0], c["after_peer"]
            for key in ("state", "config", "frames", "client_config"):
                assert got[key] == want[key], (count, key, got, want)
            assert got["connected"] == 0 and got["sequence"] == 0
            got, want = actual[1], c["after_start"]
            for key in ("state", "frames", "sequence"):
                assert got[key] == want[key], (count, key, got, want)
            assert got["keepalive_time"] == want["timestamp2"], (count, got, want)
            assert got["connected"] == want["events"].count("player_started")
            assert got["config"] == c["after_peer"]["config"]
            count += 1
    print(
        f"Production RX/negotiation stages: {count} original comparisons passed (CRC off/on)"
    )


if __name__ == "__main__":
    main()
