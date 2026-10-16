#!/usr/bin/env python3
"""Compare production Connect wire bytes and retry/stop/timeout actions.

Disconnect's later cleanup/delegate is outside this comparison. The native
oracle runs full ingress for Connected; the official reference starts at the
already stripped HandleConnected boundary.
"""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", type=Path, required=True)
    args = parser.parse_args()
    fixture = json.loads(
        (ROOT / "scripts/fixtures/steam-connect-reference.json").read_text()
    )
    checked = 0
    for case in fixture["cases"]:
        group, inp, expected = case["group"], case["input"], case["observed"]
        if group == "disconnect":
            continue
        commands = [f"START {inp.get('start', 1000000)} {inp.get('result', 0)}"]
        if group == "retry":
            commands += [f"UPDATE {now}" for now in inp["updates"]]
        elif group == "connected":
            commands += [
                "UPDATE 1000000",
                f"CONNECTED {inp['size']} {int(inp['crc'])}",
                "UPDATE 1006553",
            ]
        elif group == "timeout":
            commands += [f"PAUSE {int(inp['paused'])}", f"UPDATE {inp['now']}"]
            expected = expected[:1]  # actual disconnect cleanup is a separate contract
        elif group == "late_connected":
            commands += [
                f"UPDATE {1000000 + 15 * 65536}",
                f"CONNECTED 4 {int(inp['crc'])}",
            ]
        else:
            raise AssertionError(group)
        run = subprocess.run(
            [str(args.receiver.resolve())],
            input="\n".join(commands) + "\n",
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert run.returncode == 0, (case["case"], run.stderr)
        actual = [json.loads(line) for line in run.stdout.splitlines()]
        actual = actual if group == "retry" else actual[-len(expected) :]
        assert len(actual) == len(expected)
        for got, want in zip(actual, expected):
            outstanding = got.pop("reliable_outstanding")
            if group != "connected" or inp["size"] != 4:
                assert outstanding == 0, (
                    case["case"],
                    "Connect entered reliable window",
                )
            assert got == want, (case["case"], got, want)
        checked += 1
    assert checked == 23
    print(f"Production Connect: {checked} official-reference scenarios passed")


if __name__ == "__main__":
    main()
