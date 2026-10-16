#!/usr/bin/env python3
"""Compare production transport shutdown with fixed official client instructions.

Client-level cases compare the transport projection only; decoder/device/stats
consumers and the project's application notification have separate contracts.
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
        (ROOT / "scripts/fixtures/steam-disconnect-reference.json").read_text()
    )
    checked = 0
    for case in fixture["cases"]:
        group, inp, expected = case["group"], case["input"], case["observed"]
        if group == "udp_init":
            continue  # syscall trace proves official setup, not native IPv6/BWait equivalence
        if group == "udp_send":
            tag = ["OK", "EAGAIN", "EMSGSIZE", "EBADF", "EIO", "EINTR"].index(
                inp["errno_name"]
            )
            run = subprocess.run(
                [str(args.receiver.resolve()), "1", str(int(inp["crc"])), "0"],
                input=f"UDP {tag}\n",
                text=True,
                capture_output=True,
                timeout=10,
            )
            assert run.returncode == 0, (case["case"], run.stderr)
            assert json.loads(run.stdout) == expected, (
                case["case"],
                run.stdout,
                expected,
            )
            checked += 1
            continue
        if group == "connection_ids":
            run = subprocess.run(
                [
                    str(args.receiver.resolve()),
                    "IDS",
                    str(inp["warmup"]),
                    str(inp["count"]),
                    *map(str, inp["random"]),
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert run.returncode == 0, (case["case"], run.stderr)
            actual = json.loads(run.stdout)
            assert actual["ids"] == expected["ids"], (case["case"], actual, expected)
            if inp["prior"] == 0:
                assert actual["random_calls"] == len(expected["random_calls"])
            checked += 1
            continue
        state, crc, result = inp["state"], inp.get("crc", True), inp.get("result", 0)
        if group == "disconnect":
            commands = ["DISCONNECT", "DISCONNECT", "UPDATE 1000001", "UPDATE 1065536"]
        elif group == "close":
            commands = ["CLOSE", "CLOSE", "UPDATE 1000001"]
        elif group == "client_disconnect":
            commands = ["CLIENT", "UPDATE 1000001"]
        elif group == "peer_disconnect":
            now = 1000000 + inp.get("delay", 0)
            commands = [
                f"WIRE {now} {int(inp['mode'] != 'bad_address')} {inp['datagram']}",
                f"UPDATE {now + 1}",
            ]
        elif group == "terminal_timeout":
            commands = [
                "CLOSE" if inp["close"] else "DISCONNECT",
                "UPDATE 1000001",
                "UPDATE 2000000",
            ]
        else:
            raise AssertionError(group)
        run = subprocess.run(
            [str(args.receiver.resolve()), str(state), str(int(crc)), str(result)],
            input="\n".join(commands) + "\n",
            text=True,
            capture_output=True,
            timeout=10,
        )
        assert run.returncode == 0, (case["case"], run.stderr)
        actual = [json.loads(line) for line in run.stdout.splitlines()]
        if group == "terminal_timeout":
            actual = actual[-2:]
        assert len(actual) == len(expected)
        for got, want in zip(actual, expected):
            want = dict(want)
            want.pop("client_state")  # application auth/UI state is a separate layer
            want["actions"] = [
                a for a in want["actions"] if a["action"] in ("send", "closed")
            ]
            notices = got.pop("app_notices")
            assert notices == int(group == "client_disconnect")
            assert got == want, (case["case"], got, want)
        checked += 1
    assert checked == 136
    print(
        f"Production shutdown: {checked} official-reference transport scenarios passed"
    )


if __name__ == "__main__":
    main()
