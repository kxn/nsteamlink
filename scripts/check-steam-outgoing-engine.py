#!/usr/bin/env python3
"""Compare production outgoing cache, socket budget and send phases with Android.

Receive-update callbacks and private reliable-window metadata are excluded. Wire
bytes, unreliable window state, both budgets, blocking and rotation are compared.
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
    cases = json.loads(
        (ROOT / "scripts/fixtures/steam-outgoing-reference.json").read_text()
    )["cases"]
    count = 0
    for case in cases:
        inp, group = case["input"], case["group"]
        commands = []

        def init(rate=0, deadline=1000000, transport=0):
            commands.append(f"INIT 1000000 {rate} {deadline} {transport}")

        def channel(ch=1, priority=0, head=100, cursor=None):
            commands.append(
                f"CH {ch} {priority} {head} {head if cursor is None else cursor}"
            )

        def packet(ch, ident, reliable, n, stamp, created):
            commands.append(
                f"PK {5 if reliable else 3} {ch} {ident} {n} {stamp} {created}"
            )

        def send(reliable, ch=1, retry=False):
            commands.append(f"SENDR {ch}" if reliable else f"SENDU {ch} {int(retry)}")

        if group in ("rto", "failure"):
            continue  # Separate exact RTO oracle covers these 50 scenarios.
        if group == "factory":
            init()
            for ch in inp["requests"]:
                commands.append(f"GET {ch}")
        elif group == "sort":
            init()
            for ch, priority in enumerate(inp["priorities"]):
                channel(ch, priority)
            commands.append("UPDATE")
        elif group == "sender":
            init(65536, 1000000 + inp["deadline_offset"], inp["transport"])
            channel()
            for i, (n, stamp, created) in enumerate(inp["packets"]):
                packet(1, 100 + i, inp["reliable"], n, stamp, created)
            send(inp["reliable"])
            commands.append("TIME 1000001 0")
            send(inp["reliable"])
        elif group == "retention":
            init()
            head = inp["head"]
            channel(head=head, cursor=(head + 1) & 65535)
            created = 1000000 - inp["age"]
            packet(1, head, False, 1, 0 if inp["marked"] else created, created)
            send(False, retry=inp["retry_phase"])
        elif group == "nack":
            init()
            head = inp["head"]
            channel(head=head, cursor=(head + 4) & 65535)
            for i in range(4):
                packet(1, (head + i) & 65535, False, 1, 999000, 999000)
            bitmap = "none" if inp["bitmap"] is None else inp["bitmap"] or "empty"
            commands.append(
                f"NACK 1 {(head + inp.get('base_offset', 1)) & 65535} 1000000 {inp['echo_age']} {bitmap}"
            )
            send(False)
            send(False, retry=True)
        elif group == "nack_sequence":
            init()
            channel(cursor=104)
            for i in range(4):
                packet(1, 100 + i, False, 1, 999000, 999000)
            commands.append(
                f"NACKRAW 1 100 {inp['first_stamp']} {inp['first_body'] or 'empty'}"
            )
            commands.append(f"NACKRAW 1 101 {inp['second_stamp']} empty")
            send(False, retry=True)
        elif group == "priority_reset":
            init()
            for ch, priority in inp["entries"]:
                channel(ch, priority)
                packet(ch, 100, True, 0, 1000000, 1000000)
            commands.append("UPDATE")
            for ch, _ in inp["entries"]:
                commands.append(f"PRIO {ch} 0")
            commands.extend(["TIME 1000126 0", "UPDATE"])
        elif group == "connection":
            init(deadline=1000001 if inp["blocked"] else 1000000)
            for ch, priority in zip((2, 3, 1), inp["priorities"]):
                channel(ch, priority, cursor=101)
                packet(ch, 100, True, 0, 1000000, 1000000)
                packet(ch, 100, False, 1, 0, 1000000)
            for i in range(5):
                commands.extend([f"TIME {1000000 + i} 0", "UPDATE"])
        else:
            raise AssertionError(group)
        result = subprocess.run(
            [str(args.receiver.resolve())],
            input="\n".join(commands) + "\n",
            text=True,
            capture_output=True,
            timeout=10,
        )
        assert result.returncode == 0, (case["case"], result.stderr)
        actual = [json.loads(line) for line in result.stdout.splitlines()]
        expected = (
            case["observed"]
            if isinstance(case["observed"], list)
            else [case["observed"]]
        )
        assert len(actual) == len(expected), (case["case"], actual)
        for got, wanted in zip(actual, expected):
            if group in ("sort", "factory"):
                assert got["order"] == wanted["order"], (
                    case["case"],
                    got["order"],
                    wanted["order"],
                )
                continue
            for field in (
                "sent",
                "unreliable_deadline",
                "reliable_deadline",
                "blocked",
                "rotation",
            ):
                assert got[field] == wanted[field], (
                    case["case"],
                    field,
                    got[field],
                    wanted[field],
                )
            for w in wanted["windows"]:
                if w["reliable"]:
                    continue
                g = next(x for x in got["windows"] if x["channel"] == w["channel"])
                for field in ("head", "tail", "cursor"):
                    assert g[field] == w[field], (case["case"], field, g, w)
                for p in w["packets"]:
                    q = next(x for x in g["packets"] if x["id"] == p["id"])
                    assert q["retained"] == p["retained"], (case["case"], q, p)
                    if p["retained"]:
                        assert q == p, (case["case"], q, p)
            if (
                group in ("retention", "nack", "nack_sequence")
                or group == "sender"
                and not inp["reliable"]
            ):
                assert got["result"] == wanted["result"] if "result" in wanted else True
        count += 1
    assert count == 149
    print(f"Production outgoing engine: {count} original-reference scenarios passed")


if __name__ == "__main__":
    main()
