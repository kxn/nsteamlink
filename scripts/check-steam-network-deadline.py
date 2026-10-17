#!/usr/bin/env python3
"""Compare native full receive/update cycles with original client deadlines.

Real native socket/clock, channel RX/TX, Disconnect and next-update retirement
execute. Application notices record the transport callback boundary; original
client OnStreamDisconnected state effects are source-only, not app equivalence.
"""

import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    a = p.parse_args()
    cases = json.loads(
        (ROOT / "scripts/fixtures/steam-network-deadline-reference.json").read_text()
    )["cases"]
    states = wires = 0
    for c in cases:
        i = c["input"]
        lines = ["A " + " ".join(map(str, row)) for row in i["seeds"]]
        lines.append(f"L {i['last_receive']} {int(i['paused'])}")
        if i["disconnect"]:
            lines.append("D")
        if i["budget"]:
            lines.append("I " + " ".join(map(str, i["budget"])))
        for v in i["cycles"]:
            lines.append(
                f"B {v['tick']} {int(v['ready'])} {int(v['blocked'])} {v['eof']} {len(v['rows'])} {v['result']} {v['write_cost']}"
            )
            lines.extend("P " + " ".join(map(str, row)) for row in v["rows"])
        r = subprocess.run(
            [
                str(a.receiver.resolve()),
                str(int(i["crc"])),
                "1",
                "-1",
                "34",
                "deadline",
            ],
            input="\n".join(lines) + "\n",
            text=True,
            capture_output=True,
            timeout=10,
        )
        assert not r.returncode, (i["name"], r.stdout, r.stderr)
        got = [json.loads(s) for s in r.stdout.splitlines()]
        assert len(got) == len(c["observed"])
        for n, (actual, want) in enumerate(zip(got, c["observed"])):
            assert actual == want, (
                i["name"],
                n,
                {
                    k: (actual.get(k), want.get(k))
                    for k in set(actual) | set(want)
                    if actual.get(k) != want.get(k)
                },
            )
            states += 1
            wires += len(actual["wires"])
    print(
        f"Network deadline: {len(cases)} official cases, {states} states, {wires} wires passed"
    )


if __name__ == "__main__":
    main()
