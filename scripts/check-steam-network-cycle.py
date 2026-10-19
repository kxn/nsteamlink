#!/usr/bin/env python3
"""Compare complete controlled network cycles with official client instructions.

Native initial queue admission/dispatch, CRC RX, clock and collectors, receive
feedback and periodic outgoing paths execute; OS I/O and consumer are controlled.
This is not a global-thread, real Steam session, FEC activation or decoder test.
"""

import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    if not __debug__:
        raise SystemExit("Assertions required")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    p.add_argument("--adaptive-only", action="store_true")
    a = p.parse_args()
    source = json.loads(
        (ROOT / "scripts/fixtures/steam-network-cycle-reference.json").read_text()
    )
    assert (
        source["binary_sha256"]
        == "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"
    )
    cases = source["cases"]
    if a.adaptive_only:
        cases = [c for c in cases if c["input"]["name"].startswith("adaptive_")]
        assert len(cases) == 40
    states = wires = 0
    for c in cases:
        i = c["input"]
        lines = []
        if "initial_deadline" in i:
            lines.append(f"D {i['initial_deadline']}")
        lines.extend("A " + " ".join(map(str, row)) for row in i["seeds"])
        lines.extend(f"Q {ch} {priority}" for ch, priority in i.get("priorities", []))
        if "budget" in i:
            lines.append("I " + " ".join(map(str, i["budget"])))
        for v in i["cycles"]:
            lines.append(
                f"B {v['tick']} {int(v['ready'])} {int(v['blocked'])} {v['eof']} {len(v['rows'])} {v['result']} {v['write_cost']}"
            )
            lines.extend("P " + " ".join(map(str, row)) for row in v["rows"])
        r = subprocess.run(
            [str(a.receiver.resolve()), str(int(i["crc"])), "1", "-1", "34", "network"],
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
        f"Network cycle: {len(cases)} official cases, {states} states, {wires} wires passed"
    )


if __name__ == "__main__":
    main()
