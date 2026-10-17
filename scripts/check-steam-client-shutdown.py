#!/usr/bin/env python3
"""Compare full controlled client shutdown against pinned official instructions.

Real native CRC ingress/reliable/control crypto/FIFO/config, phase retirement,
stopping/removal and app callback execute. IO, decoder/input terminal bodies,
Streaming stage body and next ID are controlled; Source stats hooks stay separate.
"""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    a = p.parse_args()
    cases = json.loads(
        (ROOT / "scripts/fixtures/steam-client-shutdown-reference.json").read_text()
    )["cases"]
    states = 0
    for case in cases:
        i = case["input"]
        lines = [f"P {p[2]} {p[5]} {p[6]}" for p in i["controls"]] + ["N"]
        lines += [
            f"B {1000000 + 15 * 65536} {dict(timeout=0, peer=1, retire=2)[i['action']]}",
            f"B {1000000 + 15 * 65536 + 200} 0",
        ]
        r = subprocess.run(
            [
                str(a.receiver.resolve()),
                str(i["phase"]),
                str(i["mask"]),
                str(int(i["crc"])),
            ],
            input="\n".join(lines) + "\n",
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert not r.returncode, (i["name"], r.stdout, r.stderr)
        got = [json.loads(s) for s in r.stdout.splitlines()]
        want = [case["before"]] + case["observed"]
        assert len(got) == len(want)
        for n, (g, w) in enumerate(zip(got, want)):
            assert g == w, (
                i["name"],
                n,
                {
                    k: (g.get(k), w.get(k))
                    for k in set(g) | set(w)
                    if g.get(k) != w.get(k)
                },
            )
            states += 1
    print(f"Client shutdown: {len(cases)} official cases, {states} states passed")


if __name__ == "__main__":
    main()
