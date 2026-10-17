#!/usr/bin/env python3
"""Compare production control decrypt/FIFO/drain with the official client.

Native AES/HMAC and original-source Frame BDecrypt with crypto primitives adapted
receive identical cipher bytes. Source/Native own queues and phase selection run;
terminal handlers other than peer SetConfig/config99 remain explicit adapters.
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
        (ROOT / "scripts/fixtures/steam-control-handoff-reference.json").read_text()
    )["cases"]
    states = events = 0
    for c in cases:
        i = c["input"]
        r = subprocess.run(
            [str(a.receiver.resolve()), str(i["state"])],
            input="\n".join(
                " ".join(str(v) if v != "" else "-" for v in x) for x in i["actions"]
            )
            + "\n",
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert r.returncode == 0, (i["name"], r.stderr)
        got = [json.loads(line) for line in r.stdout.splitlines()]
        assert len(got) == len(c["observed"])
        for n, (actual, want) in enumerate(zip(got, c["observed"])):
            assert actual == want, (i["name"], n, actual, want)
            states += 1
            events += len(actual["events"])
    print(
        f"Control handoff: {len(cases)} official cases, {states} states, {events} consumer events passed"
    )


if __name__ == "__main__":
    main()
