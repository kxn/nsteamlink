#!/usr/bin/env python3
"""Compare production session readiness/drain/update against original Socket.

Actual native CRC RX, clock/packet collectors, reliable/media windows/feedback and
Socket-send preparation run, with wait/read elapsed/processing elapsed and final
I/O controlled. Handshaking client state avoids unrelated OnThink producers;
complete-frame FIFO is drained after each batch by a controlled consumer. No
outgoing queue, decoder, authentication or global-thread equivalence is claimed.
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
        (ROOT / "scripts/fixtures/steam-receive-cycle-reference.json").read_text()
    )["cases"]
    states = wires = 0
    for c in cases:
        i = c["input"]
        lines = [f"Q {ch} {priority}" for ch, priority in i.get("priorities", [])]
        for v in i["cycles"]:
            lines.append(
                f"B {v['tick']} {int(v['ready'])} {int(v['blocked'])} {v['eof']} {len(v['rows'])}"
            )
            lines.extend("P " + " ".join(map(str, row)) for row in v["rows"])
        r = subprocess.run(
            [str(a.receiver.resolve()), str(int(i["crc"])), "1", "-1", "34", "cycle"],
            input="\n".join(lines) + "\n",
            text=True,
            capture_output=True,
            timeout=10,
        )
        assert not r.returncode, (i, r.stdout, r.stderr)
        got = [json.loads(s) for s in r.stdout.splitlines()]
        assert len(got) == len(c["observed"])
        for n, (actual, want) in enumerate(zip(got, c["observed"])):
            assert actual == want, (i["name"], n, actual, want)
            states += 1
            wires += len(actual["wires"])
    print(
        f"Receive cycle: {len(cases)} official cases, {states} states, {wires} feedback wires passed"
    )


if __name__ == "__main__":
    main()
