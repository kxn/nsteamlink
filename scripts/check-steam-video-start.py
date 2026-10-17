#!/usr/bin/env python3
"""Compare Native Video Start/Stop and complete FIFO with official instructions.

Prepare/backend/OS results are explicit fixture inputs. Decoder metadata and
lifecycle observations come from the official factory, virtual Start/Stop and
Info terminal; Native configuration is recorded by its actual callbacks. The
Native worker intentionally cannot start, so matching frame contents can be
compared before consumption. Neither side proves real hardware or scheduling.
"""

import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def project(state):
    decoder = state["decoder"]
    return dict(
        phase=state["phase"],
        paused=state["paused"],
        channel=state["channel"],
        decoder={k: v for k, v in decoder.items() if k not in ("threads", "queued")}
        if decoder
        else None,
        pending=state["pending"],
        delays={k: v for k, v in state["delays"].items() if int(k) >= 3},
        prepares=state["steps"],
        lifecycle=[
            {
                "standalone_start": "start",
                "standalone_stop": "stop",
                "decoder_info": "info",
            }[e[0]]
            for e in state["trace"]
            if e[0] in ("standalone_start", "standalone_stop", "decoder_info")
        ],
        queued=decoder["queued"] if decoder else [],
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", type=Path, required=True)
    args = parser.parse_args()
    cases = json.loads(
        (ROOT / "scripts/fixtures/steam-video-start-reference.json").read_text()
    )["cases"]
    count = 0
    for i, case in enumerate(cases):
        inp = case["input"]
        lines = [
            " ".join(str(v) if v != "" else "-" for v in op) for op in case["actions"]
        ]
        result = subprocess.run(
            [
                str(args.receiver.resolve()),
                str(int(inp["prepare"])),
                str(int(inp["ready"])),
                str(inp.get("fallback", 4)),
            ],
            input="\n".join(lines) + "\n",
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, (
            i,
            result.returncode,
            result.stdout,
            result.stderr,
        )
        actual = [json.loads(line) for line in result.stdout.splitlines()]
        expected = [project(s) for s in case["states"]]
        assert actual == expected, (i, case["actions"], actual, expected)
        count += len(actual)
    print(f"Video startup: {len(cases)} official cases/{count} states passed")


if __name__ == "__main__":
    main()
