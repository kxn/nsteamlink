#!/usr/bin/env python3
"""Compare actual native SDL PCM output with the original Raw audio decoder.

Official uses normalized float; SDL's verified S16LE format uses the exact
inverse scale 32768. Format conversion is the only normalization here.
"""

import argparse
import json
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    a = p.parse_args()
    fixture = json.loads(
        (ROOT / "scripts/fixtures/steam-raw-audio-reference.json").read_text()
    )
    for index, c in enumerate(fixture["cases"]):
        i, o = c["input"], c["observed"]
        r = subprocess.run(
            [str(a.receiver.resolve()), i["codec_data"], i["pcm"]],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert r.returncode == 0, (index, r.stdout, r.stderr)
        floats = bytes.fromhex(o["float_pcm"])
        values = struct.unpack("<" + "f" * (len(floats) // 4), floats)
        pcm = struct.pack("<" + "h" * len(values), *(int(v * 32768) for v in values))
        assert o["start"][0] == 2
        want = dict(
            frequency=o["start"][1],
            channels=o["start"][2],
            frames=1,
            samples=len(values) // o["start"][2],
            pcm=pcm.hex(),
        )
        assert json.loads(r.stdout) == want, (index, r.stdout, want)
    print(
        f"Production Raw audio SDL output: {len(fixture['cases'])} official cases passed"
    )


if __name__ == "__main__":
    main()
