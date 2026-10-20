#!/usr/bin/env python3
"""Supply SHA-pinned official bytes to the diagnostic erasure/actual RX test."""
import argparse
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--receiver", type=Path, required=True)
args = parser.parse_args()
reference = json.loads(
    (Path(__file__).with_name("fixtures") / "steam-fec-reference.json").read_text()
)
if reference["binary_sha256"] != "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e":
    raise RuntimeError("Unrecognized official FEC source")
vector = reference["vector"]
subprocess.run(
    [str(args.receiver.resolve()), vector["payload"], *vector["wires"]],
    check=True,
    timeout=15,
)
