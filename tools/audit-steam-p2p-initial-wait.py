#!/usr/bin/env python3
"""Re-execute pinned original routing-wait instructions for the local SDK oracle.

Synthetic object memory, no network/credentials. The imported audit fails on
unknown calls/control flow and checks both return value and one-shot flag.
"""
import argparse
import importlib.util
import json
from pathlib import Path


def main():
    if not __debug__:
        raise RuntimeError("original-instruction checks require assertions; do not use -O")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location("routing_audit", root / "steam-remote-policy-audit.py")
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    elf = audit.descriptors.SampleELF(args.elf.read_bytes())
    reference = json.loads(root.parent.joinpath(
        "scripts/fixtures/steam-p2p-initial-wait-reference.json").read_text())
    if reference["sample_sha256"] != audit.descriptors.SAMPLE_SHA256:
        raise ValueError("reference is for a different source sample")
    for age, delay in reference["cold_sdr_waits"]:
        audit.initial_routing(elf, delay, sdr=True, config_ready=False, age=age)
    print(json.dumps({"sample_sha256": audit.descriptors.SAMPLE_SHA256,
                      "original_cold_sdr_waits": reference["cold_sdr_waits"]}, sort_keys=True))
    print("PASS original AArch64 initial signaling wait and one-shot flag at six boundaries")


if __name__ == "__main__":
    main()
