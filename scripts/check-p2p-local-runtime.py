#!/usr/bin/env python3
"""Check actual custom-signaling/ICE runtime and original initial-wait bounds.

The receiver uses two actual prepared SDK interfaces with synthetic generic
identities, local queued signaling and a silent owned relay endpoint. This is
neither Valve-authenticated nor a NAT/SDR interoperability test.
"""
import argparse
import json
from pathlib import Path
import subprocess


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify(observed, boundary_only=False):
    reference = json.loads(Path(__file__).with_name("fixtures").joinpath(
        "steam-p2p-initial-wait-reference.json").read_text())
    require(observed["waits"] == reference["cold_sdr_waits"],
            "initial signaling wait differs from original 2s boundary")
    require(observed["clean"] is True and observed["objects"] == observed["released"],
            "all SDK signaling objects must retire")
    if boundary_only:
        require(observed["connected"] == observed["accepted"] == observed["signals"] == 0,
                "boundary-only execution must not connect")
        return
    require(observed["connected"] == 2 and observed["accepted"] == 1,
            "both real custom-signaling connections must connect")
    require(observed["signals"] >= 2 and observed["delivered"] >= 2,
            "actual SDK rendezvous bytes must cross the signaling queue")
    require(observed["objects"] == 2 and observed["received"] == [1, 1],
            "both peers must release signaling and receive the other unreliable datagram")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--receiver", type=Path)
    source.add_argument("--observation", type=Path)
    parser.add_argument("--boundary-only", action="store_true")
    args = parser.parse_args()
    if args.receiver:
        command = [str(args.receiver.resolve())]
        if args.boundary_only:
            command.append("--boundary-only")
        result = subprocess.run(command, capture_output=True, text=True, timeout=40)
        require(result.returncode == 0, "abnormal P2P runtime: " + result.stderr[-4000:])
        observed = json.loads(result.stdout)
    else:
        observed = json.loads(args.observation.read_text())
    print(json.dumps(observed, sort_keys=True))
    verify(observed, args.boundary_only)
    print("PASS actual initial SDR signaling bound" if args.boundary_only else
          "PASS actual P2P custom signaling, selected native ICE, bidirectional datagrams and cleanup")


if __name__ == "__main__":
    main()
