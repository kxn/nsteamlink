#!/usr/bin/env python3
"""Observe original format-array allocation generations during pending reset.

Genuine pinned client/SDK, real public allocator calls/results. The UDP fixture
only receives Connect packets; video owner/parsed Frame and RequestReset(false)
are explicit API boundaries in Connecting phase. This does not prove a natural
UI/network trigger, a production UAF, or the user's original freeze cause.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import socket

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "client_check", ROOT / "scripts/audit-steam-client-client-process.py"
)
client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(client)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--sdk-directory", type=Path, required=True)
    p.add_argument("--qt-library-directory", type=Path, action="append", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    packets = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.bind(("127.0.0.1", 0))
        peer.settimeout(0.1)
        report = client.worker.process.audit(
            a.binary.resolve(),
            a.sdk_directory.resolve(),
            [q.resolve() for q in a.qt_library_directory],
            a.output,
            worker_mode="reset_pending",
            client_bootstrap="udp",
            endpoint="127.0.0.1:" + str(peer.getsockname()[1]),
            format_memory=True,
        )
        try:
            while True:
                data, sender = peer.recvfrom(65536)
                packets.append(dict(data=data.hex(), peer=list(sender)))
        except socket.timeout:
            pass
    report["loopback_packets"] = packets
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    client.verify(report, "udp", "reset_pending", packets)
    memory = report["original_start"]["format_memory"]
    assert memory["sdk_free_override"] == 0
    events = memory["events"]
    borrows = [e for e in events if e[0] == "sdk_borrow"]
    consumers = [e for e in events if e[0] == "main_consume"]
    assert len(borrows) == len(consumers) == 2
    first, last = borrows
    assert first[3]["live"] and last[3]["live"]
    freed = next(
        e
        for e in events
        if e[0] == "free_return" and e[2:4] == [first[2], first[3]["generation"]]
    )
    assert events.index(first) < events.index(freed) < events.index(consumers[0])
    assert consumers[0][3] == first[3]["generation"]
    assert (
        consumers[1][4]["live"]
        and consumers[1][3] == last[3]["generation"] == consumers[1][4]["generation"]
    )
    print(
        "Original pending-reset array freed before consumer; new callback consumes its live generation"
    )
    print("Last observed allocation at first consumer:", consumers[0][4])


if __name__ == "__main__":
    main()
