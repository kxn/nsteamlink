#!/usr/bin/env python3
"""Run complete original client construction, UDP Init and OnThink with the SDK.

Pinned genuine executable and SDK, real OS threads/socket. Loopback fixture only
receives original Connect packets and sends no reply, so there is no handshake,
authentication or streaming-phase admission. Encoded video is an explicit parsed
Frame boundary and decoder owner link, not a control StartVideo producer. Normal
OnThink consumes original deferred format; cancellation and restart preserve the
same declared media boundary. This does not prove full Qt, stats or hardware.

Fixed instruction observers avoid GDB's thread-bound FinishBreakpoint lifecycle
bug seen during extended client shutdown. No original return value, method body,
callback, async flag, gate or client phase is overwritten to make a run pass.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import socket

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "worker_check", ROOT / "scripts/audit-steam-client-worker-process.py"
)
worker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(worker)


def verify(report, bootstrap, mode, packets):
    worker.verify(report)
    s = report["original_start"]
    assert s["full_client_deleting_dtor_returned"]
    assert s["constructed_client"] == {
        "vptr_offset": 0x10FF908,
        "phase": 0,
        "hardware_preference": 1,
    }
    assert len(report["source_functions"]) == 54
    if bootstrap == "constructed":
        assert not packets and mode == "empty"
        return
    assert s["transport_init_return"] == 1 and s["client_phase"] == 1
    assert s["client_phase_after_stop"] == 1
    assert s["connection_state_after_stop"] == 0
    assert packets
    # Raw received datagrams are primary evidence, not a socket-send terminal.
    for p in packets:
        data = bytes.fromhex(p["data"])
        assert len(data) == 17 and data[0] == 1 and data[2] != 0
        assert data[3:9] == bytes(6) and data[-4:] == bytes.fromhex("c73d8f3c")
        assert p["peer"][0] == "127.0.0.1"
    trace = [x[0] for x in s["trace"]]
    if mode in ("empty", "decode", "restart"):
        begins = [i for i, n in enumerate(trace) if n == "client_think"]
        assert len(begins) == (2 if mode == "restart" else 1)
        for i, start in enumerate(begins):
            end = begins[i + 1] if i + 1 < len(begins) else len(trace)
            names = trace[start:end]
            stages = [
                "client_think",
                "pending_resets",
                "network_poll",
                "control_dispatch",
            ]
            if mode != "empty":
                stages += ["main_format", "format_selector", "decoder_info"]
            order = [names.index(n) for n in stages]
            assert order == sorted(order)
    elif mode == "reset_pending":
        assert trace.count("client_think") == 2
    elif mode == "cancel":
        assert "client_think" not in trace and "main_format" not in trace


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--sdk-directory", type=Path, required=True)
    p.add_argument("--qt-library-directory", type=Path, action="append", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    cases = []
    for bootstrap, mode in [
        ("constructed", "empty"),
        *[
            ("udp", m)
            for m in ("empty", "decode", "cancel", "restart", "reset_pending")
        ],
    ]:
        name = bootstrap + "_" + mode
        path = a.output.with_name(a.output.stem + "-" + name + ".json")
        packets = []
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as fixture_socket:
            fixture_socket.bind(("127.0.0.1", 0))
            fixture_socket.settimeout(0.1)
            endpoint = "127.0.0.1:" + str(fixture_socket.getsockname()[1])
            report = worker.process.audit(
                a.binary.resolve(),
                a.sdk_directory.resolve(),
                [q.resolve() for q in a.qt_library_directory],
                path,
                worker_mode=mode,
                client_bootstrap=bootstrap,
                endpoint=endpoint if bootstrap == "udp" else None,
            )
            try:
                while True:
                    data, peer = fixture_socket.recvfrom(65536)
                    packets.append(dict(data=data.hex(), peer=list(peer)))
            except socket.timeout:
                pass
        report["loopback_packets"] = packets
        path.write_text(json.dumps(report, indent=2) + "\n")
        verify(report, bootstrap, mode, packets)
        cases.append(report)
        print(
            name,
            len(packets),
            "raw packets",
            len(report["original_start"]["trace"]),
            "trace entries",
            flush=True,
        )
    a.output.write_text(json.dumps(dict(scope=__doc__, cases=cases), indent=2) + "\n")
    print("Original complete client: six ctor/Init/OnThink/worker/Stop modes passed")


if __name__ == "__main__":
    main()
