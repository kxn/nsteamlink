#!/usr/bin/env python3
"""Original discovery meta-dispatch/Update across repeated read failures.

The original constructor requests a 100ms Qt timer. Fixture ticks invoke the
original meta-dispatch at that declared interval; no real Qt scheduler runs.
Socket/Qt/storage/remote APIs and BProcess inherit the prior explicit terminals.
This is receive-batch/state evidence, not natural OS timing, protocol parsing,
Steam, Switch, DNS, CPU cost or loader lifecycle evidence.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("discovery", ROOT / "scripts/audit-steam-network-discovery.py")
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == d.policy.SHA
    cases = []
    programs = {
        "negative_then_recovery": [[-1]] * 5 + [[9, -1], [7, 0]],
        "zero_then_recovery": [[0]] * 5 + [[9, -1], [7, 0]],
        "positive_before_error": [[9, 7, -1], [-1], [0], [-1], [9, -1]],
        "alternating": [[-1], [0], [9, 0], [-1], [7, -1]],
    }
    for name, program in programs.items():
        machine = d.Discovery(binary, 1)
        machine.run("watcher_ctor", machine.watcher, machine.manager)
        periods = [t[1] for t in machine.trace if t[0] == "timer_start_ms"]
        assert periods == [100]
        sock = machine.alloc(8)
        machine.wi(sock + 4, 37)
        machine.wq(machine.manager + 32, sock)
        argv = machine.alloc(16)
        rows = []
        for cycle, reads in enumerate(program):
            before = len(machine.trace)
            machine.reads = reads.copy()
            machine.run("meta_dispatch", machine.watcher, 0, 0, argv)
            assert not machine.reads
            observed = machine.snapshot()
            assert observed["socket"] == sock and observed["state"] == 1
            assert not observed["calls"].get("socket_destroy", 0)
            delta = machine.trace[before:]
            assert [t[-1] for t in delta if t[0] == "recvfrom"] == reads
            assert [t[1] for t in delta if t[0] == "opaque_datagram"] == [v for v in reads if v > 0]
            rows.append(dict(tick_ms=cycle * periods[0], input_reads=reads,
                             trace=delta, state=observed["state"], socket=observed["socket"],
                             updating=observed["updating"]))
        cases.append(dict(name=name, timer_interval_ms=periods[0], cycles=rows,
                          calls=machine.snapshot()["calls"]))
    helpers = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (
        Path(__file__), ROOT / "scripts/audit-steam-network-discovery.py",
        ROOT / "scripts/audit-steam-client-fec-policy.py")}
    return dict(scope=__doc__, binary_sha256=d.policy.SHA, helpers=helpers, cases=cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--refresh-reference", action="store_true")
    args = parser.parse_args()
    result = audit(args.binary.read_bytes())
    reference = ROOT / "scripts/fixtures/steam-discovery-cycles-reference.json"
    if args.refresh_reference:
        assert not reference.exists()
        reference.write_text(json.dumps(result, indent=2) + "\n")
    else:
        assert result == json.loads(reference.read_text())
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print("Official discovery cycles:", len(result["cases"]), "programs,",
          sum(len(c["cycles"]) for c in result["cases"]), "original Update calls")


if __name__ == "__main__":
    main()
