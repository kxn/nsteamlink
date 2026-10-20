#!/usr/bin/env python3
"""Original failed BStart remains stopped until an explicit startup trigger.

Original watcher construction/meta dispatch/BStart/BInit/Update execute; inherited
Qt/socket/storage/remote/initial-empty Stop terminals remain explicit. Timer
dispatches are supplied, not natural Qt/network events. No native OS/device proof.
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
    for event in (-1, 0, 1, "explicit_start"):
        m = d.Discovery(binary)
        m.b(m.manager + 12, 1)
        m.socket_result = -1
        m.run("watcher_ctor", m.watcher, m.manager)
        failed = m.snapshot()
        assert failed["state"] == 0 and failed["socket"] == 0
        assert failed["calls"]["start"] == 1 and failed["calls"]["socket_destroy"] == 1
        argv = m.alloc(16)
        for _ in range(3):
            m.run("meta_dispatch", m.watcher, 0, 0, argv)
        idle = m.snapshot()
        assert idle["state"] == 0 and idle["calls"]["start"] == 1
        assert not any(t[0] == "recvfrom" for t in idle["trace"])
        m.socket_result = 37
        m.reads = [-1]
        if event == "explicit_start":
            assert m.run("start", m.manager) == 1
        else:
            value = m.alloc(4)
            m.wi(value, event)
            m.wq(argv + 8, value)
            m.run("meta_dispatch", m.watcher, 0, 1, argv)
        started = m.snapshot()
        assert started["state"] == 1 and started["socket"] != 0 and not m.reads
        assert started["calls"]["start"] == 2
        cases.append(dict(event=event, failed=failed, idle=idle, restarted=started))
    helpers = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (
        Path(__file__), ROOT / "scripts/audit-steam-network-discovery.py",
        ROOT / "scripts/audit-steam-client-fec-policy.py")}
    return dict(binary_sha256=d.policy.SHA, scope=__doc__, helpers=helpers, cases=cases)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    result = audit(a.binary.read_bytes())
    reference = ROOT / "scripts/fixtures/steam-discovery-startup-reference.json"
    if a.refresh_reference:
        assert not reference.exists()
        reference.write_text(json.dumps(result, indent=2) + "\n")
    else:
        assert result == json.loads(reference.read_text())
    a.output.write_text(json.dumps(result, indent=2) + "\n")
    print("Official discovery startup:", len(result["cases"]), "failure/idle/retrigger plans passed")


if __name__ == "__main__":
    main()
