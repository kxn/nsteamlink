#!/usr/bin/env python3
"""Replay original Qt online slot with nested selector/session/backend work.

Unlike the isolated slot fixture, release/select/factory/public-session/Android
backend execute in one ARM64 VM. QObject/manager/config enumeration, locks and
activation delivery retain the explicit providers of android-session-audit.
Emitted values are separately delivered to original shell meta dispatch. This
does not make that adapter a natural event loop or prove streaming recovery.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/steam-android-session-audit.py"
spec = importlib.util.spec_from_file_location("backend", SOURCE)
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)
policy, watchers = backend.policy, backend.watchers
PATCHES = {
    "nested-selector": (0x11EE1C, "bdf0ff97", "1f2003d5"),
    "nested-notification": (0x11B4B0, "24f20994", "1f2003d5"),
    "outer-notification": (0x11EE80, "b0e30994", "1f2003d5"),
    "online-store": (0x11EE00, "96520339", "1f2003d5"),
    "access-store": (0x11EE5C, "9fce00b9", "1f2003d5"),
}


class Transition(backend.Backend):
    def __init__(self, binaries, mutation):
        self.origins = []
        super().__init__(binaries["qt"], binaries["qt_core"], binaries["bearer"])
        if mutation:
            address, expected, replacement = PATCHES[mutation]
            assert bytes(self.u.mem_read(address, 4)).hex() == expected, ("mutation-signature", mutation)
            self.u.mem_write(address, bytes.fromhex(replacement))

    def hook(self, u, pc, size, context):
        if (self.plts.get(pc) == "_ZN11QMetaObject8activateEP7QObjectPKS_iPPv"
                and self.r(1) == 0x3A0DE0 and self.r(2) == 7):
            self.origins.append(dict(return_pc=hex(u.reg_read(policy.UC_ARM64_REG_X30)),
                                     saved_access=struct.unpack("<i", bytes(u.mem_read(self.private + 0xCC, 4)))[0],
                                     saved_online=bool(u.mem_read(self.private + 0xD4, 1)[0])))
        return super().hook(u, pc, size, context)

    def incoming(self, value):
        # Public QObject meta dispatch is original too; the producer bool is
        # fixture-owned, not a claimed Android connectivity query.
        argv, storage = self.alloc(16), self.alloc(4)
        self.wi(storage, value)
        self.wq(argv + 8, storage)
        self.call(0x11FA1C, self.public, 0, 17, argv)

    def result(self):
        return dict(snapshot=self.snapshot(), origins=list(self.origins),
                    created=len(self.created), deletes=list(self.deletes),
                    backend_trace=list(self.backend_trace))


def audit(args):
    binaries = {key: getattr(args, key).read_bytes() for key in ("qt", "qt_core", "bearer", "shell")}
    expected = dict(watchers.SHA, qt_core=backend.pool.access.scan.QT_CORE_SHA)
    for key, binary in binaries.items():
        assert hashlib.sha256(binary).hexdigest() == expected[key], ("binary identity", key)
    cases = []
    # Explicit counterexamples to generalizing the isolated slot's deduplication
    # table. Odd saved-access inputs are controlled boundary cases, not OS states.
    rows = [
        (1, 1, 0, [0, 0], [0], 0),
        (0, 1, 0, [0], [], 0),
        (0, 0, 0, [], [], 0),
        (0, 0, 1, [0, 1], [1], 1),
        (-1, 0, 1, [-1, 1], [1], 1),
        (1, 0, 1, [-1], [], 1),
    ]
    for access, previous, incoming, invalid_events, valid_events, final in rows:
        for valid, values in ((False, invalid_events), (True, valid_events)):
            b = Transition(binaries, args.mutation)
            b.default = b.make_config("input", 14 if valid else 1, valid)
            if valid:
                b.add_engine(b.default)
            b.wi(b.private + 0xCC, access)
            b.b(b.private + 0xD4, previous)
            b.incoming(incoming)
            observed = [event["value"] for event in b.events]
            assert observed == values, ("nested notification sequence", access, previous, incoming, valid, observed)
            assert b.snapshot()["access"] == final, "saved access after nested selector"
            assert b.snapshot()["online"] == incoming, "saved online after transition"
            assert len(b.actions) == (2 if previous != incoming else 0), "nested reconciliation"
            assert len(b.created) == int(valid and previous != incoming), "original factory/ctor executed"
            cases.append(dict(input=dict(access=access, previous=previous, incoming=incoming, valid=valid),
                              observed=b.result()))

    b = Transition(binaries, args.mutation)
    active = b.default
    b.add_engine(active)
    b.call(0x11B110, b.private, active)
    assert b.q(b.private + 0x88), "initial original session"
    # Explicitly deliver its initial queued NAM state before changing networks.
    b.deliver_state(b.invocations[-1])
    phases = []
    offline = b.make_config("offline", 1, False)
    for name, config, incoming, values, origins in (
        ("offline", offline, 0, [0, 0], ["0x11b4b4", "0x11ee84"]),
        ("repeat-offline", offline, 0, [], []),
        ("online", active, 1, [1], ["0x11ee84"]),
        ("repeat-online", active, 1, [], []),
    ):
        b.default = config
        b.events.clear()
        b.actions.clear()
        b.origins.clear()
        b.incoming(incoming)
        assert [event["value"] for event in b.events] == values, ("multi-step sequence", name)
        assert [event["return_pc"] for event in b.origins] == origins, "nested vs outer signal origin"
        if name == "offline":
            assert [event["saved_access"] for event in b.origins] == [1, 0], "store occurs between notifications"
            assert not b.q(b.private + 0x88) and b.deletes, "old session released with deferred deletion"
        phases.append(dict(name=name, observed=b.result()))
    b.events.clear()
    b.deliver_state(b.invocations[-1])
    assert b.events == [dict(signal=6, value=None)], "queued session-connected does not emit accessible again"
    cases.append(dict(input=dict(program="active-offline-repeat-online-repeat-queued-state"),
                      phases=phases, queued_delivery=b.result()))

    deliveries = []
    patterns = sorted({tuple(event["value"] for event in case["observed"]["snapshot"]["events"])
                       for case in cases if "observed" in case})
    for values in patterns:
        for state, fail in ((0, False), (1, False), (4, False), (5, False), (0, True)):
            d = watchers.discovery.Discovery(binaries["shell"], state)
            if fail:
                d.b(d.manager + 12, 1)
                d.socket_result = -1
            for value in values:
                argv, storage = d.alloc(16), d.alloc(4)
                d.wi(storage, value)
                d.wq(argv + 8, storage)
                d.run("meta_dispatch", d.watcher, 0, 1, argv)
            expected_calls = len(values) if fail else int(bool(values) and state == 0)
            assert d.calls["start"] == expected_calls, "shell gate consumes resulting state"
            assert d.calls["network_api"] == 0, "no fabricated HandleNetworkChanged producer"
            assert d.i(d.manager + 8) == (1 if expected_calls and not fail else state), "shell state after sequence"
            deliveries.append(dict(events=values, initial_state=state, fail_socket=fail, observed=d.snapshot()))

    return dict(scope=__doc__, identities={key: hashlib.sha256(value).hexdigest() for key, value in binaries.items()},
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                inherited_sha256={str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                  for path in (SOURCE, backend.SOURCE, backend.pool.SOURCE,
                                      backend.pool.access.SOURCE, backend.pool.access.scan.SOURCE,
                                      backend.pool.access.scan.bridge.SOURCE, watchers.SOURCE,
                                      ROOT / "scripts/audit-steam-client-fec-policy.py")},
                cases=cases, shell_deliveries=deliveries)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("qt", "qt-core", "bearer", "shell"):
        parser.add_argument("--" + key, type=Path, required=True)
    parser.add_argument("--mutation", choices=PATCHES)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(audit(args), indent=2) + "\n")


if __name__ == "__main__":
    main()
