#!/usr/bin/env python3
"""Execute bearer notification binding and Qt configuration online aggregation.

Original engine initialize/meta dispatch/member-function thunk execute; backend
factory, connectImpl storage and configuration scan ENTRY are explicit terminals.
Warm native notification executes, then a declared activation-delivery adapter
invokes the original captured thunk, NOT a hand-written scan call. Separately,
original Qt configurationChanged -> public signals -> active-set decision and
online edge detection execute. A keyed QHash storage provider owns membership;
it does not select active states or decide whether/what to notify. Qt locks and
activation delivery are terminals. Emitted online values enter the existing
original access/watcher fixtures after producer return. No real OS/Qt scheduling,
bearer scan results, DNS, HTTP-session reset, Steam or Switch is claimed.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/steam-network-watchers-audit.py"
spec = importlib.util.spec_from_file_location("watchers", SOURCE)
watchers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watchers)
PATCHES = {
    "initial-scan": ("bearer", 0xC2E0, "27000094"),
    "connection": ("bearer", 0xC348, "da190094"),
    "active-state": ("qt", 0x18FD14, "a1000054"),
    "online-edge": ("qt", 0x18FD5C, "a9000034"),
    "online-notify": ("qt", 0x18FD6C, "f92a0894"),
    "configuration-notify": ("qt", 0x18FCE0, "2c2b0894"),
}


def mutate(machine, kind, mutation):
    if not mutation or PATCHES[mutation][0] != kind:
        return
    _, address, signature = PATCHES[mutation]
    assert bytes(machine.u.mem_read(address, 4)) == bytes.fromhex(signature), (
        "mutation-signature", mutation, hex(address))
    machine.u.mem_write(address, bytes.fromhex("1f2003d5"))


class Engine(watchers.BearerNotification):
    def __init__(self, binary, mutation):
        super().__init__(binary)
        self.engine = self.alloc(128)
        self.connections, self.scan_entries = [], []
        self.factory_calls, self.delivered = 0, 0
        self.backend_available = True
        self.entries = set()
        mutate(self, "bearer", mutation)

    def hook(self, u, pc, size, context):
        if self.enabled:
            if pc in (0x119A0, 0xC2A4, 0xDEB8, 0xD3D0):
                self.entries.add(hex(pc))
            if pc == 0x10D98:
                self.factory_calls += 1
                return self.ret(self.singleton if self.backend_available else 0)
            if pc == 0xC37C:
                self.scan_entries.append(dict(engine=self.r(0), backend=bool(self.q(self.r(0) + 0x40))))
                return self.ret()
            name = self.plts.get(pc, "")
            if name == "_ZN7QObject11connectImplEPKS_PPvS1_S3_PN9QtPrivate15QSlotObjectBaseEN2Qt14ConnectionTypeEPKiPK11QMetaObject":
                self.connections.append(dict(sender=self.r(0), signal=hex(self.q(self.r(1))),
                    receiver=self.r(2), slot=hex(self.q(self.r(3))), slot_object=self.r(4),
                    connection_type=self.r(5), metadata=hex(self.r(7))))
                self.wq(self.r(8), 0)
                return self.ret()
            if name == "_ZN11QMetaObject10ConnectionD1Ev":
                return self.ret()
        return super().hook(u, pc, size, context)

    def initialize(self):
        self.call(0x119A0, self.engine, 0, 1, 0)

    def notify_and_deliver(self):
        self.call(0x11660, 0x101, 0x102)
        for signal in self.signals[self.delivered:]:
            assert signal == "activeNetworkChanged"
            for connection in self.connections:
                assert connection["sender"] == self.singleton
                slot = connection["slot_object"]
                # The object/function/this adjustment come from ORIGINAL
                # initialize. Execute its actual member-function thunk.
                self.call(self.q(slot + 8), 1, slot, connection["receiver"], 0, 0)
        self.delivered = len(self.signals)

    def snapshot(self):
        return dict(factory_calls=self.factory_calls, scans=list(self.scan_entries),
                    connections=list(self.connections), signals=list(self.signals),
                    original=sorted(self.entries))


class Configuration(watchers.discovery.policy.Shell):
    def __init__(self, binary, mutation):
        self.enabled = False
        super().__init__(binary)
        self.owner, self.hash_header = self.alloc(0x100), self.alloc(0x40)
        self.wq(self.owner + 0x40, self.hash_header)
        self.active = {}
        self.events, self.storage_calls = [], []
        self.entries = set()
        self.enabled = True
        mutate(self, "qt", mutation)

    def hook(self, u, pc, size, context):
        if not self.enabled:
            return super().hook(u, pc, size, context)
        if pc in (0x18FBC4, 0x2044B8, 0x204524):
            self.entries.add(hex(pc))
        name = self.plts.get(pc, "")
        if name in ("_ZN6QMutex4lockEv", "_ZN6QMutex6unlockEv"):
            return self.ret()
        if name in ("_ZN21QNetworkConfigurationC1Ev", "_ZN21QNetworkConfigurationD1Ev",
                    "_ZN35QNetworkConfigurationManagerPrivate20configurationChangedERK21QNetworkConfiguration",
                    "_ZN35QNetworkConfigurationManagerPrivate18onlineStateChangedEb"):
            return self.jump(self.symbols[name])
        if pc in (0x122C84, 0x122EB0):
            assert self.r(0) == self.owner + 0x40
            identity = self.qt_strings[self.q(self.r(1))]
            before = sorted(self.active)
            if pc == 0x122C84:
                self.active[identity] = True
            else:
                self.active.pop(identity, None)
            self.wi(self.hash_header + 0x14, len(self.active))
            self.storage_calls.append(dict(operation="insert" if pc == 0x122C84 else "remove",
                                           identity=identity, before=before, after=sorted(self.active)))
            return self.ret()
        if name == "_ZN11QMetaObject8activateEP7QObjectPKS_iPPv":
            assert self.r(0) == self.owner and self.r(1) == 0x3A5040
            method = self.r(2)
            if method == 4:
                value = self.i(self.q(self.r(3) + 8)) & 255
                event = dict(kind="online", value=value, active=sorted(self.active))
            elif method == 2:
                config = self.q(self.q(self.r(3) + 8))
                event = dict(kind="changed", identity=self.qt_strings[self.q(config + 0x18)],
                             state=self.i(config + 0x20), active=sorted(self.active))
            else:
                raise AssertionError(("unexpected configuration signal", method))
            self.events.append(event)
            return self.ret()
        return super().hook(u, pc, size, context)

    def seed(self, identities):
        # Explicit initial storage, not an executed engine scan/manager ctor.
        self.active = {identity: True for identity in identities}
        self.wi(self.hash_header + 0x14, len(self.active))

    def changed(self, identity, state):
        config = self.alloc(0x40)
        self.wi(config, 100)  # Borrowed fixture owner keeps the ref alive.
        self.wq(config + 0x10, self.qstring(identity))
        self.wq(config + 0x18, self.qstring(identity))
        self.wi(config + 0x20, state)
        reference = self.alloc(8)
        self.wq(reference, config)
        before = len(self.events)
        self.call(0x18FBC4, self.owner, reference)
        assert self.i(config) == 100, "original temporary reference balanced"
        return dict(active=sorted(self.active), events=list(self.events[before:]),
                    original=sorted(self.entries))


def audit(args):
    binaries = {name: getattr(args, name).read_bytes() for name in ("qt", "bearer", "shell")}
    for name, binary in binaries.items():
        assert hashlib.sha256(binary).hexdigest() == watchers.SHA[name], name
    meta = watchers.qt_metadata(binaries["bearer"], 0x17270)
    assert [method["name"] for method in meta["methods"]] == ["updateConfigurations", "initialize", "requestUpdate"]
    aggregate_meta = watchers.qt_metadata(binaries["qt"], 0x3A5040)
    assert aggregate_meta["methods"][2]["name"] == "configurationChanged"
    assert aggregate_meta["methods"][4]["name"] == "onlineStateChanged"
    bindings = []
    for failed_first in (False, True):
        engine = Engine(binaries["bearer"], args.mutation)
        if failed_first:
            engine.backend_available = False
            engine.initialize()
            assert engine.factory_calls == 1 and not engine.connections and not engine.scan_entries
        engine.backend_available = True
        engine.initialize()
        assert len(engine.scan_entries) == 1, "initial scan entry"
        assert len(engine.connections) == 1, "native signal subscription"
        connection = engine.connections[0]
        assert connection["signal"] == "0x12384" and connection["slot"] == "0xc37c"
        assert connection["connection_type"] == 0 and connection["metadata"] == "0x175f0"
        for expected in (2, 3):
            engine.notify_and_deliver()
            assert len(engine.scan_entries) == expected, "original bound scan dispatch"
        before = engine.snapshot()
        engine.initialize()
        assert engine.snapshot() == before, "initialized engine remains idempotent"
        engine.call(0x119A0, engine.engine, 0, 2, 0)
        assert len(engine.scan_entries) == 4 and "0xd3d0" in engine.entries
        bindings.append(dict(initial_failure=failed_first, observed=engine.snapshot()))

    programs = [
        ("overlap-handover", ["wifi"], [("mobile", 14), ("wifi", 6)], [2, 1], []),
        ("gap-handover", ["wifi"], [("wifi", 6), ("mobile", 14)], [0, 1], [0, 1]),
        ("active-repeat", ["wifi"], [("wifi", 14), ("wifi", 14)], [1, 1], []),
        ("inactive-repeat", [], [("wifi", 6), ("wifi", 6)], [0, 0], []),
        ("reactivation", [], [("wifi", 14), ("wifi", 6), ("wifi", 14)], [1, 0, 1], [1, 0, 1]),
        ("one-of-several-retired", ["wifi", "mobile"], [("wifi", 2), ("mobile", 6)], [1, 0], [0]),
    ]
    for state in (0, 1, 2, 6, 8, 15):
        programs.append((f"non-active-state-{state}", ["wifi"], [("wifi", state)], [0], [0]))
    programs.extend([
        ("suppressed-reactivation", [], [("wifi", 14), ("wifi", 6), ("wifi", 14)], [1, 0, 1], []),
        ("suppressed-gap", ["wifi"], [("wifi", 6), ("mobile", 14)], [0, 1], []),
        ("other-flag-gap", ["wifi"], [("wifi", 6), ("mobile", 14)], [0, 1], [0, 1]),
    ])
    cases = []
    for name, initial, operations, sizes, online in programs:
        c = Configuration(binaries["qt"], args.mutation)
        c.seed(initial)
        notification_flags = 1 if name.startswith("suppressed-") else 2 if name.startswith("other-flag-") else 0
        c.b(c.owner + 0x5D, notification_flags)
        qt = watchers.QtWatcher(binaries["qt"], None)
        started_online = int(bool(initial))
        qt.wi(qt.private + 0xCC, started_online)
        qt.b(qt.private + 0xD4, started_online)
        qt.b(qt.private + 0xD7, 1)
        stages, seen = [], []
        for index, (identity, state) in enumerate(operations):
            before = sorted(c.active)
            stage = c.changed(identity, state)
            assert len(stage["active"]) == sizes[index], (name, "active membership", stage)
            # Configuration signal is emitted BEFORE storage/online mutation.
            if notification_flags & 1:
                assert not stage["events"], (name, "suppressed notifications", stage)
            else:
                assert stage["events"] and stage["events"][0] == dict(
                    kind="changed", identity=identity, state=state, active=before), (name, "signal order", stage)
            for event in stage["events"]:
                if event["kind"] == "online":
                    seen.append(event["value"])
                    qt.event(event["value"])
            stages.append(stage)
        assert seen == online, (name, "online events", seen, online)
        assert qt.signals == online, (name, "accessibility events", qt.signals, online)
        # Explicit delivery to the already-running original discovery owner:
        # none of these transitions invoke BStart/HandleNetworkChanged.
        d = watchers.discovery.Discovery(binaries["shell"], 1)
        for value in qt.signals:
            argv, storage = d.alloc(16), d.alloc(4)
            d.wi(storage, value)
            d.wq(argv + 8, storage)
            d.run("meta_dispatch", d.watcher, 0, 1, argv)
        assert not d.calls["start"] and not d.calls["network_api"]
        cases.append(dict(name=name, initial_active=initial, notification_flags=notification_flags,
                          operations=operations, stages=stages,
                          online=seen, access=qt.signals, storage=c.storage_calls,
                          running_discovery=d.snapshot()))
    images = {name: watchers.discovery.policy.load_image(binary)[0] for name, binary in binaries.items()}
    ranges = {"bearer": ((0xC2A4, 0xD8), (0xDEB8, 0x64)), "qt": ((0x18FBC4, 0x1E0),)}
    return dict(scope=__doc__, identities={name: watchers.SHA[name] for name in binaries},
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                inherited_sha256={str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                  for path in (SOURCE, watchers.SOURCE,
                                      ROOT / "scripts/audit-steam-client-fec-policy.py")},
                original_ranges={name: {hex(start): dict(size=size, sha256=hashlib.sha256(
                    images[name][start:start + size]).hexdigest()) for start, size in intervals}
                    for name, intervals in ranges.items()},
                engine_metadata=meta, aggregate_metadata=aggregate_meta, bindings=bindings, cases=cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("qt", "bearer", "shell"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--mutation", choices=PATCHES)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    text = json.dumps(audit(args), indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
