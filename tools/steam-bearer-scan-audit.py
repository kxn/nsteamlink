#!/usr/bin/env python3
"""Execute pinned Android bearer configuration scan and Qt manager consumers.

Original scan control flow, record updates and notification order execute. JNI
NetworkInfo/interface observations, keyed storage and locks are explicit inputs
or providers; inline map/hash lookups still execute. QString formatting, compare,
number and hashing execute in the bundled original QtCore through a value-copy
adapter, not the inherited UI-only QString doubles. Emitted config snapshots
separately enter original Qt manager add/change/remove methods; activation is a
recording terminal. This is not Android enumeration, QObject scheduling, DNS,
HTTP/session reset, Steam interoperability or a Switch runtime test.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/steam-bearer-config-audit.py"
spec = importlib.util.spec_from_file_location("bridge", SOURCE)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)
watchers = bridge.watchers
policy = watchers.discovery.policy
QT_CORE_SHA = "687a385c0f18f8399c2f421846cfdba11d96dce75e9839840d0c169469e550a7"
PATCHES = {
    "available": (0xC75C, "80000036"),
    "connected": (0xC768, "602d0037"),
    "interface-valid": (0xCDC8, "20fa0736"),
    "interface-flag3": (0xCDD4, "c0f91f37"),
    "interface-running": (0xCDE0, "60f90f36"),
    "addresses": (0xCD08, "411d0054"),
    "change-dedupe": (0xCF20, "7a070034"),
    "remove-notify": (0xD1D0, "88160094"),
    "completion": (0xC610, "40190094"),
}


class CoreStrings(policy.Shell):
    def __init__(self, binary):
        self.ready = False
        super().__init__(binary)
        self.helpers = set()
        self.ready = True

    def hook(self, u, pc, size, context):
        if self.ready:
            name = self.plts.get(pc, "")
            # The inherited FEC/UI harness has display-only doubles for these
            # names. Bypass them: here the strings decide configuration IDs.
            if ("QString3arg" in name or "QString6number" in name) and self.symbols.get(name):
                return self.jump(self.symbols[name])
            if name in ("memcpy", "memmove"):
                dest, source, count = [self.r(i) for i in range(3)]
                u.mem_write(dest, bytes(u.mem_read(source, count)))
                return self.ret(dest)
            if name == "memset":
                dest, value, count = [self.r(i) for i in range(3)]
                u.mem_write(dest, bytes([value & 255]) * count)
                return self.ret(dest)
            if name == "strlen":
                return self.ret(len(self.cstring(self.r(0)).encode()))
            if name == "calloc":
                count = self.r(0) * self.r(1)
                address = self.alloc(count)
                u.mem_write(address, bytes(count))
                return self.ret(address)
        return super().hook(u, pc, size, context)

    def text(self, holder):
        data = self.q(holder)
        offset = struct.unpack("<q", bytes(self.u.mem_read(data + 16, 8)))[0]
        return bytes(self.u.mem_read(data + offset, self.i(data + 4) * 2)).decode("utf-16le")

    def holder(self, text):
        address = self.alloc(8)
        self.wq(address, self.qstring(text))
        return address

    def helper(self, name, *params):
        address = self.symbols[name]
        assert address, ("original QString helper missing", name)
        self.helpers.add(name)
        return self.call(address, *params)


class Scan(policy.Shell):
    def __init__(self, binary, qt_core, mutation):
        self.ready = False
        super().__init__(binary)
        self.core = CoreStrings(qt_core)
        self.engine = self.alloc(128)
        self.backend = self.alloc(32)
        self.wq(self.engine + 0x40, self.backend)
        self.hash_header, self.buckets = self.alloc(0x40), self.alloc(8)
        self.wq(self.hash_header + 8, self.buckets)
        self.wi(self.hash_header + 0x20, 1)  # Explicit one-bucket, seed=0 storage.
        self.wq(self.engine + 0x10, self.hash_header)
        self.map_header = self.alloc(0x40)
        self.wi(self.map_header, 1)
        self.wq(self.engine + 0x48, self.map_header)
        self.configs, self.names, self.infos, self.interfaces = {}, {}, {}, {}
        self.events, self.observations = [], []
        self.lock_depth = {}
        self.scan_entries = 0
        self.refresh_hash()
        self.ready = True
        if mutation:
            address, signature = PATCHES[mutation]
            assert bytes(self.u.mem_read(address, 4)).hex() == signature, ("mutation-signature", mutation)
            self.u.mem_write(address, bytes.fromhex("1f2003d5"))

    def string(self, holder):
        data = self.q(holder)
        offset = struct.unpack("<q", bytes(self.u.mem_read(data + 16, 8)))[0]
        return bytes(self.u.mem_read(data + offset, self.i(data + 4) * 2)).decode("utf-16le")

    def qlist(self, values):
        data = self.alloc(16 + 8 * max(len(values), 1))
        self.wi(data, 1)
        self.wi(data + 4, max(len(values), 1))
        self.wi(data + 12, len(values))
        for index, value in enumerate(values):
            self.wq(data + 16 + index * 8, value)
        return data

    def hash_key(self, text, seed=0):
        return self.core.helper("_Z5qHashRK7QStringj", self.core.holder(text), seed)

    def refresh_hash(self):
        next_node = self.hash_header
        for identity, config in self.configs.items():
            node = self.alloc(32)
            self.wq(node, next_node)
            self.wi(node + 8, self.hash_key(identity))
            self.wq(node + 16, self.qstring(identity))
            self.wq(node + 24, config)
            next_node = node
        self.wq(self.buckets, next_node)
        self.wi(self.hash_header + 0x14, len(self.configs))

    def refresh_map(self):
        next_node = 0
        for identity in sorted(self.names, reverse=True):
            node = self.names[identity]
            self.wq(node + 8, 0)
            self.wq(node + 16, next_node)
            next_node = node
        self.wq(self.map_header + 0x10, next_node)

    def config_snapshot(self, config):
        identity = self.string(config + 24)
        return dict(identity=identity, name=self.string(config + 16), state=self.i(config + 32),
                    bearer=self.i(config + 44), valid=self.u.mem_read(config + 48, 1)[0],
                    interface=self.string(self.names[identity] + 32) if identity in self.names else None)

    def hook(self, u, pc, size, context):
        if not self.ready:
            return super().hook(u, pc, size, context)
        if pc == 0xC37C:
            self.scan_entries += 1
        name = self.plts.get(pc, "")
        # Storage providers own keys/values and references, not notification,
        # state selection or scan iteration/order. Inline lookups are original.
        if pc == 0xD3D4:
            self.wq(self.r(8), self.qlist([self.qstring(key) for key in self.configs]))
            return self.ret()
        if pc == 0x11068:
            self.observations.append(dict(kind="NetworkInfo-list", count=len(self.infos)))
            self.wq(self.r(8), self.qlist(list(self.infos)))
            return self.ret()
        if pc == 0xD72C:
            key, config = self.string(self.r(1)), self.q(self.r(2))
            assert key not in self.configs
            self.configs[key] = config
            self.wi(config, self.i(config) + 1)  # New stored owner.
            self.refresh_hash()
            return self.ret()
        if pc == 0xD93C:
            config = self.configs.pop(self.string(self.r(1)))
            self.wq(self.r(8), config)  # Transfer stored reference to result.
            self.refresh_hash()
            return self.ret()
        if pc == 0xE350:
            key, node = self.string(self.r(1)), self.alloc(40)
            assert key not in self.names
            self.wq(node + 24, self.q(self.r(1)))
            self.wq(node + 32, self.q(self.r(2)))
            self.names[key] = node
            self.refresh_map()
            return self.ret(node)
        if pc == 0xDBD8:
            self.names.pop(self.string(self.r(1)), None)
            self.refresh_map()
            return self.ret()
        if name in ("_ZN6QMutex4lockEv", "_ZN6QMutex6unlockEv"):
            address = self.r(0)
            delta = 1 if "4lock" in name else -1
            self.lock_depth[address] = self.lock_depth.get(address, 0) + delta
            assert self.lock_depth[address] >= 0, ("unbalanced fixture lock", hex(address))
            return self.ret()
        if name in ("_ZN15QRecursiveMutexC1Ev", "_ZN15QRecursiveMutexD1Ev",
                    "_ZN9QListData7disposeEPNS_4DataE"):
            return self.ret()
        if name == "_ZNK17QJNIObjectPrivate7isValidEv":
            return self.ret(int(self.infos[self.r(0)].get("valid", True)))
        if name in ("_ZNK17QJNIObjectPrivate10callMethodIiEET_PKc",
                    "_ZNK17QJNIObjectPrivate10callMethodIhEET_PKc"):
            method = self.cstring(self.r(1))
            field = {"getType": "type", "getSubtype": "subtype", "isAvailable": "available",
                     "isConnected": "connected"}[method]
            value = self.infos[self.r(0)].get(field, 0)
            self.observations.append(dict(kind="NetworkInfo-getter", method=method, value=value))
            return self.ret(value & 0xFFFFFFFFFFFFFFFF)
        if name == "_ZN17QNetworkInterface13allInterfacesEv":
            index = min(self.interface_queries, len(self.interface_snapshots) - 1)
            values = self.interface_snapshots[index]
            self.interface_queries += 1
            self.observations.append(dict(kind="interfaces", count=len(values)))
            self.wq(self.r(8), self.qlist(values))
            return self.ret()
        if name == "_ZN17QNetworkInterfaceD1Ev":
            return self.ret()
        if name == "_ZN17QNetworkInterfaceC1ERKS_":
            self.wq(self.r(0), self.q(self.r(1)))
            return self.ret()
        if name in ("_ZNK17QNetworkInterface7isValidEv", "_ZNK17QNetworkInterface5flagsEv",
                    "_ZNK17QNetworkInterface14addressEntriesEv", "_ZNK17QNetworkInterface4nameEv"):
            interface = self.interfaces[self.q(self.r(0))]
            self.observations.append(dict(kind="interface-getter", method=name, interface=interface["name"]))
            if "isValid" in name:
                return self.ret(int(interface.get("valid", True)))
            if "flags" in name:
                return self.ret(interface.get("flags", 2))
            if "addressEntries" in name:
                self.wq(self.r(8), self.qlist([0] * interface.get("addresses", 1)))
            else:
                self.wq(self.r(8), self.qstring(interface["name"]))
            return self.ret()
        if name == "_ZN20QNetworkAddressEntryD1Ev":
            return self.ret()
        if name == "_ZN9QListData5eraseEPPv":
            header, slot = self.q(self.r(0)), self.r(1)
            end = header + 16 + 8 * self.i(header + 12)
            u.mem_write(slot, bytes(u.mem_read(slot + 8, end - slot - 8)))
            self.wi(header + 12, self.i(header + 12) - 1)
            return self.ret()
        if name == "_ZN7QString17fromLatin1_helperEPKci":
            text = bytes(u.mem_read(self.r(0), self.r(1)))
            address = self.core.alloc(len(text) + 1)
            self.core.u.mem_write(address, text + b"\0")
            data = self.core.helper(name, address, len(text))
            holder = self.core.alloc(8)
            self.core.wq(holder, data)
            return self.ret(self.qstring(self.core.text(holder)))
        if name in ("_ZeqRK7QStringS1_", "_ZltRK7QStringS1_", "_Z5qHashRK7QStringj"):
            first = self.core.holder(self.string(self.r(0)))
            second = self.r(1) if "qHash" in name else self.core.holder(self.string(self.r(1)))
            return self.ret(self.core.helper(name, first, second))
        if name == "_ZN7QStringaSERKS_":
            first = self.core.holder(self.string(self.r(0)))
            second = self.core.holder(self.string(self.r(1)))
            self.core.helper(name, first, second)
            self.wq(self.r(0), self.qstring(self.core.text(first)))
            return self.ret(self.r(0))
        if name in ("_ZNK7QString3argERKS_i5QChar", "_ZN7QString6numberEji"):
            out = self.core.alloc(8)
            self.core.u.reg_write(policy.UC_ARM64_REG_X0 + 8, out)
            if "3arg" in name:
                params = (self.core.holder(self.string(self.r(0))),
                          self.core.holder(self.string(self.r(1))), self.r(2), self.r(3))
            else:
                params = (self.r(0), self.r(1))
            self.core.helper(name, *params)
            self.wq(self.r(8), self.qstring(self.core.text(out)))
            return self.ret()
        if name.startswith("_ZN13QBearerEngine"):
            assert not self.lock_depth.get(self.engine + 0x28, 0), "signal outside engine lock"
            if "updateCompleted" in name:
                self.events.append(dict(kind="complete"))
            else:
                kind = {"configurationAdded": "added", "configurationChanged": "changed",
                        "configurationRemoved": "removed"}
                matches = [value for token, value in kind.items() if token in name]
                assert len(matches) == 1, ("unexpected bearer signal", name)
                self.events.append(dict(kind=matches[0], **self.config_snapshot(self.q(self.r(1)))))
            return self.ret()
        return super().hook(u, pc, size, context)

    def scan(self, infos, interfaces, retry_interfaces=None, backend=True):
        self.wq(self.engine + 0x40, self.backend if backend else 0)
        self.infos = {self.alloc(16): value for value in infos}
        self.interfaces = {}
        self.interface_snapshots = []
        for snapshot in (interfaces, interfaces if retry_interfaces is None else retry_interfaces):
            values = {self.alloc(8): value for value in snapshot}
            self.interfaces.update(values)
            self.interface_snapshots.append(list(values))
        self.interface_queries = 0
        before, observations = len(self.events), len(self.observations)
        self.call(0xC37C, self.engine)
        assert all(value == 0 for value in self.lock_depth.values()), "scan lock balance"
        assert all(self.i(value) == 1 for value in self.configs.values()), "stored config reference balance"
        return dict(events=self.events[before:], observations=self.observations[observations:],
                    interface_queries=self.interface_queries,
                    configurations=[self.config_snapshot(value) for value in self.configs.values()])


class ConfigurationDelivery(bridge.Configuration):
    def hook(self, u, pc, size, context):
        if self.enabled and self.plts.get(pc) == "_ZN11QMetaObject8activateEP7QObjectPKS_iPPv":
            if self.r(2) in (0, 1):
                assert self.r(0) == self.owner and self.r(1) == 0x3A5040
                config = self.q(self.q(self.r(3) + 8))
                self.events.append(dict(kind="added" if self.r(2) == 0 else "removed",
                    identity=self.qt_strings[self.q(config + 0x18)], state=self.i(config + 0x20),
                    valid=self.u.mem_read(config + 0x30, 1)[0], active=sorted(self.active)))
                return self.ret()
        return super().hook(u, pc, size, context)

    def deliver(self, event):
        if event["kind"] == "complete":
            return []
        config = self.alloc(0x40)
        self.wi(config, 100)
        self.wq(config + 0x10, self.qstring(event["name"]))
        self.wq(config + 0x18, self.qstring(event["identity"]))
        self.wi(config + 0x20, event["state"])
        self.b(config + 0x30, event["valid"])
        reference = self.alloc(8)
        self.wq(reference, config)
        prefix = {"added": "18configurationAdded", "changed": "20configurationChanged",
                  "removed": "20configurationRemoved"}[event["kind"]]
        name = "_ZN35QNetworkConfigurationManagerPrivate" + prefix + "E28QExplicitlySharedDataPointerI28QNetworkConfigurationPrivateE"
        before = len(self.events)
        self.call(self.symbols[name], self.owner, reference)
        assert self.i(config) == 100, "manager temporary reference balance"
        return self.events[before:]


def audit(args):
    binaries = {name: getattr(args, name).read_bytes() for name in ("bearer", "qt", "qt_core")}
    for name, binary in binaries.items():
        expected = QT_CORE_SHA if name == "qt_core" else watchers.SHA[name]
        assert hashlib.sha256(binary).hexdigest() == expected, name
    wifi = dict(type=1, available=1, connected=1)
    mobile = dict(type=0, subtype=13, available=1, connected=1)
    wlan = dict(name="wlan0")
    def step(infos, interfaces, expected, online, **kwargs):
        return dict(infos=infos, interfaces=interfaces, expected=expected, online=online, **kwargs)
    # Expected rows are concrete notification sequences, not a reimplementation
    # of the scan's predicates. Tuple rows are kind/name/state/bearer.
    programs = [("continuous-handover", [
        step([], [], [], []),
        step([wifi], [wlan], [("added", "WiFi", 14, 2)], [1]),
        step([wifi], [wlan], [], []),
        step([wifi], [dict(name="wlan0", addresses=2)], [], []),
        step([mobile], [dict(name="rmnet0")], [("added", "Mobile", 14, 10), ("removed", "WiFi", 14, 2)], []),
        step([mobile], [dict(name="rmnet1")], [("added", "Mobile", 14, 10), ("removed", "Mobile", 14, 10)], []),
        step([], [], [("removed", "Mobile", 14, 10)], [0]),
    ]), ("inactive-transition", [
        step([wifi], [wlan], [("added", "WiFi", 14, 2)], [1]),
        step([dict(type=1)], [], [("added", "WiFi", 2, 2), ("removed", "WiFi", 14, 2)], [0]),
        step([dict(type=1)], [], [], []),
        step([wifi], [wlan], [("added", "WiFi", 14, 2), ("removed", "WiFi", 2, 2)], [1]),
    ]), ("gap-handover", [
        step([wifi], [wlan], [("added", "WiFi", 14, 2)], [1]),
        step([], [], [("removed", "WiFi", 14, 2)], [0]),
        step([mobile], [dict(name="rmnet0")], [("added", "Mobile", 14, 10)], [1]),
    ]), ("backend-unavailable", [step([], [], [], [], backend=False), step([], [], [], [])])]
    for label, info, interfaces in (
        ("unavailable", dict(type=1, connected=1), [wlan]),
        ("disconnected", dict(type=1, available=1), [wlan]),
        ("no-interface", wifi, []),
        ("invalid-interface", wifi, [dict(name="wlan0", valid=False)]),
        ("flag3-interface", wifi, [dict(name="wlan0", flags=10)]),
        ("no-flag1-interface", wifi, [dict(name="wlan0", flags=1)]),
        ("no-address", wifi, [dict(name="wlan0", addresses=0)]),
    ):
        programs.append((label, [step([info], interfaces, [("added", "WiFi", 2, 2)], [])]))
    programs.extend([
        ("inactive-removed", [
            step([dict(type=1)], [], [("added", "WiFi", 2, 2)], []),
            step([], [], [("removed", "WiFi", 2, 2)], [0]),
        ]),
        ("interface-fallback", [step([wifi], [dict(name="bad", flags=8), dict(name="empty", addresses=0), wlan], [("added", "WiFi", 14, 2)], [1])]),
        ("interface-query-retry", [step([wifi], [], [("added", "WiFi", 14, 2)], [1], retry_interfaces=[wlan])]),
        ("invalid-networkinfo", [step([dict(type=1, valid=False)], [wlan], [], [])]),
        ("wifi-first-one-interface", [step([wifi, mobile], [wlan], [("added", "WiFi", 14, 2), ("added", "Mobile", 2, 10)], [1])]),
        ("mobile-first-one-interface", [step([mobile, wifi], [wlan], [("added", "Mobile", 14, 10), ("added", "WiFi", 2, 2)], [1])]),
        ("same-id-state-change", [
            step([dict(type=1)], [], [("added", "WiFi", 2, 2)], []),
            step([wifi], [dict(name="")], [("changed", "WiFi", 14, 2)], [1]),
            step([dict(type=1)], [], [("changed", "WiFi", 2, 2)], [0]),
        ]),
        ("mobile-subtype-change", [
            step([dict(type=0, subtype=1)], [], [("added", "Mobile", 2, 3)], []),
            step([dict(type=0, subtype=13)], [], [("changed", "Mobile", 2, 10)], []),
        ]),
    ])
    for network_type, name, bearer in ((0, "Mobile", 2), (1, "WiFi", 2), (6, "WiMax", 8),
                                      (7, "Bluetooth", 7), (9, "Ethernet", 1)):
        programs.append((f"type-{network_type}", [step([dict(type=network_type)], [], [("added", name, 2, bearer)], [])]))
    for network_type in (2, 3, 4, 5, 8, 10, -1):
        programs.append((f"unsupported-type-{network_type}", [step([dict(type=network_type)], [], [], [])]))
    cases = []
    for name, operations in programs:
        scan = Scan(binaries["bearer"], binaries["qt_core"], args.mutation)
        manager = ConfigurationDelivery(binaries["qt"], None)
        stages = []
        for operation in operations:
            inputs = {key: value for key, value in operation.items() if key not in ("expected", "online")}
            observed = scan.scan(**inputs)
            events = observed["events"]
            rows = [(event["kind"], event["name"], event["state"], event["bearer"])
                    for event in events if event["kind"] != "complete"]
            assert rows == operation["expected"], (name, "configuration sequence", rows, operation["expected"])
            assert [event["kind"] for event in events].count("complete") == int(inputs.get("backend", True)), (name, "completion signal")
            if inputs.get("backend", True):
                assert events[-1]["kind"] == "complete", (name, "completion order")
            delivered = [entry for event in events for entry in manager.deliver(event)]
            online = [entry["value"] for entry in delivered if entry["kind"] == "online"]
            assert online == operation["online"], (name, "manager online sequence", online, operation["online"])
            assert set(manager.active) == {event["identity"] for event in observed["configurations"] if event["state"] == 14}, (name, "manager active membership")
            if name == "interface-query-retry":
                assert observed["interface_queries"] == 2, "empty interface enumeration retry"
            stages.append(dict(inputs=inputs, observed=observed, manager_events=delivered, online=online))
        cases.append(dict(name=name, stages=stages, original_scan_entries=scan.scan_entries,
                          original_core_helpers={symbol: hex(scan.core.symbols[symbol])
                                                 for symbol in sorted(scan.core.helpers)}))
    ranges = {"bearer": ((0xC37C, 0xD3D0),),
              "qt": ((0x18F814, 0x18FA24), (0x18FA24, 0x18FBC4), (0x18FBC4, 0x18FDA4))}
    original_ranges = {}
    for name, intervals in ranges.items():
        image = policy.load_image(binaries[name])[0]
        original_ranges[name] = {hex(start): dict(size=end - start,
            sha256=hashlib.sha256(image[start:end]).hexdigest()) for start, end in intervals}
    return dict(scope=__doc__, identities={name: hashlib.sha256(binary).hexdigest() for name, binary in binaries.items()},
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                inherited_sha256={str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                  for path in (SOURCE, bridge.SOURCE, watchers.SOURCE, ROOT / "scripts/audit-steam-client-fec-policy.py")},
                original_ranges=original_ranges, cases=cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("qt", "bearer", "qt-core"):
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
