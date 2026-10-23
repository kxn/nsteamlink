#!/usr/bin/env python3
"""Audit bundled Android network notifications, Qt accessibility and shell slot.

Pinned original DEX is statically disassembled, not run in Android. Original
bearer JNI registration executes with explicit class/VM adapters. A warm native
entry executes through its original signal method; its singleton is fixture-
provided. Original Qt meta dispatch/private online-state slot execute;
Qt configuration/session reconciliation, object lifetime and activation delivery
are explicit terminals. Emitted values separately enter the original shell meta
dispatch/startup paths. This is NOT a natural OS/Qt event loop, bearer-engine
configuration scan, network switch, DNS invalidation or session reconnection.
The HandleNetworkChanged inventory covers direct B/BL and ELF relocation
references only, NOT all possible indirect/dlsym/external callers.
"""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import struct
import subprocess

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts/audit-steam-network-discovery.py"
spec = importlib.util.spec_from_file_location("discovery", SOURCE)
discovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(discovery)
SHA = dict(
    qt="7db24b7f4443ed0329986ca6e96bbbd0b15a195b949155c667ee8386b4ec6e0a",
    bearer="b3dc5f7bb6926b289d50d898efa84fa584f05670b3a5b6a3313bad1dbfa7058c",
    dex="a5c315d683eac7c7f8f73ec096bd414406d80f9ef68180a1ef469f052cd39e44",
    shell="15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2",
    core="50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e",
)
PATCHES = {
    "permission": (0x11EE34, "88020034"),
    "online-duplicate": (0x11EE40, "20020054"),
    "offline-duplicate": (0x11EE58, "68010034"),
    "notification": (0x11EE80, "b0e30994"),
}


def qt_metadata(binary, address):
    image, symbols, _, _ = discovery.policy.load_image(binary)
    _, strings, data, metacall = struct.unpack_from("<4Q", image, address)
    revision, _, _, _, count, offset = struct.unpack_from("<6I", image, data)
    assert revision == 8 and count <= 32
    methods = []
    for index in range(count):
        string_index, argc, params, tag, flags = struct.unpack_from(
            "<5I", image, data + (offset + index * 5) * 4)
        entry = strings + string_index * 24
        length = struct.unpack_from("<I", image, entry + 4)[0]
        displacement = struct.unpack_from("<q", image, entry + 16)[0]
        assert length <= 256
        methods.append(dict(id=index, name=image[entry + displacement:entry + displacement + length].decode(),
                            argc=argc, flags=flags))
    return dict(address=hex(address), static_metacall=hex(metacall), methods=methods)


class QtWatcher(discovery.policy.Shell):
    def __init__(self, binary, mutation):
        self.enabled = False
        super().__init__(binary)
        self.public, self.private = self.alloc(64), self.alloc(512)
        self.wq(self.public + 8, self.private)
        self.wq(self.private + 8, self.public)
        self.signals = []
        self.terminals = []
        self.original = set()
        self.configuration_state = 14
        self.enabled = True
        if mutation:
            address, signature = PATCHES[mutation]
            assert bytes(self.u.mem_read(address, 4)) == bytes.fromhex(signature), (
                "mutation-signature", mutation)
            self.u.mem_write(address, bytes.fromhex("1f2003d5"))  # ARM64 NOP.

    def hook(self, u, pc, size, context):
        if not self.enabled:
            return super().hook(u, pc, size, context)
        if pc in (0x11FA1C, 0x11F3A8, 0x11ED94, 0x1B2A00):
            self.original.add(hex(pc))
        name = self.plts.get(pc, "")
        if name == "_ZN7QObject11qt_metacallEN11QMetaObject4CallEiPPv":
            return self.ret(self.r(2))  # Already resolved inherited QObject IDs.
        if name == "_ZN11QMetaObject8activateEP7QObjectPKS_iPPv":
            assert self.r(0) == self.public and self.r(2) == 7
            self.signals.append(self.i(self.q(self.r(3) + 8)))
            return self.ret()
        if pc in (0x11E8C4, 0x11B110):
            # Qt's internal network session/configuration work is not discovery
            # policy, DNS invalidation or a whole-HTTP-lifetime proof here.
            self.terminals.append(hex(pc))
            return self.ret()
        if name == "_ZNK21QNetworkAccessManager13configurationEv":
            self.wq(self.r(8), 0)
            return self.ret()
        if name == "_ZN21QNetworkConfigurationD1Ev":
            return self.ret()
        if name == "_ZNK21QNetworkConfiguration5stateEv":
            return self.ret(self.configuration_state)
        return super().hook(u, pc, size, context)

    def event(self, incoming):
        argv, value = self.alloc(16), self.alloc(4)
        self.wi(value, incoming)
        self.wq(argv + 8, value)
        self.call(0x11FA1C, self.public, 0, 17, argv)
        assert {"0x11fa1c", "0x11f3a8", "0x11ed94", "0x1b2a00"} <= self.original
        return dict(access=self.i(self.private + 0xCC),
                    online=self.u.mem_read(self.private + 0xD4, 1)[0],
                    signals=list(self.signals), terminals=list(self.terminals), original=sorted(self.original))


class BearerNotification(discovery.policy.Shell):
    def __init__(self, binary):
        self.enabled = False
        super().__init__(binary)
        self.singleton = self.alloc(32)
        self.wq(0x1C3A8, self.singleton)
        self.b(0x1C3B0, 1)  # Declared completed singleton initialization.
        self.signals = []
        self.original = set()
        self.registrations = []
        self.local_refs_deleted = []
        self.class_valid = True
        self.registration_result = 0
        self.environment, table = self.alloc(16), self.alloc(0x700)
        self.wq(self.environment, table)
        for offset, target, callback in (
            (0xF8, discovery.policy.STOP + 0x100, self.object_class),
            (0x6B8, discovery.policy.STOP + 0x200, self.register_natives),
            (0xB8, discovery.policy.STOP + 0x300, self.delete_local_ref),
        ):
            self.wq(table + offset, target)
            self.callbacks[target] = callback
        self.enabled = True

    def object_class(self):
        assert self.r(0) == self.environment and self.r(1) == 0x501
        self.ret(0x701)

    def register_natives(self):
        assert self.r(0) == self.environment and self.r(1) == 0x701 and self.r(3) == 1
        table = self.r(2)
        self.registrations.append(dict(name=self.cstring(self.q(table)),
                                       signature=self.cstring(self.q(table + 8)),
                                       entry=hex(self.q(table + 16))))
        self.ret(self.registration_result & 0xFFFFFFFF)

    def delete_local_ref(self):
        assert self.r(0) == self.environment
        self.local_refs_deleted.append(self.r(1))
        self.ret()

    def hook(self, u, pc, size, context):
        if self.enabled:
            if pc in (0x10C80, 0x11660, 0x12384):
                self.original.add(hex(pc))
            name = self.plts.get(pc, "")
            if name == "_ZN17QJNIObjectPrivateC1EPKc":
                assert self.cstring(self.r(1)) == "org/qtproject/qt5/android/bearer/QtNetworkReceiver"
                holder = self.alloc(16)
                self.wq(holder, 0x501)
                self.wq(self.r(0), holder)
                self.wq(self.r(0) + 8, 0)  # No owning reference in this JNI fixture.
                return self.ret()
            if name == "_ZNK17QJNIObjectPrivate7isValidEv":
                return self.ret(int(self.class_valid))
            if self.plts.get(pc) == "_ZN11QMetaObject8activateEP7QObjectPKS_iPPv":
                assert self.r(0) == self.singleton and self.r(1) == 0x175F0
                assert self.r(2) == 0 and self.r(3) == 0
                self.signals.append("activeNetworkChanged")
                return self.ret()
        return super().hook(u, pc, size, context)


def dex_evidence(path, dexdump):
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SHA["dex"]
    dump = subprocess.run([str(dexdump.resolve()), "-d", str(path.resolve())], check=True,
                          capture_output=True, text=True, timeout=60).stdout
    methods = []
    for cls, name in (
        ("org.qtproject.qt5.android.bearer.QtNetworkReceiver$BroadcastReceiverPrivate", "onReceive"),
        ("org.qtproject.qt5.android.bearer.QtNetworkReceiver", "access$000"),
        ("org.qtproject.qt5.android.bearer.QtNetworkReceiver", "registerReceiver"),
    ):
        pattern = (r"^([0-9a-f]+):\s+\|\[[0-9a-f]+\] " + re.escape(cls + "." + name)
                   + r":([^\n]+)\n(.*?)(?=^      catches)")
        matches = list(re.finditer(pattern, dump, re.M | re.S))
        assert len(matches) == 1, (cls, name)
        item = matches[0]
        offset = int(item[1], 16)
        count = struct.unpack_from("<I", raw, offset + 12)[0]
        code = raw[offset + 16:offset + 16 + count * 2]
        methods.append(dict(cls=cls, name=name, signature=item[2], offset=hex(offset),
                            code=code.hex(), disassembly=item[3].splitlines()))
    assert methods[0]["code"] == "7100c40900000e00"
    assert methods[1]["code"] == "7100c50900000e00"
    assert "QtNetworkReceiver;.access$000:()V" in "\n".join(methods[0]["disassembly"])
    assert "QtNetworkReceiver;.activeNetworkInfoChanged:()V" in "\n".join(methods[1]["disassembly"])
    registration = "\n".join(methods[2]["disassembly"])
    assert '"android.net.conn.CONNECTIVITY_CHANGE"' in registration
    assert "Context;.registerReceiver:" in registration
    return dict(scope="static pinned DEX only; no Android delivery or JVM execution",
                dexdump_sha256=hashlib.sha256(dexdump.read_bytes()).hexdigest(), methods=methods)


def reference_inventory(binary):
    """Limited direct-call/relocation inventory, never proof of no indirect use."""
    elf = ELFFile(io.BytesIO(binary))
    dyn = elf.get_section_by_name(".dynsym")
    name = "_ZN14CServerManager20HandleNetworkChangedEv"
    symbol = next(s for s in dyn.iter_symbols() if s.name == name)
    target = symbol["st_value"]
    aliases = {target}
    plt = elf.get_section_by_name(".plt")["sh_addr"]
    for index, relocation in enumerate(elf.get_section_by_name(".rela.plt").iter_relocations()):
        if dyn.get_symbol(relocation["r_info_sym"]).name == name:
            aliases.add(plt + 32 + index * 16)
    relocations, branches = [], []
    for section in elf.iter_sections():
        if section["sh_type"] in ("SHT_REL", "SHT_RELA"):
            for relocation in section.iter_relocations():
                entry = dyn.get_symbol(relocation["r_info_sym"]) if relocation["r_info_sym"] else None
                if ((entry is not None and entry.name == name)
                        or (relocation["r_info_type"] == 1027 and relocation["r_addend"] == target)):
                    relocations.append(hex(relocation["r_offset"]))
        if section["sh_type"] != "SHT_PROGBITS" or not section["sh_flags"] & 4:
            continue
        data = section.data()
        for index, (word,) in enumerate(struct.iter_unpack("<I", data[:len(data) // 4 * 4])):
            if word & 0x7C000000 != 0x14000000:
                continue
            displacement = word & 0x3FFFFFF
            if displacement & (1 << 25):
                displacement -= 1 << 26
            pc = section["sh_addr"] + index * 4
            if pc + displacement * 4 in aliases:
                branches.append(hex(pc))
    return dict(target=hex(target), direct_branch_aliases=sorted(map(hex, aliases)),
                direct_b_bl_references=branches, relocation_references=relocations,
                exclusions="register-indirect/ADRP address construction/dlsym/external callers not ruled out")


def audit(args):
    binaries = {name: getattr(args, name).read_bytes() for name in SHA}
    for name, binary in binaries.items():
        assert hashlib.sha256(binary).hexdigest() == SHA[name], name
    metadata = qt_metadata(binaries["qt"], 0x3A0DE0)
    assert metadata["methods"][17]["name"] == "_q_onlineStateChanged"
    assert metadata["methods"][7]["name"] == "networkAccessibleChanged"
    assert metadata["static_metacall"] == "0x11f3a8"
    bearer_metadata = qt_metadata(binaries["bearer"], 0x175F0)
    assert bearer_metadata["methods"][0]["name"] == "activeNetworkChanged"
    bearer = BearerNotification(binaries["bearer"])
    table = 0x1BF08
    native = [bearer.q(table + 8 * index) for index in range(3)]
    assert bearer.cstring(native[0]) == "activeNetworkInfoChanged"
    assert bearer.cstring(native[1]) == "()V" and native[2] == 0x11660
    assert bearer.call(0x10C80, 0, bearer.environment) == 1
    assert bearer.registrations == [dict(name="activeNetworkInfoChanged", signature="()V", entry="0x11660")]
    assert bearer.local_refs_deleted == [0x701]
    bearer.call(native[2], 0x101, 0x102)
    assert bearer.signals == ["activeNetworkChanged"] and bearer.original == {"0x10c80", "0x11660", "0x12384"}
    registration_cases = []
    for valid, result in ((True, 0), (True, -1), (False, 0)):
        n = BearerNotification(binaries["bearer"])
        n.class_valid, n.registration_result = valid, result
        returned = n.call(0x10C80, 0, n.environment)
        assert returned == int(valid and result == 0)
        assert len(n.registrations) == int(valid) and len(n.local_refs_deleted) == int(valid)
        registration_cases.append(dict(valid=valid, registration_return=result, returned=returned,
                                       methods=n.registrations, local_refs_deleted=n.local_refs_deleted))
    dex = dex_evidence(args.dex, args.dexdump)
    cases = []
    for access in (0xFFFFFFFF, 0, 1):
        for previous in (0, 1):
            for allowed in (0, 1):
                for incoming in (0, 1):
                    q = QtWatcher(binaries["qt"], args.mutation)
                    q.wi(q.private + 0xCC, access)
                    q.b(q.private + 0xD4, previous)
                    q.b(q.private + 0xD7, allowed)
                    observed = q.event(incoming)
                    selected = 0 if incoming == 0 else 1 if allowed else access
                    expected = [selected] if selected != access else []
                    assert observed["signals"] == expected, ("accessibility notification", access,
                                                             previous, allowed, incoming, observed)
                    assert observed["access"] == selected and observed["online"] == incoming
                    cases.append(dict(input=dict(access=access, previous=previous, allowed=allowed,
                                                 incoming=incoming), observed=observed))
    for config_state in (0, 1, 2, 4, 8, 14):
        q = QtWatcher(binaries["qt"], args.mutation)
        q.b(q.private + 0xC8, 1)
        q.b(q.private + 0xD7, 1)
        q.configuration_state = config_state
        selected = int(bool(config_state & 14))
        observed = q.event(1 - selected)
        assert observed["signals"] == ([1] if selected else []), ("configured state", config_state, observed)
        assert observed["access"] == selected and observed["online"] == selected
        cases.append(dict(input=dict(configuration_state=config_state, incoming=1 - selected), observed=observed))
    deliveries = []
    # Use actual emitted values and absence from the Qt matrix. The explicit
    # activation-delivery adapter does not assert event-loop timing/causality.
    patterns = sorted({tuple(case["observed"]["signals"]) for case in cases})
    assert patterns == [(), (0,), (1,)]
    for events in patterns:
        for state in (0, 1, 4, 5):
            d = discovery.Discovery(binaries["shell"], state)
            for event in events:
                argv, value = d.alloc(16), d.alloc(4)
                d.wi(value, event)
                d.wq(argv + 8, value)
                d.run("meta_dispatch", d.watcher, 0, 1, argv)
            expected = int(bool(events) and state == 0)
            assert d.calls["start"] == expected and not d.calls["network_api"]
            assert d.i(d.manager + 8) == (1 if expected else state)
            deliveries.append(dict(input=dict(events=events, manager_state=state), observed=d.snapshot()))
    inventories = {name: reference_inventory(binaries[name]) for name in ("core", "shell")}
    assert all(not item["direct_b_bl_references"] and not item["relocation_references"]
               for item in inventories.values())
    ranges = {}
    for name, intervals in (("qt", ((0x11FA1C, 0x100), (0x11F3A8, 0x5FC), (0x11ED94, 0x118))),
                            ("bearer", ((0x10C80, 0x118), (0x11660, 0x68), (0x12384, 0x14)))):
        image = discovery.policy.load_image(binaries[name])[0]
        ranges[name] = {hex(start): dict(size=size, sha256=hashlib.sha256(image[start:start + size]).hexdigest())
                        for start, size in intervals}
    return dict(scope=__doc__, identities=SHA, tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                original_ranges=ranges,
                inherited_sha256={str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                  for path in (SOURCE, ROOT / "scripts/audit-steam-client-fec-policy.py")},
                dex=dex, qt_metadata=metadata, bearer_metadata=bearer_metadata,
                bearer_native=dict(table=hex(table), entry=hex(native[2]), signals=bearer.signals,
                                   original=sorted(bearer.original), registration_cases=registration_cases),
                qt_cases=cases, shell_deliveries=deliveries, limited_reference_inventory=inventories)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (*SHA, "dexdump"):
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
