#!/usr/bin/env python3
"""Execute Qt public session and rebased bundled Android backend in one VM.

Public ctor, engine membership/state methods, backend ctor/sync/open/close/error
and factory/cache/selector integration run original instructions. The bearer
image is rebased with its ELF relocations and imported QtNetwork data/functions.
Manager engine enumeration, engine table contents, QObject base/cast/bindings,
locks and warm registration are providers. Signals copy args/bindings at emit;
explicit delivery occurs after producer return, not as a claimed Qt event loop.
Service-network children are empty fixture input. No Android/JNI enumeration,
network route, HTTP/DNS, real QObject destruction or Switch runtime is claimed.
"""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/steam-session-pool-audit.py"
spec = importlib.util.spec_from_file_location("pool", SOURCE)
pool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pool)
policy, watchers = pool.policy, pool.access.watchers
BASE = 0x1000000  # Fixture load base inside the existing VM; no wire meaning.
PATCHES = {
    "empty-id": ("qt", 0x18B80C, "f5110034", "1f2003d5"),
    "engine-match": ("qt", 0x18B8B4, "b6000037", "1f2003d5"),
    "sync-call": ("qt", 0x18B8F8, "00013fd6", "1f2003d5"),
    "engine-ready": ("bearer", 0xBD54, "880300b4", "1f2003d5"),
    "active-state": ("bearer", 0xBD70, "81010054", "1f2003d5"),
    "open-flag": ("bearer", 0xEEC0, "68d20039", "1f2003d5"),
    "open-repeat": ("bearer", 0xEDD0, "48010036", "0a000014"),
    "connect-rejection": ("bearer", 0xBC7C, "42008052", "02008052"),
    "error-map": ("bearer", 0xFCE0, "61008052", "01008052"),
}


class Backend(pool.Pool):
    def __init__(self, qt, qt_core, bearer, mutation=None):
        self.backend_enabled = False
        super().__init__(qt, qt_core)
        image, _, plts, _ = policy.load_image(bearer)
        image = bytearray(image)
        elf, qt_elf = ELFFile(io.BytesIO(bearer)), ELFFile(io.BytesIO(qt))
        assert max(s["p_vaddr"] + s["p_memsz"] for s in qt_elf.iter_segments()
                   if s["p_type"] == "PT_LOAD") < BASE
        dyn = elf.get_section_by_name(".dynsym")
        for relocation in elf.get_section_by_name(".rela.dyn").iter_relocations():
            symbol = dyn.get_symbol(relocation["r_info_sym"])
            typ, value = relocation["r_info_type"], None
            if typ == 1027:
                value = BASE + relocation["r_addend"]
            elif typ in (257, 1025):
                if symbol["st_value"]:
                    value = BASE + symbol["st_value"] + relocation["r_addend"]
                elif self.symbols.get(symbol.name):
                    value = self.symbols[symbol.name] + relocation["r_addend"]
                elif "shared_null" in symbol.name:
                    value = self.empty
            if value is not None:
                struct.pack_into("<Q", image, relocation["r_offset"], value)
        for segment in elf.iter_segments():
            if segment["p_type"] == "PT_LOAD":
                start = segment["p_vaddr"]
                self.u.mem_write(BASE + start, bytes(image[start:start + segment["p_memsz"]]))
        self.plts.update({BASE + address: name for address, name in plts.items()})
        self.engines, self.emitted, self.session_objects, self.backend_trace = [], [], [], []
        self.manager, self.manager_present = self.alloc(32), True
        self.engine_calls, self.forwarded = [], []
        self.cursor = 0
        for offset in (0x3E9914, 0x3E9A58, 0x3E9918):
            self.wi(offset, 100)  # Warm session metatype registration.
        self.b(BASE + 0x1C390, 1)
        self.wi(BASE + 0x1C398, -1)
        self.wi(BASE + 0x1C39C, 100)
        self.wi(BASE + 0x1C3A0, 100)
        self.metas = {address: watchers.qt_metadata(qt, address) for address in (0x3A50F8, 0x3A2228)}
        self.metas.update({BASE + address: watchers.qt_metadata(bearer, address)
                           for address in (0x174D8, 0x171B8)})
        self.impl_meta = watchers.qt_metadata(bearer, 0x17388)
        assert self.impl_meta["methods"][3]["name"] == "connectionError"
        if mutation:
            kind, address, signature, replacement = PATCHES[mutation]
            address += BASE if kind == "bearer" else 0
            assert bytes(self.u.mem_read(address, 4)).hex() == signature, ("mutation-signature", mutation)
            self.u.mem_write(address, bytes.fromhex(replacement))
        self.backend_enabled = True

    def qlist(self, values):
        data = self.alloc(16 + 8 * max(1, len(values)))
        self.wi(data, -1)  # Borrowed immutable list; not a Qt allocator proof.
        self.wi(data + 12, len(values))
        for index, value in enumerate(values):
            self.wq(data + 16 + index * 8, value)
        return data

    def add_engine(self, config, contains=True, available=True, cast=True):
        engine = self.alloc(128)
        self.wq(engine, BASE + 0x172B0)  # Original engine vtable address point.
        self.wq(engine + 0x40, self.alloc(32) if available else 0)
        identity = self.string(self.q(config) + 24) if contains else "unrelated"
        mapping = self.alloc(0x40)
        self.wi(mapping, 1)
        self.wq(engine + 0x48, mapping)
        node = self.alloc(40)
        self.wq(node + 24, self.qstring(identity))
        self.wq(node + 32, self.qstring("wlan0"))
        self.wq(mapping + 16, node)
        header, buckets, node = self.alloc(0x40), self.alloc(8), self.alloc(32)
        self.wq(engine + 0x10, header)
        self.wq(header + 8, buckets)
        self.wi(header + 0x20, 1)
        self.wq(node, header)
        self.wi(node + 8, self.core.helper("_Z5qHashRK7QStringj", self.core.holder(identity), 0))
        self.wq(node + 16, self.qstring(identity))
        self.wq(node + 24, self.q(config))
        self.wq(buckets, node)
        self.wi(header + 20, 1)
        self.engines.append(dict(pointer=engine, cast=cast))
        return engine

    def hook(self, u, pc, size, context):
        if self.backend_enabled:
            offset = pc - BASE
            if offset in (0xBE80, 0xE868, 0xF964, 0xED68, 0xEF0C, 0xFC4C):
                self.backend_trace.append(hex(offset))
            if offset in (0xBBE0, 0xBC8C, 0xBC7C, 0xBC84):
                self.engine_calls.append(dict(method=hex(offset), engine=hex(self.r(0))))
            name = self.plts.get(pc, "")
            if name == "_ZN15QNetworkSessionC1ERK21QNetworkConfigurationP7QObject":
                return self.jump(self.symbols[name])  # Bypass parent ctor terminal.
            if name == "_ZN15QtSharedPointer20ExternalRefCountData16setQObjectSharedEPK7QObjectb":
                pointer = self.r(1)
                backend = self.q(pointer + 16)
                self.sessions[pointer] = dict(config=backend + 24 if backend else self.default,
                    state=self.i(backend + 48) if backend else 0, control=self.r(0))
                self.created.append(pointer)
                if pointer not in self.session_objects:
                    self.session_objects.append(pointer)
                return self.ret()
            if name in ("_ZNK15QNetworkSession13configurationEv", "_ZNK15QNetworkSession5stateEv"):
                return self.jump(self.symbols[name])  # Read live backend state.
            if name == "_ZN7QObjectC2EPS_":
                private = self.alloc(64)
                self.wq(self.r(0) + 8, private)
                self.wq(private + 8, self.r(0))
                return self.ret()
            if name in ("_ZN15QRecursiveMutexC1Ev", "_ZN15QRecursiveMutexD1Ev"):
                return self.ret()
            if name == "_Z35qNetworkConfigurationManagerPrivatev":
                return self.ret(self.manager if self.manager_present else 0)
            if name == "_ZNK35QNetworkConfigurationManagerPrivate7enginesEv":
                self.wq(self.r(8), self.qlist([engine["pointer"] for engine in self.engines]))
                return self.ret()
            if name == "_ZNK11QMetaObject4castEP7QObject":
                accepted = any(engine["pointer"] == self.r(1) and engine["cast"] for engine in self.engines)
                return self.ret(self.r(1) if accepted else 0)
            if name == "_ZltRK7QStringS1_":
                return self.ret(self.core.helper(name, self.core.holder(self.string(self.r(0))),
                    self.core.holder(self.string(self.r(1)))))
            if name == "_ZNK21QNetworkConfiguration8childrenEv":
                self.wq(self.r(8), self.qlist([]))
                return self.ret()
            if name == "_ZN11QMetaObject8activateEP7QObjectPKS_iPPv" and self.r(1) in self.metas:
                meta, index, sender = self.r(1), self.r(2), self.r(0)
                method = self.metas[meta]["methods"][index]
                args = []
                if method["argc"]:
                    if meta == BASE + 0x174D8:
                        args = [self.string(self.q(self.r(3) + 8)), self.i(self.q(self.r(3) + 16))]
                    else:
                        assert method["argc"] == 1 and method["name"] in ("stateChanged", "error"), "signal type outside fixture scope"
                        args = [self.i(self.q(self.r(3) + 8))]
                # Freeze values and eligible bindings NOW. Construction-time
                # signals cannot be retroactively forwarded through later links.
                forwards = [dict(c) for c in self.connections if c["sender"] == sender and
                            c["signal"][1:].split("(")[0] == method["name"]]
                self.emitted.append(dict(sender=sender, meta=hex(meta), method=method["name"],
                                         args=args, forwards=forwards))
                return self.ret()
        return super().hook(u, pc, size, context)

    def construct(self, config):
        pointer = self.alloc(24)
        self.session_objects.append(pointer)
        self.call(0x18B5EC, pointer, config, 0)
        return pointer

    def drain(self):
        # Explicit deterministic delivery adapter after producer return, not
        # QObject scheduling or a claim that type=0 is naturally synchronous.
        while self.cursor < len(self.emitted):
            event = self.emitted[self.cursor]
            self.cursor += 1
            for connection in event["forwards"]:
                argv, values = self.alloc(24), []
                if event["method"] == "connectionError":
                    assert connection["type"] == 2, "queued engine error binding"
                    text, integer = self.alloc(8), self.alloc(4)
                    self.wq(text, self.qstring(event["args"][0]))
                    self.wi(integer, event["args"][1])
                    values, target, method = [text, integer], BASE + 0x11AEC, 3
                elif connection["receiver"] in self.session_objects:
                    slot = connection["slot"][1:].split("(")[0]
                    method = next(m["id"] for m in self.metas[0x3A2228]["methods"] if m["name"] == slot)
                    target = 0x18C374
                    for value in event["args"]:
                        storage = self.alloc(4)
                        self.wi(storage, value)
                        values.append(storage)
                else:
                    # NAM state/error receivers remain explicit downstream
                    # boundaries here; its separate state delivery is §180.
                    continue
                for index, value in enumerate(values):
                    self.wq(argv + 8 + index * 8, value)
                self.forwarded.append(dict(signal=event["method"], slot=connection["slot"], type=connection["type"]))
                self.call(target, connection["receiver"], 0, method, argv)

    def observe(self, pointer):
        backend = self.q(pointer + 16)
        return dict(backend=hex(backend), state=self.call(0x18BD80, pointer),
                    open=bool(self.call(0x18BD68, pointer)), error=self.call(0x18BD98, pointer),
                    selected_engine=hex(self.q(backend + 0x40)) if backend else None,
                    want_open=bool(self.u.mem_read(backend + 0x5C, 1)[0]) if backend else False)

    def public_events(self):
        return [(event["method"], event["args"]) for event in self.emitted if event["meta"] == "0x3a2228"]

    def report(self):
        return dict(signals=list(self.emitted), forwarded=list(self.forwarded), connections=list(self.connections),
                    engine_calls=list(self.engine_calls), backend_trace=list(self.backend_trace), pool=self.pool_snapshot())


def audit(args):
    binaries = {name: getattr(args, name).read_bytes() for name in ("qt", "qt_core", "bearer")}
    for name, binary in binaries.items():
        expected = pool.access.scan.QT_CORE_SHA if name == "qt_core" else watchers.SHA[name]
        assert hashlib.sha256(binary).hexdigest() == expected, name
    def fresh():
        return Backend(binaries["qt"], binaries["qt_core"], binaries["bearer"], args.mutation)
    cases = []
    for state, expected in ((0, 0), (1, 1), (2, 1), (6, 5), (8, 0), (14, 3), (15, 3)):
        b = fresh()
        config = b.make_config("wifi", state)
        engine = b.add_engine(config)
        pointer = b.construct(config)
        observed = b.observe(pointer)
        assert observed["state"] == expected and not observed["open"] and observed["error"] == 0, (state, "construction state", observed)
        assert observed["selected_engine"] == hex(engine), "engine selected by original membership"
        assert not b.public_events() and all(not event["forwards"] for event in b.emitted), "constructor signals precede public bindings"
        assert not any(call["method"] in ("0xbc7c", "0xbc84") for call in b.engine_calls), "construct does not call engine connect"
        cases.append(dict(name=f"state-{state}", observed=observed, evidence=b.report()))

    for name in ("empty-id", "manager-absent", "no-engines", "unmatched"):
        b = fresh()
        config = b.make_config("" if name == "empty-id" else "wifi", 14)
        if name != "no-engines":
            b.add_engine(config, contains=name != "unmatched")
        b.manager_present = name != "manager-absent"
        pointer = b.construct(config)
        observed = b.observe(pointer)
        assert observed["backend"] == "0x0" and observed["state"] == 0 and observed["error"] == 4, (name, "missing backend", observed)
        b.call(0x18BAE4, pointer)
        assert b.public_events() == [("error", [4])], "open without backend error"
        cases.append(dict(name=name, observed=observed, evidence=b.report()))

    b = fresh()
    config = b.make_config("wifi", 14)
    b.add_engine(config, contains=False)
    selected = b.add_engine(config)
    b.add_engine(config)
    pointer = b.construct(config)
    assert b.observe(pointer)["selected_engine"] == hex(selected), "ordered first matching engine"
    cases.append(dict(name="ordered-engines", observed=b.observe(pointer), evidence=b.report()))

    for name, options in (("engine-backend-absent", dict(available=False)), ("cast-rejected", dict(cast=False))):
        b = fresh()
        config = b.make_config("wifi", 14)
        b.add_engine(config, **options)
        pointer = b.construct(config)
        observed = b.observe(pointer)
        assert observed["backend"] != "0x0" and observed["state"] == 0 and not observed["open"], (name, "backend presence is not network state")
        cases.append(dict(name=name, observed=observed, evidence=b.report()))

    b = fresh()
    config = b.make_config("wifi", 14)
    b.add_engine(config)
    pointer = b.construct(config)
    b.drain()
    b.call(0x18BAE4, pointer)
    assert b.observe(pointer)["open"] and not b.public_events(), "open flag before explicit forwarding"
    b.drain()
    assert b.public_events() == [("opened", [])], "opened forwarded through original public signal"
    count = len(b.emitted)
    b.call(0x18BAE4, pointer)
    b.drain()
    assert len(b.emitted) == count, "repeated open idempotence"
    b.call(0x18BD04, pointer)
    b.drain()
    observed = b.observe(pointer)
    assert not observed["open"] and observed["state"] == 3, "close leaves engine network state"
    assert b.public_events() == [("opened", []), ("closed", [])], "closed forwarded once"
    assert not any(call["method"] in ("0xbc7c", "0xbc84") for call in b.engine_calls), "active open close has no engine connect call"
    cases.append(dict(name="active-open-close", observed=observed, evidence=b.report()))

    b = fresh()
    config = b.make_config("wifi", 6)
    b.add_engine(config)
    pointer = b.construct(config)
    b.drain()
    b.call(0x18BAE4, pointer)
    produced = b.observe(pointer)
    assert (produced["state"], produced["error"], produced["open"]) == (2, 0, False), "connecting before queued engine error"
    assert any(event["method"] == "connectionError" and event["args"] == ["wifi", 2] for event in b.emitted), "original engine rejection value"
    b.drain()
    observed = b.observe(pointer)
    assert (observed["state"], observed["error"], observed["open"], observed["want_open"]) == (5, 3, False, False), "queued engine rejection consumer"
    assert b.public_events() == [("stateChanged", [2]), ("stateChanged", [5]), ("error", [3])], "queued failure public sequence"
    cases.append(dict(name="defined-open-engine-rejection", produced=produced, observed=observed, evidence=b.report()))

    for state in (0, 1, 2, 8):
        b = fresh()
        config = b.make_config("wifi", state)
        b.add_engine(config)
        pointer = b.construct(config)
        b.drain()
        b.call(0x18BAE4, pointer)
        b.drain()
        observed = b.observe(pointer)
        assert (observed["state"], observed["error"], observed["open"]) == (0, 4, False), "insufficient config open error"
        assert b.public_events() == [("stateChanged", [0]), ("error", [4])]
        cases.append(dict(name=f"open-state-{state}", observed=observed, evidence=b.report()))

    for kind, constructor_state, error in ((1, 1, 3), (2, 0, 4), (3, 0, 4)):
        b = fresh()
        config = b.make_config("wifi", 14)
        b.wi(b.q(config) + 36, kind)
        b.add_engine(config)
        pointer = b.construct(config)
        constructed = b.observe(pointer)
        assert constructed["state"] == constructor_state and not constructed["open"], "non-interface constructor state"
        b.drain()
        b.call(0x18BAE4, pointer)
        b.drain()
        observed = b.observe(pointer)
        assert (observed["error"], observed["open"]) == (error, False), "non-interface open error"
        expected_events = [("error", [3])] if kind == 1 else [("stateChanged", [0]), ("error", [4])]
        assert b.public_events() == expected_events, "non-interface public sequence"
        cases.append(dict(name=f"config-type-{kind}", constructed=constructed, observed=observed, evidence=b.report()))

    b = fresh()
    config = b.make_config("wifi", 14)
    b.add_engine(config)
    first, second = b.get(config), b.get(config)
    assert b.q(first) == b.q(second) and len(b.created) == 1, "original factory uses original constructor"
    observed = b.observe(b.q(first))
    assert observed["state"] == 3 and not observed["open"], "factory state is not open"
    cases.append(dict(name="factory-real-ctor-integration", observed=observed, evidence=b.report()))

    ranges = {"qt": ((0x18B5EC, 0x18BA78), (0x18BAE4, 0x18BB7C)),
              "bearer": ((0xBE80, 0xBF0C), (0xE868, 0xED68), (0xED68, 0xEF70),
                         (0xF964, 0xFA70), (0xFC4C, 0xFD24), (0x12160, 0x121C4))}
    fingerprints = {}
    for name, intervals in ranges.items():
        image = policy.load_image(binaries[name])[0]
        fingerprints[name] = {hex(start): dict(size=end - start, sha256=hashlib.sha256(image[start:end]).hexdigest())
                              for start, end in intervals}
    return dict(scope=__doc__, identities={name: hashlib.sha256(binary).hexdigest() for name, binary in binaries.items()},
        bearer_load_base=hex(BASE), tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        inherited_sha256={str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                         for path in (SOURCE, pool.SOURCE, pool.access.SOURCE, pool.access.scan.SOURCE,
                                      pool.access.scan.bridge.SOURCE, watchers.SOURCE,
                                      ROOT / "scripts/audit-steam-client-fec-policy.py")},
        metadata={hex(address): value for address, value in b.metas.items()}, backend_metadata=b.impl_meta,
        original_ranges=fingerprints, cases=cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("qt", "qt-core", "bearer"):
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
