#!/usr/bin/env python3
"""Run pinned QNetworkAccessManager construction/configuration/session policy.

Original manager/private constructors run with warm global/type registration,
QObject base, proxy/cache construction and configuration services as declared
adapters. Original public meta dispatch -> configuration slot -> session release
and selection execute. Session factory/configuration/state, QObject binding and
queued invocation delivery are providers; reference operations execute original
instructions on borrowed controls. QString compare/hash run original QtCore.
No OS event loop, real QNetworkSession factory, HTTP socket, DNS cache reset,
Steam peer, Switch runtime or cold Qt/global lifetime is claimed.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/steam-bearer-scan-audit.py"
spec = importlib.util.spec_from_file_location("scan", SOURCE)
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)
watchers, policy = scan.watchers, scan.policy
PATCHES = {
    "constructor-config": (0x11A314, "e3f50994", "1f2003d5"),
    "constructor-online": (0x11A2E8, "eef50994", "1f2003d5"),
    "active-mask": (0x11EF0C, "210f0054", "1f2003d5"),
    "known-dedupe": (0x11EF7C, "e1120054", "1f2003d5"),
    "online-check": (0x11EFAC, "08080034", "1f2003d5"),
    "default-equality": (0x11F070, "f6010037", "1f2003d5"),
    "inactive-empty": (0x11F174, "28030034", "1f2003d5"),
    "release-call": (0x11F088, "0ffeff97", "1f2003d5"),
    "select-call": (0x11F0A0, "1cf0ff97", "1f2003d5"),
    "queued-type": (0x11B418, "42008052", "02008052"),
}


class Access(policy.Shell):
    def __init__(self, binary, qt_core, state=14, capabilities=0, mutation=None):
        self.ready = False
        super().__init__(binary)
        self.core = scan.CoreStrings(qt_core)
        self.public, self.private = self.alloc(64), 0
        self.capabilities = capabilities
        self.configs, self.sessions = {}, {}
        self.connections, self.disconnects, self.events = [], [], []
        self.actions, self.invocations, self.factory_calls = [], [], []
        self.original, self.cache_calls, self.cache_terminals = set(), [], []
        self.known = set()
        self.factory_mode, self.session_state = "new", 3
        self.default = self.make_config("default", state)
        # These are explicit completed global/type-registration inputs. They
        # avoid running a process-global cold Qt factory/atexit lifecycle.
        for offset in (0x3E9810, 0x3E9828):
            self.b(offset, 1)
        for offset in (0x3E9818, 0x3E9830):
            self.wi(offset, -1)
        for offset in (0x3E9834, 0x3E9838, 0x3E983C, 0x3E9860, 0x3E9864, 0x3E98A8, 0x3E98AC):
            self.wi(offset, 100)
        if mutation:
            address, signature, replacement = PATCHES[mutation]
            assert bytes(self.u.mem_read(address, 4)).hex() == signature, ("mutation-signature", mutation)
            self.u.mem_write(address, bytes.fromhex(replacement))
        self.ready = True
        self.call(0x119DB0, self.public, 0)
        # Nested QObject construction also occurs. Use the original public
        # object's installed d-pointer, never the last base ctor encountered.
        self.private = self.q(self.public + 8)
        self.hash_header, self.buckets = self.alloc(0x40), self.alloc(8)
        self.wq(self.hash_header + 8, self.buckets)
        self.wi(self.hash_header + 0x20, 1)  # Fixture storage: one bucket, seed=0.
        self.wq(self.private + 0x58, self.hash_header)
        self.refresh_hash()

    def string(self, holder):
        data = self.q(holder)
        offset = struct.unpack("<q", bytes(self.u.mem_read(data + 16, 8)))[0]
        return bytes(self.u.mem_read(data + offset, self.i(data + 4) * 2)).decode("utf-16le")

    def make_config(self, identity, state, valid=True):
        data = self.alloc(0x40)
        self.wi(data, 100)  # Borrowed fixture references keep it alive.
        self.wq(data + 16, self.qstring(identity))
        self.wq(data + 24, self.qstring(identity))
        self.wi(data + 32, state)
        self.b(data + 48, int(valid))
        holder = self.alloc(8)
        self.wq(holder, data)
        self.configs[data] = dict(identity=identity, state=state, valid=valid)
        return holder

    def config_value(self, holder):
        return self.configs.get(self.q(holder))

    def copy_config(self, dest, source):
        data = self.q(source)
        self.wq(dest, data)
        if data:
            self.wi(data, self.i(data) + 1)

    def make_session(self, config, state=3):
        pointer, control = self.alloc(32), self.alloc(16)
        # The factory argument can be an original stack temporary. A session
        # provider must own a copy of the value, never retain its container.
        owned_config = self.alloc(8)
        self.copy_config(owned_config, config)
        self.wi(control, 100)
        self.wi(control + 4, 100)
        self.sessions[pointer] = dict(config=owned_config, state=state, control=control)
        return pointer

    def attach(self, pointer, strong=True):
        control = self.sessions[pointer]["control"]
        if strong:
            self.wq(self.private + 0x88, pointer)
            self.wq(self.private + 0x90, control)
            self.wi(control, self.i(control) + 1)
            self.wi(control + 4, self.i(control + 4) + 1)
        self.wq(self.private + 0x98, control)
        self.wq(self.private + 0xA0, pointer)
        self.wi(control, self.i(control) + 1)

    def refresh_hash(self):
        tail = self.hash_header
        for key in sorted(self.known):
            node = self.alloc(32)
            self.wq(node, tail)
            value = self.core.helper("_Z5qHashRK7QStringj", self.core.holder(key), 0)
            self.wi(node + 8, value)
            self.wq(node + 16, self.qstring(key))
            tail = node
        self.wq(self.buckets, tail)
        self.wi(self.hash_header + 0x14, len(self.known))

    def hook(self, u, pc, size, context):
        if not self.ready:
            return super().hook(u, pc, size, context)
        if pc in (0x119DB0, 0x11FBA8, 0x11FA1C, 0x11F3A8, 0x11EEAC, 0x11E8C4,
                  0x11B110, 0x11EB24, 0x1B2A00):
            self.original.add(hex(pc))
        if pc in (0x11D564, 0x11D5D4):
            self.cache_calls.append(hex(pc))
        if pc in (0x11E8C4, 0x11B110):
            self.actions.append(dict(kind="release" if pc == 0x11E8C4 else "select",
                config=self.config_value(self.r(1)) if pc == 0x11B110 else None))
        name = self.plts.get(pc, "")
        if pc in (0x123348, 0x120A34):
            # Auth/cache value construction and completed metatype helper.
            return self.ret()
        if pc in (0x12340C, 0x11E5C4, 0x119260):
            self.cache_terminals.append(hex(pc))
            return self.ret()
        if pc in (0x122C84, 0x122EB0):
            assert self.r(0) == self.private + 0x58
            key = self.string(self.r(1))
            if pc == 0x122C84:
                self.known.add(key)
            else:
                self.known.discard(key)
            self.refresh_hash()
            return self.ret()
        if pc == 0x1916A8:
            self.factory_calls.append(self.config_value(self.r(0)))
            if self.factory_mode == "none":
                pointer = control = 0
            else:
                pointer = self.make_session(self.r(0), self.session_state)
                control = self.sessions[pointer]["control"]
                self.wi(control, self.i(control) + 1)
                self.wi(control + 4, self.i(control + 4) + 1)
            self.wq(self.r(8), pointer)
            self.wq(self.r(8) + 8, control)
            return self.ret()
        if name == "_ZN14QObjectPrivateC2Ei":
            return self.ret()
        if name == "_ZN7QObjectC2ER14QObjectPrivatePS_":
            self.wq(self.r(0) + 8, self.r(1))
            self.wq(self.r(1) + 8, self.r(0))
            return self.ret()
        if name in ("_ZN13QNetworkProxyC1Ev", "_ZN28QNetworkConfigurationManagerC1EP7QObject"):
            return self.ret()
        if name == "_ZNK28QNetworkConfigurationManager20defaultConfigurationEv":
            self.copy_config(self.r(8), self.default)
            return self.ret()
        if name == "_ZNK28QNetworkConfigurationManager12capabilitiesEv":
            return self.ret(self.capabilities)
        if name in ("_ZN6QMutex4lockEv", "_ZN6QMutex6unlockEv"):
            return self.ret()
        if name == "_ZN7QObject7connectEPKS_PKcS1_S3_N2Qt14ConnectionTypeE":
            self.connections.append(dict(sender=self.r(0), signal=self.cstring(self.r(1)),
                receiver=self.r(2), slot=self.cstring(self.r(3)), type=self.r(4)))
            self.wq(self.r(8), 0)
            return self.ret()
        if name == "_ZN11QMetaObject10ConnectionD1Ev":
            return self.ret()
        if name == "_ZN7QObject10disconnectEPKS_PKcS1_S3_":
            self.disconnects.append(dict(sender=self.r(0), signal=self.cstring(self.r(1)),
                receiver=self.r(2), slot=self.cstring(self.r(3))))
            return self.ret(1)
        if name == "_ZN7QObject11qt_metacallEN11QMetaObject4CallEiPPv":
            return self.ret(self.r(2))
        if name == "_ZNK15QNetworkSession13configurationEv":
            self.copy_config(self.r(8), self.sessions[self.r(0)]["config"])
            return self.ret()
        if name == "_ZNK15QNetworkSession5stateEv":
            return self.ret(self.sessions[self.r(0)]["state"])
        if name.startswith("_ZN11QMetaObject12invokeMethodEP7QObjectPKc"):
            self.invocations.append(dict(method=self.cstring(self.r(1)), type=self.r(2),
                argument_type=self.cstring(self.r(6)), argument=self.i(self.r(5))))
            return self.ret(1)
        if name in ("_ZeqRK7QStringS1_", "_Z5qHashRK7QStringj"):
            first = self.core.holder(self.string(self.r(0)))
            second = self.r(1) if "qHash" in name else self.core.holder(self.string(self.r(1)))
            return self.ret(self.core.helper(name, first, second))
        if name == "_ZN11QMetaObject8activateEP7QObjectPKS_iPPv":
            assert self.r(0) == self.public and self.r(1) == 0x3A0DE0
            kind = self.r(2)
            assert kind in (6, 7), ("unexpected access signal", kind)
            value = None if kind == 6 else struct.unpack("<i", bytes(u.mem_read(self.q(self.r(3) + 8), 4)))[0]
            self.events.append(dict(signal=kind, value=value))
            return self.ret()
        return super().hook(u, pc, size, context)

    def changed(self, identity, state):
        config = self.make_config(identity, state)
        argv = self.alloc(16)
        self.wq(argv + 8, config)
        self.call(0x11FA1C, self.public, 0, 15, argv)

    def deliver_state(self, invocation):
        assert invocation["method"] == "_q_networkSessionStateChanged"
        assert invocation["type"] == 2 and invocation["argument_type"] == "QNetworkSession::State", "queued state delivery"
        argv, value = self.alloc(16), self.alloc(4)
        self.wi(value, invocation["argument"])
        self.wq(argv + 8, value)
        self.call(0x11FA1C, self.public, 0, 14, argv)

    def snapshot(self):
        return dict(online=self.u.mem_read(self.private + 0xD4, 1)[0],
                    allowed=self.u.mem_read(self.private + 0xD7, 1)[0],
                    access=struct.unpack("<i", bytes(self.u.mem_read(self.private + 0xCC, 4)))[0],
                    connections=list(self.connections), disconnects=list(self.disconnects),
                    actions=list(self.actions), events=list(self.events), known=sorted(self.known),
                    invocations=list(self.invocations), session=hex(self.q(self.private + 0x88)),
                    factory_calls=list(self.factory_calls), original=sorted(self.original),
                    refs={hex(pointer): dict(weak=self.i(value["control"]),
                            strong=self.i(value["control"] + 4)) for pointer, value in self.sessions.items()},
                    cache_calls=list(self.cache_calls), cache_terminals=list(self.cache_terminals))


def audit(args):
    binaries = {name: getattr(args, name).read_bytes() for name in ("qt", "qt_core")}
    assert hashlib.sha256(binaries["qt"]).hexdigest() == watchers.SHA["qt"]
    assert hashlib.sha256(binaries["qt_core"]).hexdigest() == scan.QT_CORE_SHA
    meta = watchers.qt_metadata(binaries["qt"], 0x3A0DE0)
    assert meta["methods"][15]["name"] == "_q_configurationChanged"
    assert meta["methods"][14]["name"] == "_q_networkSessionStateChanged"
    initial = []
    bindings = [("2onlineStateChanged(bool)", "1_q_onlineStateChanged(bool)", 0),
                ("2configurationChanged(QNetworkConfiguration)", "1_q_configurationChanged(QNetworkConfiguration)", 0)]
    for state, online, access in ((0, 0, 0), (1, 0, -1), (2, 0, 0), (6, 0, 0),
                                  (8, 0, 0), (14, 1, 1), (15, 1, 1)):
        for capabilities in (0, 64):
            a = Access(binaries["qt"], binaries["qt_core"], state, capabilities, args.mutation)
            result = a.snapshot()
            assert [(c["signal"], c["slot"], c["type"]) for c in a.connections] == bindings, "constructor bindings"
            assert all(c["sender"] == a.private + 0xB0 and c["receiver"] == a.public for c in a.connections)
            assert (result["online"], result["access"], result["allowed"]) == (online, access, 1), "constructor access state"
            assert a.u.mem_read(a.private + 0xC9, 1)[0] == (capabilities >> 6), "constructor capability bit"
            initial.append(dict(state=state, capabilities=capabilities, observed=result))
    cases = []
    programs = [
        dict(name="switch-default", actions=["release", "select"], known=["incoming"]),
        dict(name="session-is-default", same=True, actions=[], known=[]),
        dict(name="offline", online=0, actions=[], known=[]),
        dict(name="already-tracked", known_before=["incoming"], actions=[], known=["incoming"]),
        dict(name="no-session", session=False, actions=[], known=[]),
        dict(name="weak-session", strong=False, actions=["release", "select"], known=["incoming"]),
        dict(name="inactive-unknown", state=6, known_before=["other"], actions=[], known=["other"]),
        dict(name="inactive-final-key", state=6, known_before=["incoming"], actions=[], known=[]),
        dict(name="inactive-with-another-key", state=6, known_before=["incoming", "other"],
             new_state=0, actions=["release", "select"], known=["other"], target="incoming"),
        dict(name="superset-state", state=15, actions=["release", "select"], known=["incoming"]),
        dict(name="factory-empty", factory="none", actions=["release", "select"], known=["incoming"], failure=-1),
        dict(name="invalid-default", invalid=True, actions=["release", "select"], known=["incoming"], failure=-1),
        dict(name="allow-after-queued", access=0, actions=["release", "select"], known=["incoming"], queued_access=1),
        dict(name="deny-after-queued", access=0, allowed=0, actions=["release", "select"], known=["incoming"]),
    ]
    session_bindings = [("2opened()", "2networkSessionConnected()", 2),
                        ("2closed()", "1_q_networkSessionClosed()", 2),
                        ("2stateChanged(QNetworkSession::State)", "1_q_networkSessionStateChanged(QNetworkSession::State)", 2),
                        ("2error(QNetworkSession::SessionError)", "1_q_networkSessionFailed(QNetworkSession::SessionError)", 0)]
    for program in programs:
        a = Access(binaries["qt"], binaries["qt_core"], mutation=args.mutation)
        if program.get("invalid"):
            a.default = a.make_config("invalid", 1, False)
        old = None
        if program.get("session", True):
            old = a.make_session(a.default if program.get("same") else a.make_config("old", 14))
            a.attach(old, program.get("strong", True))
        a.known = set(program.get("known_before", []))
        a.refresh_hash()
        if "online" in program:
            a.b(a.private + 0xD4, program["online"])
        if "access" in program:
            a.wi(a.private + 0xCC, program["access"])
        if "allowed" in program:
            a.b(a.private + 0xD7, program["allowed"])
        a.factory_mode = program.get("factory", "new")
        a.session_state = program.get("new_state", 3)
        a.changed("incoming", program.get("state", 14))
        produced = a.snapshot()
        assert [entry["kind"] for entry in a.actions] == program["actions"], (program["name"], "session actions", produced)
        assert sorted(a.known) == program["known"], (program["name"], "configuration ID collection")
        assert not a.cache_calls and not a.cache_terminals, "configuration path cache entry calls"
        if program["actions"]:
            assert a.actions[-1]["config"]["identity"] == program.get("target", "invalid" if program.get("invalid") else "default"), "selection configuration argument"
            assert len(a.disconnects) == 4, "old session bindings removed"
            assert all(a.i(a.sessions[old]["control"] + offset) == 100 for offset in (0, 4)), "old reference baseline restored"
            if "failure" in program:
                assert a.events == [dict(signal=7, value=program["failure"])], "empty session access notification"
                assert not a.invocations and not a.q(a.private + 0x88)
                assert len(a.factory_calls) == (0 if program.get("invalid") else 1), "validity gates session factory"
            else:
                assert [(c["signal"], c["slot"], c["type"]) for c in a.connections[2:]] == session_bindings, "replacement session bindings"
                assert not a.events, "queued state not delivered inline"
                pointer = a.q(a.private + 0x88)
                control = a.sessions[pointer]["control"]
                assert (a.i(control), a.i(control + 4)) == (102, 101), "new strong and weak owners"
                expected = [] if a.session_state == 0 else [dict(method="_q_networkSessionStateChanged", type=2,
                    argument_type="QNetworkSession::State", argument=3)]
                assert a.invocations == expected, "queued state delivery"
                for invocation in a.invocations:
                    a.deliver_state(invocation)
                expected_events = [] if not expected else [dict(signal=6, value=None)]
                if program.get("queued_access"):
                    expected_events.append(dict(signal=7, value=program["queued_access"]))
                assert a.events == expected_events, "queued state signal sequence"
        else:
            assert not a.events and not a.invocations and not a.disconnects, "no replacement side effects"
        # Repeating an already recorded active ID must not reschedule selection.
        if program["name"] == "switch-default":
            before = a.snapshot()
            a.changed("incoming", 14)
            assert a.snapshot() == before, "repeated active ID idempotence"
        cases.append(dict(inputs=program, produced=produced, delivered=a.snapshot()))
    control = Access(binaries["qt"], binaries["qt_core"])
    control.call(0x11D5D4, control.public)
    assert control.cache_calls == ["0x11d5d4"] and control.cache_terminals == ["0x12340c", "0x11e5c4"], "cache observer positive control"
    image = policy.load_image(binaries["qt"])[0]
    ranges = ((0x119DB0, 0x11A414), (0x11FBA8, 0x11FCF4), (0x11EEAC, 0x11F25C),
              (0x11E8C4, 0x11EB24), (0x11B110, 0x11B528), (0x11EB24, 0x11ED80))
    return dict(scope=__doc__, identities={name: hashlib.sha256(binary).hexdigest() for name, binary in binaries.items()},
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        inherited_sha256={str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                         for path in (SOURCE, scan.SOURCE, scan.bridge.SOURCE, watchers.SOURCE,
                                      ROOT / "scripts/audit-steam-client-fec-policy.py")},
        metadata=meta, constructors=initial, cases=cases, cache_control=control.snapshot(),
        original_ranges={hex(start): dict(size=end - start, sha256=hashlib.sha256(image[start:end]).hexdigest())
                         for start, end in ranges})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("qt", "qt-core"):
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
