#!/usr/bin/env python3
"""Execute original Qt thread-local shared-network-session factory and storage.

Original factory, libc++ map hash/equality/insert/rehash/erase, weak promotion,
size-triggered pruning, registry, TLS cleanup and deferred-delete destroyer run.
TLS storage/registration, allocator, next-prime arithmetic and QNetworkSession
construction are declared providers. QObject deleteLater is recorded, not run
as an event loop or destruction. Original QtCore checks normal expired controls.
The producer can also be called by the original NAM config/session selector in
the same emulator. No OS threads, negative QObject sentinel, full session/backend
construction, HTTP/DNS reset, Steam peer or Switch loader lifetime is claimed.
"""
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/steam-access-config-audit.py"
spec = importlib.util.spec_from_file_location("access", SOURCE)
access = importlib.util.module_from_spec(spec)
spec.loader.exec_module(access)
policy = access.policy
PATCHES = {
    "reuse": (0x1917C4, "e80600b5", "1f2003d5"),
    "threshold": (0x1916F4, "1f4500f1", "1f4100f1"),
    "sweep": (0x191700, "360f00b5", "1f2003d5"),
    "expired-promotion": (0x191740, "4b010054", "1f2003d5"),
    "identity": (0x18D798, "e0179f1a", "20008052"),
    "purpose-hash": (0x191D90, "974208aa", "f70314aa"),
    "cache-weak-owner": (0x191874, "b7170894", "1f2003d5"),
    "tls-read": (0x1916E0, "84230894", "1f2003d5"),
    "deferred-delete": (0x192194, "6f180814", "c0035fd6"),
}


class Pool(access.Access):
    def __init__(self, qt, qt_core, mutation=None):
        self.pool_enabled = False
        super().__init__(qt, qt_core)
        self.thread = 0
        self.slots = {}
        self.deletes, self.freed, self.created, self.sweeps = [], [], [], []
        self.tls_events, self.registrations, self.exit_registrations = [], [], []
        self.primes, self.control_checks = [], []
        self.pool_original = set()
        self.releasing = False
        if mutation:
            address, signature, replacement = PATCHES[mutation]
            assert bytes(self.u.mem_read(address, 4)).hex() == signature, ("mutation-signature", mutation)
            self.u.mem_write(address, bytes.fromhex(replacement))
        self.pool_enabled = True
        self.call(0x192198)
        assert self.registrations == [dict(descriptor="0x3e9a7c", cleanup="0x191b7c")], "TLS cleanup registration"
        assert len(self.exit_registrations) == 1 and self.exit_registrations[0]["function"] == "0x191b78"

    def config_value(self, holder):
        # These programs mutate the shared private record. Report its current
        # fields, not the constructor-time metadata kept by the parent fixture.
        data = self.q(holder)
        if not data:
            return None
        return dict(identity=self.string(data + 24), state=self.i(data + 32),
                    type=self.i(data + 36), purpose=self.i(data + 40), bearer=self.i(data + 44),
                    valid=bool(self.u.mem_read(data + 48, 1)[0]))

    def hook(self, u, pc, size, context):
        if self.pool_enabled:
            if pc in (0x1916A8, 0x191A58, 0x191B7C, 0x191C08, 0x191D3C,
                      0x192034, 0x192190, 0x192198, 0x18D78C):
                self.pool_original.add(hex(pc))
            if pc == 0x1916A8:
                self.factory_calls.append(self.config_value(self.r(0)))
                return  # Bypass the parent factory terminal: execute its body.
            if pc == 0x1918E4:
                self.sweeps.append(dict(thread=self.thread, node=hex(self.r(22))))
            if self.releasing and pc == 0x1917C0:
                return self.jump(policy.STOP)
            name = self.plts.get(pc, "")
            if name in ("_ZNK18QThreadStorageData3getEv", "_ZN18QThreadStorageData3setEPv"):
                assert self.r(0) == 0x3E9A7C
                operation = "get" if "3get" in name else "set"
                self.tls_events.append(dict(thread=self.thread, operation=operation))
                if operation == "get":
                    return self.ret(self.slots.get(self.thread, 0))
                if self.thread not in self.slots:
                    self.slots[self.thread] = self.alloc(8)
                slot = self.slots[self.thread]
                self.wq(slot, self.r(1))
                return self.ret(slot)
            if name == "_ZN18QThreadStorageDataC1EPFvPvE":
                self.registrations.append(dict(descriptor=hex(self.r(0)), cleanup=hex(self.r(1))))
                return self.ret()
            if name == "__cxa_atexit":
                self.exit_registrations.append(dict(function=hex(self.r(0)), argument=hex(self.r(1))))
                return self.ret(0)
            if name == "_ZN15QNetworkSessionC1ERK21QNetworkConfigurationP7QObject":
                assert self.r(2) == 0
                pointer, owned = self.r(0), self.alloc(8)
                self.copy_config(owned, self.r(1))
                self.sessions[pointer] = dict(config=owned, state=self.session_state, control=0)
                self.created.append(pointer)
                return self.ret()
            if name == "_ZN15QtSharedPointer20ExternalRefCountData16setQObjectSharedEPK7QObjectb":
                assert self.r(2) == 1
                self.sessions[self.r(1)]["control"] = self.r(0)
                return self.ret()
            if name == "_ZN15QtSharedPointer20ExternalRefCountData18checkQObjectSharedEPK7QObject":
                # Normal expired (strong=0) and positive controls only. Copy the
                # control value to original QtCore; do not fabricate promotion.
                strong = self.i(self.r(0) + 4)
                assert strong < 0x80000000, "negative QObject sentinel outside fixture scope"
                control = self.core.alloc(16)
                self.core.u.mem_write(control, bytes(u.mem_read(self.r(0), 16)))
                self.core.helper(name, control, 0)
                self.control_checks.append(strong)
                return self.ret()
            if name == "_ZNSt6__ndk112__next_primeEm":
                original, candidate = self.r(0), max(2, self.r(0))
                while any(candidate % divisor == 0 for divisor in range(2, math.isqrt(candidate) + 1)):
                    candidate += 1
                self.primes.append(dict(input=original, output=candidate))
                return self.ret(candidate)
            if name == "_ZN7QObject11deleteLaterEv":
                self.deletes.append(self.r(0))
                return self.ret()
            if name == "_ZdlPv":
                self.freed.append(self.r(0))
        return super().hook(u, pc, size, context)

    def get(self, config):
        output = self.alloc(16)
        self.u.reg_write(policy.UC_ARM64_REG_X0 + 8, output)
        self.call(0x1916A8, config)
        return output

    def register(self, config, output):
        self.call(0x191A58, config, output)

    def release(self, output):
        control = self.q(output + 8)
        assert control, "owned result already consumed"
        # Execute the factory's actual strong/weak release block, stopping at
        # its continuation. Only the register boundary/container consumption is
        # adapted; reference decisions and destroyer calls are original.
        self.u.reg_write(policy.UC_ARM64_REG_X0 + 22, control)
        self.releasing = True
        self.call(0x191780)
        self.releasing = False
        self.wq(output, 0)
        self.wq(output + 8, 0)

    def pool_pointer(self):
        return self.q(self.slots[self.thread]) if self.thread in self.slots else 0

    def cleanup_thread(self):
        pointer = self.pool_pointer()
        self.call(0x191B7C, pointer)
        if self.thread in self.slots:
            # Explicit TLS-owner delivery boundary, not executed OS thread exit.
            self.wq(self.slots[self.thread], 0)

    def pool_snapshot(self):
        pool, rows, visited = self.pool_pointer(), [], set()
        node = self.q(pool + 16) if pool else 0
        while node:
            assert node not in visited, "original pool node cycle"
            visited.add(node)
            control = self.q(node + 24)
            rows.append(dict(node=hex(node), key=hex(self.q(node + 16)), hash=self.q(node + 8),
                object=hex(self.q(node + 32)), control=hex(control),
                strong=self.i(control + 4) if control else None, weak=self.i(control) if control else None))
            node = self.q(node)
        assert len(rows) == (self.q(pool + 24) if pool else 0), "original pool size"
        return dict(thread=self.thread, size=len(rows), buckets=self.q(pool + 8) if pool else 0, rows=rows,
            created=[hex(pointer) for pointer in self.created], delete_later=[hex(pointer) for pointer in self.deletes],
            freed=[hex(pointer) for pointer in self.freed], sweep_visits=len(self.sweeps),
            original=sorted(self.pool_original), tls=list(self.tls_events), primes=list(self.primes),
            control_checks=list(self.control_checks), factory_inputs=list(self.factory_calls),
            tls_registration=list(self.registrations), exit_registration=list(self.exit_registrations),
            original_core_helpers={name: hex(self.core.symbols[name]) for name in sorted(self.core.helpers)})


def audit(args):
    qt, qt_core = args.qt.read_bytes(), args.qt_core.read_bytes()
    assert hashlib.sha256(qt).hexdigest() == access.watchers.SHA["qt"]
    assert hashlib.sha256(qt_core).hexdigest() == access.scan.QT_CORE_SHA
    cases = []
    def fresh():
        return Pool(qt, qt_core, args.mutation)
    def record(name, pool, stages):
        cases.append(dict(name=name, stages=stages, final=pool.pool_snapshot()))

    p = fresh()
    config = p.make_config("wifi", 14)
    first, alias = p.get(config), p.get(config)
    original = p.q(first)
    assert p.q(alias) == original and len(p.created) == 1, "live cache reuse"
    row = p.pool_snapshot()["rows"][0]
    assert (row["strong"], row["weak"]) == (2, 3), "weak cache owner"
    stages = [p.pool_snapshot()]
    p.release(first)
    assert not p.deletes and p.pool_snapshot()["rows"][0]["strong"] == 1
    p.release(alias)
    assert p.deletes == [original], "deferred delete request"
    assert (p.pool_snapshot()["rows"][0]["strong"], p.pool_snapshot()["rows"][0]["weak"]) == (0, 1)
    stages.append(p.pool_snapshot())
    replacement = p.get(config)
    assert p.q(replacement) != original and len(p.created) == 2, "expired cache replacement"
    assert stages[0]["rows"][0]["control"] in p.pool_snapshot()["freed"], "expired cached control release"
    record("reuse-expire-replace", p, stages)

    p = fresh()
    config = p.make_config("same-id", 14)
    alias_config = p.alloc(8)
    p.copy_config(alias_config, config)
    separate = p.make_config("same-id", 14)
    first, alias, other = p.get(config), p.get(alias_config), p.get(separate)
    assert p.q(first) == p.q(alias) and p.q(first) != p.q(other), "private object identity"
    before = p.pool_snapshot()
    p.wi(p.q(config) + 32, 2)
    changed_state = p.get(config)
    p.wq(p.q(config) + 24, p.qstring("different-id"))
    changed_id = p.get(config)
    assert p.q(first) == p.q(changed_state) == p.q(changed_id), "state and ID do not replace pointer key"
    record("identity-state-id", p, [before])

    for label, offset, value, expected_hash in (("type", 36, 1, 1), ("bearer", 44, 2, 512),
                                               ("purpose", 40, 3, 196608)):
        p = fresh()
        config = p.make_config("wifi", 14)
        first = p.get(config)
        p.wi(p.q(config) + offset, value)
        second = p.get(config)
        result = p.pool_snapshot()
        assert p.q(first) != p.q(second) and result["size"] == 2, (label, "property hash changes lookup")
        assert {row["hash"] for row in result["rows"]} == {0, expected_hash}, (label, "property hash value")
        record("mutable-" + label + "-hash", p, [])

    p = fresh()
    config = p.make_config("wifi", 14)
    first = p.get(config)
    p.thread = 1
    second = p.get(config)
    second_thread = p.pool_snapshot()
    p.thread = 0
    again = p.get(config)
    assert p.q(first) == p.q(again) != p.q(second), "thread-local cache isolation"
    assert p.pool_snapshot()["size"] == second_thread["size"] == 1
    record("two-TLS-inputs", p, [second_thread])

    p = fresh()
    handles = [p.get(p.make_config(str(index), 14)) for index in range(16)]
    for handle in handles:
        p.release(handle)
    before = p.pool_snapshot()
    seventeenth = p.get(p.make_config("17", 14))
    boundary = p.pool_snapshot()
    assert before["size"] == 16 and boundary["size"] == 17 and boundary["sweep_visits"] == 0, "prune threshold before insertion"
    eighteenth = p.get(p.make_config("18", 14))
    pruned = p.pool_snapshot()
    assert pruned["size"] == 2 and pruned["sweep_visits"] == 17, "expired entries pruned"
    p.cleanup_thread()
    for handle in (seventeenth, eighteenth):
        control = p.q(handle + 8)
        assert (p.i(control), p.i(control + 4)) == (1, 1), "TLS cleanup drops weak owners only"
        p.release(handle)
        assert control in p.freed, "last owned control release"
    assert len(p.deletes) == 18
    record("16-to-17-expired-pruning", p, [before, boundary, pruned])

    p = fresh()
    handles = [p.get(p.make_config(str(index), 14)) for index in range(17)]
    eighteenth = p.get(p.make_config("18", 14))
    result = p.pool_snapshot()
    assert result["size"] == 18 and result["sweep_visits"] == 17 and not p.deletes, "live entries not a hard capacity"
    record("17-live-entries-retained", p, [])

    p = fresh()
    configs = [p.make_config(str(index), 14) for index in range(17)]
    handles = [p.get(config) for config in configs]
    for handle in handles[::2]:
        p.release(handle)
    reused = p.get(configs[1])
    result = p.pool_snapshot()
    assert result["size"] == 8 and p.q(reused) == p.q(handles[1]) and len(p.created) == 17, "mixed pruning before live lookup"
    record("mixed-live-expired-pruning", p, [])

    p = fresh()
    source, target = p.make_config("source", 14), p.make_config("target", 14)
    first = p.get(source)
    p.register(target, first)
    reused = p.get(target)
    assert p.q(first) == p.q(reused) and len(p.created) == 1 and p.pool_snapshot()["size"] == 2, "explicit registry weak binding"
    record("registry-additional-key", p, [])

    p = fresh()
    config = p.make_config("wifi", 14)
    live = p.get(config)
    empty = p.alloc(16)
    p.register(config, empty)
    replacement = p.get(config)
    assert p.q(replacement) != p.q(live) and not p.deletes, "empty registry does not own old strong result"
    record("registry-empty-replacement", p, [])

    p = fresh()
    old = p.make_session(p.make_config("old", 14))  # Explicit pre-existing borrowed session.
    p.attach(old)
    p.changed("incoming", 14)
    selected = p.q(p.private + 0x88)
    control = p.sessions[selected]["control"]
    assert len(p.created) == 1 and (p.i(control), p.i(control + 4)) == (3, 1), "NAM consumes original factory owner"
    alias = p.get(p.default)
    assert p.q(alias) == selected, "NAM and direct factory share live object"
    p.release(alias)
    before = dict(access=p.snapshot(), pool=p.pool_snapshot())
    p.call(0x11E8C4, p.private)
    assert p.deletes == [selected] and (p.i(control), p.i(control + 4)) == (1, 0), "NAM release leaves expired cached weak"
    p.call(0x11B110, p.private, p.default)
    replacement = p.q(p.private + 0x88)
    assert replacement != selected and len(p.created) == 2 and control in p.freed, "NAM selector replaces expired original cache result"
    record("NAM-original-factory-integration", p, [before])

    image = policy.load_image(qt)[0]
    ranges = ((0x1916A8, 0x191A58), (0x191A58, 0x191B78), (0x191B7C, 0x191C08),
              (0x191C08, 0x191D3C), (0x191D3C, 0x192034), (0x192034, 0x192198), (0x18D78C, 0x18D7A0))
    return dict(scope=__doc__, identities=dict(qt=hashlib.sha256(qt).hexdigest(), qt_core=hashlib.sha256(qt_core).hexdigest()),
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        inherited_sha256={str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                         for path in (SOURCE, access.SOURCE, access.scan.SOURCE, access.scan.bridge.SOURCE,
                                      access.watchers.SOURCE, ROOT / "scripts/audit-steam-client-fec-policy.py")},
        original_ranges={hex(start): dict(size=end - start, sha256=hashlib.sha256(image[start:end]).hexdigest())
                         for start, end in ranges}, cases=cases)


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
