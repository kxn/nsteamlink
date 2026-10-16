#!/usr/bin/env python3
"""Compare production SDR policy C functions with the pinned APK instructions.

Uses the original audit's inputs and native-instruction expectations; no network
access. External object construction/metrics are still the audit's explicit stubs.
This is a selector/timeout comparison, not whole-client equivalence.
"""
import argparse
import ctypes as c
import importlib.util
import json
import random
from pathlib import Path
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location('sdr_audit', Path(__file__).with_name('steam-sdr-policy-audit.py'))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

class Candidate(c.Structure):
    _fields_ = [(n, c.c_int32) for n in ('score', 'minimum', 'maximum', 'other_penalty',
        'shutdown_seconds', 'migration', 'buckets', 'front_samples', 'cluster', 'alternate_penalty')]
    _fields_ += [(n, c.c_int64) for n in ('last_received', 'front_oldest', 'last_ping_sent', 'bucket_end', 'gap')]
    _fields_ += [(n, c.c_bool) for n in ('eligible', 'draining', 'ping_pending')]

class Selection(c.Structure):
    _fields_ = [('primary', c.c_int32), ('backup', c.c_int32), ('probe', c.c_bool * 128)]

class Timeouts(c.Structure):
    _fields_ = [(n, c.c_int64) for n in ('ping_deadline', 'request_deadline', 'last_received')]
    _fields_ += [('ping_failures', c.c_uint), ('request_failures', c.c_uint), ('established', c.c_bool)]

class Downtime(c.Structure):
    _fields_ = [('shutdown', c.c_int64), ('avoid', c.c_int64), ('known', c.c_bool)]

class ProbeInput(c.Structure):
    _fields_ = [(n, c.c_int) for n in ('ping', 'probes', 'received', 'front_samples',
        'failures', 'reachability', 'pop_type', 'tier', 'special')]
    _fields_ += [('estimate', c.c_float), ('since_sent', c.c_int64), ('since_received', c.c_int64)]

class FailedAddress(c.Structure):
    _fields_ = [('address', c.c_uint64), ('failed', c.c_int64)]

class Cache(c.Structure):
    _fields_ = [('entries', FailedAddress * 3), ('count', c.c_uint), ('failures', c.c_uint),
        ('reachability', c.c_int), ('last_probe', c.c_int64)]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', required=True, type=Path)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--random-cases', type=int, default=256)
    args = parser.parse_args()
    if not __debug__:
        parser.error('assertions are required')
    root = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix='nsl-sdr-policy-') as temp:
        library = Path(temp) / 'policy.so'
        subprocess.run(['cc', '-std=c11', '-O2', '-shared', '-fPIC',
            str(root / 'app/platforms/common/sdr_policy.c'), '-o', str(library)], check=True)
        lib = c.CDLL(str(library))
        lib.sl_sdr_select.argtypes = [c.POINTER(Candidate), c.c_size_t, c.c_int32, c.c_int32,
            c.c_bool, c.c_int64, c.POINTER(Selection)]
        lib.sl_sdr_select.restype = c.c_bool
        lib.sl_sdr_expire.argtypes = [c.POINTER(Timeouts), c.c_int64]
        lib.sl_sdr_expire.restype = c.c_uint
        original_select, original_timeout = audit.select, audit.timeout_decision

        def select(elf, routes, active, expected, pings=(), migration_pending=False):
            original_select(elf, routes, active, expected, pings, migration_pending)
            inputs = (Candidate * len(routes))()
            cluster_ids, fronts = [], {}
            for i, route in enumerate(routes):
                shared = route.get('cluster', i)
                cluster_ids.append(cluster_ids[shared] if shared < i else i)
                fronts[cluster_ids[-1]] = route
            for i, r in enumerate(routes):
                front = fronts[cluster_ids[i]]
                m = inputs[i]
                ping = r.get('ping', 20)
                penalty = r.get('penalty', 0)
                score = lambda x: x + x // 10 + penalty
                m.score, m.minimum, m.maximum = score(ping), score(r.get('minimum', ping)), score(r.get('maximum', ping))
                m.other_penalty, m.shutdown_seconds = penalty, r.get('shutdown_seconds', 0x7fffffff)
                m.migration, m.buckets = r.get('migration', 0), r.get('samples', 15)
                m.front_samples, m.cluster = front.get('front_samples', 3), cluster_ids[i]
                m.alternate_penalty = r.get('alternate', 0)
                m.last_received, m.front_oldest = audit.NOW-r.get('age', 0), audit.NOW-front.get('front_age', 0)
                m.last_ping_sent, m.bucket_end = audit.NOW-front.get('probe_age', 0), audit.NOW+1000000
                m.gap, m.eligible = r.get('gap', 0), r.get('eligible', True)
                m.draining, m.ping_pending = r.get('shutdown', False), bool(r.get('pending', 0))
            result = Selection()
            assert lib.sl_sdr_select(inputs, len(routes), active[0] if active else -1,
                active[1] if len(active) > 1 else -1, migration_pending, audit.NOW, c.byref(result))
            actual = [i for i in (result.primary, result.backup) if i >= 0]
            actual_pings = [i for i in range(len(routes)) if result.probe[i]]
            assert actual == expected and actual_pings == sorted(pings), (routes, active, expected, actual, pings, actual_pings)

        def timeout(elf, ping_failures, request_failures, expected_removed, expected_ping=False,
                    ping_due=None, request_due=None, never_received=False, sessions=1):
            original_timeout(elf, ping_failures, request_failures, expected_removed, expected_ping,
                ping_due, request_due, never_received, sessions)
            t = Timeouts(audit.NOW+ping_due if ping_due is not None else 0,
                audit.NOW+request_due if request_due is not None else 0,
                0 if never_received else audit.NOW, ping_failures, request_failures, bool(sessions))
            events = lib.sl_sdr_expire(c.byref(t), audit.NOW)
            assert bool(events & 8) == expected_removed and bool(events & 4) == expected_ping
            assert t.ping_failures == ping_failures+int(ping_due is not None and ping_due <= 0)
            expired = request_due is not None and request_due <= 0 and not (expected_removed and request_failures < 3)
            assert t.request_failures == request_failures+int(expired)

        original_downtime, original_probe = audit.downtime, audit.probe_priorities
        original_ready = audit.routing_readiness
        original_add, original_expire, original_received = audit.failed_cache_add, audit.failed_cache_expire, audit.received
        lib.sl_sdr_warn_downtime.argtypes = [c.POINTER(Downtime), c.c_int32, c.c_float, c.c_int64]
        lib.sl_sdr_warn_downtime.restype = c.c_bool
        lib.sl_sdr_probe_priority.argtypes = [c.POINTER(ProbeInput), c.c_bool, c.c_bool, c.POINTER(c.c_float)]
        lib.sl_sdr_probe_priority.restype = c.c_bool
        lib.sl_sdr_routing_ready.argtypes = [c.c_int] * 5 + [c.c_int64]
        lib.sl_sdr_routing_ready.restype = c.c_bool
        lib.sl_sdr_fail_address.argtypes = [c.POINTER(Cache), c.c_uint64, c.c_uint, c.c_int64]
        lib.sl_sdr_expire_addresses.argtypes = [c.POINTER(Cache), c.c_uint, c.c_int64]
        lib.sl_sdr_address_received.argtypes = [c.POINTER(Cache), c.c_uint64]
        def downtime(elf, seconds, old, expected, random_seconds=50):
            original_downtime(elf, seconds, old, expected, random_seconds)
            t = Downtime(audit.NOW+old*1000000 if old is not None else 0, 123, old is not None)
            changed = lib.sl_sdr_warn_downtime(c.byref(t), seconds, random_seconds, audit.NOW)
            assert changed == (old is None or seconds < old-3)
            assert t.shutdown == audit.NOW+expected*1000000
            assert t.avoid == (audit.NOW+(seconds-random_seconds)*1000000 if changed else 123)
        def priorities(elf, routes, expected, need_any=False, need_backup=False):
            original_probe(elf, routes, expected, need_any, need_backup)
            actual = []
            for i, r in enumerate(routes):
                p = ProbeInput(r.get('ping', 20), r.get('probes', 8), r.get('received', 8),
                    r.get('front_samples', 3), r.get('failures', 0), r.get('reachable', 1),
                    r.get('pop_type', 1), r.get('pop_tier', 1), r.get('special', 0),
                    r.get('estimate', 5000), r.get('probe_age', 0), r.get('front_newest_age', 0))
                value = c.c_float()
                if lib.sl_sdr_probe_priority(c.byref(p), need_any, need_backup, c.byref(value)):
                    actual.append((i, value.value, 4))
            assert len(actual) == len(expected), (routes, actual, expected)
            for a, b in zip(actual, expected):
                assert a[0] == b[0] and abs(a[1]-b[1]) <= max(0.01, abs(b[1])*1e-6), (routes, actual, expected)
        def ready(elf, total, measured, fast, medium, broad, age, expected):
            original_ready(elf, total, measured, fast, medium, broad, age, expected)
            assert lib.sl_sdr_routing_ready(total, measured, fast, medium, broad, age) == expected
        def cache_of(addresses, times, failures, reachability=1):
            t = Cache(); t.count = len(addresses); t.failures = failures; t.reachability = reachability
            for i, (address, stamp) in enumerate(zip(addresses, times)):
                t.entries[i] = FailedAddress(address, stamp)
            return t
        def cache_values(t): return [t.entries[i].address for i in range(t.count)]
        def add(elf, cached, addresses, aggregate, expected, unreachable):
            original_add(elf, cached, addresses, aggregate, expected, unreachable)
            t = cache_of(cached, [audit.NOW-1]*len(cached), aggregate)
            lib.sl_sdr_fail_address(c.byref(t), 1, addresses, audit.NOW)
            assert cache_values(t) == expected and (t.reachability < 0) == unreachable
            assert t.entries[t.count-1].failed == audit.NOW
        def expire(elf, ages, addresses, expected, probe_age=0, expected_reset=False):
            original_expire(elf, ages, addresses, expected, probe_age, expected_reset)
            now = audit.NOW+300000000
            t = cache_of(range(1, len(ages)+1), [now-age for age in ages], 4)
            t.last_probe = now-probe_age
            lib.sl_sdr_expire_addresses(c.byref(t), addresses, now)
            assert cache_values(t) == expected and t.failures == (0 if expected_reset else 4)
        def received(elf, cached, expected, reachability):
            original_received(elf, cached, expected, reachability)
            t = cache_of(cached, [audit.NOW-1]*len(cached), 4, reachability)
            lib.sl_sdr_address_received(c.byref(t), 1)
            assert cache_values(t) == expected and t.failures == 0 and t.reachability == 1
        original_state, original_established = audit.transport_state_change, audit.session_established
        lib.sl_sdr_state_action.argtypes = lib.sl_sdr_established_action.argtypes = [c.c_int]
        lib.sl_sdr_state_action.restype = lib.sl_sdr_established_action.restype = c.c_int
        def state_change(elf, state, active, selected, peer_closed):
            original_state(elf, state, active, selected, peer_closed)
            expected = 1 if state in (-2, 1, 2, 3) else 2 if state in (-1, 4, 5) else 0
            assert lib.sl_sdr_state_action(state) == expected
        def established(elf, state, token, next_sequence, existing=True, warning=False):
            original_established(elf, state, token, next_sequence, existing, warning)
            expected = 1 if state in (-2, 1, 2, 3) else 2 if state in (-1, 4, 5) else 3
            assert lib.sl_sdr_established_action(state) == expected
        audit.transport_state_change, audit.session_established = state_change, established
        audit.select, audit.timeout_decision = select, timeout
        audit.downtime, audit.probe_priorities, audit.routing_readiness = downtime, priorities, ready
        audit.failed_cache_add, audit.failed_cache_expire, audit.received = add, expire, received
        elf = audit.policy.descriptors.SampleELF(args.elf.read_bytes())
        groups = {'active_selection', 'active_switch_confirmation', 'active_candidate_order', 'timeout_decisions', 'downtime_warning', 'global_probe_priority_matrix',
            'global_routing_readiness', 'failed_cache_insertion', 'failed_cache_expiry', 'received_packet_recovery', 'transport_state_change', 'session_established'}
        # Select group names from the existing audit; fail if they are renamed.
        counts = audit.audit(elf, groups)
        assert set(counts) == groups, counts
        rng = random.Random(0x534452)
        generated = rejected = 0
        class NativeAssertion(Exception): pass
        def invalid_graph(m):
            raise NativeAssertion()
        for _ in range(args.random_cases):
            routes = []
            for i in range(rng.randrange(1, 5)):
                ping = rng.choice((20, 30, 40, 60, 100))
                routes.append({'ping': ping, 'minimum': rng.choice((ping, max(0, ping-10))),
                    'maximum': rng.choice((ping, ping+20)), 'penalty': rng.choice((0, 20, 51, 100)),
                    'samples': rng.choice((0, 14, 15, 17)), 'front_samples': rng.choice((2, 3)),
                    'front_age': rng.choice((0, 5000000, 5000001)), 'age': rng.choice((0, 100, 250000, 250001)),
                    'probe_age': rng.choice((0, 199999, 200000)), 'pending': rng.choice((0, audit.NOW+1)),
                    'gap': rng.choice((0, 0, 1)), 'migration': rng.choice((-1, 0, 1)),
                    'shutdown': rng.choice((False, True)), 'shutdown_seconds': rng.choice((10, 20, 0x7fffffff)),
                    'eligible': rng.choice((True, True, False)), 'cluster': rng.randrange(i+1)})
            active = list(range(min(len(routes), rng.randrange(3))))
            migrating = rng.choice((False, True))
            fixture = audit.SDR(elf, routes); fixture.active(active)
            fixture.m.write(fixture.base+64, int(migrating))
            fixture.m.stubs[0xc097e0] = invalid_graph  # Original AssertFailed; never silently bypass it.
            try:
                fixture.m.run(0x81c55c, 0x81ddb8, fixture.base, audit.NOW, budget=100000)
            except NativeAssertion:
                rejected += 1
                continue
            expected = fixture.selected()
            probes = [e[1] for e in fixture.m.events if e[0] == 'ping']
            # This API exposes a set of probe requests; the caller owns socket
            # scheduling. Do not claim packet-send ordering from this check.
            select(elf, routes, active, expected, probes, migrating)
            generated += 1
        counts['generated_active_selection'] = generated
        report = {'sample_sha256': audit.policy.descriptors.SAMPLE_SHA256,
            'method': 'production C policy versus original APK instructions on identical inputs',
            'passed': sum(counts.values()), 'groups': counts, 'generated_inputs_rejected_by_native_assert': rejected,
            'network_interoperability': False}
        if args.report:
            args.report.write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report))

if __name__ == '__main__':
    main()
