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

class StatsProbe(c.Structure):
    _fields_ = [('activity', c.c_int), ('failures', c.c_int)]
    _fields_ += [(n, c.c_int64) for n in ('last_received','last_immediate_request','last_ping')]
    _fields_ += [('pending',c.c_bool)]

class Selection(c.Structure):
    _fields_ = [('primary', c.c_int32), ('backup', c.c_int32), ('probe', c.c_bool * 128)]

class PrimaryLoss(c.Structure):
    _fields_ = [('since',c.c_int64),('reason',c.c_char*64)]

class Timeouts(c.Structure):
    _fields_ = [(n, c.c_int64) for n in ('ping_deadline', 'request_deadline', 'last_received')]
    _fields_ += [('ping_failures', c.c_uint), ('request_failures', c.c_uint), ('established', c.c_bool)]

class Downtime(c.Structure):
    _fields_ = [('shutdown', c.c_int64), ('avoid', c.c_int64), ('known', c.c_bool)]

class ProbeInput(c.Structure):
    _fields_ = [(n, c.c_int) for n in ('ping', 'probes', 'received', 'front_samples',
        'failures', 'reachability', 'pop_type', 'tier', 'special','failed_addresses')]
    _fields_ += [('estimate', c.c_float), ('since_sent', c.c_int64), ('since_received', c.c_int64)]
class ProbeCandidate(c.Structure):
    _fields_=[('index',c.c_uint),('priority',c.c_float)]
class ProbePlan(c.Structure):
    _fields_=[('candidates',ProbeCandidate*128),('count',c.c_size_t),('cutoff',c.c_float),('budget',c.c_uint)]
class AdvertCluster(c.Structure):
    _fields_=[('ping',c.c_int32),('penalty',c.c_int32),('special',c.c_int32),('remote_used',c.c_bool),('old_member',c.c_bool)]
class AdvertRoute(c.Structure):
    _fields_=[('local',c.c_uint),('remote',c.c_uint),('forward',c.c_int32),('reverse',c.c_int32),
        ('internal',c.c_bool),('forced',c.c_bool),('old_member',c.c_bool)]

class FailedAddress(c.Structure):
    _fields_ = [('address', c.c_uint64), ('failed', c.c_int64)]

class Cache(c.Structure):
    _fields_ = [('entries', FailedAddress * 3), ('count', c.c_uint), ('failures', c.c_uint),
        ('reachability', c.c_int), ('last_probe', c.c_int64)]

class Latency(c.Structure):
    _fields_ = [('pop', c.c_uint32), ('ping', c.c_int32), ('penalty', c.c_int32),
        ('flags', c.c_uint32), ('measured', c.c_int64)]

class Latencies(c.Structure):
    _fields_ = [('entries', Latency*128), ('count', c.c_size_t), ('last_full', c.c_int64)]

class Pop(c.Structure):
    _fields_ = [('id',c.c_uint32),('tier',c.c_int),('type',c.c_int),('relay_public_key',c.c_uint8*32),
        ('have_relay_key',c.c_bool),('first_endpoint',c.c_size_t),('endpoint_count',c.c_size_t)]
class Endpoint(c.Structure):
    _fields_ = [('ipv4',c.c_uint32),('port_min',c.c_uint16),('port_max',c.c_uint16),('pop',c.c_uint)]
class Alias(c.Structure):
    _fields_ = [('id',c.c_uint32),('pop',c.c_uint)]
class Config(c.Structure):
    _fields_ = [('revision',c.c_uint64),('relay_public_key',c.c_uint8*32),('have_relay_key',c.c_bool),
        ('pops',Pop*128),('endpoints',Endpoint*1024),('aliases',Alias*512),
        ('pop_count',c.c_size_t),('endpoint_count',c.c_size_t),('alias_count',c.c_size_t)]
class Edge(c.Structure):
    _fields_=[('source',c.c_uint),('target',c.c_uint),('ping',c.c_int32)]

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
            '-I'+str(root/'third_party/jsmn'),str(root/'app/platforms/common/sdr_config.c'),
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
        lib.sl_sdr_plan_probes.argtypes=[c.POINTER(ProbeInput),c.c_size_t,c.c_int,c.c_bool,c.c_bool,c.POINTER(ProbePlan)]
        lib.sl_sdr_plan_probes.restype=c.c_bool
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
        def priorities(elf, routes, expected, need_any=False, need_backup=False, nearest_limit=20):
            native=original_probe(elf, routes, expected, need_any, need_backup,nearest_limit)
            actual = []
            inputs=(ProbeInput*len(routes))()
            for i, r in enumerate(routes):
                p = ProbeInput(r.get('ping', 20), r.get('probes', 8), r.get('received', 8),
                    r.get('front_samples', 3), r.get('failures', 0), r.get('reachable', 1),
                    r.get('pop_type', 1), r.get('pop_tier', 1), r.get('special', 0),r.get('failed_addresses',0),
                    r.get('estimate', 5000), r.get('probe_age', 0), r.get('front_newest_age', 0))
                inputs[i]=p
            plan=ProbePlan()
            assert lib.sl_sdr_plan_probes(inputs,len(routes),nearest_limit,need_any,need_backup,c.byref(plan))
            actual=[(plan.candidates[i].index,plan.candidates[i].priority,4) for i in range(plan.count)]
            expected=native['candidates']
            assert abs(plan.cutoff-native['cutoff']) <= native['cutoff']*1e-6,(routes,plan.cutoff,native)
            assert plan.budget == (10 if need_backup or not need_any else 1)
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
        original_clean = audit.clean_routes
        lib.sl_sdr_clean_active.argtypes = [c.POINTER(c.c_bool), c.c_size_t, c.POINTER(c.c_int32), c.POINTER(c.c_int32)]
        lib.sl_sdr_clean_active.restype = c.c_bool
        def clean(elf, tokens, active, expected, fresh=False, state=3, targets=None):
            original_clean(elf, tokens, active, expected, fresh, state, targets)
            if fresh or not 1 <= state <= 3: return
            targets = list(range(len(tokens))) if targets is None else targets
            desired = (c.c_bool*len(tokens))(*(target is not None and bool(tokens[target]) for target in targets))
            primary, backup = c.c_int32(active[0] if active else -1), c.c_int32(active[1] if len(active)>1 else -1)
            assert lib.sl_sdr_clean_active(desired,len(tokens),c.byref(primary),c.byref(backup))
            assert [i for i in (primary.value,backup.value) if i>=0] == expected
        audit.clean_routes = clean
        original_latencies, original_penalty = audit.receive_latencies, audit.cluster_penalty
        lib.sl_sdr_latencies_begin.argtypes = [c.POINTER(Latencies), c.c_uint32, c.c_int64]
        lib.sl_sdr_latencies_begin.restype = c.c_bool
        lib.sl_sdr_latency_measure.argtypes = [c.POINTER(Latencies), c.c_uint32, c.c_int32, c.c_bool, c.c_int64]
        lib.sl_sdr_latency_measure.restype = c.c_bool
        lib.sl_sdr_latency_estimate.argtypes = [c.POINTER(Latencies), c.c_uint32, c.c_int32]
        lib.sl_sdr_latency_exception.argtypes = [c.POINTER(Latencies), c.c_uint32, c.c_uint32, c.c_int32]
        lib.sl_sdr_cluster_penalty.argtypes = [c.c_int32]
        lib.sl_sdr_cluster_penalty.restype = c.c_int32
        def receive_latencies(elf, initial, ordinary, p2p, exceptions, flags, expected, dirty, reverse=None):
            original_latencies(elf,initial,ordinary,p2p,exceptions,flags,expected,dirty,reverse)
            cache=Latencies()
            for key, values in initial.items():
                cache.entries[cache.count]=Latency(key,*values); cache.count+=1
            actual_dirty=lib.sl_sdr_latencies_begin(c.byref(cache),flags,audit.NOW)
            for values, is_p2p in ((ordinary,False),(p2p,True)):
                for key, ping in values:
                    assert lib.sl_sdr_latency_measure(c.byref(cache),key,ping,is_p2p,audit.NOW)
            if ordinary or p2p:
                if reverse:
                    for key, (old,result) in reverse.items():
                        other=Latencies()
                        if old is not None:
                            other.entries[0]=Latency(100,*old); other.count=1
                        source=next(e for e in cache.entries[:cache.count] if e.pop==key)
                        lib.sl_sdr_latency_estimate(c.byref(other),100,source.ping)
                        entry=other.entries[0]
                        assert (entry.ping,entry.penalty,entry.flags,entry.measured)==result
                for key, bits, penalty in exceptions:
                    lib.sl_sdr_latency_exception(c.byref(cache),key,bits,penalty)
                actual_dirty=True
            actual={e.pop:(e.ping & 0xffffffff,e.penalty & 0xffffffff,e.flags,e.measured)
                    for e in cache.entries[:cache.count]}
            assert actual==expected and bool(actual_dirty)==dirty,(actual,expected)
        def cluster_penalty(elf,old,incoming):
            original_penalty(elf,old,incoming)
            assert lib.sl_sdr_cluster_penalty(incoming)==max(0,min(5000,incoming))
        audit.receive_latencies, audit.cluster_penalty = receive_latencies, cluster_penalty
        original_canonical=audit.canonical_pop
        lib.sl_sdr_config_canonical.argtypes=[c.POINTER(Config),c.c_uint32]
        lib.sl_sdr_config_canonical.restype=c.c_uint32
        def canonical_pop(elf,pops,aliases,incoming,expected):
            original_canonical(elf,pops,aliases,incoming,expected)
            config=Config(); config.pop_count=len(pops); config.alias_count=len(aliases)
            for i,pop in enumerate(pops): config.pops[i].id=pop
            for i,(key,pop) in enumerate(aliases.items()): config.aliases[i]=Alias(key,pop)
            assert lib.sl_sdr_config_canonical(c.byref(config),incoming)==expected
        audit.canonical_pop=canonical_pop
        native_pop_type,native_key,native_front=audit.config_pop_type,audit.relay_key_selection,audit.front_eligibility
        lib.sl_sdr_config_parse.argtypes=[c.c_char_p,c.c_size_t,c.POINTER(Config)]
        lib.sl_sdr_config_parse.restype=c.c_bool
        lib.sl_sdr_config_relay_key.argtypes=[c.POINTER(Config),c.c_uint32]
        lib.sl_sdr_config_relay_key.restype=c.POINTER(c.c_uint8)
        lib.sl_sdr_front_eligible.argtypes=[c.c_int]*4
        lib.sl_sdr_front_eligible.restype=c.c_bool
        def pop_type(elf,first,second):
            expected=native_pop_type(elf,first,second)
            raw=json.dumps({'success':True,'revision':1,'relay_public_key':'01'*32,'pops':{'sin':{'ping_only':first,'relay_ping_only':second,
                'relays':[{'ipv4':'192.0.2.1','port_range':[27015,27015]}]}}}).encode()
            config=Config()
            assert lib.sl_sdr_config_parse(raw,len(raw),c.byref(config))
            assert config.pops[0].type==expected,(first,second,config.pops[0].type,expected)
        def key_selection(elf,cluster,global_key):
            expected=native_key(elf,cluster,global_key)
            config=Config(); config.pop_count=1; config.pops[0].id=100
            config.pops[0].have_relay_key=cluster; config.have_relay_key=global_key
            config.pops[0].relay_public_key[:]=bytes([2])*32; config.relay_public_key[:]=bytes([1])*32
            result=lib.sl_sdr_config_relay_key(c.byref(config),100)
            assert bool(result)==bool(expected)
            if result: assert bytes(result[:32])==bytes([2 if expected=='cluster' else 1])*32
        def front_eligibility(elf,kind,ping,reachability,special):
            expected=native_front(elf,kind,ping,reachability,special)
            assert lib.sl_sdr_front_eligible(kind,ping,reachability,special)==expected
        audit.config_pop_type,audit.relay_key_selection,audit.front_eligibility=pop_type,key_selection,front_eligibility
        native_hex_key=audit.config_hex_key
        def hex_key(elf,text):
            expected=native_hex_key(elf,text)
            raw=json.dumps({'success':True,'revision':1,'relay_public_key':text,
                'pops':{'sin':{'relays':[{'ipv4':'192.0.2.1','port_range':[443,443]}]}}}).encode()
            config=Config()
            actual=lib.sl_sdr_config_parse(raw,len(raw),c.byref(config))
            assert actual==(expected is not None),(text,actual,expected)
            if actual: assert bytes(config.relay_public_key)==expected
        audit.config_hex_key=hex_key
        original_advertise=audit.advertise
        lib.sl_sdr_mark_advertisement.argtypes=[c.POINTER(AdvertCluster),c.c_size_t,c.POINTER(AdvertRoute),
            c.c_size_t,c.c_bool,c.POINTER(c.c_uint8),c.POINTER(c.c_uint8)]
        lib.sl_sdr_mark_advertisement.restype=c.c_bool
        lib.sl_sdr_order_advertisement.argtypes=[c.POINTER(AdvertCluster),c.c_size_t,c.POINTER(AdvertRoute),
            c.c_size_t,c.c_bool,c.POINTER(c.c_uint8),c.POINTER(c.c_uint8),c.POINTER(c.c_uint),c.POINTER(c.c_uint)]
        lib.sl_sdr_order_advertisement.restype=c.c_bool
        def advertise(elf,pings,routes,expected_clusters,expected_routes,old=False,forced=(),
                      metadata=None,internal=(),old_clusters=None,old_routes=None):
            native=original_advertise(elf,pings,routes,expected_clusters,expected_routes,old,forced,
                metadata,internal,old_clusters,old_routes)
            clusters=(AdvertCluster*len(pings))(); inputs=(AdvertRoute*len(routes))()
            for i,ping in enumerate(pings):
                info=(metadata or {}).get(i,{})
                clusters[i]=AdvertCluster(ping,info.get('penalty',0),info.get('special',0),
                    info.get('remote_used',False),old and (old_clusters is None or i in old_clusters))
            for i,(local,remote,forward,reverse) in enumerate(routes):
                inputs[i]=AdvertRoute(local,remote,forward,reverse,i in internal,i in forced,
                    old and (old_routes is None or i in old_routes))
            cr=(c.c_uint8*len(pings))(*([99]*len(pings))); rr=(c.c_uint8*len(routes))(*([99]*len(routes)))
            ok=lib.sl_sdr_mark_advertisement(clusters,len(pings),inputs,len(routes),old,cr,rr)
            assert ok==(native is not None),(pings,routes,ok,native)
            if ok:
                assert dict(enumerate(cr))==native[0],(list(cr),native)
                actual={(r[0],r[1]):rr[i] for i,r in enumerate(routes)}
                assert actual==native[1],(actual,native)
                co=(c.c_uint*len(pings))(); ro=(c.c_uint*len(routes))()
                assert lib.sl_sdr_order_advertisement(clusters,len(pings),inputs,len(routes),old,cr,rr,co,ro)
                assert [i for i in co if cr[i]]==native[2],(list(co),native)
                assert [(routes[i][0],routes[i][1]) for i in ro if rr[i]]==native[3],(list(ro),native)
            else: assert all(x==99 for x in list(cr)+list(rr))
        audit.advertise=advertise
        native_old_advertisement=audit.old_advertisement
        lib.sl_sdr_old_metric_valid.argtypes=[c.c_int32]*4
        lib.sl_sdr_old_metric_valid.restype=c.c_bool
        def old_advertisement(elf,ping,old_ping,penalty,old_penalty,expected,
                              span=(20,30),token=b'',old_token=b'',known=True):
            native_old_advertisement(elf,ping,old_ping,penalty,old_penalty,expected,span,token,old_token,known)
            actual=known and token==old_token and lib.sl_sdr_old_metric_valid(ping,old_ping,*span) and \
                lib.sl_sdr_old_metric_valid(penalty,old_penalty,-1,-1)
            assert actual==expected
        audit.old_advertisement=old_advertisement
        original_estimates=audit.datacenter_routes
        lib.sl_sdr_route_estimates.argtypes=[c.POINTER(c.c_int32),c.c_size_t,c.POINTER(Edge),c.c_size_t,c.POINTER(c.c_int32)]
        lib.sl_sdr_route_estimates.restype=c.c_bool
        def datacenter_routes(elf,fronts,edges,expected,measured=True):
            native=original_estimates(elf,fronts,edges,expected,measured)
            inputs=(c.c_int32*len(fronts))(*fronts)
            links=(Edge*len(edges))(*(Edge(*edge) for edge in edges))
            result=(c.c_int32*len(fronts))()
            assert lib.sl_sdr_route_estimates(inputs,len(fronts),links,len(edges),result)
            assert list(result)==native,(fronts,edges,list(result),native)
        audit.datacenter_routes=datacenter_routes
        original_router=audit.router_ping_reply
        lib.sl_sdr_router_ping_ms.argtypes=[c.c_uint32,c.c_int64,c.POINTER(c.c_int32)]
        lib.sl_sdr_router_ping_ms.restype=c.c_bool
        lib.sl_sdr_router_cookie.argtypes=[c.c_uint32,c.c_uint32,c.c_uint32,c.c_bool]
        lib.sl_sdr_router_cookie.restype=c.c_bool
        def router_ping_reply(elf,delay,expected_ping,**kwargs):
            original_router(elf,delay,expected_ping,**kwargs)
            now=kwargs.get('clock',audit.NOW); ping=c.c_int32(-1234)
            accepted=lib.sl_sdr_router_ping_ms((now-delay)&0xffffffff,now,c.byref(ping))
            assert bool(accepted)==(expected_ping is not None)
            assert ping.value==(expected_ping if accepted else -1234)
            cookie=kwargs.get('cookie',11); session=kwargs.get('session',False)
            counts=kwargs.get('counts',(1,1))
            actual_dispatch=accepted and lib.sl_sdr_router_cookie(cookie,11,22,session) and counts[0]==counts[1]
            expected_dispatch=expected_ping is not None and (cookie==11 or (session and cookie==22)) and counts[0]==counts[1]
            assert bool(actual_dispatch)==expected_dispatch
        audit.router_ping_reply=router_ping_reply
        original_ping_size=audit.ping_request_size
        lib.sl_sdr_ping_request_size.argtypes=[c.c_int64,c.c_int64]
        lib.sl_sdr_ping_request_size.restype=c.c_size_t
        def ping_request_size(elf,last_full,expected):
            original_ping_size(elf,last_full,expected)
            assert lib.sl_sdr_ping_request_size(last_full,audit.NOW)==expected
        audit.ping_request_size=ping_request_size
        audit.select, audit.timeout_decision = select, timeout
        audit.downtime, audit.probe_priorities, audit.routing_readiness = downtime, priorities, ready
        audit.failed_cache_add, audit.failed_cache_expire, audit.received = add, expire, received
        original_outer = audit.outer_routes_delivery
        lib.sl_sdr_outer_probe.argtypes=[c.c_bool,c.c_bool,c.POINTER(StatsProbe),c.c_int64]
        lib.sl_sdr_outer_probe.restype=c.c_bool
        lib.sl_sdr_outer_relay_sufficient.argtypes=[c.c_bool]*4+[c.POINTER(StatsProbe)]*2+[c.c_int64]
        lib.sl_sdr_outer_relay_sufficient.restype=c.c_bool
        def outer(elf,expected_events,**kw):
            native=original_outer(elf,expected_events,**kw)
            now=audit.NOW
            r=StatsProbe(0,kw.get('relay_fail',0),now-kw.get('relay_age',0),0,0,False)
            e=StatsProbe(0,kw.get('e2e_fail',0),now-kw.get('e2e_age',0),
                now-kw.get('immediate_age',0),0,kw.get('reply_pending',False))
            usable=kw.get('active',True) and kw.get('token',True)
            need=kw.get('need',False)
            probe=lib.sl_sdr_outer_probe(usable,need,c.byref(e),now)
            due=not kw.get('acked',False) and kw.get('deadline_delta',-1)<=0
            ack=kw.get('pending_ack',False)
            actual=[]
            if due or ack:
                sent=usable and kw.get('state',3)==3 and kw.get('stats_ok',True)
                if usable and kw.get('state',3)==3: actual.append(('stats',3 if probe else 2 if due else 1))
                enough=lib.sl_sdr_outer_relay_sufficient(sent,need,not sent,False if sent else due,
                    c.byref(r),c.byref(e),now)
                if not enough:
                    actual.append(('signal',))
                    if probe and not sent: actual.append(('stats',3))
            elif probe: actual.append(('stats',3))
            assert actual==[x for x in native if x[0]!='diagnostic'],(kw,actual,native)
        audit.outer_routes_delivery=outer
        original_generic = audit.generic_stats_producer
        lib.sl_sdr_stats_request_flags.argtypes = [c.POINTER(StatsProbe), c.POINTER(StatsProbe),
            c.c_int, c.c_int, c.c_uint32, c.c_bool, c.c_int64]
        lib.sl_sdr_stats_request_flags.restype = c.c_uint32
        def generic(elf, expected, **kw):
            native = original_generic(elf, expected, **kw)
            now = audit.NOW
            r = StatsProbe(kw.get('activity',0),kw.get('relay_fail',0),
                now-kw.get('relay_recv_age',0), now-kw.get('immediate_age',0),
                now-kw.get('relay_age',0),kw.get('pending',False))
            e = StatsProbe(kw.get('e2e_activity',kw.get('activity',0)),kw.get('e2e_fail',0),
                now-kw.get('e2e_recv_age',0),now-kw.get('immediate_age',0),
                now-kw.get('e2e_age',0),kw.get('e2e_pending',False))
            content = bool(kw.get('queued',0) or kw.get('instant_age',0)>=20000000 or
                kw.get('mode',0) and kw.get('e2e_instant_age',0)>=20000000)
            actual = lib.sl_sdr_stats_request_flags(c.byref(r),c.byref(e),kw.get('request',0),
                kw.get('mode',0),kw.get('base_flags',0),content,now)
            assert actual == native, (kw,actual,native)
        audit.generic_stats_producer = generic
        original_loss = audit.primary_loss_history
        lib.sl_sdr_primary_removed.argtypes = [c.POINTER(PrimaryLoss),c.c_bool,c.c_char_p,c.c_int64]
        lib.sl_sdr_primary_gap.argtypes = [c.POINTER(PrimaryLoss),c.c_int64,c.c_int64,c.POINTER(c.c_uint32)]
        lib.sl_sdr_primary_gap.restype = c.c_bool
        def loss_history(elf,removed,reason,seed=False):
            native = original_loss(elf,removed,reason,seed)
            loss = PrimaryLoss(audit.NOW-7000000 if seed else 0,b'previous' if seed else b'')
            lib.sl_sdr_primary_removed(c.byref(loss),removed==0,reason,audit.NOW)
            assert (loss.since,loss.reason)==native,(removed,reason,seed,loss.since,loss.reason,native)
        audit.primary_loss_history = loss_history
        original_expiry = audit.session_idle_expiry
        lib.sl_sdr_session_expired.argtypes = [c.c_int64,c.c_int64]
        lib.sl_sdr_session_expired.restype = c.c_bool
        def idle_expiry(elf,ages,root_age=0):
            native = original_expiry(elf,ages,root_age)
            actual = [i for i in reversed(range(len(ages))) if
                      lib.sl_sdr_session_expired(audit.NOW-ages[i],audit.NOW)]
            assert actual==native,(ages,root_age,actual,native)
        audit.session_idle_expiry = idle_expiry
        original_report = audit.primary_switch_report
        def loss_report(elf,packets,since,**kw):
            native = original_report(elf,packets,since,**kw)
            if not native: return
            age = kw.get('lost_age')
            loss = PrimaryLoss(0 if age is None else audit.NOW-age,kw.get('dropped_reason',b'')[:63])
            ms = c.c_uint32()
            present = lib.sl_sdr_primary_gap(c.byref(loss),kw.get('metrics_gap',0),audit.NOW,c.byref(ms))
            assert (present,ms.value)==native[0][1:],(kw,present,ms.value,native)
        audit.primary_switch_report = loss_report
        elf = audit.policy.descriptors.SampleELF(args.elf.read_bytes())
        groups = {'active_selection', 'active_switch_confirmation', 'active_candidate_order', 'timeout_decisions', 'downtime_warning', 'global_probe_priority_matrix',
            'global_routing_readiness', 'failed_cache_insertion', 'failed_cache_expiry', 'received_packet_recovery', 'transport_state_change', 'session_established', 'clean_route_targets',
            'datacenter_latency_updates', 'reverse_latency_estimation', 'cluster_penalty_updates', 'canonical_pop_mapping',
            'datacenter_route_estimation','router_ping_reply_dispatch','ping_request_size','probe_failure_history',
            'nearest_probe_planning','config_pop_type','relay_key_selection','p2p_front_eligibility','config_hex_key',
            'route_advertisement','advertisement_union','old_advertisement_hysteresis','generic_stats_production','outer_routes_delivery',
            'primary_loss_history','primary_switch_report','session_idle_expiry'}
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
        for _ in range(64):
            fronts=[rng.choice((-1,-1,0,20,50,100,500,2000,2001)) for _ in range(rng.randrange(2,7))]
            edges=[(a,b,rng.choice((-1,0,10,50,100,300))) for a in range(len(fronts))
                   for b in range(len(fronts)) if a != b and rng.randrange(3)==0]
            datacenter_routes(elf,fronts,edges,None,measured=rng.choice((False,True)))
        counts['generated_route_estimation']=64
        for _ in range(512):
            kw = {name:rng.choice((0,4999999,5000000,5000001,6999999,7000000,7000001))
                  for name in ('relay_age','e2e_age')}
            kw.update(activity=rng.choice((0,1,2)),mode=rng.randrange(3),request=rng.randrange(4),
                relay_fail=rng.randrange(2),e2e_fail=rng.randrange(2),
                immediate_age=rng.choice((199999,200000,200001)),
                relay_recv_age=rng.choice((0,9999999,10000000,59999999,60000000)),
                pending=rng.choice((False,True)),queued=rng.choice((0,1)),base_flags=rng.choice((0,8,16,32)),
                e2e_activity=rng.choice((0,1,2)),e2e_pending=rng.choice((False,True)),
                e2e_recv_age=rng.choice((9999999,10000000,59999999,60000000)))
            generic(elf,None,**kw)
        counts['generated_stats_production']=512

        report = {'sample_sha256': audit.policy.descriptors.SAMPLE_SHA256,
            'method': 'production C policy versus original APK instructions on identical inputs',
            'passed': sum(counts.values()), 'groups': counts, 'generated_inputs_rejected_by_native_assert': rejected,
            'network_interoperability': False}
        if args.report:
            args.report.write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report))

if __name__ == '__main__':
    main()
