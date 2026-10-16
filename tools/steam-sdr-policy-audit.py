#!/usr/bin/env python3
"""Execute pinned Steam Link SDR client policy instructions offline.

Synthetic relay/session objects and explicit external-call stubs only. No network
or interoperability claim. Reuses the pinned ELF loader and fail-closed emulator
from steam-remote-policy-audit.py; requires its Python dependencies.
"""
import argparse
import importlib.util
import itertools
import json
from pathlib import Path
import struct

spec = importlib.util.spec_from_file_location(
    'remote_policy', Path(__file__).with_name('steam-remote-policy-audit.py'))
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
Machine, arm, NOW = policy.Machine, policy.arm, policy.NOW
METRICS = policy.RETURN+0x100
REQUEST = policy.RETURN+0x200


def address(ip, port=27015):
    return struct.pack('<I', ip)+bytes(16)+struct.pack('<HH', 3, port)


class SDR:
    def __init__(self, elf, routes):
        self.m = m = Machine(elf)
        self.base, self.connection, self.vt = [m.alloc(8192) for _ in range(3)]
        self.global_map, self.map_nodes = m.alloc(128), m.alloc(max(1, len(routes))*40)
        self.sessions = []
        self.relays = []
        self.clusters = []
        self.inputs = routes
        m.write(self.base, self.vt, 8)
        m.write(self.base+8, self.connection, 8)
        m.write(self.connection+6852, 3)
        m.write(self.base+68, -1)
        m.write(self.vt+152, METRICS, 8)
        m.write(self.vt+168, REQUEST, 8)
        m.write(self.base+240, 1, 8)
        m.write(self.base+248, 1, 8)  # Valid thinker callback, not invoked by stubs.
        m.write(0xc80000+2800, self.global_map, 8)
        m.write(self.global_map+48, self.map_nodes, 8)
        m.write(self.global_map+68, len(routes))
        m.write(self.global_map+72, len(routes))
        self.logging = m.alloc(128)
        m.write(0xc80000+2184, self.logging, 8)
        m.write(0xc80000+2880, self.logging, 8)
        self.array = m.alloc(max(1, len(routes))*8)
        for index, route in enumerate(routes):
            relay, session, cluster, alternate = [m.alloc(8192) for _ in range(4)]
            self.relays.append(relay)
            self.sessions.append(session)
            shared = route.get('cluster', index)
            self.clusters.append(self.clusters[shared] if shared < index else cluster)
            cluster = self.clusters[-1]
            m.write(relay, index)
            m.uc.mem_write(relay+8, address(index+1))
            m.write(relay+32, cluster, 8)
            m.write(cluster, shared)
            m.write(cluster+76, route.get('ping', 20))
            m.write(cluster+72, route.get('front_samples', 3))
            m.write(cluster+32, NOW-route.get('front_newest_age', 0), 8)
            m.write(cluster+64, NOW-route.get('front_age', 0), 8)
            m.write(cluster+80, NOW-route.get('probe_age', 0), 8)
            m.write(cluster+504, 0)
            m.write(cluster+96, NOW+1000000, 8)
            m.write(relay+248, NOW-route.get('age', 0), 8)
            m.write(relay+136, route.get('pending', 0), 8)
            m.write(relay+760, relay, 8)
            m.write(relay+804, int(route.get('shutdown', False)), 1)
            if route.get('alternate', 0):
                m.write(relay+792, alternate, 8)
                m.write(alternate+28, route['alternate'])
            m.write(session, relay, 8)
            m.write(session+8, self.base, 8)
            m.write(self.array+index*8, session, 8)
            m.write(self.map_nodes+index*40+24, relay, 8)
        m.write(self.base+40, self.array, 8)
        m.write(self.base+56, len(routes))
        m.stubs.update({0xc12630: self.capacity, 0xc12640: self.capacity,
                        0xc09990: lambda m: None,
                        0xc12610: self.base_metrics, METRICS: self.derived_metrics,
                        0xc123a0: self.ping,
                        0xc120d0: lambda m: None,
                        0xc11df0: lambda m: m.events.append(('think', m.reg(1))),
                        0xc11de0: lambda m: m.events.append(('set_think', m.reg(1))),
                        0xc124a0: lambda m: None,
                        REQUEST: lambda m: m.events.append(('request', self.relays.index(m.reg(1))))})
        # The actual comparator/sort is part of the policy, not a Python substitute.
        m.redirects[0xc12670] = 0x8327c0
        m.allowed.append((0x8327c0, 0x834000))

    def capacity(self, m):
        count = max(16, m.reg(1))
        m.write(m.reg(0), m.alloc(count*104), 8)
        m.write(m.reg(0)+8, count)

    def base_metrics(self, m):
        route = self.inputs[self.relays.index(m.reg(1))]
        out = m.reg(2)
        m.uc.mem_write(out, bytes(80))
        ping = route.get('ping', 20)
        for offset, value in [(4, ping), (8, route.get('minimum', ping)),
                              (12, route.get('maximum', ping)),
                              (16, route.get('samples', 15)),
                              (48, route.get('penalty', 0)),
                              (56, route.get('shutdown_seconds', 0x7fffffff)),
                              (72, route.get('migration', 0))]:
            m.write(out+offset, value)
        m.write(out+64, route.get('gap', 0), 8)
        m.reg(0, 1)

    def derived_metrics(self, m):
        route = self.inputs[self.relays.index(m.reg(1))]
        m.reg(0, int(route.get('eligible', True)))

    def ping(self, m):
        index = self.relays.index(m.reg(0))
        m.events.append(('ping', index))
        m.write(m.reg(0)+136, NOW+1250000, 8)

    def active(self, indices):
        self.m.write(self.base+36, len(indices))
        for index, value in enumerate(indices):
            self.m.write(self.base+20+index*8, self.sessions[value], 8)

    def selected(self):
        count = self.m.read(self.base+36)
        return [self.sessions.index(self.m.read(self.base+20+i*8, 8)) for i in range(count)]


def select(elf, routes, active, expected, pings=(), migration_pending=False):
    fixture = SDR(elf, routes)
    fixture.active(active)
    m = fixture.m
    m.write(fixture.base+64, int(migration_pending))
    m.run(0x81c55c, 0x81ddb8, fixture.base, NOW, budget=100000)
    assert fixture.selected() == expected, (routes, active, expected, fixture.selected(), m.events)
    assert [e[1] for e in m.events if e[0] == 'ping'] == list(pings), m.events


def pursue(elf, routes, expected, limit=2, existing=(), choose=(), deadlines=()):
    fixture = SDR(elf, routes)
    m = fixture.m
    # Cluster table (24-byte hash entries) and advertised POP descriptors.
    table, entries = m.alloc(128), m.alloc(max(1, len(routes))*24)
    restrictions = m.alloc(24)
    m.write(0xc80000+2824, table, 8)
    m.write(table+48, entries, 8)
    m.write(0xc80000+2792, restrictions, 8)
    vector, items = m.alloc(24), m.alloc(max(1, len(routes))*56)
    m.write(vector, items, 8)
    m.write(vector+8, items+len(routes)*56, 8)
    m.write(fixture.base+56, len(existing))
    for index, value in enumerate(existing):
        m.write(fixture.array+index*8, fixture.sessions[value], 8)
    for index, route in enumerate(routes):
        relay, cluster = fixture.relays[index], fixture.clusters[index]
        pop = m.alloc(128)
        m.write(cluster+8, pop, 8)
        m.write(cluster+16, index)
        m.write(pop+52, 1)
        m.write(entries+index*24+8, cluster, 8)
        m.write(items+index*56, index)
        m.write(items+index*56+52, -1)
        m.write(relay+200, route.get('challenge', 123), 8)
        m.write(relay+192, route.get('server_time', 123))
        m.write(relay+208, NOW-route.get('challenge_age', 0), 8)
        m.write(relay+256, route.get('failures', 0))
        m.write(relay+144, route.get('request_pending', 0), 8)
    picked = iter(choose or range(len(routes)))
    m.stubs[0x81e504] = lambda m: m.reg(0, next(picked))
    m.run(0x81df30, 0x81e504, fixture.base, vector, limit, NOW)
    actual = [event for event in m.events if event[0] in ('request', 'ping')]
    assert actual == list(expected), (routes, actual, expected)
    for index, value in deadlines:
        assert m.read(fixture.relays[index]+144, 8) == value


def received(elf, cached, expected, reachability):
    fixture = SDR(elf, [{}])
    m, relay, cluster = fixture.m, fixture.relays[0], fixture.clusters[0]
    state = m.alloc(128)
    m.write(0xc80000+2904, state, 8)
    m.write(state, 100)
    m.write(cluster+560, reachability)
    m.write(cluster+552, 4)
    m.write(relay+256, 3)
    m.write(cluster+660, len(cached))
    for index, value in enumerate(cached):
        m.uc.mem_write(cluster+564+index*32, address(value)+struct.pack('<Q', NOW-1))
    def compare(m):
        m.reg(0, bytes(m.uc.mem_read(m.reg(0), 24)) == bytes(m.uc.mem_read(m.reg(1), 24)))
    m.stubs[0xc0dc80] = compare
    m.stubs[0xbff660] = lambda m: m.uc.mem_write(m.reg(0), bytes(m.uc.mem_read(m.reg(1), m.reg(2))))
    m.stubs[0x810c34] = lambda m: m.events.append(('reachability_changed',))
    m.run(0x812834, 0x812a28, relay, 10, NOW)
    count = m.read(cluster+660)
    assert [m.read(cluster+564+i*32) for i in range(count)] == expected
    assert m.read(cluster+560) == 1
    assert m.read(cluster+552) == m.read(relay+256) == 0
    assert m.read(relay+248, 8) == NOW
    assert bytes(m.uc.mem_read(cluster+528, 24)) == address(1)
    assert bool(m.events) == (reachability != 1)


def route_lists(elf, clusters, routes, expected_any, expected_token):
    m = Machine(elf)
    m.buffers()
    selector, cluster_array, raw_routes = m.alloc(256), m.alloc(len(clusters)*56), m.alloc(len(routes)*32)
    shared_vector, shared_array = m.alloc(24), m.alloc(len(clusters)*8)
    m.write(0xc80000+2856, shared_vector, 8)
    m.write(shared_vector, shared_array, 8)
    m.write(selector, cluster_array, 8)
    m.write(selector+8, cluster_array+len(clusters)*56, 8)
    best = m.alloc(len(clusters)*32)
    m.write(selector+24, best, 8)
    m.write(selector+32, best+len(clusters)*32, 8)
    m.write(selector+40, best+len(clusters)*32, 8)
    for offset in (48, 72):
        out = m.alloc(len(clusters)*56)
        m.write(selector+offset, out, 8)
        m.write(selector+offset+8, out+len(clusters)*56, 8)
        m.write(selector+offset+16, out+len(clusters)*56, 8)
    m.write(selector+96, raw_routes, 8)
    m.write(selector+104, raw_routes+len(routes)*32, 8)
    for index, cluster in enumerate(clusters):
        shared = m.alloc(1024)
        m.write(shared_array+index*8, shared, 8)
        m.write(shared+16, index)
        m.write(cluster_array+index*56, shared, 8)
        m.write(cluster_array+index*56+8, 20)
        m.write(cluster_array+index*56+16, 30)
        if cluster:
            m.set_string(cluster_array+index*56+24, b'synthetic-token')
    for index, route in enumerate(routes):
        local, remote, forward, reverse = route
        ptr = raw_routes+index*32
        for offset, value in [(0, local), (4, remote), (8, index+1),
                              (24, forward), (28, reverse)]:
            m.write(ptr+offset, value)
    m.allowed.append((0x83f748, 0x8411c4))  # Original route comparator and sort.
    m.run(0x83a124, 0x83a8c8, selector, budget=100000)
    def result(offset):
        begin, end = m.read(selector+offset, 8), m.read(selector+offset+8, 8)
        return [(m.read(ptr), m.read(ptr+24)) for ptr in range(begin, end, 56)]
    assert result(72) == expected_any, (routes, result(72), expected_any)
    assert result(48) == expected_token, (routes, result(48), expected_token)


def probe_priorities(elf, routes, expected, need_any=False, need_backup=False):
    fixture = SDR(elf, routes)
    m = fixture.m
    m.buffers()
    m.redirects[0xc123c0] = 0x8b23e8
    m.allowed.append((0x8b23e8, 0x8b24c0))
    table, entries, ordered = m.alloc(128), m.alloc(len(routes)*24), m.alloc(len(routes)*8)
    output = []
    m.write(0xc80000+2824, table, 8)
    m.write(table+48, entries, 8)
    for slot, value in ((3080, 4), (2920, 8)):
        config = m.alloc(128)
        m.write(0xc80000+slot, config, 8)
        m.write(config+60, value)
    for index, route in enumerate(routes):
        cluster, pop = fixture.clusters[index], m.alloc(128)
        for sample in range(3):
            m.write(cluster+24+sample*16, max(0, route.get('ping', 20)))
        m.write(cluster+8, pop, 8)
        m.write(pop+52, route.get('pop_type', 1))
        m.write(pop+12, route.get('pop_tier', 1))
        for offset, value in [(552, route.get('failures', 0)), (556, route.get('probes', 8)),
                              (560, route.get('reachable', 1)), (764, route.get('special', 0)),
                              (508, route.get('received', 8))]:
            m.write(cluster+offset, value)
        m.write(entries+index*24+8, cluster, 8)
        m.write(ordered+index*8, index)
        m.uc.mem_write(ordered+index*8+4, struct.pack('<f', route.get('estimate', 5000)))
    sp = m.uc.reg_read(arm.UC_ARM64_REG_SP)
    for offset, value in [(28, 20), (40, int(need_backup)), (48, int(need_any))]:
        m.write(sp+offset, value)
    m.write(sp+56, ordered, 8)
    for reg, value in [(19, NOW), (20, len(routes)), (22, table),
                        (24, ordered), (26, ordered+len(routes)*8)]:
        m.reg(reg, value)
    m.stops[0x82445c] = ('probe_candidates_built',)
    m.run(0x823e84, 0x82445c, budget=100000)
    for ptr in range(m.reg(28), m.reg(21), 16):
        priority = struct.unpack('<f', bytes(m.uc.mem_read(ptr+4, 4)))[0]
        output.append((m.read(ptr), priority, m.read(ptr+12)))
    assert len(output) == len(expected), (routes, output, expected)
    for actual, wanted in zip(output, expected):
        assert actual[0] == wanted[0] and abs(actual[1]-wanted[1]) <= max(0.01, abs(wanted[1])*1e-6), output
        assert actual[2] == wanted[2], output


def probe_budget(elf, count, need_any, need_backup, expected, pending=()):
    fixture = SDR(elf, [{} for _ in range(count)])
    m = fixture.m
    table, entries, candidates = m.alloc(128), m.alloc(count*24), m.alloc(count*16)
    m.write(0xc80000+2824, table, 8)
    m.write(table+48, entries, 8)
    for index in range(count):
        m.write(entries+index*24+8, fixture.clusters[index], 8)
        m.write(candidates+index*16, index)
        if index in pending:
            m.write(fixture.relays[index]+136, NOW+1, 8)
    sp = m.uc.reg_read(arm.UC_ARM64_REG_SP)
    m.write(sp+40, int(need_backup))
    m.write(sp+48, int(need_any))
    m.write(sp+88, candidates, 8)
    m.reg(19, NOW)
    m.reg(21, candidates+count*16)
    m.reg(22, table)
    m.uc.reg_write(arm.UC_ARM64_REG_S8, struct.unpack('<I', struct.pack('<f', 10000.0))[0])
    m.stubs[0x81e504] = lambda m: m.reg(0, fixture.clusters.index(m.reg(0)))
    m.stops[0x8245c8] = ('probe_budget_complete',)
    m.run(0x8244bc, 0x8245c8)
    assert [e[1] for e in m.events if e[0] == 'ping'] == expected


def routing_readiness(elf, total, measured, fast, medium, broad, age, expected):
    m = Machine(elf)
    good, clients, logging = m.alloc(8), m.alloc(24), m.alloc(128)
    m.write(0xc80000+2808, clients, 8)
    m.write(0xc80000+2184, logging, 8)
    m.write(0xf49000+1088, NOW-age, 8)
    m.reg(19, NOW)
    m.reg(22, good)
    m.reg(25, total)
    m.reg(26, 0xf49000)
    sp = m.uc.reg_read(arm.UC_ARM64_REG_SP)
    for offset, value in [(16, broad), (20, medium), (24, fast), (36, measured)]:
        m.write(sp+offset, value)
    m.stops[0x824cc8] = ('routing_readiness_complete',)
    m.run(0x824bbc, 0x824cc8)
    assert bool(m.read(good, 1)) == expected


def address_stubs(m):
    m.stubs.update({
        0xc0dc80: lambda m: m.reg(0, bytes(m.uc.mem_read(m.reg(0), 24)) == bytes(m.uc.mem_read(m.reg(1), 24))),
        0xc0dba0: lambda m: m.reg(0, m.read(m.reg(0)) != 0),
        0xc119d0: lambda m: m.reg(0, NOW),
        0xc0da00: lambda m: None,
        0xbff660: lambda m: m.uc.mem_write(m.reg(0), bytes(m.uc.mem_read(m.reg(1), m.reg(2)))),
    })


def downtime(elf, seconds, old, expected, random_seconds=50):
    fixture = SDR(elf, [{}])
    m, relay = fixture.m, fixture.relays[0]
    cache = m.alloc(120)
    address_stubs(m)
    m.write(0xf49400, cache, 8)
    m.write(0xf49408, 3)
    m.write(0xf49410, int(old is not None))
    if old is not None:
        m.uc.mem_write(cache, address(1))
        m.write(cache+24, NOW+old*1000000, 8)
        m.write(cache+32, 123, 8)
    def random(m):
        assert m.uc.reg_read(arm.UC_ARM64_REG_S0) == struct.unpack('<I', struct.pack('<f', 45.0))[0]
        assert m.uc.reg_read(arm.UC_ARM64_REG_S1) == struct.unpack('<I', struct.pack('<f', 60.0))[0]
        m.events.append(('random',))
        m.uc.reg_write(arm.UC_ARM64_REG_S0, struct.unpack('<I', struct.pack('<f', random_seconds))[0])
    m.stubs[0xc0d370] = random
    m.run(0x817db0, 0x817fc0, relay, seconds, NOW)
    assert m.read(0xf49410) == 1
    assert m.read(cache+24, 8) == NOW+expected*1000000
    changed = old is None or seconds < old-3
    assert bool(m.events) == changed
    assert m.read(cache+32, 8) == (NOW+(seconds-random_seconds)*1000000 if changed else 123)


def migration(elf, pop, failed, cutoff, expected, create_result=5):
    fixture = SDR(elf, [{}])
    m, relay, cluster = fixture.m, fixture.relays[0], fixture.clusters[0]
    fixture.active([0])
    m.write(fixture.base+64, 1)
    m.uc.mem_write(relay+216, address(2))
    address_stubs(m)
    m.stubs[0xc11e70] = lambda m: m.reg(0, pop)
    def create(m):
        m.events.append(('create',))
        assert bytes(m.uc.mem_read(m.reg(0), 24)) == address(2)
        assert m.reg(1) == cluster
        m.reg(0, create_result)
    m.stubs[0x819410] = create
    if failed:
        m.uc.mem_write(cluster+564, address(2))
        m.write(cluster+660, 1)
    if cutoff is not None:
        cache = m.alloc(40)
        m.write(0xf49400, cache, 8)
        m.write(0xf49410, 1)
        m.uc.mem_write(cache, address(2))
        m.write(cache+24, NOW+100000000, 8)
        m.write(cache+32, NOW+cutoff, 8)
    m.run(0x8190a8, 0x819410, fixture.base, NOW)
    assert (m.read(fixture.base+64), m.read(fixture.base+68)) == ((2, 5) if expected else (0, 0xffffffff))
    assert bool(m.events) == (pop == 0 and not failed and (cutoff is None or cutoff >= 0))


def choose_relay(elf, routes, active, expected, target=-1, random_invalid=False, random_count=0):
    fixture = SDR(elf, routes)
    m = fixture.m
    fixture.active(active)
    cluster = fixture.clusters[0]
    shared_relays, pop = m.alloc(len(routes)*8), m.alloc(128)
    clients, client_ptrs, restrictions = m.alloc(24), m.alloc(8), m.alloc(24)
    m.write(0xc80000+2808, clients, 8)
    m.write(clients, client_ptrs, 8)
    m.write(clients+8, client_ptrs+8, 8)
    m.write(client_ptrs, fixture.base, 8)
    m.write(fixture.base+68, target)
    m.write(0xc80000+2792, restrictions, 8)
    m.write(cluster+8, pop, 8)
    m.write(pop+48, 10)
    m.write(cluster+776, shared_relays, 8)
    m.write(cluster+784, shared_relays+len(routes)*8, 8)
    # Preferred-address map lookup is not needed for a zero last-good address.
    m.write(fixture.global_map+68, 0)
    for index, route in enumerate(routes):
        relay = fixture.relays[index]
        m.write(relay+32, cluster, 8)
        m.write(relay+800, route.get('shutdown_seconds', 0x7fffffff))
        sessions = m.alloc(8)
        m.write(sessions, fixture.sessions[index], 8)
        m.write(relay+112, sessions, 8)
        m.write(relay+128, int(route.get('has_session', True)))
        m.write(shared_relays+index*8, relay, 8)
    address_stubs(m)
    def random(m):
        m.events.append(('random',))
        m.uc.mem_write(m.reg(8), address(0 if random_invalid else 99))
    m.stubs[0xc121f0] = random
    m.stubs[0xc11e70] = lambda m: m.reg(0, 0)
    m.stubs[0x819410] = lambda m: m.reg(0, 91)
    m.run(0x81e504, 0x81eb90, cluster)
    assert m.reg(0) & 0xffffffff == expected & 0xffffffff
    assert len(m.events) == random_count, m.events


def timeout_decision(elf, ping_failures, request_failures, expected_removed, expected_ping=False,
                     ping_due=None, request_due=None, never_received=False, sessions=1):
    fixture = SDR(elf, [{}])
    m, relay, cluster = fixture.m, fixture.relays[0], fixture.clusters[0]
    for slot, value in ((3080, 4), (3088, 2)):
        config = m.alloc(128)
        m.write(0xc80000+slot, config, 8)
        m.write(config+60, value)
    m.write(relay+128, sessions)
    m.write(relay+248, 0 if never_received else NOW, 8)
    m.write(relay+256, ping_failures)
    m.write(relay+152, request_failures)
    if ping_due is not None:
        m.write(relay+136, NOW+ping_due, 8)
    if request_due is not None:
        m.write(relay+144, NOW+request_due, 8)
    for reg, value in [(19, NOW), (20, 0), (24, cluster), (28, relay)]:
        m.reg(reg, value)
    m.stops.update({0x823424: ('remove',), 0x82350c: ('keep',)})
    m.run(0x8232ec, 0x823590)
    assert (('remove',) in m.events) == expected_removed, m.events
    assert (('ping', 0) in m.events) == expected_ping, m.events
    assert m.read(relay+256) == ping_failures+int(ping_due is not None and ping_due <= 0)
    request_expired = request_due is not None and request_due <= 0 and not (expected_removed and request_failures < 3)
    assert m.read(relay+152) == request_failures+int(request_expired)


def failed_cache_add(elf, cached, pop_addresses, aggregate, expected, expected_unreachable):
    fixture = SDR(elf, [{}])
    m, relay, cluster = fixture.m, fixture.relays[0], fixture.clusters[0]
    pop = m.alloc(128)
    m.write(cluster+8, pop, 8)
    m.write(pop+48, pop_addresses)
    m.write(cluster+552, aggregate)
    m.write(cluster+560, 1)
    m.write(cluster+660, len(cached))
    for index, value in enumerate(cached):
        m.uc.mem_write(cluster+564+index*32, address(value)+struct.pack('<Q', NOW-1))
    address_stubs(m)
    m.stubs[0x810c34] = lambda m: None
    for reg, value in [(19, NOW), (24, cluster), (28, relay)]:
        m.reg(reg, value)
    m.stops[0x823210] = ('failure_cached',)
    m.run(0x823424, 0x823828)
    count = m.read(cluster+660)
    assert [m.read(cluster+564+i*32) for i in range(count)] == expected
    assert m.read(cluster+560) == (0xffffffff if expected_unreachable else 1)
    assert m.read(cluster+564+(count-1)*32+24, 8) == NOW


def failed_cache_expire(elf, ages, pop_addresses, expected, probe_age=0, expected_reset=False):
    fixture = SDR(elf, [{}])
    m, cluster, tick = fixture.m, fixture.clusters[0], NOW+300000000
    table, entries, pop = m.alloc(128), m.alloc(24), m.alloc(128)
    m.write(0xc80000+2824, table, 8)
    m.write(table+48, entries, 8)
    m.write(table+72, 1)
    m.write(entries+8, cluster, 8)
    m.write(cluster+8, pop, 8)
    m.write(pop+48, pop_addresses)
    m.write(cluster+552, 4)
    m.write(cluster+80, tick-probe_age, 8)
    m.write(cluster+660, len(ages))
    for index, age in enumerate(ages):
        m.uc.mem_write(cluster+564+index*32, address(index+1)+struct.pack('<Q', tick-age))
    address_stubs(m)
    m.stubs[0x810c34] = lambda m: None
    m.reg(19, tick)
    m.stops[0x823a04] = ('failed_cache_expiry_complete',)
    m.run(0x823828, 0x823a04)
    count = m.read(cluster+660)
    assert [m.read(cluster+564+i*32) for i in range(count)] == expected
    assert m.read(cluster+552) == (0 if expected_reset else 4)


def expected_probe(route, need_any, need_backup):
    """Single-POP executable transcription of the documented probe priority rules."""
    ping, probes = route.get('ping', 20), route.get('probes', 8)
    ordinary, special = route.get('pop_type', 1) == 1, route.get('special', 0)
    tiered = route.get('pop_tier', 1) >= 1 and special <= 0
    unreachable = route.get('failures', 0) >= 4 or route.get('reachable', 1) < 0
    if special > 0 and probes < 8:
        return [(0, -1e30, 4)]
    estimate = route.get('estimate', 5000)
    if ping < 0:
        if probes < 4 or not unreachable:
            return [(0, float(estimate+(10000 if tiered else 0)), 4)]
        numerator = int(estimate+2000)
    else:
        numerator = ping+50
    if probes >= 8:
        if not ordinary and not need_any and special < 1:
            return []
        if ping >= 0 and route.get('front_samples', 3) >= 3 and route.get('received', 8) >= 8:
            if not need_any or route.get('front_newest_age', 0) <= 120000000:
                return []
        if not need_backup and unreachable and route.get('probe_age', 0) < 120000000:
            return []
    numerator += 0 if ordinary else 75
    return [(0, 20000.0+numerator/(max(0, route.get('probe_age', 0)/1000000)+0.5), 4)]


def advertise(elf, pings, routes, expected_clusters, expected_routes, old=False, forced=()):
    m = Machine(elf)
    m.buffers()
    selector, builder, reason = m.alloc(256), m.alloc(64), m.alloc(1024)
    clusters, raw_routes = m.alloc(len(pings)*56), m.alloc(len(routes)*32)
    cluster_items, route_items = m.alloc(len(pings)*32), m.alloc(len(routes)*32)
    restrictions = m.alloc(24)
    m.write(0xc80000+2784, restrictions, 8)
    m.write(builder, cluster_items, 8)
    m.write(builder+8, cluster_items+len(pings)*32, 8)
    m.write(builder+24, route_items, 8)
    m.write(builder+32, route_items+len(routes)*32, 8)
    m.write(builder+48, int(old), 1)
    for index, ping in enumerate(pings):
        shared = m.alloc(1024)
        m.write(clusters+index*56, shared, 8)
        m.write(shared, index)
        m.write(clusters+index*56+8, ping)
        m.write(cluster_items+index*32, clusters+index*56, 8)
        if old:
            m.write(cluster_items+index*32+24, m.alloc(64), 8)
    for index, (local, remote, forward, reverse) in enumerate(routes):
        ptr = raw_routes+index*32
        for offset, value in [(0, local), (4, remote), (24, forward), (28, reverse)]:
            m.write(ptr+offset, value)
        m.write(route_items+index*32, ptr, 8)
        if old:
            m.write(route_items+index*32+24, m.alloc(64), 8)
        if index in forced:
            m.write(route_items+index*32+9, 1, 1)
    m.allowed.append((0x841578, 0x84c6f0))  # Original four route sorts and cluster sorts.
    m.run(0x83b1d8, 0x83c848, selector, builder, reason, budget=150000)
    assert m.reg(0) == 1
    actual_clusters = {i: m.read(cluster_items+i*32+20) for i in range(len(pings))}
    actual_routes = {((m.read(m.read(route_items+i*32, 8))),
                       m.read(m.read(route_items+i*32, 8)+4)): m.read(route_items+i*32+20)
                     for i in range(len(routes))}
    assert actual_clusters == expected_clusters, (actual_clusters, expected_clusters)
    assert actual_routes == expected_routes, (actual_routes, expected_routes)
    m.run(0x83c848, 0x83c920, builder)
    for offset in (0, 24):
        begin, end = m.read(builder+offset, 8), m.read(builder+offset+8, 8)
        assert all(m.read(ptr+20) > 0 for ptr in range(begin, end, 32))


def old_advertisement(elf, ping, old_ping, penalty, old_penalty, expected,
                       span=(20, 30), token=b'', old_token=b'', known=True):
    m = Machine(elf)
    m.buffers()
    selector, builder, old, reason = m.alloc(256), m.alloc(64), m.alloc(128), m.alloc(1024)
    cluster, shared, pop, item = m.alloc(56), m.alloc(1024), m.alloc(128), m.alloc(32)
    restrictions, cluster_pb, elements = m.alloc(24), m.alloc(64), m.alloc(16)
    m.write(0xc80000+2784, restrictions, 8)
    m.write(selector, cluster, 8)
    m.write(selector+8, cluster+56, 8)
    m.write(cluster, shared, 8)
    m.write(shared+8, pop, 8)
    m.write(pop+8, 123)
    m.write(cluster+8, ping)
    m.write(cluster+12, penalty)
    m.write(builder, item, 8)
    m.write(builder+8, item+32, 8)
    m.write(item, cluster, 8)
    if token:
        session = m.alloc(128)
        m.set_string(session+16, token)
        m.write(item+8, session, 8)
    m.write(old+32, 1)
    m.write(old+40, elements, 8)
    m.write(elements+8, cluster_pb, 8)
    m.write(cluster_pb+24, m.string(old_token), 8)
    m.write(cluster_pb+32, 123)
    m.write(cluster_pb+36, old_ping)
    m.write(cluster_pb+40, old_penalty)
    m.stubs[0xc11f50] = lambda m: m.reg(0, 0 if known else -1)
    m.stubs[0xc11910] = lambda m: None
    def range_provider(m):
        assert m.reg(0) == shared+24
        m.write(m.reg(1), span[0])
        m.write(m.reg(2), span[1])
        m.reg(0, 15)
    m.stubs[0xc125f0] = range_provider
    m.redirects[0xc12bd0] = 0x83b1d8
    m.allowed.extend([(0x83b1d8, 0x83c848), (0x841578, 0x84c6f0)])
    m.run(0x83aa9c, 0x83b1d8, selector, builder, old, NOW, reason)
    assert bool(m.reg(0)) == expected, (ping, old_ping, penalty, old_penalty, token, old_token)


def forward_score(elf, local, remote, interior, penalties, token, expected, stamp=NOW):
    m = Machine(elf)
    selector, clusters, raw_routes = m.alloc(256), m.alloc(112), m.alloc(64)
    network, pops, shared_vector, shared_array, cached = [m.alloc(256) for _ in range(5)]
    m.write(selector, clusters, 8)
    m.write(selector+8, clusters+112, 8)
    m.write(selector+96, raw_routes, 8)
    m.write(selector+104, raw_routes, 8)
    m.write(selector+112, raw_routes+64, 8)
    m.write(0xc80000+2816, network, 8)
    m.write(network+8, pops, 8)
    m.write(pops+120+8, 123)
    m.write(0xc80000+2856, shared_vector, 8)
    m.write(shared_vector, shared_array, 8)
    for index in range(2):
        shared = m.alloc(1024)
        m.write(shared_array+index*8, shared, 8)
        m.write(clusters+index*56, shared, 8)
    for ptr, offset, value in [(clusters, 8, local), (clusters+56, 16, remote),
                                (clusters, 12, penalties[0]), (clusters+56, 20, penalties[1])]:
        m.write(ptr+offset, value)
    if token:
        m.set_string(clusters+56+24, b'synthetic-token')
    m.write(cached, interior)
    m.write(cached+4, penalties[2])
    m.write(cached+16, stamp, 8)
    m.stubs[0xc120f0] = lambda m: m.reg(0, m.reg(1))
    m.stubs[0xc12230] = lambda m: m.reg(0, cached)
    m.redirects[0xc12240] = 0x8159dc
    m.allowed.append((0x8159dc, 0x815aa0))
    m.run(0x83988c, 0x839b9c, selector, 0, 1)
    if expected is None:
        assert m.reg(0) & 0xffffffff == 0xffffffff
        return
    assert m.reg(0) == 0
    assert m.read(raw_routes+24) == expected
    assert m.read(raw_routes+28) == 0x0fffffff
    assert m.read(raw_routes+20, 1) == int(token)
    assert m.read(raw_routes+12) == int(stamp == 0)


def base_think(elf, state, good):
    fixture = SDR(elf, [])
    m = fixture.m
    m.write(fixture.connection+6852, state)
    restrictions, flag = m.alloc(24), m.alloc(8)
    m.write(0xc80000+2784, restrictions, 8)
    m.write(0xc80000+2792, restrictions, 8)
    m.write(0xc80000+3016, flag, 8)
    m.write(flag, int(good), 1)
    m.write(fixture.vt+144, policy.RETURN+0x300, 8)
    m.write(fixture.vt+160, policy.RETURN+0x400, 8)
    m.stubs[0xc124a0] = lambda m: m.events.append(('cancel_migration_if_invalid',))
    m.stubs[policy.RETURN+0x300] = lambda m: m.events.append(('select_active',))
    m.stubs[policy.RETURN+0x400] = lambda m: m.events.append(('pursue',))
    m.run(0x81bf60, 0x81c0e4, fixture.base, NOW)
    expected = [('cancel_migration_if_invalid',), ('select_active',)] if 1 <= state <= 3 else []
    if expected and good:
        expected.append(('pursue',))
    assert m.events == expected


def cancel_migration(elf, state, expected, target=1, active=True, requested=2, port=27015,
                     draining=False, penalty=0):
    fixture = SDR(elf, [{}, {'shutdown': draining, 'alternate': penalty}])
    m = fixture.m
    fixture.active([0] if active else [])
    m.write(fixture.base+64, state)
    m.write(fixture.base+68, target)
    m.uc.mem_write(fixture.relays[0]+216, address(requested, port))
    address_stubs(m)
    m.run(0x818c7c, 0x818edc, fixture.base)
    assert (m.read(fixture.base+64), m.read(fixture.base+68)) == expected


def audit(elf, groups=None):
    counts = {}

    def case(group, fn, *args, **kwargs):
        if groups and group not in groups:
            return
        try:
            fn(elf, *args, **kwargs)
        except Exception as error:
            raise RuntimeError('SDR audit '+group+' '+fn.__name__) from error
        counts[group] = counts.get(group, 0)+1

    case('active_selection', select, [], [], [])
    case('active_selection', select, [{}], [], [0])
    case('active_selection', select, [{'ping': 40}, {'ping': 20}], [], [1, 0])
    case('active_selection', select, [{'ping': 40}, {'ping': 20}], [0, 1], [1, 0])
    case('active_selection', select, [{'ping': 30}, {'ping': 20}], [0, 1], [0, 1])
    case('active_selection', select, [{'ping': 40}, {'ping': 20, 'cluster': 0}], [], [1])
    case('active_selection', select, [{'ping': 20}, {'eligible': False}], [0, 1], [0, 1])
    for age, pending, pings in [(250000, 0, ()), (250001, 0, (1,)),
                                (250001, NOW+1, ())]:
        case('active_selection', select,
             [{'ping': 40, 'shutdown': True}, {'ping': 20, 'age': age, 'pending': pending}],
             [0, 1], [1, 0] if age == 250000 else [0, 1], pings)
    for current, proposed, chosen, pings in [
        ({'ping': 40, 'gap': 1, 'age': 200}, {'ping': 20, 'age': 100}, [1, 0], ()),
        ({'ping': 40, 'gap': 1}, {'ping': 20, 'age': 100}, [0, 1], (1,)),
        ({'ping': 40, 'samples': 14}, {'ping': 20}, [0, 1], ()),
        ({'ping': 40, 'samples': 14}, {'ping': 20, 'probe_age': 200000}, [0, 1], (0,)),
        ({'ping': 40}, {'ping': 20, 'samples': 0}, [0, 1], ()),
        ({'ping': 40}, {'ping': 20, 'samples': 0, 'probe_age': 200000}, [0, 1], (1,)),
        ({'ping': 40}, {'ping': 20, 'samples': 14, 'front_age': 5000001}, [0, 1], (1,)),
        ({'ping': 40}, {'ping': 20, 'samples': 14, 'front_age': 5000000}, [0, 1], ()),
        ({'ping': 40}, {'ping': 20, 'front_samples': 2}, [0, 1], (1,)),
        ({'ping': 40}, {'ping': 20, 'age': 250001}, [0, 1], (1,)),
    ]:
        case('active_switch_confirmation', select, [current, proposed], [0, 1], chosen, pings)
    case('active_switch_confirmation', select, [{'ping': 30}, {'ping': 20}], [0, 1],
         [1, 0], migration_pending=True)
    for routes, expected in [([{'migration': 1}, {'migration': 0}], [1, 0]),
                              ([{'shutdown_seconds': 10}, {'shutdown_seconds': 20}], [1, 0]),
                              ([{}, {}], [0, 1]),
                              ([{'ping': 40}, {'ping': 20}, {'ping': 30}], [1, 2])]:
        case('active_candidate_order', select, routes, [], expected)
    for cached, expected in [([], []), ([1], []), ([2], [2]),
                              ([1, 2, 3], [2, 3]), ([2, 1, 3], [2, 3]),
                              ([2, 3, 1], [2, 3])]:
        for reachability in (-1, 0, 1):
            case('received_packet_recovery', received, cached, expected, reachability)
    case('pursue_sessions', pursue, [], [])
    case('pursue_sessions', pursue, [{}], [('request', 0)], deadlines=[(0, NOW+750000)])
    case('pursue_sessions', pursue, [{}, {}], [('request', 0)], deadlines=[(1, 0)])
    case('pursue_sessions', pursue, [{}, {}], [('request', 1)], existing=[0], choose=[1])
    case('pursue_sessions', pursue, [{}, {}], [], limit=1, existing=[0])
    for field, value in [('challenge', 0), ('server_time', 0), ('challenge_age', 10000001),
                          ('age', 20000001), ('front_samples', 2),
                          ('front_newest_age', 20000001), ('failures', 1)]:
        case('pursue_sessions', pursue, [{field: value}], [('ping', 0)], deadlines=[(0, 0)])
    for field, value in [('challenge_age', 10000000), ('age', 20000000),
                          ('front_newest_age', 20000000)]:
        case('pursue_sessions', pursue, [{field: value}], [('request', 0)])
    case('pursue_sessions', pursue, [{'request_pending': NOW+1}], [], deadlines=[(0, NOW+1)])
    case('pursue_sessions', pursue, [{'challenge': 0, 'pending': NOW+1}], [])
    case('pursue_sessions', pursue, [{'challenge': 0}, {}], [('ping', 0)], limit=1)
    case('pursue_sessions', pursue, [{'challenge': 0, 'failures': 2}, {}],
         [('ping', 0), ('request', 1)], limit=1)
    inf = 0x7fffffff
    case('route_lists', route_lists, [True, True], [(0, 1, 30, inf), (1, 0, 20, inf)],
         [(1, 2), (0, 1)], [(1, 2), (0, 1)])
    case('route_lists', route_lists, [False, True], [(0, 1, 30, inf), (1, 0, 20, inf)],
         [(1, 2), (0, 1)], [(0, 1)])
    case('route_lists', route_lists, [True, True], [(0, 1, 20, 100), (1, 0, 40, inf)],
         [(1, 2), (0, 1)], [(1, 2), (0, 1)])
    case('route_lists', route_lists, [True, True], [(0, 1, 30, inf), (0, 0, 20, inf)],
         [(0, 2)], [(0, 2)])
    case('route_lists', route_lists, [False, True], [(0, 1, 30, inf), (0, 0, 20, inf)],
         [(0, 2)], [(0, 1)])
    case('route_lists', route_lists, [True, True], [(0, 1, 268435455, inf)], [], [])
    for need_any in (False, True):
        for need_backup in (False, True):
            budget = 10 if need_backup or not need_any else 1
            case('global_probe_budget', probe_budget, 12, need_any, need_backup, list(range(budget)))
    case('global_probe_budget', probe_budget, 12, True, False, [2], pending=[0, 1])
    for routes, expected, active in [
        ([{}], [], False), ([{}], [], True),
        ([{'probes': 7}], [(0, 20140.0, 4)], False),
        ([{'probes': 7, 'special': 1}], [(0, -1e30, 4)], False),
        ([{'ping': -1, 'probes': 0, 'reachable': 0}], [(0, 15000.0, 4)], False),
        ([{'ping': -1, 'probes': 0, 'reachable': 0, 'pop_tier': 0}], [(0, 5000.0, 4)], False),
        ([{'front_newest_age': 120000001}], [(0, 20140.0, 4)], True),
        ([{'front_newest_age': 120000000}], [], True),
    ]:
        case('global_probe_priorities', probe_priorities, routes, expected, need_any=active)
    for total, measured, fast, medium, broad, age, expected in [
        (10, 7, 1, 2, 4, 8000000, False),
        (10, 8, 0, 0, 0, 7000000, False),
        (10, 8, 0, 0, 0, 7000001, True),
        (10, 8, 1, 0, 0, 1, True),
        (10, 8, 0, 1, 0, 1, False),
        (10, 8, 0, 2, 0, 1, True),
        (10, 8, 0, 0, 3, 1, False),
        (10, 8, 0, 0, 4, 1, True),
        (20, 14, 1, 2, 4, 8000000, False),
        (20, 15, 0, 0, 0, 7000001, True),
    ]:
        case('global_routing_readiness', routing_readiness, total, measured, fast, medium, broad, age, expected)
    for seconds, old, expected in [(120, None, 120), (120, 120, 120), (121, 120, 120),
                                    (117, 120, 120), (116, 120, 116)]:
        for random_seconds in (45, 60):
            case('downtime_warning', downtime, seconds, old, expected, random_seconds)
    for pop, failed, cutoff, expected in [(0, False, None, True), (-1, False, None, False),
                                          (1, False, None, False), (0, True, None, False),
                                          (0, False, -1, False), (0, False, 0, True),
                                          (0, False, 1, True)]:
        case('migration_validation', migration, pop, failed, cutoff, expected)
    case('migration_validation', migration, 0, False, None, False, create_result=-1)
    for routes, active, expected in [([{}, {}], [], 0), ([{}, {}], [1, 0], 1),
                                      ([{'shutdown_seconds': 10}, {'shutdown_seconds': 20}], [], 1),
                                      ([{'shutdown': True}, {}], [0, 1], 1),
                                      ([{'alternate': 8191}, {}], [0, 1], 1),
                                      ([{'alternate': 8190}, {}], [0, 1], 0)]:
        case('relay_choice', choose_relay, routes, active, expected)
    case('relay_choice', choose_relay, [{'shutdown': True}, {}], [1], 0, target=0)
    case('relay_choice', choose_relay, [{'shutdown': True}], [], 91, random_count=1)
    case('relay_choice', choose_relay, [{'shutdown': True}], [], -1, random_invalid=True, random_count=99)
    for failures, due, removed in [(2, 1, False), (2, 0, False), (3, 1, False),
                                     (3, 0, True), (3, -1, True), (4, None, True)]:
        case('timeout_decisions', timeout_decision, failures, 0, removed, ping_due=due)
    for failures, due, removed, ping in [(0, 0, False, False), (1, 0, False, True),
                                         (2, 0, False, False), (3, 0, True, False),
                                         (3, 1, False, False)]:
        case('timeout_decisions', timeout_decision, 0, failures, removed, ping, request_due=due)
    case('timeout_decisions', timeout_decision, 1, 0, True, ping_due=0, never_received=True, sessions=0)
    case('timeout_decisions', timeout_decision, 1, 0, False, ping_due=1, never_received=True, sessions=0)
    for cached, addresses, aggregate, expected, unreachable in [
        ([], 10, 1, [1], False), ([2], 10, 4, [2, 1], False),
        ([2], 10, 5, [2, 1], True), ([2, 3], 10, 1, [2, 3, 1], True),
        ([2, 3, 4], 10, 1, [3, 4, 1], True), ([2, 1, 3], 10, 1, [2, 3, 1], True),
        ([2], 1, 1, [1], False), ([2, 3], 2, 1, [3, 1], True),
    ]:
        case('failed_cache_insertion', failed_cache_add, cached, addresses, aggregate, expected, unreachable)
    for ages, addresses, expected in [([], 10, []), ([120000000], 10, [1]),
                                       ([120000001], 10, []), ([120000001, 120000000, 1], 10, [2, 3]),
                                       ([1, 2], 2, [2]), ([1], 1, [])]:
        case('failed_cache_expiry', failed_cache_expire, ages, addresses, expected)
    for age, reset in [(120000000, False), (120000001, True)]:
        case('failed_cache_expiry', failed_cache_expire, [], 10, [], probe_age=age, expected_reset=reset)
    for ping, kind, tier, special, probes, failures, active, backup in itertools.product(
            (-1, 20), (1, 2), (0, 1), (-1, 0, 1), (0, 4, 8), (0, 4), (False, True), (False, True)):
        route = {'ping': ping, 'pop_type': kind, 'pop_tier': tier, 'special': special,
                 'probes': probes, 'failures': failures}
        case('global_probe_priority_matrix', probe_priorities, [route],
             expected_probe(route, active, backup), need_any=active, need_backup=backup)
    case('route_advertisement', advertise, [20], [], {0: 3}, {})
    case('route_advertisement', advertise, [20, 30], [(0, 1, 70, inf)],
         {0: 3, 1: 3}, {(0, 1): 3})
    case('route_advertisement', advertise, [20+i for i in range(8)],
         [(i, (i+1) % 8, 70+i, inf) for i in range(8)],
         {i: 3 if i < 4 else 1 if i < 6 else 0 for i in range(8)},
         {(i, (i+1) % 8): 3 if i < 2 else 1 if i < 4 else 0 for i in range(8)})
    for ping, old_ping, penalty, old_penalty, expected in [
        (20, 20, 0, 0, True), (20, 20, 4, 0, True), (20, 20, 5, 0, False),
        (20, 25, 0, 0, True), (20, 26, 0, 0, True), (20, 31, 0, 0, False),
        (40, 20, 0, 0, True), (40, 19, 0, 0, False),
    ]:
        case('old_advertisement_hysteresis', old_advertisement, ping, old_ping, penalty, old_penalty, expected)
    case('old_advertisement_hysteresis', old_advertisement, 20, 20, 0, 0, True, token=b'a', old_token=b'a')
    case('old_advertisement_hysteresis', old_advertisement, 20, 20, 0, 0, False, token=b'a', old_token=b'b')
    case('old_advertisement_hysteresis', old_advertisement, 20, 20, 0, 0, False, old_token=b'a')
    case('old_advertisement_hysteresis', old_advertisement, 20, 20, 0, 0, False, known=False)
    for local, remote, interior, penalties, token, expected in [
        (20, 30, 10, (0, 0, 0), False, 65),
        (21, 38, 10, (1, 2, 3), True, 80),
        (-1, 30, 10, (0, 0, 0), False, None),
        (20, 30, -1, (0, 0, 0), False, None),
    ]:
        case('forward_route_score', forward_score, local, remote, interior, penalties, token, expected)
    case('forward_route_score', forward_score, 20, 30, 10, (0, 0, 0), False, 65, stamp=0)
    case('route_lists', route_lists, [True, True], [(0, 1, 20, 0x0fffffff), (0, 0, 40, 40)],
         [(0, 2)], [(0, 2)])
    for state, good in itertools.product((0, 1, 2, 3, 4, 5), (False, True)):
        case('base_selection_dispatch', base_think, state, good)
    case('global_probe_priorities', probe_priorities,
         [{'ping': -1, 'probes': 0, 'reachable': 0} for _ in range(25)],
         [(i, 15000.0, 4) for i in range(20)])
    case('route_advertisement', advertise, [20+i for i in range(8)],
         [(i, 0, i+10, 17-i) for i in range(8)],
         {i: 3 if i < 4 or i >= 6 else 1 for i in range(8)},
         {(i, 0): 3 if i < 2 or i >= 6 else 1 for i in range(8)})
    case('route_advertisement', advertise, [20+i for i in range(8)],
         [(i, (i+1) % 8, 70+i, inf) for i in range(8)],
         {i: 3 if i == 7 or i < 4 else 1 if i < 6 else 0 for i in range(8)},
         {(i, (i+1) % 8): 3 if i in (0, 7) else 1 if i < 3 else 0 for i in range(8)},
         forced=[7])
    for old in (False, True):
        case('route_advertisement', advertise, [20, 30], [(0, 1, 70, 60)],
             {0: 3, 1: 3}, {(0, 1): 3}, old=old)
    for current, proposed, expected in [
        ({'ping': 60, 'minimum': 41}, {'ping': 20, 'maximum': 30}, [0, 1]),
        ({'ping': 60, 'minimum': 42}, {'ping': 20, 'maximum': 30}, [1, 0]),
        ({'ping': 40, 'minimum': 19, 'penalty': 51, 'samples': 0}, {'ping': 20, 'samples': 0}, [0, 1]),
        ({'ping': 40, 'minimum': 20, 'penalty': 51, 'samples': 0}, {'ping': 20, 'samples': 0}, [1, 0]),
        ({'ping': 40, 'migration': 1, 'samples': 0}, {'ping': 20, 'samples': 0}, [1, 0]),
    ]:
        case('active_switch_confirmation', select, [current, proposed], [0, 1], expected)
    cancelled = (0, 0xffffffff)
    case('migration_cancellation', cancel_migration, 0, cancelled, target=1)
    case('migration_cancellation', cancel_migration, 1, (1, 0xffffffff), target=-1)
    case('migration_cancellation', cancel_migration, 1, cancelled, target=-1, active=False)
    case('migration_cancellation', cancel_migration, 2, (2, 1))
    case('migration_cancellation', cancel_migration, 2, cancelled, active=False)
    case('migration_cancellation', cancel_migration, 2, cancelled, requested=0)
    case('migration_cancellation', cancel_migration, 2, cancelled, port=0)
    case('migration_cancellation', cancel_migration, 2, cancelled, requested=3)
    case('migration_cancellation', cancel_migration, 2, cancelled, draining=True)
    case('migration_cancellation', cancel_migration, 2, (2, 1), penalty=8190)
    case('migration_cancellation', cancel_migration, 2, cancelled, penalty=8191)
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', required=True, type=Path)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--group', action='append', help='Run only this group; repeat to select several groups')
    args = parser.parse_args()
    if not __debug__:
        parser.error('assertions are required; run without Python -O')
    elf = policy.descriptors.SampleELF(args.elf.read_bytes())
    counts = audit(elf, set(args.group) if args.group else None)
    if not counts:
        parser.error('no audit cases selected')
    report = {'sample_sha256': policy.descriptors.SAMPLE_SHA256,
              'method': 'offline original SDR client instructions with explicit external stubs',
              'selection': args.group or 'all',
              'network_interoperability': False, 'passed': sum(counts.values()), 'groups': counts}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
