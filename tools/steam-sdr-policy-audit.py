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


def session_idle_expiry(elf, ages, root_age=0):
    fixture = SDR(elf,[{} for _ in ages])
    m, relay = fixture.m, fixture.relays[0]
    slots = m.alloc(len(ages)*8)
    m.write(relay+112,slots,8)
    m.write(relay+128,len(ages))
    m.write(relay+248,NOW-root_age,8)
    m.write(fixture.connection+24,m.alloc(64),8)
    for i,age in enumerate(ages):
        m.write(slots+i*8,fixture.sessions[i],8)
        m.write(fixture.sessions[i]+2512,NOW-age,8)
    destroyed=[]
    def destroy(m):
        target=m.reg(1)
        destroyed.append(fixture.sessions.index(target))
        count=m.read(relay+128)
        remaining=[m.read(slots+i*8,8) for i in range(count) if m.read(slots+i*8,8)!=target]
        for i,item in enumerate(remaining): m.write(slots+i*8,item,8)
        m.write(relay+128,len(remaining))
    m.write(fixture.vt+120,policy.RETURN+0x500,8)
    m.stubs.update({policy.RETURN+0x500:destroy,0xc117e0:lambda m:None,0xc117b0:lambda m:None})
    m.reg(28,relay);m.reg(19,NOW);m.reg(23,0x383ea7)
    m.stops[0x823228]=('done',)
    m.run(0x82350c,0x823590)
    expected=[i for i in reversed(range(len(ages))) if ages[i]>60000000]
    assert destroyed==expected,(ages,root_age,destroyed,expected)
    assert m.read(relay+248,8)==NOW-root_age
    return destroyed


def primary_loss_history(elf, removed, reason, seed=False):
    fixture = SDR(elf, [{}, {}, {}])
    fixture.active([0, 1])
    m, base = fixture.m, fixture.base
    before = b'previous' if seed else b''
    m.uc.mem_write(base+124, before+b'\0')
    m.write(base+112, NOW-7000000 if seed else 0, 8)
    text = m.alloc(len(reason)+1)
    m.uc.mem_write(text, reason+b'\0')
    def copy_reason(m):
        # Explicit bounded-copy provider; native instructions choose when to
        # copy and whether a backup or the entire active list is discarded.
        assert m.reg(2) == 64
        value = bytes(m.uc.mem_read(m.reg(1),len(reason))).split(b'\0')[0][:63]
        m.uc.mem_write(m.reg(0),value+b'\0')
    m.stubs.update({0xc09f60:copy_reason,0xc12290:lambda m:None,0xbff250:lambda m:None})
    m.run(0x8188f4,0x818c78,base,fixture.sessions[removed],text,NOW)
    expected_active = [] if removed == 0 else [0] if removed == 1 else [0,1]
    assert fixture.selected() == expected_active
    assert m.read(base+56) == 2
    actual = (m.read(base+112,8),bytes(m.uc.mem_read(base+124,64)).split(b'\0')[0])
    expected = (NOW,reason[:63]) if removed == 0 else (NOW-7000000 if seed else 0,before)
    assert actual == expected,(actual,expected)
    return actual


def primary_switch_report(elf, packets, since, ip=True, port=True, pop=True,
                          dropped_reason=b'', lost_age=None, metrics_gap=0):
    fixture = SDR(elf, [{'ping':60}, {'ping':20}])
    fixture.active([0])
    m, base = fixture.m, fixture.base
    for index, cluster in enumerate(fixture.clusters):
        descriptor = m.alloc(128)
        m.write(cluster+8, descriptor, 8)
        m.write(descriptor+8, 100+index)
    m.uc.mem_write(base+72, address(1 if ip else 0, 27015 if port else 0))
    m.write(base+96, 100 if pop else 0)
    m.write(base+104, NOW-10000000 if since else 0, 8)
    m.write(base+120, packets)
    m.uc.mem_write(base+124,dropped_reason[:63]+b'\0')
    m.write(base+112,0 if lost_age is None else NOW-lost_age,8)
    fixture.inputs[0]['gap'] = metrics_gap
    reports=[]
    details=[]
    def constructor(m):
        m.uc.mem_write(m.reg(0), bytes(112))
    def send(m):
        assert m.reg(0) == fixture.relays[1] and m.reg(1) == 16
        obj=m.reg(2)
        qualities=[]
        for offset in (32,40):
            q=m.read(obj+offset,8)
            qualities.append(tuple(m.read(q+i) for i in (16,24,28,32)))
        reports.append((m.read(obj+16),tuple(m.read(obj+i) for i in range(64,88,4)),qualities))
        details.append((m.read(obj+16)&1 != 0,m.read(obj+16)&0x800 != 0,m.read(obj+88)))
        m.reg(0,100)
    def set_reason(m):
        obj=m.reg(0)
        assert bytes(m.uc.mem_read(m.reg(1),64)).split(b'\0')[0] == dropped_reason[:63]
        m.write(obj+16,m.read(obj+16)|1)
    m.stubs.update({0xbffad0:constructor,0xc003c0:lambda m:None,
        0xc0dba0:lambda m:m.reg(0,int(ip)),0xc003e0:lambda m:m.reg(0,m.alloc(128)),
        0xc12390:send,0xc12680:set_reason})
    m.run(0x81c55c,0x81ddb8,base,NOW,budget=100000)
    wanted=packets>=101 and since and ip and port and pop
    assert len(reports)==int(wanted),reports
    if wanted:
        gap = lost_age if lost_age is not None else metrics_gap if metrics_gap > 0 else None
        expected_mask = 0x7e6 | bool(dropped_reason) | (0x800 if gap is not None else 0)
        assert reports==[(expected_mask,(0,1,27015,100,10,packets),[(7,66,60,0),(7,22,20,0)])],reports
        assert details==[(bool(dropped_reason),gap is not None,0 if gap is None else (gap//1000)&0xffffffff)],details
    assert m.read(base+120)==0 and m.read(base+104,8)==NOW
    assert m.read(base+96)==101
    assert m.read(base+112,8)==0 and m.read(base+124,1)==0
    return details


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


def config_pop_type(elf, ping_only, relay_ping_only):
    m=Machine(elf)
    pop,source,frame=m.alloc(128),m.alloc(32),m.alloc(256)
    def value(raw):
        obj=m.alloc(32)
        if raw is None: kind=0
        elif isinstance(raw,bool): kind=5; m.write(obj+8,int(raw),1)
        elif isinstance(raw,(int,float)): kind=4; m.uc.mem_write(obj+8,struct.pack('<d',raw))
        elif isinstance(raw,str): kind=3; m.set_string(obj+8,raw.encode())
        elif isinstance(raw,list): kind=2
        else: kind=1
        m.write(obj,kind)
        return obj
    values={b'ping_only':value(ping_only),b'relay_ping_only':value(relay_ping_only)}
    def lookup(m):
        key=bytes(m.uc.mem_read(m.reg(1),32)).split(b'\0')[0]
        m.reg(0,values[key])
    m.stubs[0xc14820]=lookup
    m.redirects[0xc14840]=0x8dc880
    m.allowed.append((0x8dc880,0x8dca4c))
    m.reg(20,pop); m.reg(24,source); m.reg(29,frame+128)
    m.stops[0x898e10]=('pop_type_parsed',)
    m.run(0x898da0,0x898e10)
    return m.read(pop+52)


def relay_key_selection(elf, cluster_key, global_key):
    m=Machine(elf)
    cluster,network,pop,vt=m.alloc(128),m.alloc(128),m.alloc(128),m.alloc(32)
    m.write(cluster+8,pop,8)
    m.write(pop+80,vt,8); m.write(network+32,vt,8); m.write(vt+16,METRICS,8)
    def valid(m):
        m.reg(0,int(cluster_key if m.reg(0)==pop+80 else global_key))
    m.stubs[METRICS]=valid # Explicit IsValid results; not a crypto-provider audit.
    m.reg(10,cluster); m.reg(23,network)
    m.stops[0x8384dc]=('encrypt',); m.stops[0x838894]=('plaintext',)
    m.run(0x8384a4,0x8384dc)
    expected='cluster' if cluster_key else 'global' if global_key else None
    assert m.events[-1]==(('encrypt',) if expected else ('plaintext',))
    if expected: assert m.reg(22)==(pop+80 if cluster_key else network+32)
    return expected


def config_hex_key(elf, text):
    m=Machine(elf)
    obj,vt,raw=m.alloc(64),m.alloc(64),m.alloc(len(text.encode())+1)
    m.uc.mem_write(raw,text.encode()+b'\0'); m.write(obj,vt,8)
    m.write(vt+24,METRICS,8); m.write(vt+48,0x746508,8)
    m.stubs[METRICS]=lambda m: None # Wipe; raw storage itself is external.
    decoded=[]
    def store(m):
        assert m.reg(2)==32
        decoded.append(bytes(m.uc.mem_read(m.reg(1),32)))
        m.reg(0,1)
    m.stubs[0xc09890]=store
    m.stubs[0xc09a90]=lambda m: m.reg(0,len(bytes(m.uc.mem_read(m.reg(0),len(text.encode())+1)).split(b'\0')[0]))
    m.redirects[0xc09bd0]=0x74c78c
    m.allowed.extend([(0x74c78c,0x74c994),(0x746508,0x74651c)])
    m.run(0x757208,0x7572f8,obj,raw)
    assert bool(m.reg(0))==bool(decoded)
    return decoded[0] if decoded else None


def front_eligibility(elf, kind, ping, reachability, special):
    m=Machine(elf)
    cluster,pop,record=m.alloc(1024),m.alloc(128),m.alloc(64)
    for offset,value in [(76,ping),(560,reachability),(764,special)]: m.write(cluster+offset,value)
    m.write(cluster+8,pop,8); m.write(pop+52,kind)
    m.reg(10,0); m.reg(11,record); m.reg(12,cluster)
    m.stops[0x8396ec]=('ineligible',); m.stops[0x839790]=('eligible',)
    m.run(0x839750,0x839790)
    return m.events[-1]==('eligible',)


def probe_priorities(elf, routes, expected, need_any=False, need_backup=False, nearest_limit=20):
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
                              (508, route.get('received', 8)), (660,route.get('failed_addresses',0))]:
            m.write(cluster+offset, value)
        m.write(entries+index*24+8, cluster, 8)
        m.write(ordered+index*8, index)
        m.uc.mem_write(ordered+index*8+4, struct.pack('<f', route.get('estimate', 5000)))
    sp = m.uc.reg_read(arm.UC_ARM64_REG_SP)
    for offset, value in [(28, max(5,nearest_limit)), (40, int(need_backup)), (48, int(need_any))]:
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
    if expected is not None:
        assert len(output) == len(expected), (routes, output, expected)
        for actual, wanted in zip(output, expected):
            assert actual[0] == wanted[0] and abs(actual[1]-wanted[1]) <= max(0.01, abs(wanted[1])*1e-6), output
            assert actual[2] == wanted[2], output
    m.stops.pop(0x82445c)
    m.stops[0x8244ac]=('probe_cutoff_selected',)
    m.run(0x82445c,0x8244ac)  # Includes the actual counter compare/fcsel, before sort.
    cutoff=struct.unpack('<f',struct.pack('<I',m.uc.reg_read(arm.UC_ARM64_REG_S8)))[0]
    return {'candidates':output,'cutoff':cutoff}


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
    failures=route.get('failures',0)
    unreachable = failures >= 4 or (failures >= 2 and route.get('failed_addresses',0)>0) or route.get('reachable',1)<0
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


def advertise(elf, pings, routes, expected_clusters, expected_routes, old=False, forced=(),
              metadata=None, internal=(), old_clusters=None, old_routes=None):
    m = Machine(elf)
    m.buffers()
    selector, builder, reason = m.alloc(256), m.alloc(64), m.alloc(1024)
    clusters, raw_routes = m.alloc(len(pings)*56), m.alloc(len(routes)*32)
    cluster_items, route_items = m.alloc(len(pings)*32), m.alloc(len(routes)*32)
    restrictions = m.alloc(24)
    network,pops=m.alloc(128),m.alloc(max(1,len(pings))*120)
    m.write(0xc80000+2816,network,8); m.write(network+8,pops,8)
    m.stubs[0xc11910]=lambda m: None # Error-reason formatting only.
    m.write(0xc80000+2784, restrictions, 8)
    m.write(builder, cluster_items, 8)
    m.write(builder+8, cluster_items+len(pings)*32, 8)
    m.write(builder+24, route_items, 8)
    m.write(builder+32, route_items+len(routes)*32, 8)
    m.write(builder+48, int(old), 1)
    for index, ping in enumerate(pings):
        info=(metadata or {}).get(index,{})
        shared = m.alloc(1024)
        m.write(clusters+index*56, shared, 8)
        m.write(shared, index)
        m.write(shared+764,info.get('special',0))
        m.write(clusters+index*56+8, ping)
        m.write(clusters+index*56+12,info.get('penalty',0))
        m.write(clusters+index*56+48,int(info.get('remote_used',False)),1)
        m.write(cluster_items+index*32, clusters+index*56, 8)
        if old and (old_clusters is None or index in old_clusters):
            m.write(cluster_items+index*32+24, m.alloc(64), 8)
    for index, (local, remote, forward, reverse) in enumerate(routes):
        ptr = raw_routes+index*32
        for offset, value in [(0, local), (4, remote), (24, forward), (28, reverse)]:
            m.write(ptr+offset, value)
        m.write(route_items+index*32, ptr, 8)
        if index in internal: m.write(route_items+index*32+8,1,1)
        if old and (old_routes is None or index in old_routes):
            m.write(route_items+index*32+24, m.alloc(64), 8)
        if index in forced:
            m.write(route_items+index*32+9, 1, 1)
    m.allowed.append((0x841578, 0x84c6f0))  # Original four route sorts and cluster sorts.
    m.run(0x83b1d8, 0x83c848, selector, builder, reason, budget=150000)
    if m.reg(0) != 1:
        assert expected_clusters is None and expected_routes is None
        return None
    actual_clusters = {i: m.read(cluster_items+i*32+20) for i in range(len(pings))}
    actual_routes = {((m.read(m.read(route_items+i*32, 8))),
                       m.read(m.read(route_items+i*32, 8)+4)): m.read(route_items+i*32+20)
                     for i in range(len(routes))}
    if expected_clusters is not None:
        assert actual_clusters == expected_clusters, (actual_clusters, expected_clusters)
        assert actual_routes == expected_routes, (actual_routes, expected_routes)
    m.run(0x83c848, 0x83c920, builder)
    for offset in (0, 24):
        begin, end = m.read(builder+offset, 8), m.read(builder+offset+8, 8)
        assert all(m.read(ptr+20) > 0 for ptr in range(begin, end, 32))
    begin,end=m.read(builder,8),m.read(builder+8,8)
    cluster_order=[m.read(m.read(m.read(ptr,8),8)) for ptr in range(begin,end,32)]
    begin,end=m.read(builder+24,8),m.read(builder+32,8)
    route_order=[(m.read(m.read(ptr,8)),m.read(m.read(ptr,8)+4)) for ptr in range(begin,end,32)]
    return actual_clusters,actual_routes,cluster_order,route_order


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


def route_serialization_fields(elf, interior, penalty, forward):
    m=Machine(elf)
    pb,route,network,pops,item=m.alloc(64),m.alloc(32),m.alloc(128),m.alloc(240),m.alloc(32)
    m.write(network+8,pops,8); m.write(pops+8,123); m.write(pops+128,456)
    for offset,value in [(0,0),(4,1),(8,interior),(16,penalty),(24,forward)]: m.write(route+offset,value)
    for reg,value in [(0,pb),(21,route),(22,11),(23,120),(25,item),(26,item+32),(27,network)]: m.reg(reg,value)
    m.stops[0x8377c8]=('route_written',)
    m.run(0x837688,0x8376f8)
    actual=tuple(m.read(pb+offset) for offset in (16,24,28,32,36))
    assert actual==(15,123,456,forward,interior+penalty),actual


def snapshot_readiness_gate(elf, good):
    m=Machine(elf)
    transport,connection,state=m.alloc(8192),m.alloc(8192),m.alloc(8)
    m.write(0xc80000+3016,state,8); m.write(state,int(good),1)
    m.write(transport+8,connection,8); m.write(connection+4912,1)
    m.reg(19,transport)
    m.stubs[0xc12bb0]=lambda m: m.events.append(('init_builder',))
    m.stops[0x836dd0]=('ready',); m.stops[0x836de8]=('not_ready',)
    m.run(0x836d7c,0x836de8)
    assert m.events==([('init_builder',),('ready',)] if good else [('not_ready',)]),m.events


def snapshot_primary_contract(elf, controlling, role, old=True, count=1, first=(123,456)):
    m=Machine(elf)
    transport,connection,metrics,session=[m.alloc(8192) for _ in range(4)]
    cluster,pop,item,old_array,old_route=[m.alloc(128) for _ in range(5)]
    m.write(transport+8,connection,8); m.write(connection+344,int(controlling),1)
    m.write(metrics,session,8); m.write(metrics+8,role)
    m.reg(8,session); m.reg(19,transport); m.reg(21,metrics)
    m.stops[0x8371a4]=('force_primary',); m.stops[0x837160]=('skip',)
    m.run(0x837190,0x8371a4)
    force=controlling and role==0
    assert m.events[-1]==(('force_primary',) if force else ('skip',))
    if not force: return
    m.events.clear()
    m.write(cluster+8,pop,8); m.write(pop+8,123)
    m.write(transport+1032,count); m.write(transport+1040,old_array,8)
    m.write(old_array+8,old_route,8)
    m.write(old_route+24,first[0]); m.write(old_route+28,first[1])
    sp=m.uc.reg_read(arm.UC_ARM64_REG_SP); m.write(sp+8,int(old))
    m.reg(20,cluster); m.reg(26,item); m.reg(27,456)
    m.stubs[0xc09f60]=lambda m: None # Rebuild-reason string only.
    m.run(0x837384,0x837400)
    assert m.read(item+9,1)==1
    assert bool(m.read(sp+8))==(old and count>0 and first==(123,456))


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


def base_metrics_failure_owner(elf, relay_failures, session_failures, age):
    """Run actual base metrics with contradictory root/session failure state."""
    fixture=SDR(elf,[{}])
    m=fixture.m
    relay,session=fixture.relays[0],fixture.sessions[0]
    out=m.alloc(80)
    m.write(fixture.base+68,-1)
    m.write(relay+800,0x7fffffff)
    m.write(relay+256,relay_failures)
    m.write(relay+248,NOW-age,8)
    m.write(session+4136,session_failures)
    # Front/bucket metrics are external here; owner/penalty/gap are native.
    m.stubs[0xc125e0]=lambda m:m.reg(0,1)
    m.run(0x81c3f0,0x81c55c,fixture.base,relay,out,NOW)
    assert m.reg(0)==1
    assert m.read(out+48)==(100 if relay_failures and age>1750000 else 0)
    assert m.read(out+64,8)==(age if relay_failures and age>500000 else 0)


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


def ping_request_size(elf,last_full,expected):
    fixture=SDR(elf,[{}]); m=fixture.m
    m.write(fixture.clusters[0]+768,last_full,8)
    sp=m.uc.reg_read(arm.UC_ARM64_REG_SP)
    m.write(sp+37,2,1)
    m.reg(19,fixture.relays[0]); m.reg(20,NOW)
    def send(m):
        iov=m.reg(2); ptr=m.read(iov,8); size=m.read(iov+8,8)
        m.events.append((size,m.read(ptr+1,1)))
        m.reg(0,1)
    m.stubs[0xc12380]=send
    m.stops[0x81793c]=('sender_fragment_complete',)
    m.run(0x8178ec,0x81793c)
    assert m.events==[(expected,0x82 if expected==100 else 2),('sender_fragment_complete',)],m.events


def router_ping_reply(elf, delay, expected_ping, cookie=11, session=False, pending=False,
                      counts=(1,1), warning=False, clock=NOW):
    fixture=SDR(elf,[{}]); m=fixture.m
    relay, cluster=fixture.relays[0],fixture.clusters[0]
    pb,packet,clients=m.alloc(256),m.alloc(64),m.alloc(24)
    m.write(0xc80000+2808,clients,8)
    m.write(relay+104,11); m.write(cluster+512,-2)
    m.write(relay+136,clock+100000 if pending else 0,8)
    m.write(relay+320,clock-123456,8) # Last send differs; handler does not match it.
    sessions=m.alloc(8); m.write(sessions,fixture.sessions[0],8)
    m.write(relay+112,sessions,8); m.write(relay+128,int(session))
    m.write(fixture.connection+384,22)
    m.write(pb+200,cookie); m.write(pb+176,clock-delay)
    m.write(pb+24,counts[0]); m.write(pb+48,counts[1])
    m.write(pb+16,32 if warning else 0); m.write(pb+196,120); m.write(pb+204,17)
    m.write(packet+16,clock,8)
    m.stubs.update({0xc12060:lambda m:m.events.append(('received',)),
        0xc12070:lambda m:m.events.append(('ping',m.reg(1))),
        0xc12080:lambda m:m.events.append(('warning',)),
        0xc12090:lambda m:m.events.append(('penalty',m.reg(1))),
        0xc120a0:lambda m:m.events.append(('challenge',)),
        0xc120b0:lambda m:m.events.append(('latencies',)),
        0xc120c0:lambda m:m.events.append(('alternates',))})
    m.run(0x812178,0x812794,relay,pb,packet)
    accepted=expected_ping is not None and (cookie==11 or (session and cookie==22)) and counts[0]==counts[1]
    expected=[]
    if accepted:
        expected=[('received',),('ping',expected_ping)]+([('warning',)] if warning else [])
        expected += [('penalty',17),('challenge',),('latencies',),('alternates',)]
    assert m.events==expected,(delay,cookie,session,pending,m.events,expected)


def canonical_pop(elf, pops, aliases, incoming, expected):
    m=Machine(elf)
    network, records=m.alloc(200),m.alloc(max(1,len(pops))*120)
    m.write(network+8,records,8)
    for i,pop in enumerate(pops): m.write(records+i*120+8,pop)
    table={pop:i for i,pop in enumerate(pops)}
    table.update(aliases)
    def tree(items):
        if not items: return 0
        mid=len(items)//2; key,index=items[mid]; node=m.alloc(40)
        m.write(node,tree(items[:mid]),8); m.write(node+8,tree(items[mid+1:]),8)
        m.write(node+28,key); m.write(node+32,index)
        return node
    m.write(network+160,tree(sorted(table.items())),8)
    m.run(0x897e70,0x897ed0,network,incoming)
    assert m.reg(0)==expected,(pops,aliases,incoming,m.reg(0),expected)


def receive_latencies(elf, initial, ordinary, p2p, exceptions, flags, expected, dirty, reverse=None):
    m = Machine(elf)
    cluster, relay, pb, pop, other_clusters = [m.alloc(8192) for _ in range(5)]
    nodes, buckets = m.alloc(16*40), m.alloc(64*4)
    m.uc.mem_write(buckets, b'\xff'*(64*4))
    logging = m.alloc(128)
    m.write(0xc80000+2184, logging, 8)
    m.write(0xc80000+2824, other_clusters, 8)
    m.write(cluster+8, pop, 8)
    m.write(pop+8, 100)
    m.write(cluster+664, buckets, 8)
    m.write(cluster+680, 64)
    m.write(cluster+712, nodes, 8)
    m.write(cluster+748, 64)  # All buckets rehashed; no secondary-table fallback.
    indices = {}
    def insert_entry(key):
        if key in indices:
            return indices[key], False
        index = len(indices)
        assert index < 16
        indices[key] = index
        previous = m.read(buckets+(key & 63)*4)
        m.write(buckets+(key & 63)*4, index)
        m.write(nodes+index*40, key)
        m.write(nodes+index*40+32, previous)
        m.write(cluster+732, len(indices))
        m.write(cluster+736, len(indices))
        return index, True
    for key, values in initial.items():
        index, _ = insert_entry(key)
        ping, penalty, bits, stamp = values
        for offset, value in [(8, ping), (12, penalty), (16, bits)]:
            m.write(nodes+index*40+offset, value)
        m.write(nodes+index*40+24, stamp, 8)
    reverse_objects = {}
    if reverse:
        global_buckets, global_nodes = m.alloc(64*4), m.alloc(len(reverse)*24)
        m.uc.mem_write(global_buckets, b'\xff'*(64*4))
        m.write(other_clusters, global_buckets, 8)
        m.write(other_clusters+16, 64)
        m.write(other_clusters+48, global_nodes, 8)
        m.write(other_clusters+68, len(reverse))
        m.write(other_clusters+84, 64)
        for index, (key, (old, result)) in enumerate(reverse.items()):
            obj, node = m.alloc(8192), m.alloc(40)
            reverse_objects[obj+664] = [obj, node, old is None, result]
            m.write(obj+712, node, 8)
            m.write(global_nodes+index*24, key)
            m.write(global_nodes+index*24+8, obj, 8)
            m.write(global_nodes+index*24+16, m.read(global_buckets+(key & 63)*4))
            m.write(global_buckets+(key & 63)*4, index)
            if old is not None:
                for offset, value in zip((8, 12, 16, 24), old):
                    m.write(node+offset, value, 8 if offset == 24 else 4)
    def insert(m):
        if m.reg(0) in reverse_objects:
            obj, node, added, result = reverse_objects[m.reg(0)]
            assert m.read(m.reg(1)) == 100
            m.write(m.reg(2), 0)
            m.reg(0, 0 if added else -1)
            reverse_objects[obj+664][2] = False
            return
        assert m.reg(0) == cluster+664
        index, added = insert_entry(m.read(m.reg(1)))
        m.write(m.reg(2), index)
        m.reg(0, index if added else -1)
    m.stubs[0xc11f00] = insert
    m.stubs[0xc120e0] = lambda m: None
    m.stubs[0xc120f0] = lambda m: m.reg(0, m.reg(1))
    m.stubs[0x810c34] = lambda m: m.events.append(('routing_dirty',))
    for values, count_offset, id_offset, ping_offset in [(ordinary, 24, 32, 56), (p2p, 120, 128, 152)]:
        ids, pings = m.alloc(max(1, len(values))*4), m.alloc(max(1, len(values))*4)
        m.write(pb+count_offset, len(values))
        m.write(pb+count_offset+24, len(values))
        m.write(pb+id_offset, ids, 8)
        m.write(pb+ping_offset, pings, 8)
        for index, (key, ping) in enumerate(values):
            m.write(ids+index*4, key)
            m.write(pings+index*4, ping)
    elements = m.alloc(8+len(exceptions)*8)
    m.write(pb+80, len(exceptions))
    m.write(pb+88, elements, 8)
    for index, (key, bits, penalty) in enumerate(exceptions):
        item = m.alloc(40)
        m.write(elements+8+index*8, item, 8)
        for offset, value in [(24, key), (28, bits), (32, penalty)]:
            m.write(item+offset, value)
    m.write(pb+212, flags)
    m.run(0x812f40, 0x8134d8, cluster, relay, pb, NOW)
    actual = {key: tuple(m.read(nodes+index*40+offset, 8 if offset == 24 else 4)
                         for offset in (8, 12, 16, 24)) for key, index in indices.items()}
    assert actual == expected, (actual, expected)
    assert bool(m.events) == dirty
    for obj, node, added, result in reverse_objects.values():
        actual_reverse = tuple(m.read(node+offset, 8 if offset == 24 else 4) for offset in (8, 12, 16, 24))
        assert actual_reverse == result, (actual_reverse, result)


def datacenter_routes(elf, fronts, edges, expected, measured=True):
    m = Machine(elf)
    network, vector, logging = m.alloc(128), m.alloc(24), m.alloc(128)
    pops, pointers = m.alloc(len(fronts)*120), m.alloc(len(fronts)*8)
    m.write(0xc80000+2816, network, 8)
    m.write(0xc80000+2856, vector, 8)
    m.write(0xc80000+2880, logging, 8)
    m.write(network+8, pops, 8)
    m.write(network+16, pops+len(fronts)*120, 8)
    m.write(vector, pointers, 8)
    m.write(vector+8, pointers+len(fronts)*8, 8)
    clusters = []
    for index, front in enumerate(fronts):
        cluster = m.alloc(8192)
        clusters.append(cluster)
        m.write(pointers+index*8, cluster, 8)
        m.write(cluster, index)
        m.write(cluster+8, pops+index*120, 8)
        m.write(pops+index*120+8, 100+index)
        m.write(cluster+560, int(front >= 0))
        m.write(cluster+76, front)
        outgoing = [edge for edge in edges if edge[0] == index]
        nodes = m.alloc(max(1, len(outgoing))*40)
        m.write(cluster+712, nodes, 8)
        m.write(cluster+736, len(outgoing))
        for number, (_, remote, ping) in enumerate(outgoing):
            ptr = nodes+number*40
            m.write(ptr, 100+remote)
            m.write(ptr+8, ping)
            m.write(ptr+24, NOW if measured else 0, 8)
            m.write(ptr+32, -1)
    m.stubs[0xc11f50] = lambda m: m.reg(0, m.reg(1)-100 if 100 <= m.reg(1) < 100+len(fronts) else -1)
    m.run(0x810e70, 0x8113c4, budget=100000)
    result=[m.read(c+832) for c in clusters]
    if expected is not None: assert result == expected,(result,expected)
    assert m.read(0xf49000+1016, 1) == 1
    # Only directly measured edges seed nearest-route slots, never estimates.
    for index, cluster in enumerate(clusters):
        nearest = m.read(cluster+806, 2)
        eligible = [(fronts[a]+ping+(fronts[a]//10), a) for a, b, ping in edges
                    if b == index and 0 <= fronts[a] <= 2000 and ping >= 0 and measured]
        assert nearest == (min(eligible)[1] if eligible else 0xffff), (index, nearest, eligible)
    return result


def alternate_updates(elf, initial, advertised, partial, expected, removed=()):
    fixture = SDR(elf, [{}])
    m, relay = fixture.m, fixture.relays[0]
    m.buffers()
    address_stubs(m)
    entries, pb = m.alloc(16*80), m.alloc(256)
    m.write(relay+768, entries, 8)
    m.write(relay+776, entries+len(initial)*80, 8)
    m.write(relay+784, entries+16*80, 8)
    children = {}
    for index, (ip, port, protocol, penalty, child) in enumerate(initial):
        ptr = entries+index*80
        m.uc.mem_write(ptr, address(ip, port))
        m.write(ptr+24, protocol)
        m.write(ptr+28, penalty)
        m.set_string(ptr+32, b'old')
        m.write(ptr+64, -1)
        if child:
            child_ptr = m.alloc(8192)
            children[100+index] = child_ptr
            m.write(child_ptr, 100+index)
            m.write(child_ptr+792, ptr, 8)
            m.write(ptr+56, child_ptr, 8)
    m.stubs[0xbff410] = lambda m: m.set_string(m.reg(0), m.get_string(m.reg(1)))
    def append(m):
        vector = m.reg(0)
        assert vector == relay+768 and m.reg(1) == 1
        end = m.read(vector+8, 8)
        m.uc.mem_write(end, bytes(80))
        m.write(end+64, -1)
        m.write(vector+8, end+80, 8)
    m.stubs[0x82b42c] = append
    def remove(m):
        handle = m.reg(0)
        m.events.append(('remove', handle))
        child = children[handle]
        entry = m.read(child+792, 8)
        m.write(entry+56, 0, 8)
    m.stubs[0xc11e10] = remove
    m.write(pb+212, 2 if partial else 0)
    elements = m.alloc(8+len(advertised)*8)
    m.write(pb+104, len(advertised))
    m.write(pb+112, elements, 8)
    for index, (ip, port, protocol, legacy_penalty) in enumerate(advertised):
        item = m.alloc(64)
        m.write(elements+8+index*8, item, 8)
        m.write(item+24, m.string(b'new'), 8)
        if ip is not None:
            m.write(item+16, 2)
            m.write(item+32, ip)
        m.write(item+36, port)
        m.write(item+40, legacy_penalty)
        m.write(item+44, protocol)
    m.run(0x8134d8, 0x813bd0, relay, pb, NOW, budget=100000)
    begin, end = m.read(relay+768, 8), m.read(relay+776, 8)
    result = []
    for ptr in range(begin, end, 80):
        result.append((m.read(ptr), m.read(ptr+22, 2), m.read(ptr+24), m.read(ptr+28), m.get_string(ptr+32)))
        child = m.read(ptr+56, 8)
        if child:
            assert m.read(child+792, 8) == ptr
    assert result == expected, (result, expected)
    assert [e[1] for e in m.events if e[0] == 'remove'] == list(removed)


def create_alternate(elf, failure_age, expected_created, existing=False, create_ok=True):
    fixture = SDR(elf, [{}])
    m, relay, cluster = fixture.m, fixture.relays[0], fixture.clusters[0]
    entry, created, tick = m.alloc(80), m.alloc(8192), NOW+200000000
    m.uc.mem_write(entry, address(2))
    m.write(relay+768, entry, 8)
    m.write(relay+776, entry+80, 8)
    m.write(entry+72, tick-failure_age, 8)
    if existing:
        m.write(entry+56, created, 8)
    def create(m):
        assert m.reg(0) == 0 and m.reg(1) == entry and m.reg(2) == cluster
        assert m.reg(3) == relay and m.reg(4) == entry
        m.events.append(('create',))
        m.reg(0, created if create_ok else 0)
    m.stubs[0xc11f30] = create
    m.run(0x810d38, 0x810e70, relay, 0, tick)
    assert bool(m.events) == expected_created
    assert m.reg(0) == (created if existing or (expected_created and create_ok) else 0)
    assert m.read(entry+72, 8) == (tick if expected_created and not create_ok else tick-failure_age)


def alternate_probe_schedule(elf, routes, expected):
    fixture = SDR(elf, routes)
    m, tick = fixture.m, NOW+200000000
    roots = []
    for index, route in enumerate(routes):
        relay, root, entry = fixture.relays[index], m.alloc(8192), m.alloc(80)
        roots.append(root)
        m.write(relay+760, root, 8)
        m.write(relay+792, entry, 8)
        m.write(entry+28, 8191)
        m.write(entry+64, route.get('measured', -1))
        m.write(relay+256, route.get('failures', 0))
        m.write(relay+748, route.get('received', 0))
        m.write(relay+320, tick-route.get('age', 1000000), 8)
        m.write(relay+136, tick+1 if route.get('pending', False) else 0, 8)
        m.write(root+256, route.get('root_failures', 0))
        m.write(root+320, tick-route.get('root_age', 1000000), 8)
        m.write(root+136, tick+1 if route.get('root_pending', False) else 0, 8)
    for slot, value in ((3080, 4), (2920, 8)):
        config = m.alloc(128)
        m.write(0xc80000+slot, config, 8)
        m.write(config+60, value)
    def ping(m):
        ptr = m.reg(0)
        m.events.append(('root_ping', roots.index(ptr)) if ptr in roots else ('ping', fixture.relays.index(ptr)))
    m.stubs[0xc123a0] = ping
    def remove(m):
        m.events.append(('probe_done', m.reg(0)))
        m.write(fixture.map_nodes+m.reg(0)*40+32, -2)
    m.stubs[0xc11e10] = remove
    m.reg(19, tick)
    m.reg(24, fixture.global_map)
    m.stops[0x824ea8] = ('alternate_probes_complete',)
    m.run(0x824d38, 0x824ea8)
    assert [e for e in m.events if e[0] != 'alternate_probes_complete'] == expected, m.events


def bad_route(elf, tokens, failed):
    fixture = SDR(elf, [{}])
    m = fixture.m
    pb, elements = m.alloc(64), m.alloc(8+len(tokens)*8)
    m.write(pb+24, m.string(failed), 8)
    m.write(fixture.base+928, len(tokens))
    m.write(fixture.base+936, elements, 8)
    clusters = []
    for index, token in enumerate(tokens):
        item = m.alloc(64)
        clusters.append(item)
        m.write(elements+8+index*8, item, 8)
        m.write(item+24, m.string(token), 8)
        m.write(item+16, 15)
    m.stubs[0xc0a110] = lambda m: m.reg(0, int(bytes(m.uc.mem_read(m.reg(0), m.reg(2))) != bytes(m.uc.mem_read(m.reg(1), m.reg(2)))))
    m.run(0x83cd68, 0x83cf94, fixture.base, fixture.sessions[0], pb, 10, NOW)
    match = tokens.index(failed) if failed in tokens else -1
    assert [m.get_string(m.read(item+24, 8)) for item in clusters] == [b'' if i == match else value for i, value in enumerate(tokens)]
    assert [m.read(item+16) for item in clusters] == [14 if i == match else 15 for i in range(len(tokens))]
    assert bool(m.read(fixture.base+1088, 8)) == (match >= 0)


def no_session(elf, presence, challenge):
    fixture = SDR(elf, [{}])
    m, relay = fixture.m, fixture.relays[0]
    pb = m.alloc(64)
    m.write(fixture.connection+24, m.alloc(64), 8)
    m.write(pb+16, presence)
    m.write(pb+24, 123)
    m.write(pb+28, 456)
    m.write(pb+32, challenge, 8)
    m.write(pb+40, 120)
    m.write(pb+44, 23456)
    m.write(relay+192, 1)
    m.write(relay+200, 2, 8)
    m.write(relay+208, NOW-1, 8)
    m.redirects[0xc12550] = 0x81a358
    m.allowed.append((0x81a358, 0x81a4c8))
    m.stubs[0xc12080] = lambda m: m.events.append(('warning', m.reg(1)))
    m.stubs[0xc117e0] = lambda m: m.events.append(('lock',))
    m.stubs[0xc117b0] = lambda m: m.events.append(('unlock',))
    def destroyed(m):
        assert m.reg(0) == fixture.base and m.reg(1) == fixture.sessions[0]
        assert m.read(relay+200, 8) == (challenge if presence & 4 else 2)
        m.events.append(('destroy_session',))
    m.write(fixture.vt+120, policy.RETURN+0x500, 8)
    m.write(fixture.vt+112, policy.RETURN+0x600, 8)
    m.stubs[policy.RETURN+0x500] = destroyed
    m.stubs[policy.RETURN+0x600] = lambda m: m.events.append(('rethink',))
    m.run(0x81a290, 0x81a358, fixture.base, fixture.sessions[0], pb, 10, NOW, 0)
    expected = [('warning', 120)] if presence & 8 else []
    assert m.events == expected+[('lock',), ('destroy_session',), ('unlock',), ('rethink',)]
    assert m.read(relay+192) == (456 if presence & 4 else 1)
    assert m.read(relay+208, 8) == (NOW if presence & 4 else NOW-1)
    assert m.read(relay+168) == (123 if presence & 4 else 0)


def session_established(elf, state, token, next_sequence, existing=True, warning=False):
    fixture = SDR(elf, [{}])
    m, relay, session = fixture.m, fixture.relays[0], fixture.sessions[0]
    m.buffers()
    pb = m.alloc(64)
    m.write(pb+24, m.string(token), 8)
    m.write(pb+32, 123)
    m.write(pb+36, 120)
    m.write(pb+40, next_sequence)
    m.write(pb+16, 4 if warning else 0)
    m.write(fixture.connection+384, 123)
    m.write(fixture.connection+6848, state)
    m.write(fixture.connection+4912, 1)
    m.write(relay+144, NOW+1, 8)
    m.write(relay+152, 7)
    relay_sessions = m.alloc(8)
    m.write(relay_sessions, session, 8)
    m.write(relay+112, relay_sessions, 8)
    m.write(relay+128, int(existing))
    accepted = bool(token) and state in (-2, 1, 2, 3)
    session_result = [session]
    def construct(m):
        assert m.reg(1) == relay and m.reg(2) == fixture.base
        session_result[0] = m.reg(0)
        m.write(m.reg(0), relay, 8)
        m.write(m.reg(0)+8, fixture.base, 8)
        m.events.append(('construct',))
    m.stubs[0xc12a10] = construct
    m.stubs[0xbff410] = lambda m: m.set_string(m.reg(0), m.get_string(m.reg(1)))
    m.stubs[0xc12080] = lambda m: m.events.append(('warning',))
    m.stubs[0xc12cd0] = lambda m: m.events.append(('init_sequence', m.reg(1)))
    m.stubs[0xc124f0] = lambda m: m.reg(0, m.reg(1) & 65535)
    m.stubs[0xc12ca0] = lambda m: m.events.append(('track_sequence', m.reg(1)))
    m.stubs[0xc124d0] = lambda m: m.events.append(('connection_closed',))
    def diagnostic(m):
        m.events.append(('diagnostic', m.reg(1)))
        m.reg(0, 1)
    m.stubs[0xc097e0] = diagnostic
    m.write(fixture.vt+112, policy.RETURN+0x600, 8)
    m.stubs[policy.RETURN+0x600] = lambda m: m.events.append(('rethink',))
    m.run(0x83dac8, 0x83e034, fixture.base, relay, pb, 50, NOW)
    expected = [('warning',)] if token and warning else []
    if accepted:
        if not existing:
            expected.append(('construct',))
        if next_sequence:
            expected += [('init_sequence', (next_sequence-1) & 65535), ('track_sequence', next_sequence)]
        expected.append(('rethink',))
    elif not token:
        expected.append(('diagnostic', 2166))
    elif state in (-1, 4, 5):
        expected.append(('connection_closed',))
    else:
        expected.append(('diagnostic', 2182))
    assert m.events == expected, m.events
    assert m.read(relay+144, 8) == (0 if token else NOW+1)
    assert m.read(relay+152) == (0 if accepted else 7)
    if accepted:
        out = session_result[0]
        assert m.get_string(out+16) == token
        assert m.read(out+2512, 8) == NOW
        assert m.read(out+2320, 8) == 1 and m.read(out+2344, 8) == 50


def transport_state_change(elf, state, active, selected, peer_closed):
    fixture = SDR(elf, [{}, {}])
    fixture.active(active)
    m = fixture.m
    m.write(fixture.connection+6848, state)
    m.write(fixture.connection+40, fixture.base if selected else fixture.base+1, 8)
    for i in peer_closed: m.write(fixture.sessions[i]+4552, 1, 1)
    m.stubs[0xc12590] = lambda m: None
    m.stubs[0xc124d0] = lambda m: m.events.append(('closed', fixture.sessions.index(m.reg(2)), bool(m.reg(3))))
    m.run(0x81ba8c, 0x81bbdc, fixture.base, 3)
    if state in (-2, 1, 2, 3):
        expected = [('set_think', 1)]
    elif state in (-1, 4, 5):
        expected = [('closed', i, bool(selected and (not active or active[0] == i)))
                    for i in range(2) if i not in peer_closed]
    else: expected = []
    assert m.events == expected, (state, active, selected, peer_closed, m.events, expected)


def connection_closed_sender(elf, remote_id, end_to_end):
    """Execute the sender hidden behind the old 'no_connection' event label.

    Message allocation/derived population are explicit stubs; the original
    sender sets the IDs and chooses the wire message type itself.
    """
    fixture = SDR(elf, [{}])
    m = fixture.m
    relay, session = fixture.relays[0], fixture.sessions[0]
    m.write(fixture.connection+384, 123)
    m.write(fixture.connection+388, remote_id)
    def initialize(m): m.uc.mem_write(m.reg(0), bytes(136))
    def send(m):
        message = m.reg(2)
        m.events.append(('send', m.reg(1), m.read(message+104), m.read(message+100)))
        m.reg(0, 50)
    populate = policy.RETURN+0x700
    m.write(fixture.vt+176, populate, 8)
    m.stubs.update({0xbffb10: initialize, 0xc00690: lambda m: None,
        0xc12390: send, populate: lambda m: m.events.append(('populate', m.reg(3), m.reg(4)))})
    m.run(0x81b554, 0x81b6a4, fixture.base, relay, session, int(end_to_end))
    assert m.events == [('populate', session, int(end_to_end)), ('send', 20, 123, remote_id)]


def stats_migration(elf, requested, port, old, active=True, source=0, state=0, target=-1):
    fixture = SDR(elf, [{}, {}])
    m, pb = fixture.m, fixture.m.alloc(128)
    fixture.active([0] if active else [])
    relay = fixture.relays[source]
    m.uc.mem_write(relay+216, address(old, 27015 if old else 0))
    m.write(fixture.base+64, state)
    m.write(fixture.base+68, target)
    m.write(pb+84, requested)
    m.write(pb+88, port)
    m.write(fixture.sessions[source]+4152, 2)  # No per-session keepalive work in this case.
    address_stubs(m)
    m.run(0x83e034, 0x83e624, fixture.base, fixture.sessions[source], pb, 0, NOW)
    changed = requested != 0 and port != 0 and active and source == 0 and (requested != old or port & 65535 != (27015 if old else 0))
    expected_pair = (1, 0xffffffff) if changed else (state, target & 0xffffffff)
    assert (m.read(fixture.base+64), m.read(fixture.base+68)) == expected_pair
    assert bytes(m.uc.mem_read(relay+216, 24)) == (address(requested, port & 65535) if changed else address(old, 27015 if old else 0))


def stats_revisions(elf, forward_ack, old_forward_acked, peer_ack, old_peer_ack=5, deadline=NOW+1,
                     flags=0, primary_transport=True, quality=False):
    fixture = SDR(elf, [{}])
    m, session = fixture.m, fixture.sessions[0]
    pb = m.alloc(128)
    presence = (256 if forward_ack is not None else 0) | (512 if peer_ack is not None else 0) | (4 if quality else 0)
    m.write(pb+16, presence)
    m.write(pb+100, forward_ack or 0)
    m.write(pb+104, peer_ack or 0)
    m.write(pb+96, flags)
    m.write(session+100, 5)
    m.write(session+104, int(old_forward_acked), 1)
    m.write(fixture.base+1048, 10)
    m.write(fixture.base+1232, old_peer_ack)
    m.write(fixture.base+1224, deadline, 8)
    m.write(fixture.connection+4912, 1)
    m.write(fixture.connection+40, fixture.base if primary_transport else 0, 8)
    m.stubs[0xc12ce0] = lambda m: m.events.append(('common',))
    m.write(fixture.vt+136, policy.RETURN+0x700, 8)
    m.stubs[policy.RETURN+0x700] = lambda m: m.events.append(('send_stats',))
    m.run(0x83d860, 0x83dac8, fixture.base, session, pb, 0, NOW)
    assert bool(m.read(session+104, 1)) == (old_forward_acked if forward_ack is None else forward_ack == 5)
    assert m.read(fixture.base+1232) == (peer_ack if peer_ack is not None and peer_ack <= 10 else old_peer_ack)
    assert m.read(fixture.base+1224, 8) == (0 if peer_ack == 10 else deadline)
    send = bool((flags & 2 or quality) and (flags & 4 or not primary_transport))
    assert m.events == [('common',)]+([('send_stats',)] if send else [])


def receive_routes(elf, old_revision, new_revision, valid):
    fixture = SDR(elf, [])
    m = fixture.m
    m.write(fixture.base+968, old_revision)
    m.write(fixture.connection+4912, 1)
    m.stubs[0xbffc10] = lambda m: m.uc.mem_write(m.reg(0), bytes(80))
    m.stubs[0xc00b50] = lambda m: None
    def parse(m):
        m.write(m.reg(0)+72, new_revision)
        m.reg(0, int(valid))
    m.stubs[0xc11bf0] = parse
    m.stubs[0xc00b80] = lambda m: m.write(m.reg(0)+72, m.read(m.reg(1)+72))
    m.stubs[0xc09b00] = lambda m: m.reg(0, 1)
    m.run(0x834df0, 0x834f94, fixture.base, m.string(b'synthetic'))
    updated = valid and new_revision > old_revision
    assert m.read(fixture.base+968) == (new_revision if updated else old_revision)
    assert m.read(fixture.base+1096, 1) == 1
    assert bool(m.read(fixture.base+1088, 8)) == updated


def stats_ack_queue(elf, queued, incoming, flags, e2e=False):
    fixture = SDR(elf, [{}])
    m, session = fixture.m, fixture.sessions[0]
    pb = m.alloc(128)
    m.write(pb+16, 4096 if e2e else 2048)
    m.write(pb+112, incoming)
    m.write(pb+116, incoming)
    m.write(pb+96, flags)
    m.write(session+4152, 2)
    m.write(session+4500, len(queued))
    for index, value in enumerate(queued):
        m.write(session+4504+index*8, value | (NOW-1) << 16, 8)
    m.stubs[0xc12d10] = lambda m: m.events.append(('e2e_ack', m.reg(1)))
    m.write(fixture.vt+224, policy.RETURN+0x800, 8)
    m.stubs[policy.RETURN+0x800] = lambda m: m.events.append(('valid_e2e',))
    m.run(0x83e034, 0x83e624, fixture.base, session, pb, 0, NOW)
    expected = list(queued)
    if flags & 1 and (not expected or expected[-1] != incoming):
        if len(expected) == 5:
            if flags & 4:
                expected[-1] = incoming
        else:
            expected.append(incoming)
    assert [m.read(session+4504+i*8, 2) for i in range(m.read(session+4500))] == expected
    assert bool(m.read(session+4496, 1)) == bool(flags & 1 and flags & 4)
    assert [e for e in m.events if e[0] == 'e2e_ack'] == ([('e2e_ack', int(bool(flags & 4)))] if e2e and flags & 2 else [])


def integrated_select(elf, routes, active, expected):
    """Compose original base metrics, bucket ranges, P2P metrics, sort and selector."""
    fixture = SDR(elf, routes)
    fixture.active(active)
    m = fixture.m
    m.stubs.pop(0xc12610)
    m.stubs.pop(METRICS)
    m.redirects.update({0xc12610: 0x81c3f0, 0xc125e0: 0x81c0e4,
                        0xc125f0: 0x81c1f4, METRICS: 0x837f2c})
    m.allowed.extend([(0x81c0e4, 0x81c55c), (0x837f2c, 0x8381b4)])
    cluster_metrics, route_metrics = m.alloc(len(routes)*56), m.alloc(len(routes)*32)
    m.write(fixture.base+1104, cluster_metrics, 8)
    m.write(fixture.base+1128, route_metrics, 8)
    for index, route in enumerate(routes):
        cluster, relay = fixture.clusters[index], fixture.relays[index]
        pop = m.alloc(128)
        ping, remote, interior = route.get('ping', 20), route.get('remote', 30), route.get('interior', 40)
        local_penalty, remote_penalty, interior_penalty = [route.get(key, 0) for key in ('local_penalty', 'remote_penalty', 'interior_penalty')]
        m.write(cluster+8, pop, 8)
        m.write(pop+52, 1)
        m.write(cluster+560, 1)
        m.write(cluster+760, local_penalty)
        m.write(cluster+504, 16)
        m.write(relay+800, route.get('shutdown_seconds', 0x7fffffff))
        m.write(relay+256, route.get('failures', 0))
        count = route.get('buckets', 15)
        for number in range(17):
            bucket = cluster+96+number*24
            end = NOW-(16-number)*1000000 if number >= 17-count else NOW-16000001
            m.write(bucket, end, 8)
            m.write(bucket+8, 1)
            m.write(bucket+12, route.get('minimum', ping))
            m.write(bucket+16, route.get('maximum', ping))
        c, r = cluster_metrics+index*56, route_metrics+index*32
        m.write(c, cluster, 8)
        for offset, value in [(8, ping), (12, local_penalty), (16, remote), (20, remote_penalty)]:
            m.write(c+offset, value)
        internet = ping+remote
        score = internet+internet//10+interior+local_penalty+remote_penalty+interior_penalty
        for offset, value in [(0, index), (4, index), (8, interior), (12, 0), (16, interior_penalty), (24, score)]:
            m.write(r+offset, value)
        m.write(r+20, int(route.get('token', True)), 1)
    m.run(0x81c55c, 0x81ddb8, fixture.base, NOW, budget=100000)
    assert fixture.selected() == expected, (routes, fixture.selected(), expected)
    for index, route in enumerate(routes):
        if route.get('token', True):
            assert m.read(fixture.sessions[index]+4576) == route.get('buckets', 15)


def clean_routes(elf, tokens, active, expected_active, fresh=False, state=3, targets=None):
    fixture = SDR(elf, [{} for _ in tokens])
    fixture.active(active)
    m = fixture.m
    count = len(tokens)
    targets = list(range(count)) if targets is None else targets
    network, pops, shared, pointers, revision, good = [m.alloc(max(128, count*120)) for _ in range(6)]
    m.write(0xc80000+2816, network, 8)
    m.write(network+8, pops, 8)
    m.write(network+16, pops+count*120, 8)
    m.write(0xc80000+2856, shared, 8)
    m.write(shared, pointers, 8)
    m.write(shared+8, pointers+count*8, 8)
    table = m.alloc(128)
    m.write(0xc80000+2824, table, 8)
    m.write(table+68, count)
    m.write(0xc80000+2864, revision, 8)
    m.write(revision, 10)
    m.write(0xc80000+3016, good, 8)
    m.write(good, 1, 1)
    m.write(fixture.base+1080, 10 if fresh else 9)
    m.write(fixture.connection+4912, 1)
    m.write(fixture.connection+6852, state)
    clusters, best = m.alloc(count*56), m.alloc(count*32)
    m.write(fixture.base+1104, clusters, 8)
    m.write(fixture.base+1128, best, 8)
    for index, token in enumerate(tokens):
        cluster = fixture.clusters[index]
        m.write(pointers+index*8, cluster, 8)
        m.write(cluster+8, pops+index*120, 8)
        m.write(pops+index*120+8, 1000+index)
        m.write(clusters+index*56, cluster, 8)
        m.set_string(clusters+index*56+24, token or b'')
        target = targets[index]
        valid = target is not None and bool(tokens[target])
        m.write(best+index*32+4, target if valid else -1)
        m.write(best+index*32+20, int(valid), 1)
        m.set_string(fixture.sessions[index]+40, b'old'*10)
        m.write(fixture.sessions[index]+64, 2000+index)
    m.stubs.update({0xc12b70: lambda m: m.events.append(('init',)),
                    0xc12b80: lambda m: m.events.append(('mark_remote',)),
                    0xc12b90: lambda m: m.events.append(('build_lists',)),
                    0xbff410: lambda m: m.set_string(m.reg(0), m.get_string(m.reg(1))),
                    0xc0a110: lambda m: m.reg(0, int(bytes(m.uc.mem_read(m.reg(0), m.reg(2))) != bytes(m.uc.mem_read(m.reg(1), m.reg(2))))),
                    0xbff660: lambda m: m.uc.mem_write(m.reg(0), bytes(m.uc.mem_read(m.reg(1), m.reg(2))))})
    m.run(0x83627c, 0x836980, fixture.base)
    rebuilt = not fresh and 1 <= state <= 3
    assert m.events == ([('init',), ('mark_remote',), ('build_lists',)] if rebuilt else [])
    assert fixture.selected() == expected_active
    assert m.read(fixture.base+56) == count  # Removing an active role never destroys the session.
    for index, token in enumerate(tokens):
        session = fixture.sessions[index]
        target = targets[index]
        selected = tokens[target] if target is not None else None
        assert m.get_string(session+40) == ((selected or b'') if rebuilt else b'old'*10)
        assert m.read(session+64) == ((1000+target if selected else 0) if rebuilt else 2000+index)


def forward_target(elf, old, desired, acked, revision, desired_pop=123, old_pop=122):
    fixture = SDR(elf, [{}])
    m, session = fixture.m, fixture.sessions[0]
    m.set_string(session+40, desired)
    m.set_string(session+72, old)
    m.write(session+64, desired_pop)
    m.write(session+96, old_pop)
    m.write(session+100, revision)
    m.write(session+104, int(acked), 1)
    m.write(fixture.connection+4912, 1)
    m.stubs[0xbff410] = lambda m: m.set_string(m.reg(0), m.get_string(m.reg(1)))
    m.stubs[0xc0a110] = lambda m: m.reg(0, int(bytes(m.uc.mem_read(m.reg(0), m.reg(2))) != bytes(m.uc.mem_read(m.reg(1), m.reg(2)))))
    m.run(0x83505c, 0x835290, fixture.base, session)
    changed = bool(desired) and desired != old
    assert bool(m.reg(0)) == bool(desired)
    assert m.get_string(session+72) == (desired if changed else old)
    assert m.read(session+100) == ((revision+1) & 0xffffffff if changed else revision)
    assert m.read(session+96) == (desired_pop if changed else old_pop)
    assert bool(m.read(session+104, 1)) == (False if changed else acked)



def populate_context(elf, primary, force, needs_confirm, pending_ack, deadline_delta,
                     own_acked=False, token=True, primary_transport=True):
    fixture = SDR(elf, [{}])
    fixture.active([0] if primary else [])
    m, session = fixture.m, fixture.sessions[0]
    context = m.alloc(256)
    for offset in (88, 96):
        m.write(context+offset, m.string(b''), 8)
    m.write(context, NOW, 8)
    m.write(context+160, session, 8)
    m.write(fixture.connection+4912, 1)
    m.write(fixture.connection+40, fixture.base if primary_transport else 0, 8)
    m.set_string(session+40, b'target' if token else b'')
    m.set_string(session+72, b'target')
    m.write(session+100, 5)
    m.write(session+104, 0, 1)
    m.write(fixture.base+288, int(needs_confirm), 1)
    m.write(fixture.base+1096, int(pending_ack), 1)
    m.write(fixture.base+968, 7)
    m.write(fixture.base+1048, 10)
    m.write(fixture.base+1232, 10 if own_acked else 9)
    m.write(fixture.base+1224, NOW+deadline_delta, 8)
    m.stubs.update({0xc12ac0: lambda m: m.events.append(('generic', m.reg(2), m.reg(3), m.reg(4), m.reg(5), m.reg(6))),
                    0xc0acd0: lambda m: m.events.append(('serialize',)),
                    0xc097e0: lambda m: m.reg(0, 1)})
    m.stubs[0xbff410] = lambda m: m.set_string(m.reg(0), m.get_string(m.reg(1)))
    m.stubs[0xc0a110] = lambda m: m.reg(0, int(bytes(m.uc.mem_read(m.reg(0), m.reg(2))) != bytes(m.uc.mem_read(m.reg(1), m.reg(2)))))
    m.redirects[0xc12aa0] = 0x83505c
    m.allowed.append((0x83505c, 0x835290))
    m.run(0x835400, 0x8355f8, fixture.base, context, 0, int(force))
    eligible = token and (primary or force)
    ack = eligible and (pending_ack or needs_confirm)
    routes = eligible and not own_acked and (deadline_delta < 0 or needs_confirm)
    mode = 0 if not token else 2 if force or ack or routes else 1 if primary else 0
    flags = (0 if primary else 8) | (0 if primary_transport else 16)
    assert m.events == ([('serialize',)] if routes else [])+[('generic', 0, mode, 9, flags, 0)], m.events
    presence = m.read(context+48)
    assert bool(presence & 1) == token
    assert bool(presence & 64) == token
    assert bool(presence & 128) == bool(ack)
    assert bool(presence & 2) == bool(routes)
    assert m.read(fixture.base+1224, 8) == NOW+deadline_delta  # Populate alone does not start the timer.
    assert bool(m.read(fixture.base+1096, 1)) == pending_ack


def rendezvous_routes(elf, deadline_delta, own_acked=False, disconnect=False):
    fixture = SDR(elf, [])
    m = fixture.m
    msg = m.alloc(256)
    m.write(msg+16, 64 if disconnect else 0)
    m.write(msg+72, m.string(b''), 8)
    m.write(fixture.base+968, 7)
    m.write(fixture.base+1096, 1, 1)
    m.write(fixture.base+1048, 10)
    m.write(fixture.base+1232, 10 if own_acked else 9)
    m.write(fixture.base+1224, NOW+deadline_delta, 8)
    table = m.alloc(128)
    m.write(0xc80000+2824, table, 8)
    m.stubs.update({0xc12a80: lambda m: m.events.append(('rebuild_check',)),
                    0xc0acd0: lambda m: m.events.append(('serialize',))})
    m.run(0x834bc0, 0x834d04, fixture.base, msg, NOW)
    sending = not disconnect and not own_acked and deadline_delta <= 0
    assert m.events == ([] if disconnect else [('rebuild_check',)])+([('serialize',)] if sending else [])
    assert bool(m.read(msg+16) & 1) == sending
    assert m.read(msg+132) == 7 and m.read(msg+16) & 256
    assert m.read(fixture.base+1096, 1) == 0
    assert m.read(fixture.base+1224, 8) == (NOW+1000000 if sending else NOW+deadline_delta)


def track_sent_routes(elf, presence, flags):
    fixture = SDR(elf, [{}])
    m = fixture.m
    msg = m.alloc(256)
    m.write(msg+16, presence)
    m.write(msg+104, 7)
    m.write(msg+96, flags)
    m.write(fixture.base+968, 7)
    m.write(fixture.base+1096, 1, 1)
    m.write(fixture.base+1224, 12345, 8)
    m.stubs.update({0xc12b40: lambda m: m.events.append(('track_common',)),
                    0xc12b50: lambda m: m.events.append(('track_e2e', m.reg(2)))})
    m.run(0x835f00, 0x835fbc, fixture.base, fixture.sessions[0], msg, m.empty, NOW)
    assert m.read(fixture.base+1096, 1) == int(not bool(presence & 128))
    assert m.read(fixture.base+1224, 8) == (NOW+500000 if presence & 2 else 12345)
    assert m.events == [('track_common',)]+([('track_e2e', int(not flags & 4))] if presence & 8 or flags & 2 else [])


def connectivity_transition(elf, confirmed_call, needs_confirm, can_send=True):
    fixture = SDR(elf, [])
    m = fixture.m
    m.write(fixture.base+272, fixture.base, 8)
    m.write(fixture.base+288, int(needs_confirm), 1)
    m.write(fixture.connection+4912, 1)
    m.write(fixture.vt+32, METRICS, 8)
    m.stubs.update({METRICS: lambda m: m.reg(0, int(can_send)),
                    0xc138b0: lambda m: m.events.append(('changed',)),
                    0xc09b00: lambda m: m.reg(0, 1)})
    if confirmed_call:
        m.run(0x87877c, 0x8788b0, fixture.base+264, NOW)
        assert bool(m.read(fixture.base+288, 1)) == (needs_confirm and not can_send)
        assert m.events == ([('changed',)] if needs_confirm and can_send else [])
    else:
        m.run(0x878698, 0x87877c, fixture.base+264, NOW)
        # The pinned APK really returns immediately when the flag is zero.
        assert bool(m.read(fixture.base+288, 1)) == needs_confirm
        assert m.events == ([('changed',)] if needs_confirm else [])



def stats_sequence_dispatch(elf, state, e2e, relay_result=101, e2e_result=201,
                            gap=1, relay_gap=1, delayed=False, reorder_result=1, auth_context=False):
    fixture = SDR(elf, [{}])
    m, session = fixture.m, fixture.sessions[0]
    msg, packet = m.alloc(160), m.alloc(48)
    m.write(msg+16, 4096 if e2e else 0)
    m.write(msg+112, (100+relay_gap) & 65535)
    m.write(msg+116, (200+gap) & 65535)
    m.write(session+2312, 100, 2)
    m.write(fixture.connection+2592, 200, 2)
    m.write(fixture.connection+4488, int(delayed), 8)
    m.write(fixture.connection+6848, state)
    m.write(fixture.connection+328, int(auth_context), 8)
    m.write(packet+8, 123)
    m.write(packet+16, NOW, 8)
    m.write(fixture.vt+40, REQUEST, 8)
    m.stubs.update({0xc124f0: lambda m: (m.events.append(('expand_relay',)), m.reg(0, relay_result)),
                    0xc12c80: lambda m: (m.events.append(('expand_e2e',)), m.reg(0, e2e_result)),
                    0xc12c90: lambda m: m.events.append(('receive_e2e',)),
                    0xc12ca0: lambda m: m.events.append(('track_relay',)),
                    0xc12cb0: lambda m: m.events.append(('receive_stats',)),
                    0xc12500: lambda m: (m.events.append(('out_of_order',)), m.reg(0, reorder_result)),
                    0xc12510: lambda m: m.events.append(('closed', m.reg(2))),
                    REQUEST: lambda m: m.events.append(('connecting_e2e',)),
                    0xc097e0: lambda m: (m.events.append(('diagnostic',)), m.reg(0, 1))})
    m.run(0x83cf94, 0x83d3ac, fixture.base, session, msg, packet)
    closed, accepted = state in (-1, 4, 5), state in (-2, 1, 2, 3)
    expected = []
    if closed:
        expected = [('closed', int(e2e))]
    elif not accepted or (state == 1 and auth_context):
        expected = [('diagnostic',)]
    else:
        if state == 1 and e2e:
            expected.append(('connecting_e2e',))
        needs_reorder = e2e and (delayed or (gap >= 2 and gap == relay_gap and gap <= 3))
        if needs_reorder:
            expected.append(('out_of_order',))
        if not needs_reorder or reorder_result in (1, 2):
            expected.append(('expand_relay',))
            if e2e:
                expected.append(('expand_e2e',))
            if relay_result > 0 and (not e2e or e2e_result > 0):
                if e2e:
                    expected.append(('receive_e2e',))
                expected.extend([('track_relay',), ('receive_stats',)])
        elif reorder_result != 0:
            expected.append(('diagnostic',))
    assert m.events == expected, (state, e2e, gap, relay_gap, delayed, m.events, expected)
    accepted_e2e = ('receive_e2e',) in expected
    assert m.read(fixture.connection+2600, 8) == int(accepted_e2e)
    assert m.read(fixture.connection+2624, 8) == (123 if accepted_e2e else 0)


def outer_active_cleanup(elf, needs_confirm, active):
    fixture = SDR(elf, [{}])
    fixture.active([0] if active else [])
    m = fixture.m
    m.write(fixture.base+272, fixture.base, 8)
    m.write(fixture.base+288, int(needs_confirm), 1)
    m.stubs.update({0xc12b60: lambda m: m.events.append(('clean',)),
                    0xc12620: lambda m: m.events.append(('select',)),
                    0xc12a80: lambda m: m.events.append(('rebuild_check',))})
    m.redirects[0xc12ba0] = 0x878698
    m.allowed.append((0x878698, 0x87877c))
    m.run(0x836a60, 0x836ae4, fixture.base, NOW)
    assert m.events == [('clean',), ('select',), ('rebuild_check',)]
    assert (0x878698 in m.visited) == (not needs_confirm and not active)
    assert bool(m.read(fixture.base+288, 1)) == needs_confirm



def out_of_order(elf, pending_gap, redelivered, window):
    m = Machine(elf)
    tracker, packet, vtable, pending, config = [m.alloc(8192) for _ in range(5)]
    m.write(tracker, vtable, 8)
    m.write(vtable+16, METRICS, 8)
    m.write(packet+16, NOW, 8)
    m.write(packet+48, int(redelivered), 1)
    m.write(0xc80000+2360, config, 8)
    m.write(config+60, window)
    log = m.alloc(128)
    m.write(0xc80000+2184, log, 8)
    if pending_gap is not None:
        m.write(tracker+4096, pending, 8)
        m.write(pending+104, (200+pending_gap) & 65535)
        m.write(pending+64, 1, 1)
    def detach(m):
        m.events.append(('detach',))
        m.write(tracker+4096, 0, 8)
    def construct(m):
        m.events.append(('construct', m.reg(2), m.reg(3)))
    def own(m):
        m.events.append(('own',))
        m.write(m.reg(1)+4096, m.reg(0), 8)
    m.stubs.update({0xbff420: lambda m: m.reg(0, m.alloc(m.reg(0))),
                    0xc13950: lambda m: m.events.append(('remove',)),
                    0xc13980: detach,
                    0xc13990: lambda m: m.events.append(('queue',)),
                    0xc139a0: construct, 0xc139b0: own,
                    METRICS: lambda m: m.events.append(('confirmed_reorder',))})
    m.run(0x86a844, 0x86ab88, 200, tracker, packet)
    if pending_gap is None:
        events = [] if redelivered or window < 1 else [('construct', NOW+window, 200), ('own',), ('queue',)]
        result = 1 if not events else 0
    elif pending_gap >= 2:
        events, result = [], 1
    else:
        events = [('remove',), ('detach',), ('queue',)]
        if redelivered:
            result = 1
        elif pending_gap == 1:
            events += [('confirmed_reorder',)]
            result = 2
        else:
            events += [('construct', 1, 200), ('queue',)]
            result = 0
    assert m.events == events, (pending_gap, redelivered, window, m.events, events)
    assert m.reg(0) == result


def cluster_penalty(elf, old, incoming):
    fixture = SDR(elf, [{}])
    m = fixture.m
    m.write(fixture.clusters[0]+760, old)
    m.stubs.update({0xc097e0: lambda m: (m.events.append(('diagnostic',)), m.reg(0, 1)),
                    0x810c34: lambda m: m.events.append(('dirty',))})
    m.run(0x812cb4, 0x812dd4, fixture.relays[0], incoming)
    clamped = max(0, min(incoming, 5000))
    assert m.read(fixture.clusters[0]+760) == clamped
    assert m.events == ([('diagnostic',)] if incoming < 0 or incoming >= 5000 else [])+([('dirty',)] if old != clamped else [])



def statistics_schedule(elf, instantaneous_age, lifetime_age, received, sent,
                        activity=0, in_flight=False, reason=False, reply_delta=None):
    m = Machine(elf)
    tracker, reasons, next_time = m.alloc(8192), m.alloc(32), m.alloc(8)
    clock = NOW*10
    m.write(tracker+4088, clock-instantaneous_age, 8)
    m.write(tracker+4080, clock-lifetime_age, 8)
    m.write(tracker+2528, received, 8)
    m.write(tracker+2144, sent, 8)
    m.write(tracker+4040, activity)
    m.write(tracker+3984, int(in_flight), 8)
    m.write(next_time, clock+200000000, 8)
    if reply_delta is not None:
        m.write(tracker+4008, clock+reply_delta, 8)
    for index in range(4):
        m.write(reasons+index*8, 0 if index == 0 else policy.RETURN+index*8, 8)
    m.redirects[0xc14d30] = 0x8b33e8
    m.allowed.append((0x8b33e8, 0x8b34f0))
    m.stubs[0xc097e0] = lambda m: m.reg(0, 1)
    result, effective_instant, effective_lifetime = 0, instantaneous_age, lifetime_age
    next_delta = min(200000000, reply_delta) if reply_delta is not None else 200000000
    if activity == 0 and not in_flight:
        inst_limit = 30000000 if reason else 20000000
        if instantaneous_age >= inst_limit:
            if max(received, sent) > instantaneous_age//3000000:
                result |= 1 if reason or instantaneous_age >= 30000000 else 2
            else:
                effective_instant = 0
        if reason and not result & 1:
            next_delta = min(next_delta, 30000000-effective_instant)
        life_limit = 140000000 if reason else 120000000
        if lifetime_age >= life_limit:
            if max(received, sent) > 100:
                result |= 2 if reason else 4 if effective_instant >= 140000000 else 8
            else:
                effective_lifetime = 0
        if reason and not result & 2:
            next_delta = min(next_delta, 140000000-effective_lifetime)
    if reason:
        m.run(0x8b36c4, 0x8b38bc, tracker, clock, reasons, next_time)
        assert m.reg(0) == (policy.RETURN+result*8 if result else 0)
        assert m.read(next_time, 8) == clock+next_delta
    else:
        m.run(0x8b3580, 0x8b36c4, tracker, clock)
        assert m.reg(0) == result, (instantaneous_age, lifetime_age, received, sent, m.reg(0), result)
    assert m.read(tracker+4088, 8) == clock-effective_instant
    assert m.read(tracker+4080, 8) == clock-effective_lifetime
    if effective_instant != instantaneous_age:
        assert m.read(tracker+4048, 8) == received and m.read(tracker+4056, 8) == sent
    assert m.read(tracker+4064, 8) == 0 and m.read(tracker+4072, 8) == 0


def reply_deadline(elf, smoothed, samples, delayed, pending=False):
    m = Machine(elf)
    tracker = m.alloc(8192)
    m.write(tracker+68, smoothed)
    m.write(tracker+64, len(samples))
    for index, value in enumerate(samples):
        m.write(tracker+16+index*16, value)
    m.write(tracker+4008, NOW+99 if pending else 0, 8)
    m.write(tracker+4016, 1234, 8)
    m.run(0x8b4108, 0x8b420c, tracker, NOW, int(delayed))
    maximum = max(samples) if samples else smoothed
    timeout = 1250000 if smoothed < 0 else min(maximum*2000, 1000000)+250000
    assert m.read(tracker+4008, 8) == (NOW+99 if pending else NOW+timeout+(200000 if delayed else 0))
    assert m.read(tracker+4016, 8) == (1234 if delayed else NOW)


def sequence_window(elf, latest, incoming, already_received, cross_path=False, kind='e2e'):
    m = Machine(elf)
    tracker = m.alloc(8192)
    m.write(tracker+2200, latest, 8)
    expanded = latest+((incoming-latest+32768) % 65536-32768)
    block = (expanded-(latest & ~63))//64
    if already_received and -1 <= block <= 0:
        mask = 1 << (expanded & 63)
        m.write(tracker+2336+(block+1)*8, mask, 8)
        if not cross_path:
            m.write(tracker+2416+(block+1)*8, mask, 8)
    m.stubs[0xc097e0] = lambda m: m.reg(0, 1)
    start, end = (0x83d3ac, 0x83d540) if kind == 'e2e' else (0x819e08, 0x819f9c)
    m.run(start, end, tracker, incoming & 65535, 0)
    too_old = expanded <= latest and block <= -2
    duplicate = already_received and expanded <= latest and -1 <= block <= 0
    expected = 0 if too_old or duplicate else expanded
    assert m.reg(0) == expected, (kind, latest, incoming, m.reg(0), expected)
    assert m.read(tracker+2528, 8) == 1 and m.read(tracker+2484) == 1
    assert m.read(tracker+2500) == int(too_old)
    assert m.read(tracker+2504) == int(duplicate and not cross_path)
    assert m.read(tracker+2448, 8) == int(duplicate and cross_path)
    assert m.read(tracker+2200, 8) == latest  # Expansion itself never advances the received high-water mark.



def packed_ack_encoding(elf, ages):
    m = Machine(elf)
    queue, repeated, tracker, vt = [m.alloc(8192) for _ in range(4)]
    m.write(tracker, vt, 8)
    m.write(vt+8, METRICS, 8)
    m.write(queue, 1, 1)
    m.write(queue+4, len(ages))
    for index, age in enumerate(ages):
        m.write(queue+8+index*8, ((NOW-age) << 16) | (100+index), 8)
    def reserve(m):
        m.write(m.reg(0)+4, max(16, m.reg(1)))
        m.write(m.reg(0)+8, m.alloc(max(16, m.reg(1))*4), 8)
    m.stubs.update({0xbffe80: reserve, METRICS: lambda m: m.set_string(m.reg(8), b'tracker'),
                    0xc09b00: lambda m: m.reg(0, 1)})
    m.run(0x840fd8, 0x841190, queue, repeated, NOW, tracker)
    expected = [(100+index) << 16 | (age//64 if 0 <= age < 65536*64 else 65535)
                for index, age in enumerate(ages)]
    assert [m.read(m.read(repeated+8, 8)+index*4) for index in range(m.read(repeated))] == expected
    assert m.read(queue+4) == len(ages) and m.read(queue, 1) == 1


def relay_request_clocks(elf, session_pending, root_pending, delayed, ping):
    fixture = SDR(elf, [{}])
    m, session, root, cluster = fixture.m, fixture.sessions[0], fixture.relays[0], fixture.clusters[0]
    tracker = session+112
    m.write(tracker+4432, session, 8)
    m.write(tracker+68, ping)
    m.write(tracker+4008, 0 if session_pending is None else NOW+session_pending, 8)
    m.write(root+136, 0 if root_pending is None else NOW+root_pending, 8)
    m.stubs.update({0xc123c0: lambda m: m.reg(0, ping),
                    0xc12e40: lambda m: m.events.append(('expected_ack',))})
    for call, start, end in [(0xc12d30, 0x8b4108, 0x8b420c),
                              (0xc12370, 0x817304, 0x817330)]:
        m.redirects[call] = start
        m.allowed.append((start, end))
    native_call(m, 0x84f8b4, 0x84fb9c, tracker, NOW, int(delayed))
    timeout = (1250000 if ping < 0 else min(ping*2000, 1000000)+250000) + (200000 if delayed else 0)
    assert m.read(tracker+4008, 8) == NOW+(timeout if session_pending is None else session_pending)
    assert m.read(root+136, 8) == NOW+(timeout if root_pending is None else root_pending)
    assert m.read(root+320, 8) == NOW and m.read(cluster+80, 8) == NOW
    assert m.read(cluster+556) == 1 and m.events == [('expected_ack',)]


def receive_packed_ack(elf, elapsed, delay, matching=True, override=-2, native_root=False):
    fixture = SDR(elf, [{}])
    m, tracker = fixture.m, fixture.sessions[0]+112
    m.write(tracker+4432, fixture.sessions[0], 8)
    m.write(fixture.clusters[0]+512, override)
    m.write(tracker+2136, 1001, 8)
    m.write(tracker+3984, 1000, 8)
    m.write(tracker+3992, 1, 1)
    m.write(tracker+3993, 1, 1)
    m.write(tracker+2528, 77, 8)
    m.write(tracker+2144, 88, 8)
    m.write(tracker+4088, 1234, 8)
    m.write(tracker+4080, 1234, 8)
    m.stubs.update({0xc12e20: lambda m: (m.events.append(('lookup', m.reg(1))),
                                       m.reg(0, 0 if elapsed is None else -1 if elapsed == 'invalid' else NOW-elapsed)),
                    0xc12070: lambda m: m.events.append(('relay_ping', m.reg(1))),
                    0xc120d0: lambda m: m.events.append(('tracker_ping', m.reg(1)))})
    if native_root:
        root = fixture.relays[0]
        m.write(root+752, -2)
        m.write(root+136, NOW+1000, 8)
        m.redirects[0xc12070] = 0x812a28
        del m.stubs[0xc12070]
        m.allowed.append((0x812a28, 0x812cb4))
        m.stubs[0x810c34] = lambda m: None  # Routing-score dirty notification.
    sequence = 1000 if matching else 999
    m.run(0x84f1f0, 0x84f424, tracker, (sequence << 16) | delay, NOW)
    measured = raw_measured = None
    valid = elapsed != 'invalid'
    if isinstance(elapsed, int) and elapsed >= 1:
        corrected = elapsed-delay*64
        measured = abs(corrected)//1000 * (-1 if corrected < 0 else 1)
        valid = -1 <= measured <= 3000
        raw_measured = max(measured, 0)
        measured = raw_measured if override == -2 else override
    samples = isinstance(elapsed, int) and elapsed >= 1 and valid
    updates = ([('tracker_ping', raw_measured),
                ('tracker_ping', measured), ('tracker_ping', measured)] if native_root else
               [('relay_ping', measured), ('tracker_ping', measured)]) if samples else []
    assert m.events == [('lookup', sequence)]+updates
    if native_root:
        assert m.read(root+136, 8) == (0 if samples else NOW+1000)
        assert m.read(root+748) == int(samples) and m.read(fixture.clusters[0]+508) == int(samples)
    assert bool(m.reg(0)) == valid
    assert m.read(tracker+3984, 8) == (0 if matching else 1000)
    assert m.read(tracker+4088, 8) == (NOW if matching else 1234)
    assert m.read(tracker+4080, 8) == (NOW if matching else 1234)
    assert m.read(tracker+3992, 2) == (0 if matching else 257)
    if matching:
        assert [m.read(tracker+offset, 8) for offset in (4048, 4064)] == [77, 77]
        assert [m.read(tracker+offset, 8) for offset in (4056, 4072)] == [88, 88]


def relay_stats_timeout(elf, activity, reply_delta, failures=0, interval_age=0):
    m = Machine(elf)
    tracker = m.alloc(8192)
    m.write(tracker+4040, activity)
    m.write(tracker+4000, NOW-interval_age, 8)
    m.write(tracker+4008, 0 if reply_delta is None else NOW+reply_delta, 8)
    m.write(tracker+4024, failures)
    m.write(tracker+4032, NOW-10 if failures else 0, 8)
    m.stubs[0xc129f0] = lambda m: m.events.append(('update_interval',))
    m.run(0x83235c, 0x8324e0, tracker, NOW)
    expired = reply_delta is not None and reply_delta <= 0
    assert m.read(tracker+4008, 8) == (0 if expired or reply_delta is None else NOW+reply_delta)
    assert m.read(tracker+4024) == failures+int(expired)
    assert m.read(tracker+4032, 8) == (NOW-10 if failures else NOW if expired else 0)
    assert m.events == ([('update_interval',)] if activity == 0 and interval_age >= 5000000 else [])


def relay_ack_schedule(elf, age, queued, force=False, statistics=False):
    m = Machine(elf)
    tracker, reply, next_time = m.alloc(8192), m.alloc(8), m.alloc(8)
    m.write(tracker+4388, queued)
    m.write(tracker+4384, int(force), 1)
    m.write(next_time, NOW+2000000, 8)
    m.stubs.update({0xc128f0: lambda m: m.reg(0, policy.RETURN+16 if statistics else 0),
                    0xc12900: lambda m: m.reg(0, age)})
    m.run(0x822c9c, 0x822e84, tracker, NOW, reply, next_time)
    sending = statistics or queued > 0 and (force or age >= 250000 or queued >= 5)
    assert m.read(reply) == (2 if statistics else 1 if sending else 0)
    assert bool(m.reg(0)) == sending
    expected_next = NOW+250000-age if queued and not sending else NOW+2000000
    assert m.read(next_time, 8) == expected_next



def send_stats_path(elf, state, primary, current, force, flags, quality, scheduled, snp_ok, socket_ok):
    fixture = SDR(elf, [{}])
    fixture.active([0] if primary else [])
    m, session = fixture.m, fixture.sessions[0]
    m.write(fixture.connection+6852, state)
    m.write(fixture.connection+40, fixture.base if current else 0, 8)
    m.write(session+2248, 100, 8)
    m.write(fixture.connection+2528, 200, 8)
    m.write(fixture.connection+384, 123)
    def populate(m):
        context = m.reg(1)
        m.write(context+24, flags)
        m.write(context+128, flags)
        m.write(context+48, (32 if flags else 0) | (8 if quality else 0))
    def send(m):
        msg = m.reg(2)
        m.events.append(('send_control', m.reg(1), m.read(msg+108), m.read(msg+112),
                         m.read(msg+116) if m.read(msg+16) & 1024 else None))
        m.reg(0, 60 if socket_ok else -1)
    m.stubs.update({0xbffb30: lambda m: m.uc.mem_write(m.reg(0), bytes(128)),
                    0xc009b0: lambda m: None, 0xc12ab0: populate,
                    0xc12b00: lambda m: (m.events.append(('snp',)), m.reg(0, int(snp_ok))),
                    0xc12b30: lambda m: m.reg(0, NOW if scheduled else 0x7fffffffffffffff),
                    0xc12390: send,
                    0xc12b10: lambda m: m.events.append(('snp_non_data',)),
                    0xc12b20: lambda m: m.events.append(('track_sent',)),
                    0xc097e0: lambda m: m.reg(0, 1)})
    m.run(0x835c64, 0x835f00, fixture.base, session, 0, int(force), NOW, m.empty)
    e2e = bool(flags & 2 or quality or force)
    attempt = state == 3 and (e2e or primary and current and scheduled)
    control = not (attempt and snp_ok)
    expected = [('snp',)] if attempt else []
    if control:
        expected += [('send_control', 26, 123, 100, 200 if e2e else None)]
        if socket_ok:
            if e2e:
                expected += [('snp_non_data',)]
            expected += [('track_sent',)]
    assert m.events == expected, (state, primary, current, force, flags, quality, scheduled, m.events, expected)
    assert bool(m.reg(0)) == (attempt and snp_ok or control and socket_ok)
    assert m.read(session+2248, 8) == 100+int(control)
    assert m.read(fixture.connection+2528, 8) == 200+int(control and e2e)



def generic_stats_producer(elf, expected, mode=0, request=0, relay_age=0, e2e_age=0,
                           relay_fail=0, e2e_fail=0, immediate_age=0, queued=0,
                           relay_recv_age=0, pending=False, activity=0,
                           instant_age=0, e2e_instant_age=0, base_flags=0,
                           e2e_recv_age=0, e2e_pending=False, e2e_activity=None):
    fixture = SDR(elf, [{}])
    m, session = fixture.m, fixture.sessions[0]
    context = m.alloc(256)
    m.write(context, NOW, 8)
    m.write(context+160, session, 8)
    m.write(fixture.connection+5340, 1200)
    for tracker, age in [(session+112, instant_age), (fixture.connection+392, e2e_instant_age)]:
        m.write(tracker+4088, NOW-age, 8)
        m.write(tracker+4080, NOW, 8)
        m.write(tracker+2528, 100 if age else 0, 8)
        m.write(tracker+4040, activity)
    for offset, value in [(136, NOW-relay_age), (184, NOW-relay_age),
                          (2512, NOW-relay_recv_age), (4128, NOW-immediate_age)]:
        m.write(session+offset, value, 8)
    m.write(session+4136, relay_fail)
    m.write(session+4120, NOW+1000000 if pending else 0, 8)
    m.write(session+4500, queued)
    for offset in (416, 464):
        m.write(fixture.connection+offset, NOW-e2e_age, 8)
    m.write(fixture.connection+2792, NOW-e2e_recv_age, 8)
    m.write(fixture.connection+4400, NOW+1000000 if e2e_pending else 0, 8)
    m.write(fixture.connection+4408, NOW-immediate_age, 8)
    m.write(fixture.connection+4416, e2e_fail)
    m.write(fixture.connection+4432, activity if e2e_activity is None else e2e_activity)
    def quality(m):
        need = m.reg(1)
        m.write(m.reg(2)+16, int(bool(need & 3)) | int(bool(need & 12)) << 1)
        m.events.append(('quality', 'relay' if m.reg(0) == session+112 else 'e2e', need))
    m.redirects.update({0xc12ad0: 0x8b3580, 0xc14d30: 0x8b33e8})
    m.allowed.extend([(0x8b33e8, 0x8b34f0), (0x8b3580, 0x8b36c4)])
    m.stubs.update({0xc006d0: lambda m: m.reg(0, m.alloc(128)), 0xc12ae0: quality,
                    0xc12af0: lambda m: m.events.append(('put_acks',)),
                    0xc009d0: lambda m: m.reg(0, 10)})
    m.run(0x8355f8, 0x835c64, fixture.base, context, request, mode, 9, base_flags, 0)
    if expected is not None:
        assert m.read(context+24) == expected, (expected, m.read(context+24), m.events)
    expected = m.read(context+24)
    expected_quality = []
    for label, age in [('relay', instant_age), ('e2e', e2e_instant_age if mode else 0)]:
        if age >= 20000000:
            expected_quality.append(('quality', label, 1 if age >= 30000000 else 2))
    assert sorted(e for e in m.events if e[0] == 'quality') == sorted(expected_quality)
    assert (('put_acks',) in m.events) == bool(queued)
    presence = m.read(context+48)
    quality_flags = int(instant_age >= 20000000) | (int(bool(mode) and e2e_instant_age >= 20000000) << 1)
    assert ((m.read(context+128) if presence & 32 else 0) | ((presence >> 2) & 3)) == expected | quality_flags
    return expected



def expected_ack_removal(elf, sequences, incoming):
    m = Machine(elf)
    tracker = m.alloc(8192)
    m.write(tracker, len(sequences), 8)
    for index, sequence in enumerate(sequences):
        m.write(tracker+24+index*8, ((NOW-1000-index) << 16) | sequence, 8)
    m.stubs.update({0xbff660: lambda m: m.uc.mem_write(m.reg(0), bytes(m.uc.mem_read(m.reg(1), m.reg(2)))),
                    0xc12900: lambda m: m.reg(0, 1000)})
    m.run(0x84f424, 0x84f5cc, tracker, incoming, NOW)
    expected, remaining = 0, sequences[:]
    for index, sequence in enumerate(sequences):
        diff = (sequence-incoming+32768) % 65536-32768
        if diff == 0:
            expected = NOW-1000-index
            remaining.pop(index)
            break
        if diff < -16384 or diff > 16384:
            expected = -1
            break
        if diff > 0:
            break
    assert m.reg(0) == expected & 0xffffffffffffffff
    assert [m.read(tracker+24+index*8, 2) for index in range(m.read(tracker, 8))] == remaining



def native_call(m, start, end, *args):
    """Enter a fresh ABI call on the same object graph, preserving protocol state."""
    m.uc.reg_write(arm.UC_ARM64_REG_LR, policy.RETURN)
    m.run(start, end, *args, budget=150000)


def receive_sequence_chain(elf, packets, delivered, expected, initial=(100, 200), flags=0,
                           relay_quality=False, e2e_quality=False):
    fixture = SDR(elf, [{}])
    fixture.active([0])
    m, session = fixture.m, fixture.sessions[0]
    relay_tracker, e2e_tracker = session+112, fixture.connection+392
    m.write(fixture.connection+6848, 3)
    m.write(fixture.connection+4912, 1)
    m.write(fixture.connection+40, fixture.base, 8)
    msg, packet, quality, config, reasons = [m.alloc(256) for _ in range(5)]
    m.write(0xc80000+2360, config, 8)  # A zero reordering delay is an explicit input.
    m.write(0xc80000+3064, reasons, 8)
    for index in range(1, 4):
        m.write(reasons+index*8, m.string(b'statistics'), 8)
    m.write(msg+16, 2048 | 4096 | (2 if relay_quality else 0) | (4 if e2e_quality else 0))
    m.write(msg+96, flags)
    m.write(msg+64, quality, 8)
    m.write(msg+72, quality, 8)
    m.write(packet+8, 123)
    m.write(session+2512, NOW, 8)
    for tracker in (relay_tracker, e2e_tracker):
        m.write(tracker+4088, NOW, 8)
        m.write(tracker+4080, NOW, 8)
    for tracker, sequence in zip((relay_tracker, e2e_tracker), initial):
        native_call(m, 0x8b29e0, 0x8b2a64, tracker, sequence)
    redirects = {0xc124f0: (0x819e08, 0x819f9c), 0xc12c80: (0x83d3ac, 0x83d540),
                 0xc12ca0: (0x83d540, 0x83d860), 0xc12c90: (0x85597c, 0x8559d4),
                 0xc131b0: (0x8559d4, 0x855d04), 0xc12cb0: (0x83d860, 0x83dac8),
                 0xc12ce0: (0x83e034, 0x83e624), 0xc12500: (0x86a844, 0x86ab88),
                 0xc12cc0: (0x8b3204, 0x8b33d8), 0xc12cd0: (0x8b29e0, 0x8b2a64),
                 0xc12430: (0x822c9c, 0x822e84), 0xc128f0: (0x8b36c4, 0x8b38bc),
                 0xc12900: (0x822e84, 0x822f94)}
    for call, (start, end) in redirects.items():
        m.redirects[call] = start
        m.allowed.append((start, end))
    m.write(fixture.vt+224, 0x83f314, 8)
    m.allowed.append((0x83f314, 0x83f748))
    m.write(fixture.vt+136, policy.RETURN+0x800, 8)
    m.stubs.update({0xc12e00: lambda m: None,  # SNP diagnostic invariant; not the tracker.
                    0xc131c0: lambda m: m.events.append(('snp_receive', m.reg(1))),
                    0xc12d10: lambda m: m.events.append(('queue_e2e_ack', m.reg(1))),
                    0xc12de0: lambda m: m.events.append(('select_transport',)),
                    policy.RETURN+0x800: lambda m: m.events.append(('send_stats',))})
    for index, (relay_sequence, e2e_sequence) in enumerate(packets):
        m.write(msg+112, relay_sequence & 65535)
        m.write(msg+116, e2e_sequence & 65535)
        m.write(packet+16, NOW+index*1000, 8)
        m.write(fixture.base+792, NOW+123, 8)
        m.write(fixture.base+800, 2)
        native_call(m, 0x83cf94, 0x83d3ac, fixture.base, session, msg, packet)
        assert m.read(fixture.base+792, 8) == (0 if index in delivered else NOW+123)
        assert m.read(fixture.base+800) == (0 if index in delivered else 2)
        actual = [event[1] for event in m.events if event[0] == 'snp_receive']
        wanted = [packets[n][1] for n in delivered if n <= index]
        assert actual == wanted, (packets, index, actual, wanted)
    # Explicit traces specify final high-water marks and loss/late/lurch counters.
    latest_relay, latest_e2e, dropped, late, lurch = expected
    assert [m.read(t+2200, 8) for t in (relay_tracker, e2e_tracker)] == [latest_relay, latest_e2e]
    for tracker in (relay_tracker, e2e_tracker):
        assert [m.read(tracker+off) for off in (2488, 2492, 2500)] == [dropped, late, lurch]
        assert m.read(tracker+2528, 8) == len(packets)
    assert len([e for e in m.events if e[0] == 'select_transport']) == len(delivered)
    assert len([e for e in m.events if e[0] == 'queue_e2e_ack']) == (len(delivered) if flags & 2 or e2e_quality else 0)
    assert len([e for e in m.events if e[0] == 'send_stats']) == (len(delivered) if flags & 4 and (flags & 2 or e2e_quality) else 0)
    requested = [packets[n][0] & 65535 for n in delivered] if flags & 1 or relay_quality else []
    queued = requested[:5] if not flags & 4 else requested[:4]+requested[-1:] if len(requested) > 5 else requested
    assert [m.read(session+4504+n*8, 2) for n in range(m.read(session+4500))] == queued
    assert bool(m.read(session+4496, 1)) == bool(requested and flags & 4)



def p2p_confirmation_think(elf, expected_request, *, state=3, pending_delta=None, failures=0,
                           need=False, quota=0, selected='self', selected_need=False,
                           smoothed=20, samples=3, total=10, probe_age=0, can_send=True,
                           sends=True):
    fixture = SDR(elf, [])
    m, p2p = fixture.m, fixture.base+264
    other = m.alloc(1024)
    m.write(p2p+8, fixture.base, 8)
    m.write(fixture.connection+6848, state)
    m.write(fixture.connection+4912, 1)
    m.write(fixture.connection+7288, p2p if selected == 'self' else other if selected == 'other' else 0, 8)
    m.write(other+24, int(selected_need), 1)
    m.write(p2p+24, int(need), 1)
    m.write(p2p+80, samples)
    m.write(p2p+84, smoothed)
    m.write(p2p+88, NOW-probe_age, 8)
    m.write(p2p+516, total)
    m.write(p2p+528, 0 if pending_delta is None else NOW+pending_delta, 8)
    m.write(p2p+536, failures)
    m.write(p2p+540, quota)
    m.write(p2p+592, 0x7fffffffffffffff, 8)
    m.write(fixture.vt+32, METRICS, 8)
    m.write(fixture.vt+48, REQUEST, 8)
    def send(m):
        request = m.reg(1)
        m.events.append(('probe', request))
        if sends:
            m.write(p2p+528, NOW+1000000, 8)  # Explicit transport send result.
    def schedule(m):
        m.write(m.reg(0)+8, m.reg(1), 8)
        m.events.append(('schedule', m.reg(1)))
    m.stubs.update({METRICS: lambda m: m.reg(0, int(can_send)), REQUEST: send,
                    0xc138b0: lambda m: m.events.append(('changed',)), 0xc11de0: schedule})
    m.redirects[0xc12ba0] = 0x878698
    m.allowed.append((0x878698, 0x87877c))
    native_call(m, 0x878404, 0x878698, p2p, NOW)
    active = state in (-2, 2, 3)
    expired = active and pending_delta is not None and pending_delta <= 0
    assert m.read(p2p+536) == failures+int(expired)
    assert m.read(p2p+24, 1) == int(need)
    assert [e for e in m.events if e[0] == 'probe'] == ([('probe', expected_request)] if expected_request else [])
    assert [e for e in m.events if e[0] == 'changed'] == ([('changed',)] if expired and failures >= 2 and not need else [])
    if active:
        deadline = NOW+2000000
        if expected_request and sends:
            deadline = min(deadline, NOW+1000000)
        elif pending_delta is not None and pending_delta > 0:
            deadline = min(deadline, NOW+pending_delta)
        elif can_send and not expected_request and selected == 'other' and not selected_need:
            deadline = min(deadline, NOW-probe_age+10000000)
        assert m.read(p2p+592, 8) == deadline, m.events
    else:
        assert not m.events


def p2p_track_request(elf, pending, delayed, quota):
    fixture = SDR(elf, [])
    m, p2p = fixture.m, fixture.base+264
    m.write(p2p+84, -1)
    m.write(p2p+528, NOW+99 if pending else 0, 8)
    m.write(p2p+540, quota)
    m.write(p2p+592, 0x7fffffffffffffff, 8)
    def schedule(m):
        m.write(m.reg(0)+8, m.reg(1), 8)
    m.stubs[0xc11de0] = schedule
    native_call(m, 0x8782a0, 0x878404, p2p, NOW, int(delayed))
    expected_deadline = NOW+99 if pending else NOW+1250000+int(delayed)*200000
    assert m.read(p2p+528, 8) == expected_deadline
    assert m.read(p2p+88, 8) == NOW
    assert m.read(p2p+540) == (quota if pending else max(0, quota-1))
    assert m.read(p2p+592, 8) == (0x7fffffffffffffff if pending else expected_deadline)


def outer_routes_delivery(elf, expected_events, *, state=3, active=True, token=True, acked=False,
                          deadline_delta=-1, pending_ack=False, need=False, reply_pending=False,
                          immediate_age=0, relay_age=0, e2e_age=0, relay_fail=0, e2e_fail=0,
                          stats_ok=True):
    fixture = SDR(elf, [{}])
    fixture.active([0] if active else [])
    m = fixture.m
    m.write(fixture.connection+6848, state)
    m.write(fixture.connection+6852, state)
    m.write(fixture.connection+4912, 1)
    m.write(fixture.connection+4400, NOW+1000000 if reply_pending else 0, 8)
    m.write(fixture.connection+4408, NOW-immediate_age, 8)
    m.write(fixture.connection+4416, e2e_fail)
    m.write(fixture.connection+2792, NOW-e2e_age, 8)
    m.write(fixture.base+288, int(need), 1)
    m.write(fixture.base+1232, 10 if acked else 9)
    m.write(fixture.base+1048, 10)
    m.write(fixture.base+1224, NOW+deadline_delta, 8)
    m.write(fixture.base+1096, int(pending_ack), 1)
    m.write(fixture.relays[0]+248, NOW-relay_age, 8)
    m.write(fixture.relays[0]+256, relay_fail)
    m.write(fixture.vt+136, REQUEST, 8)
    def stats(m):
        m.events.append(('stats', m.reg(2)))
        if stats_ok:
            m.write(fixture.base+1096, 0, 1)
            m.write(fixture.base+1224, NOW+500000, 8)
            m.write(fixture.connection+4400, NOW+1000000, 8)
        m.reg(0, int(stats_ok))
    m.stubs.update({0xc125d0: lambda m: None,
                    0xc12aa0: lambda m: m.reg(0, int(token)), REQUEST: stats,
                    0xc11c90: lambda m: m.uc.mem_write(m.reg(0), b'route\0'),
                    0xc0a230: lambda m: None,
                    0xc08f60: lambda m: None, 0xc09530: lambda m: None,
                    0xc12c00: lambda m: m.events.append(('signal',)),
                    0xc097e0: lambda m: (m.events.append(('diagnostic',)), m.reg(0, 1))})
    native_call(m, 0x837a90, 0x837f2c, fixture.base, NOW)
    assert m.events == expected_events, (m.events, expected_events)
    return m.events



def native_stats_send_chain(elf, socket_ok, *, desired=b'new-target', force=False, request=2,
                            routes_due=True, queued=3, instantaneous=False, outer=False,
                            deadline_delta=-1, pending_ack=True, inline=False, payload_size=1000):
    fixture = SDR(elf, [{}])
    fixture.active([0])
    m, session = fixture.m, fixture.sessions[0]
    connection, transport = fixture.connection, fixture.base
    relay_tracker, e2e_tracker = session+112, connection+392
    m.write(connection+40, transport, 8)
    m.write(connection+4912, 1)
    m.write(connection+5340, 1200)
    m.write(connection+2528, 200, 8)
    m.write(session+2248, 100, 8)
    m.write(session+64, 123)
    m.set_string(session+40, desired)
    m.set_string(session+72, b'old-target')
    m.write(session+96, 122)
    m.write(session+100, 5)
    m.write(session+104, 1, 1)
    m.write(transport+968, 7)
    m.write(transport+1048, 10)
    m.write(transport+1232, 9 if routes_due else 10)
    m.write(transport+1224, NOW+deadline_delta, 8)
    m.write(transport+1096, int(pending_ack), 1)
    m.write(transport+348, -1)
    m.write(transport+856, 0x7fffffffffffffff, 8)
    for tracker in (relay_tracker, e2e_tracker):
        m.write(tracker+68, -1)
        m.write(tracker+4088, NOW-30000000 if instantaneous else NOW, 8)
        m.write(tracker+4080, NOW, 8)
        m.write(tracker+2528, 100 if instantaneous else 0, 8)
        m.write(tracker+24, NOW, 8)
        m.write(tracker+72, NOW, 8)
        m.write(tracker+2400, NOW, 8)
    m.write(relay_tracker+4432, session, 8)
    m.write(relay_tracker+4112, 16, 8)
    m.write(relay_tracker+4120, m.alloc(128), 8)
    m.write(session+4496, 1, 1)
    m.write(session+4500, queued)
    for index in range(queued):
        m.write(session+4504+index*8, index+1 | (NOW-1000) << 16, 8)
    def construct(m):
        obj = m.reg(0)
        m.uc.mem_write(obj, bytes(128))
        for offset in (56, 64):
            m.write(obj+offset, m.string(b''), 8)
    def populate(m):
        mask = m.reg(1)
        m.write(m.reg(2)+16, int(bool(mask & 3)) | (int(bool(mask & 12)) << 1))
    messages = []
    def socket(m):
        msg = m.reg(2)
        messages.append((m.read(msg+16), m.read(msg+96), m.read(msg+112), m.read(msg+116)))
        m.reg(0, 100 if socket_ok else -1)
    def reserve(m):
        m.write(m.reg(0)+4, max(16, m.reg(1)))
        m.write(m.reg(0)+8, m.alloc(max(16, m.reg(1))*4), 8)
    def schedule(m):
        m.write(m.reg(0)+8, m.reg(1), 8)
    m.stubs.update({0xbffb30: construct, 0xc009b0: lambda m: None,
                    0xbff410: lambda m: m.set_string(m.reg(0), m.get_string(m.reg(1))),
                    0xc0a110: lambda m: m.reg(0, int(bytes(m.uc.mem_read(m.reg(0), m.reg(2))) != bytes(m.uc.mem_read(m.reg(1), m.reg(2))))),
                    0xc0acd0: lambda m: m.set_string(m.reg(1), b'synthetic-routes'),
                    0xc006d0: lambda m: m.reg(0, m.alloc(128)), 0xc12ae0: populate,
                    0xc009d0: lambda m: m.reg(0, 100), 0xbffe80: reserve,
                    0xc12b00: lambda m: m.reg(0, 0),
                    0xc12b30: lambda m: m.reg(0, 0x7fffffffffffffff),
                    0xc12390: socket, 0xc12b10: lambda m: None, 0xc11de0: schedule,
                    0xc097e0: lambda m: m.reg(0, 1)})
    calls = {0xc12ab0: (0x835400, 0x8355f8), 0xc12aa0: (0x83505c, 0x835290),
             0xc12ac0: (0x8355f8, 0x835c64), 0xc12ad0: (0x8b3580, 0x8b36c4),
             0xc14d30: (0x8b33e8, 0x8b34f0), 0xc12af0: (0x840fd8, 0x8411c4),
             0xc12b20: (0x835f00, 0x835fbc), 0xc12b40: (0x83e624, 0x83e8f4),
             0xc12d20: (0x84f8b4, 0x84fb9c), 0xc12d30: (0x8b4108, 0x8b420c),
             0xc12370: (0x817304, 0x817330), 0xc12e40: (0x84fb9c, 0x84fd5c),
             0xc12d40: (0x84fd5c, 0x84fe20), 0xc12b50: (0x8782a0, 0x878404)}
    for call, (start, end) in calls.items():
        m.redirects[call] = start
        m.allowed.append((start, end))
    if inline:
        context, chunk = m.alloc(256), m.alloc(payload_size)
        m.reg(0, context+32)
        construct(m)
        m.write(context, NOW, 8)
        m.write(context+16, m.empty, 8)
        m.write(context+160, session, 8)
        m.write(connection+4832, 1)
        m.write(connection+4836, 0)
        m.allowed.append((0x84ff68, 0x850374))
        m.redirects[0xc12d90] = 0x84ff68
        def serialize(m):
            m.uc.mem_write(m.reg(1), bytes(100))
            m.reg(0, m.reg(1)+100)
        gathered = []
        def gather(m):
            vectors = m.reg(2)
            header, length = m.read(vectors, 8), m.read(vectors+8, 8)
            gathered.append((m.reg(3), length, m.read(header, 1), m.read(transport+1224, 8), m.read(session+4500)))
            m.reg(0, int(socket_ok))
        m.stubs.update({0xc0be20: serialize, 0xc12380: gather})
        native_call(m, 0x835400, 0x8355f8, transport, context, request, int(force))
        native_call(m, 0x83ed9c, 0x83f0a8, transport, chunk, payload_size, context)
        attached = 101 < 1291-payload_size
        header_size = 110 if attached else 9
        packet_size = header_size+payload_size
        assert gathered == [(packet_size, header_size, 0xa1 if attached else 0xa0,
                             NOW+500000 if attached else NOW-1, 0 if attached else queued)], gathered
        assert m.reg(0) == (packet_size if socket_ok else 0)
        # Included inline stats commit before gather; omitted stats never register.
        assert m.read(session+4500) == (0 if attached else queued)
        assert m.read(session+4496, 1) == int(not attached)
        assert m.read(transport+1096, 1) == int(not attached)
        assert m.read(transport+1224, 8) == (NOW+500000 if attached else NOW-1)
        assert m.read(session+2248, 8) == 101 and m.read(connection+2528, 8) == 201
        assert m.read(relay_tracker+4104, 8) == int(attached)
        assert bool(m.read(relay_tracker+4008, 8)) == attached
        assert bool(m.read(transport+792, 8)) == attached
        # Session ACK registration reaches RelayServer::TrackSentPingRequest,
        # even before a failed inline gather. Root and session clocks coexist.
        assert m.read(fixture.relays[0]+136, 8) == m.read(relay_tracker+4008, 8)
        assert m.read(fixture.relays[0]+320, 8) == (NOW if attached else 0)
        assert m.read(fixture.clusters[0]+556) == int(attached)
        return
    if outer:
        # ABI bridge: CM service's (connection,msg,now) -> PopulateRendezvous(transport,msg,now).
        bridge = policy.RETURN+0x900
        m.uc.mem_write(bridge, struct.pack('<IIIQ', 0xf9400000 | ((6888//8) << 10),
                                          0x58000050, 0xd61f0200, 0x834bc0))
        m.allowed.extend([(bridge, bridge+12), (0x834bc0, 0x834d04), (0x835c64, 0x835f00)])
        m.redirects[0xc12c00] = bridge
        m.write(connection+6888, transport, 8)
        m.write(fixture.vt+136, 0x835c64, 8)
        m.write(0xc80000+2824, m.alloc(128), 8)
        m.write(connection+6848, 3)
        m.write(connection+2792, NOW, 8)
        m.write(connection+4912, 1)
        def rendezvous(m):
            msg = m.reg(0)
            m.uc.mem_write(msg, bytes(144))
            m.write(msg+72, m.string(b''), 8)
        m.stubs.update({0xc125d0: lambda m: None, 0xc12a80: lambda m: None,
                        0xc11c90: lambda m: m.uc.mem_write(m.reg(0), b'route\0'),
                        0xc0a230: lambda m: None, 0xc08f60: rendezvous,
                        0xc09530: lambda m: None})
        native_call(m, 0x837a90, 0x837f2c, transport, NOW)
        due = routes_due and deadline_delta <= 0
        attempted = due or pending_ack
        signal = attempted and (not socket_ok or due and deadline_delta == 0)
        assert len(messages) == int(attempted), (deadline_delta, pending_ack, messages)
        assert (bridge in m.visited) == signal, (deadline_delta, socket_ok, messages, bridge in m.visited)
        wanted_deadline = NOW+1000000 if signal and due else NOW+500000 if attempted and socket_ok and due else NOW+deadline_delta
        assert m.read(transport+1224, 8) == wanted_deadline
        assert m.read(transport+1096, 1) == (0 if attempted else int(pending_ack))
        if attempted:
            assert bool(messages[0][0] & 2) == (due and deadline_delta < 0)
        return
    native_call(m, 0x835c64, 0x835f00, transport, session, request, int(force), NOW, m.empty)
    assert len(messages) == 1 and bool(m.reg(0)) == socket_ok
    presence, wire_flags, relay_seq, e2e_seq = messages[0]
    assert relay_seq == 100 and (e2e_seq == 200 if presence & 1024 else e2e_seq == 0)
    assert m.read(session+2248, 8) == 101
    assert m.read(connection+2528, 8) == 200+int(bool(presence & 1024))
    # Target registration occurs during Populate, even when the socket fails.
    assert m.get_string(session+72) == (desired if desired else b'old-target')
    assert m.read(session+100) == (6 if desired else 5)
    assert bool(m.read(session+104, 1)) == (not bool(desired))
    assert m.read(transport+1224, 8) == (NOW+500000 if socket_ok and presence & 2 else NOW-1)
    assert m.read(transport+1096, 1) == (0 if socket_ok and presence & 128 else 1)
    assert m.read(session+4500) == (0 if socket_ok else queued)
    assert m.read(session+4496, 1) == (0 if socket_ok and queued else 1)
    relay_ack = bool(wire_flags & 1 or presence & 4)
    e2e_ack = bool(wire_flags & 2 or presence & 8)
    assert m.read(relay_tracker+4104, 8) == int(socket_ok and relay_ack)
    assert m.read(relay_tracker+4008, 8) != 0 if socket_ok and relay_ack else m.read(relay_tracker+4008, 8) == 0
    assert bool(m.read(transport+792, 8)) == bool(socket_ok and e2e_ack)
    assert m.read(fixture.relays[0]+136, 8) == m.read(relay_tracker+4008, 8)
    assert m.read(fixture.relays[0]+320, 8) == (NOW if socket_ok and relay_ack else 0)
    assert m.read(fixture.clusters[0]+556) == int(socket_ok and relay_ack)
    assert m.read(relay_tracker+3984, 8) == (100 if socket_ok and presence & 4 else 0)
    assert m.read(e2e_tracker+3984, 8) == (200 if socket_ok and presence & 8 else 0)



def valid_end_to_end(elf, need, active, smoothed, override=-2, can_send=True, evaluation_future=False):
    fixture = SDR(elf, [{}])
    fixture.active([0] if active else [])
    m, base, session = fixture.m, fixture.base, fixture.sessions[0]
    m.write(base+272, base, 8)
    m.write(base+288, int(need), 1)
    m.write(base+348, smoothed)
    m.write(base+784, override)
    m.write(base+792, NOW+1000, 8)
    m.write(base+800, 2)
    m.write(fixture.connection+4912, 1)
    m.write(fixture.connection+7312, NOW+1 if evaluation_future else 0, 8)
    for offset, value in [(4564, 10), (4580, 20), (4584, 30)]:
        m.write(session+offset, value)
    m.write(fixture.vt+112, REQUEST, 8)
    m.write(fixture.vt+32, METRICS, 8)
    m.stubs.update({REQUEST: lambda m: m.events.append(('select_sessions',)),
                    METRICS: lambda m: m.reg(0, int(can_send)),
                    0xc138b0: lambda m: m.events.append(('confirmed_changed',)),
                    0xc12de0: lambda m: m.events.append(('select_transport',)),
                    0xc120d0: lambda m: m.events.append(('ping_seed', m.reg(1))),
                    0xc09b00: lambda m: (m.events.append(('diagnostic',)), m.reg(0, 1))})
    m.redirects[0xc12dd0] = 0x87877c
    m.allowed.append((0x87877c, 0x8788b0))
    native_call(m, 0x83f314, 0x83f748, base, NOW, m.empty, session)
    events = []
    if need:
        events.append(('select_sessions',))
        if active:
            events.append(('confirmed_changed',) if can_send else ('diagnostic',))
            if smoothed < 0 and override != -1:
                events.append(('ping_seed', 60 if override < -1 else override))
    if (not need or active) and not evaluation_future:
        events.append(('select_transport',))
    assert m.events == events, (need, active, smoothed, override, m.events, events)
    assert m.read(base+792, 8) == 0 and m.read(base+800) == 0
    assert bool(m.read(base+288, 1)) == (need and (not active or not can_send))
    assert m.read(base+780) == int(need and active and smoothed < 0 and override != -1)



def connectivity_change_callback(elf, need, selected, quota, wire_state=3, recorded=False, age=12345):
    fixture = SDR(elf, [])
    m, p2p, connection = fixture.m, fixture.base+264, fixture.connection
    m.write(p2p+24, int(need), 1)
    m.write(p2p+540, quota)
    m.write(connection+7288, p2p if selected else 0, 8)
    m.write(connection+6888, fixture.base, 8)
    m.write(connection+7304, NOW-age, 8)
    m.write(connection+6852, wire_state)
    m.write(connection+7320, 1, 1)
    m.write(connection+7312, NOW+1000000, 8)
    m.write(connection+6912, 64 if recorded else 0)
    m.write(connection+6944, 999 if recorded else 0)
    native_call(m, 0x874c2c, 0x874d80, connection, p2p, NOW)
    urgent = need == selected
    assert m.read(connection+7320, 1) == int(not urgent)
    assert m.read(connection+7312, 8) == (1 if urgent else NOW+1000000)
    assert m.read(p2p+540) == max(5, quota)
    assert m.events == [('think', 1)]
    records = not need and 1 <= wire_state <= 3
    assert m.read(connection+6912) == (64 if recorded or records else 0)
    assert m.read(connection+6944) == (999 if recorded else max(1, (age+500)//1000) if records else 0)



def inline_stats_budget(elf, relay_mask, e2e_mask, room, expected_masks, encoded, body_base=10, flags=3):
    fixture = SDR(elf, [{}])
    m, context, serializer, buffer = fixture.m, fixture.m.alloc(256), fixture.m.alloc(32), fixture.m.alloc(1024)
    relay, e2e = m.alloc(128), m.alloc(128)
    m.write(context, NOW, 8)
    m.write(context+160, fixture.sessions[0], 8)
    m.write(context+24, flags)
    presence = (4 if relay_mask is not None else 0) | (8 if e2e_mask is not None else 0)
    implicit = (presence >> 2) & 3
    explicit = bool(flags & ~implicit)
    m.write(context+48, presence | (32 if explicit else 0))
    m.write(context+128, flags | implicit if explicit else 0)
    for offset, obj, mask in [(104, relay, relay_mask), (112, e2e, e2e_mask)]:
        m.write(context+offset, obj, 8)
        m.write(obj+16, mask or 0)
    def size():
        result = body_base+int(bool(m.read(context+48) & 32))*2
        for parent_bit, obj in [(4, relay), (8, e2e)]:
            if m.read(context+48) & parent_bit:
                result += 6*int(bool(m.read(obj+16) & 1))+12*int(bool(m.read(obj+16) & 2))
        return result
    initial = size()
    m.write(context+152, initial)
    m.write(context+156, initial+(1 if initial < 128 else 2))
    m.write(serializer, buffer+9, 8)
    m.write(serializer+8, buffer+9+room, 8)
    m.write(serializer+16, buffer, 8)
    m.write(buffer, 0xa0, 1)
    def clear(m, bit):
        m.write(context+48, m.read(context+48) & ~bit)
    def serialize(m):
        count = size()
        m.uc.mem_write(m.reg(1), bytes([0x55])*count)
        m.reg(0, m.reg(1)+count)
    m.stubs.update({0xc00990: lambda m: clear(m, 4), 0xc009a0: lambda m: clear(m, 8),
                    0xc009d0: lambda m: m.reg(0, size()), 0xc0be20: serialize,
                    0xc12b20: lambda m: m.events.append(('track_inline',))})
    native_call(m, 0x84ff68, 0x850374, fixture.base, serializer, context)
    actual = tuple(m.read(obj+16) if m.read(context+48) & bit else None for bit, obj in [(4, relay), (8, e2e)])
    assert actual == expected_masks, (relay_mask, e2e_mask, room, actual, expected_masks)
    assert m.events == ([('track_inline',)] if encoded else [])
    assert bool(m.read(buffer, 1) & 1) == encoded
    if encoded:
        count = size()
        prefix = bytes([count]) if count < 128 else bytes([(count & 127) | 128, count >> 7])
        assert bytes(m.uc.mem_read(buffer+9, len(prefix))) == prefix
        assert m.read(serializer, 8) == buffer+9+len(prefix)+count
    else:
        assert m.read(serializer, 8) == buffer+9


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
    for failures, cached, probes, active, backup in itertools.product((1,2,3),(0,1),(3,4,7,8),(False,True),(False,True)):
        route={'ping':-1,'failures':failures,'failed_addresses':cached,'probes':probes}
        case('probe_failure_history',probe_priorities,[route],expected_probe(route,active,backup),
             need_any=active,need_backup=backup)
    # These are already in routing-score order, as at 0x823e84. Execute the
    # original nearest-N walk, including its prefix count and tier-zero cutoff
    # counters. The implementation audit compares the returned native oracle.
    unknown={'ping':-1,'probes':0,'reachable':0}
    planning=[([dict(unknown) for _ in range(24)],n) for n in (-1,5,6,20,21,30)]
    for changed in ({'reachable':-1},{'failures':4},{'failures':2,'failed_addresses':1},
                    {'failures':1,'failed_addresses':1},{'pop_tier':0},{'special':1},
                    {'special':-1},{'pop_type':2},{'pop_type':2,'pop_tier':0}):
        routes=[dict(unknown) for _ in range(24)]
        for i in (0,5,19,20,23): routes[i].update(changed)
        planning.append((routes,20))
    for other in ([{'ping':-1,'probes':0,'pop_tier':0}],
                  [{'ping':-1,'probes':0,'pop_type':2,'pop_tier':0}],
                  [{'ping':-1,'probes':0,'special':1}],
                  [{'ping':-1,'probes':0,'pop_tier':0},{'pop_tier':0}],
                  [{'ping':-1,'probes':0,'pop_tier':0},{'pop_type':2,'pop_tier':0}],
                  [{'ping':-1,'probes':0,'pop_tier':0},{'pop_tier':0,'reachable':-1}],
                  [{'ping':-1,'probes':0,'pop_tier':0},{'pop_tier':0,'failures':4}]):
        planning.append((other+[dict(unknown) for _ in range(21)],20))
    for routes,limit in planning:
        for active,backup in itertools.product((False,True),(False,True)):
            case('nearest_probe_planning',probe_priorities,routes,None,need_any=active,
                 need_backup=backup,nearest_limit=limit)
    values=(None,False,True,0,1,-1,0.5,"true","TRUE","TrUe","false","1","0","truex","",[],{},"true\0x")
    for first,second in itertools.product(values,(None,False,True,"true")):
        case('config_pop_type',config_pop_type,first,second)
    for cluster_key,global_key in itertools.product((False,True),(False,True)):
        case('relay_key_selection',relay_key_selection,cluster_key,global_key)
    key='0123456789abcdef'*4
    for text in ('',key,key.upper(),'gg'+key,' '.join(key),key+'f',key+'ff',key[:-1],key[:-2],
                 'bad',key+'\0junk','é'+key,'\\'+key,':'.join(key[i:i+2] for i in range(0,64,2))):
        case('config_hex_key',config_hex_key,text)
    for kind,ping,reachable,special in itertools.product((0,1,2),(-1,0,20),(-1,0,1,2),(-1,0,1)):
        case('p2p_front_eligibility',front_eligibility,kind,ping,reachable,special)
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
    for seed in range(12):
        pings=[20+(i*7+seed*3)%25 for i in range(8)]
        routes=[(i,(i+seed)%8,80+(i*37+seed*11)%200,80+(i*91+seed)%200) for i in range(8)]
        metadata={7:{'remote_used':True},0:{'penalty':1000,'special':-1}} if seed%3==0 else {}
        for old in (False,True):
            case('advertisement_union',advertise,pings,routes,None,None,old=old,
                 forced=[7] if seed%2 else [],internal=[0,4] if seed%4==0 else [],metadata=metadata)
        case('advertisement_union',advertise,pings,routes,None,None,old=True,
             old_clusters=[0,1,2,3,4,5],old_routes=[0,1,2,3,4,5])
    case('advertisement_union',advertise,[-1,20,30],[],None,None,
         metadata={0:{'penalty':0x10000000}})
    for interior,penalty,forward in [(0,0,30),(10,0,65),(10,3,80),(999,5000,6100)]:
        case('route_serialization_fields',route_serialization_fields,interior,penalty,forward)
    for good in (False,True): case('snapshot_readiness_gate',snapshot_readiness_gate,good)
    for rf,sf,age in itertools.product((0,1),(0,5),(500000,500001,1750000,1750001)):
        case('base_metrics_failure_owner',base_metrics_failure_owner,rf,sf,age)
    for controlling,role in itertools.product((False,True),(0,1,0x7fffffff)):
        case('snapshot_primary_contract',snapshot_primary_contract,controlling,role)
    for old,count,first in itertools.product((False,True),(0,1),((123,456),(999,456),(123,999))):
        case('snapshot_primary_contract',snapshot_primary_contract,True,0,old,count,first)
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
    initial = {200: (30, 7, 8, NOW-100)}
    for full,size in [(0,1300),(NOW-5000001,1300),(NOW-5000000,1300),(NOW-4999999,100),(NOW,100)]:
        case('ping_request_size',ping_request_size,full,size)
    for pending in (False,True):
        for delay,ping in [(0,0),(999,0),(1000,1),(10000000,10000),(10000001,None),
                           (-1,None),(-2,0),(-1999,None),(-2000,0),(-2002,None)]:
            case('router_ping_reply_dispatch',router_ping_reply,delay,ping,pending=pending)
    case('router_ping_reply_dispatch',router_ping_reply,1000,1,cookie=22,session=True)
    case('router_ping_reply_dispatch',router_ping_reply,1000,1,cookie=22,session=False)
    case('router_ping_reply_dispatch',router_ping_reply,1000,1,cookie=33,session=True)
    case('router_ping_reply_dispatch',router_ping_reply,1000,1,counts=(1,0))
    case('router_ping_reply_dispatch',router_ping_reply,1000,1,warning=True)
    case('router_ping_reply_dispatch',router_ping_reply,1000,1,clock=NOW+0x100000000)
    for incoming, expected in [(0,0),(50,50),(100,100),(150,150),(200,200),(201,200),
                               (202,200),(300,300),(301,100),(400,400),(0xffffffff,0xffffffff)]:
        case('canonical_pop_mapping',canonical_pop,[100,200,300],{201:1,202:1,301:0},incoming,expected)
    case('canonical_pop_mapping',canonical_pop,[],{},100,100)
    for flags in (0, 1):
        retained = (30, 7, 8, NOW-100 if flags else 0)
        case('datacenter_latency_updates', receive_latencies, initial, [], [], [], flags,
             {200: retained}, flags == 0)
        case('datacenter_latency_updates', receive_latencies, initial, [(201, 40)], [], [], flags,
             {200: retained, 201: (40, 0, 0, NOW)}, True)
        case('datacenter_latency_updates', receive_latencies, initial, [(200, 40)], [], [], flags,
             {200: (40, 0, 0, NOW)}, True)
        case('datacenter_latency_updates', receive_latencies, initial, [], [(200, 40)], [], flags,
             {200: (40, 0, 0x20000000, NOW)}, True)
        case('datacenter_latency_updates', receive_latencies, initial, [(200, 40)], [(200, 50)],
             [(200, 4, 9)], flags, {200: (50, 9, 0x20000004, NOW)}, True)
        case('datacenter_latency_updates', receive_latencies, initial, [], [], [(200, 4, 9)], flags,
             {200: retained}, flags == 0)
    case('datacenter_latency_updates', receive_latencies, {}, [(200, 40), (200, 50)], [], [], 0,
         {200: (50, 0, 0, NOW)}, True)
    case('datacenter_latency_updates', receive_latencies, {}, [(200, 40)], [], [(201, 4, 9)], 0,
         {200: (40, 0, 0, NOW)}, True)
    case('datacenter_latency_updates', receive_latencies, {}, [(200, 40)], [], [(200, 4, 9000)], 0,
         {200: (40, 9000, 4, NOW)}, True)
    case('datacenter_latency_updates', receive_latencies, {}, [(200, 0xffffffff)], [], [], 1,
         {200: (0xffffffff, 0, 0, NOW)}, True)
    for measured in (False, True):
        case('datacenter_route_estimation', datacenter_routes, [20, -1], [(0, 1, 10)], [20, 20], measured)
        case('datacenter_route_estimation', datacenter_routes, [20, -1], [(0, 1, 100)], [20, 60], measured)
    case('datacenter_route_estimation', datacenter_routes, [-1, -1], [(0, 1, 10)], [0x0fffffff]*2)
    case('datacenter_route_estimation', datacenter_routes, [20, 50], [(0, 1, 10)], [20, 50])
    case('datacenter_route_estimation', datacenter_routes, [2000,-1], [(0,1,100)], [2000,2000])
    case('datacenter_route_estimation', datacenter_routes, [2001,-1], [(0,1,100)], [2001,0x0fffffff])
    case('datacenter_route_estimation', datacenter_routes, [20,-1], [(0,1,-1)], [20,0x0fffffff])
    case('datacenter_route_estimation', datacenter_routes, [20, -1, -1, -1, -1],
         [(0, 1, 10), (1, 2, 10), (2, 3, 10), (3, 4, 10)], [20, 20, 40, 50, 60])
    case('datacenter_route_estimation', datacenter_routes, [-1, -1, -1, -1, 20],
         [(4, 3, 10), (3, 2, 10), (2, 1, 10), (1, 0, 10)], [0x0fffffff, 50, 40, 20, 20])
    initial_alt = [(2, 27016, 0, 25, True)]
    case('alternate_updates', alternate_updates, initial_alt, [], True, [(2, 27016, 0, 25, b'old')])
    case('alternate_updates', alternate_updates, initial_alt, [], False, [], removed=[100])
    for penalty in (0, 99999):
        case('alternate_updates', alternate_updates, initial_alt, [(2, 27016, 0, penalty)], False,
             [(2, 27016, 0, 8191, b'new')])
    case('alternate_updates', alternate_updates, [], [(None, 27016, 0, 0)], False,
         [(1, 27016, 0, 8191, b'new')])
    case('alternate_updates', alternate_updates, initial_alt, [(2, 27016, 1, 0)], False, [], removed=[100])
    case('alternate_updates', alternate_updates, [(2, 27016, 0, 25, True), (3, 27017, 0, 25, True)],
         [(3, 27017, 0, 0)], False, [(3, 27017, 0, 8191, b'new')], removed=[100])
    for age, expected in [(119999999, False), (120000000, False), (120000001, True)]:
        case('alternate_creation', create_alternate, age, expected)
    case('alternate_creation', create_alternate, 1, False, existing=True)
    case('alternate_creation', create_alternate, 120000001, True, create_ok=False)
    for routes, expected in [
        ([{'age': 499999}], []), ([{'age': 500000}], [('ping', 0)]),
        ([{'age': 1000000, 'pending': True}], []),
        ([{'age': 1000000}, {'age': 89999}], []),
        ([{'age': 1000000}, {'age': 90000}], [('ping', 0)]),
        ([{'age': 1000000}, {'age': 1500000}], [('ping', 1)]),
        ([{'age': 1000000}, {'age': 1000000}], [('ping', 1)]),
        ([{'received': 7, 'measured': 20}], [('ping', 0)]),
        ([{'received': 8, 'measured': 20}], [('probe_done', 0)]),
        ([{'failures': 4}], []),
        ([{'root_failures': 1}], [('root_ping', 0)]),
        ([{'root_failures': 1, 'root_pending': True}], []),
    ]:
        case('alternate_probe_schedule', alternate_probe_schedule, routes, expected)
    for tokens, failed in [([], b'x'), ([b'a', b'b'], b'b'), ([b'a', b'b'], b'x'),
                            ([b'a', b'a'], b'a'), ([b'', b'b'], b''),
                            ([b'a'*40, b'b'*40], b'b'*40), ([b'a'*40], b'x'*40)]:
        case('bad_route_token_invalidation', bad_route, tokens, failed)
    for presence, challenge in itertools.product((0, 4, 8, 12), (0, 123456789)):
        case('no_session_recovery', no_session, presence, challenge)
    for state, token in itertools.product((-2, -1, 0, 1, 2, 3, 4, 5, 6), (b'', b'token')):
        case('session_established', session_established, state, token, 0)
    for sequence in (1, 65535):
        case('session_established', session_established, 3, b'token', sequence)
    case('session_established', session_established, 3, b'token', 1, existing=False, warning=True)
    for state, active, selected, closed in itertools.product(range(-3, 6), ([], [0], [0, 1]), (False, True), ([], [0])):
        case('transport_state_change', transport_state_change, state, active, selected, closed)
    for remote_id, end_to_end in itertools.product((0, 456), (False, True)):
        case('connection_closed_sender', connection_closed_sender, remote_id, end_to_end)
    for requested, port, old, active, source in [
        (2, 27015, 0, True, 0), (2, 27015, 2, True, 0), (3, 27015, 2, True, 0),
        (0, 27015, 2, True, 0), (3, 0, 2, True, 0), (3, 27015, 2, False, 0),
        (3, 27015, 2, True, 1),
        (2, 92551, 2, True, 0), (3, 65536, 2, True, 0),
    ]:
        case('stats_migration_updates', stats_migration, requested, port, old, active, source, state=2, target=1)
    for forward_ack, old_acked, peer_ack in itertools.product((None, 4, 5, 6), (False, True), (None, 9, 10, 11)):
        case('stats_revision_acks', stats_revisions, forward_ack, old_acked, peer_ack)
    case('stats_revision_acks', stats_revisions, None, False, 9, old_peer_ack=10, deadline=0)
    for flags, primary, quality in itertools.product((0, 2, 4, 6), (False, True), (False, True)):
        case('stats_ack_sending', stats_revisions, None, False, None, flags=flags,
             primary_transport=primary, quality=quality)
    for old, new, valid in [(5, 4, True), (5, 5, True), (5, 6, True), (5, 6, False),
                              (5, 0xffffffff, True), (0xffffffff, 0, True)]:
        case('routes_revision_receive', receive_routes, old, new, valid)
    for queued, incoming, flags in [([], 10, 1), ([10], 10, 1), ([10, 11], 10, 1),
                                     ([1, 2, 3, 4, 5], 6, 1), ([1, 2, 3, 4, 5], 6, 5),
                                     ([1, 2, 3, 4, 5], 5, 5), ([], 10, 0)]:
        case('stats_pending_ack_queue', stats_ack_queue, queued, incoming, flags)
    for flags in (0, 2, 4, 6):
        case('stats_pending_ack_queue', stats_ack_queue, [], 10, flags, e2e=True)
    for routes, active, expected in [
        ([{'ping': 40}, {'ping': 20}], [], [1, 0]),
        ([{'ping': 40}, {'ping': 20}], [0, 1], [1, 0]),
        ([{'ping': 30}, {'ping': 20}], [0, 1], [0, 1]),
        ([{'ping': 20, 'remote': 200}, {'ping': 40, 'remote': 20}], [], [1, 0]),
        ([{'shutdown_seconds': 29}, {}], [0, 1], [1, 0]),
        ([{'ping': 40, 'token': False}, {'ping': 20}], [], [1]),
        ([{'ping': 20, 'local_penalty': 30}, {'ping': 40}], [], [1, 0]),
        ([{'ping': 20, 'remote_penalty': 30}, {'ping': 40}], [], [1, 0]),
        ([{'ping': 20, 'interior_penalty': 30}, {'ping': 40}], [], [1, 0]),
    ]:
        case('integrated_metrics_and_selection', integrated_select, routes, active, expected)
    for tokens, active, expected in [([b'a', b'b'], [0, 1], [0, 1]),
                                      ([None, b'b'], [0, 1], [1]),
                                      ([b'a', None], [0, 1], [0]),
                                      ([None, None], [0, 1], []),
                                      ([None, b'b', None], [0, 1], [1])]:
        case('clean_route_targets', clean_routes, tokens, active, expected)
    case('clean_route_targets', clean_routes, [None, None], [0, 1], [0, 1], fresh=True)
    case('clean_route_targets', clean_routes, [None, None], [0, 1], [0, 1], state=4)
    for old, desired, acked, revision in [(b'', b'a', False, 0), (b'a', b'a', True, 5),
                                          (b'a', b'', True, 5), (b'a', b'b', True, 5),
                                          (b'a', b'b', True, 0xffffffff),
                                          (b'a'*40, b'a'*40, False, 5), (b'a'*40, b'b'*40, True, 5)]:
        case('forward_target_revision', forward_target, old, desired, acked, revision)
    for primary, force, need, pending, deadline in itertools.product((False, True), (False, True), (False, True), (False, True), (-1, 0, 1)):
        case('stats_context_routes', populate_context, primary, force, need, pending, deadline)
    for token, transport, acked in itertools.product((False, True), (False, True), (False, True)):
        case('stats_context_routes', populate_context, True, True, False, True, -1,
             own_acked=acked, token=token, primary_transport=transport)
    for deadline, acked, closed in itertools.product((-1, 0, 1), (False, True), (False, True)):
        case('rendezvous_routes_sending', rendezvous_routes, deadline, acked, closed)
    for presence, flags in itertools.product((0, 2, 8, 128, 138), (0, 2, 4, 6)):
        case('stats_routes_sent', track_sent_routes, presence, flags)
    for confirmed_call, need, can_send in itertools.product((False, True), (False, True), (False, True)):
        case('connectivity_transition', connectivity_transition, confirmed_call, need, can_send)
    for state, e2e in itertools.product((-2, -1, 0, 1, 2, 3, 4, 5, 6), (False, True)):
        case('stats_sequence_dispatch', stats_sequence_dispatch, state, e2e)
    case('stats_sequence_dispatch', stats_sequence_dispatch, 1, True, auth_context=True)
    for relay_result, e2e_result in itertools.product((-1, 0, 101), (-1, 0, 201)):
        case('stats_sequence_dispatch', stats_sequence_dispatch, 3, True, relay_result, e2e_result)
    for gap, relay_gap, delayed, outcome in [
        (2, 2, False, 0), (3, 3, False, 0), (4, 4, False, 0),
        (2, 1, False, 0), (2, 1, False, 1), (2, 1, False, 2), (2, 1, False, 3),
        (1, 1, True, 0), (1, 1, True, 1), (-1, -1, False, 0),
    ]:
        case('stats_sequence_dispatch', stats_sequence_dispatch, 3, True,
             gap=gap, relay_gap=relay_gap, delayed=delayed, reorder_result=outcome)
    for need, active in itertools.product((False, True), (False, True)):
        case('outer_active_connectivity', outer_active_cleanup, need, active)
    for pending, redelivered, window in itertools.product((None, -1, 0, 1, 2, 3), (False, True), (0, 1000)):
        case('out_of_order_handling', out_of_order, pending, redelivered, window)
    for old, incoming in [(0, -1), (20, -1), (0, 0), (20, 20), (20, 4999), (20, 5000),
                             (5000, 5000), (5000, 5001), (0, 0x7fffffff), (0, -0x80000000)]:
        case('cluster_penalty_updates', cluster_penalty, old, incoming)
    for reason, instant_age, lifetime_age, rx_count, sent in itertools.product(
            (False, True), (19999999, 20000000, 29999999, 30000000, 140000000),
            (119999999, 120000000, 139999999, 140000000), (0, 101), (0, 101)):
        case('linkstats_scheduling', statistics_schedule, instant_age, lifetime_age,
             rx_count, sent, reason=reason)
    for reason, activity, flight in itertools.product((False, True), (0, 1, 2), (False, True)):
        case('linkstats_scheduling', statistics_schedule, 30000000, 140000000, 101, 101,
             activity=activity, in_flight=flight, reason=reason, reply_delta=1000)
    for smoothed, samples, delayed, pending in itertools.product(
            (-1, 0, 20, 600), ([], [20], [20, 40, 30]), (False, True), (False, True)):
        case('reply_deadlines', reply_deadline, smoothed, samples, delayed, pending)
    for kind, latest, delta, seen, cross in itertools.product(('e2e', 'relay'), (65535, 65536+127),
            (1, 0, -1, -64, -127, -128, 32767, 32768), (False, True), (False, True)):
        case('sequence_windows', sequence_window, latest, latest+delta, seen, cross, kind)
    for ages in ([], [0], [63, 64, 65], [4194303, 4194304], [-1]):
        case('packed_ack_encoding', packed_ack_encoding, ages)
    for elapsed, delay, matching in itertools.product((None, 'invalid', -1, 0, 1, 999, 1000, 3000000, 3001000),
                                                     (0, 32, 65535), (False, True)):
        case('packed_ack_receiving', receive_packed_ack, elapsed, delay, matching)
    case('packed_ack_receiving', receive_packed_ack, 50000, 0, override=100)
    for activity, delta, failures in itertools.product((0, 1, 2), (None, -1, 0, 1), (0, 2)):
        case('relay_stats_timeouts', relay_stats_timeout, activity, delta, failures)
    for age in (4999999, 5000000, 5000001):
        case('relay_stats_timeouts', relay_stats_timeout, 0, None, interval_age=age)
    for age, queued, force, statistics in itertools.product((249999, 250000), (0, 1, 4, 5), (False, True), (False, True)):
        case('relay_ack_scheduling', relay_ack_schedule, age, queued, force, statistics)
    for primary, current, force, scheduled, snp_ok, socket_ok in itertools.product((False, True), repeat=6):
        case('stats_send_paths', send_stats_path, 3, primary, current, force, 0, False,
             scheduled, snp_ok, socket_ok)
    for state, flags, quality, snp_ok in itertools.product((1, 2, 3), (0, 2), (False, True), (False, True)):
        case('stats_send_paths', send_stats_path, state, False, False, False, flags, quality,
             False, snp_ok, True)
    for expected, params in [
        (0, {}), (0, {'relay_age': 5000000}), (0, {'relay_age': 5000001}),
        (1, {'relay_age': 5000001, 'queued': 1}), (0, {'relay_age': 7000000}),
        (1, {'relay_age': 7000001}), (2, {'mode': 1, 'e2e_age': 7000001}),
        (3, {'mode': 1, 'relay_age': 7000001, 'e2e_age': 7000001}),
        (1, {'request': 2, 'mode': 1}), (3, {'request': 2, 'mode': 2}),
        (5, {'request': 3}), (5, {'request': 3, 'mode': 1}), (7, {'request': 3, 'mode': 2}),
        (0, {'relay_fail': 1, 'immediate_age': 199999}),
        (5, {'relay_fail': 1, 'immediate_age': 200000}),
        (7, {'mode': 1, 'e2e_fail': 1, 'immediate_age': 200000}),
        (0, {'e2e_fail': 1, 'immediate_age': 200000}),
        (0, {'relay_recv_age': 10000000}),
        (1, {'relay_recv_age': 10000000, 'pending': True}),
        (0, {'relay_recv_age': 59999999, 'pending': True, 'activity': 1}),
        (1, {'relay_recv_age': 60000000, 'pending': True, 'activity': 1}),
        (0, {'relay_recv_age': 60000000, 'pending': True, 'activity': 2}),
        (0, {'instant_age': 20000000}), (0, {'instant_age': 30000000}),
        (0, {'mode': 1, 'instant_age': 30000000, 'e2e_instant_age': 30000000}),
    ]:
        case('generic_stats_production', generic_stats_producer, expected, **params)
    for packets, since in itertools.product((0,100,101,102), (False,True)):
        case('primary_switch_report',primary_switch_report,packets,since)
    for field in ('ip','port','pop'):
        case('primary_switch_report',primary_switch_report,101,True,**{field:False})
    for removed, seed, reason in itertools.product(range(3),(False,True),
            (b'',b'received_nosession',b'consecutive_ping_timeout',b'x'*80)):
        case('primary_loss_history',primary_loss_history,removed,reason,seed)
    for ages,root_age in itertools.product(((0,),(59999999,),(60000000,),(60000001,),
            (60000001,0,60000002),(60000001,60000002,60000003)),(0,90000000)):
        case('session_idle_expiry',session_idle_expiry,ages,root_age)
    for reason, lost_age, metrics_gap in itertools.product((b'',b'received_nosession'),
            (None,0,999,1000,1234567),(0,999,2000000)):
        case('primary_switch_report',primary_switch_report,101,True,
             dropped_reason=reason,lost_age=lost_age,metrics_gap=metrics_gap)
    case('clean_route_targets', clean_routes, [b'a', b'b'], [0, 1], [0, 1], targets=[1, 0])
    case('clean_route_targets', clean_routes, [b'a', b'b'], [0, 1], [1], targets=[None, 0])
    for sequences, incoming in [([], 1000), ([1000, 1001, 1002], 1001),
                                 ([1000, 1001, 1002], 999), ([1000, 1001, 1002], 1003),
                                 ([65535, 0, 1], 0), ([0], 16384), ([0], 16385),
                                 ([16384], 0), ([16385], 0), ([32768], 0)]:
        case('expected_ack_removal', expected_ack_removal, sequences, incoming)
    for old, expected_reverse in [(None, (40, 0, 0, 0)),
                                   ((90, 42, 17, 0), (40, 42, 17, 0)),
                                   ((90, 42, 17, NOW-1), (90, 42, 17, NOW-1))]:
        case('reverse_latency_estimation', receive_latencies, {}, [(200, 40)], [], [], 1,
             {200: (40, 0, 0, NOW)}, True, reverse={200: (old, expected_reverse)})
    traces = [
        ([(101, 201), (102, 202)], [0, 1], (102, 202, 0, 0, 0)),
        ([(102, 202), (101, 201)], [0, 1], (102, 202, 0, 1, 0)),
        ([(102, 202), (102, 202)], [0], (102, 202, 1, 0, 0)),
        ([(101, 201), (102, 201), (102, 202)], [0, 2], (102, 202, 0, 0, 0)),
        ([(101, 201), (101, 202), (102, 202)], [0, 2], (102, 202, 0, 0, 0)),
        ([(199, 299), (298, 398)], [0, 1], (298, 398, 196, 0, 0)),
        ([(200, 300), (201, 301), (199, 299)], [0, 1], (201, 301, 0, 0, 1)),
        ([(101+n, 201+n) for n in range(7)], list(range(7)), (107, 207, 0, 0, 0)),
    ]
    for packets, delivered, expected in traces:
        for flags in (0, 3, 7):
            case('native_receive_sequence_chain', receive_sequence_chain, packets, delivered, expected, flags=flags)
    case('native_receive_sequence_chain', receive_sequence_chain,
         [(65535, 65535), (65536, 65536), (65537, 65537)], [0, 1, 2],
         (65537, 65537, 0, 0, 0), initial=(65534, 65534), flags=3)
    for relay_quality, e2e_quality in itertools.product((False, True), (False, True)):
        case('native_receive_sequence_chain', receive_sequence_chain,
             [(101, 201), (102, 202)], [0, 1], (102, 202, 0, 0, 0),
             relay_quality=relay_quality, e2e_quality=e2e_quality)
    for elapsed, delay in itertools.product((None, 'invalid', 1000, 150000, 3000001), (0, 10, 65535)):
        case('relay_ack_root_feedback', receive_packed_ack, elapsed, delay, native_root=True)
    for session_pending, root_pending, delayed, ping in itertools.product(
            (None, 20000), (None, -1, 0, 50000), (False, True), (-1, 20, 700)):
        case('relay_request_clocks', relay_request_clocks, session_pending, root_pending, delayed, ping)
    for request, params in [
        (0, {}), (3, {'quota': 1}), (3, {'need': True}), (3, {'failures': 1}),
        (3, {'smoothed': -1}), (3, {'samples': 2}), (3, {'total': 9}),
        (0, {'samples': 3, 'total': 10}),
        (0, {'selected': 'other', 'probe_age': 9999999}),
        (2, {'selected': 'other', 'probe_age': 10000000}),
        (0, {'selected': 'other', 'selected_need': True}),
        (3, {'selected': 'other', 'selected_need': True, 'samples': 2}),
        (0, {'pending_delta': 1, 'need': True}),
        (3, {'pending_delta': 0}), (3, {'pending_delta': -1}),
        (3, {'pending_delta': 0, 'failures': 2}),
        (3, {'pending_delta': 0, 'failures': 2, 'need': True}),
        (3, {'need': True, 'sends': False}), (0, {'need': True, 'can_send': False}),
    ]:
        case('p2p_confirmation_thinker', p2p_confirmation_think, request, **params)
    for state in (-2, -1, 0, 1, 2, 3, 4, 5):
        case('p2p_confirmation_thinker', p2p_confirmation_think,
             3 if state in (-2, 2, 3) else 0, state=state, need=True)
    for pending, delayed, quota in itertools.product((False, True), (False, True), (0, 1, 5)):
        case('p2p_probe_request_tracking', p2p_track_request, pending, delayed, quota)
    for events, params in [
        ([('stats', 2)], {}), ([('stats', 2)], {'deadline_delta': 0}),
        ([], {'deadline_delta': 1}), ([], {'acked': True}),
        ([('stats', 1)], {'acked': True, 'pending_ack': True}),
        ([('stats', 2), ('signal',)], {'stats_ok': False}),
        ([('signal',)], {'state': 2}), ([('signal',)], {'active': False}),
        ([('diagnostic',), ('signal',)], {'token': False}),
        ([('stats', 2), ('signal',)], {'relay_age': 10000000}),
        ([('stats', 2)], {'relay_age': 9999999}),
        ([('stats', 2), ('signal',)], {'e2e_age': 10000000}),
        ([('stats', 2), ('signal',)], {'relay_fail': 1}),
        ([('stats', 2), ('signal',)], {'e2e_fail': 1}),
        ([('stats', 3)], {'acked': True, 'need': True}),
        ([('stats', 3), ('diagnostic',)], {'acked': True, 'need': True, 'stats_ok': False}),
        ([('stats', 3), ('signal',)], {'need': True}),
        ([], {'acked': True, 'need': True, 'reply_pending': True, 'immediate_age': 199999}),
        ([('stats', 3)], {'acked': True, 'need': True, 'reply_pending': True, 'immediate_age': 200000}),
        ([('stats', 3), ('signal',), ('stats', 3), ('diagnostic',)], {'need': True, 'stats_ok': False}),
    ]:
        case('outer_routes_delivery', outer_routes_delivery, events, **params)
    for ok, force, request in itertools.product((False, True), (False, True), (0, 2, 3)):
        case('native_stats_send_chain', native_stats_send_chain, ok, force=force, request=request)
    for ok, token, instantaneous in itertools.product((False, True), (b'', b'new-target'), (False, True)):
        case('native_stats_send_chain', native_stats_send_chain, ok, desired=token,
             instantaneous=instantaneous)
    case('native_stats_send_chain', native_stats_send_chain, True, routes_due=False, queued=0)
    for need, active, smoothed in itertools.product((False, True), (False, True), (-1, 20)):
        case('valid_end_to_end_recovery', valid_end_to_end, need, active, smoothed)
    for override, can_send, future in itertools.product((-1, 123), (False, True), (False, True)):
        case('valid_end_to_end_recovery', valid_end_to_end, True, True, -1, override, can_send, future)
    for need, selected, quota in itertools.product((False, True), (False, True), (0, 5, 8)):
        case('connectivity_change_callback', connectivity_change_callback, need, selected, quota)
    for state, recorded, age in itertools.product((1, 4), (False, True), (1, 1500)):
        case('connectivity_change_callback', connectivity_change_callback, False, True, 0,
             wire_state=state, recorded=recorded, age=age)
    for ok, deadline, pending_ack, due in itertools.product((False, True), (-1, 0, 1), (False, True), (False, True)):
        case('native_outer_stats_signal_chain', native_stats_send_chain, ok, outer=True,
             deadline_delta=deadline, pending_ack=pending_ack, routes_due=due)
    for ok, instantaneous in itertools.product((False, True), (False, True)):
        case('native_inline_stats_send_chain', native_stats_send_chain, ok, inline=True,
             force=True, instantaneous=instantaneous)
    for room, masks, encoded in [(48, (3, 3), True), (47, (2, 3), True),
                                  (41, (None, 3), True), (31, (None, 2), True),
                                  (25, (None, None), True), (13, (None, None), False)]:
        case('inline_stats_budget', inline_stats_budget, 3, 3, room, masks, encoded)
    for relay, e2e, room, masks, encoded in [
        (1, None, 17, (None, None), True), (1, None, 13, (None, None), False),
        (2, 2, 35, (None, 2), True), (None, 3, 29, (None, 2), True),
        (None, None, 14, (None, None), True), (None, None, 13, (None, None), False),
    ]:
        case('inline_stats_budget', inline_stats_budget, relay, e2e, room, masks, encoded)
    for body, room, encoded in [(127, 129, True), (127, 128, False), (128, 131, True), (128, 130, False)]:
        case('inline_stats_budget', inline_stats_budget, None, None, room, (None, None), encoded, body_base=body, flags=0)
    for ok, payload in itertools.product((False, True), (1189, 1190, 1291)):
        case('native_inline_stats_send_chain', native_stats_send_chain, ok, inline=True,
             force=True, payload_size=payload)
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
    unknown = set(args.group or ())-set(counts)
    if unknown:
        parser.error('unknown audit group(s): '+', '.join(sorted(unknown)))
    report = {'sample_sha256': policy.descriptors.SAMPLE_SHA256,
              'method': 'offline original SDR client instructions with explicit external stubs',
              'selection': args.group or 'all',
              'network_interoperability': False, 'passed': sum(counts.values()), 'groups': counts}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
