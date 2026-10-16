#!/usr/bin/env python3
"""Offline branch audit of the pinned Steam Link AArch64 ELF using Unicorn.

Executes original instructions with synthetic objects. External calls are explicit
stubs; unknown control flow fails closed. This is NOT a network interoperability
test and does not test the mocked crypto, containers, or SDK implementations.
Requires google.protobuf, unicorn, and cryptography. No captured data is used.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as arm
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

spec = importlib.util.spec_from_file_location(
    'steam_remote_descriptors', Path(__file__).with_name('steam-remote-descriptors.py'))
descriptors = importlib.util.module_from_spec(spec)
spec.loader.exec_module(descriptors)

HEAP = 0x10000000
STACK = 0x20000000
TLS = 0x30000000
RETURN = 0x40000000
UPDATE_METRICS = RETURN + 0x100
BACKEND_UPDATE = RETURN + 0x300
POP_SIGNAL = RETURN + 0x400
WANTS_CLOUD = RETURN + 0x500
KEY_VALID = RETURN + 0x600
KEY_RAW = RETURN + 0x700
QUERY_STATE = RETURN + 0x800
NOTIFY_DISCONNECT = RETURN + 0x900
UTIL_TIME = RETURN + 0xa00
CONNECTION_INFO = RETURN + 0xb00
QUICK_STATUS = RETURN + 0xc00
SDK_CLOSE = RETURN + 0xd00
SDK_SEND = RETURN + 0xe00
RELIABLE_DELIVER = RETURN + 0xf00
NOW = 100000000


class Machine:
    def __init__(self, elf):
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        end = max(p[3]+p[6] for p in elf.segments if p[0] == 1)
        self.uc.mem_map(0, (end+4095) & ~4095)
        for kind, _, offset, va, _, size, _, _ in elf.segments:
            if kind == 1:
                self.uc.mem_write(va, elf.raw[offset:offset+size])
        for target, value in elf.relative.items():
            self.write(target, value, 8)
        self.uc.mem_map(HEAP, 0x200000)
        self.uc.mem_map(STACK, 0x100000)
        self.uc.mem_map(TLS, 4096)
        self.uc.mem_map(RETURN, 4096)
        self.uc.reg_write(arm.UC_ARM64_REG_SP, STACK+0xf0000)
        self.uc.reg_write(arm.UC_ARM64_REG_TPIDR_EL0, TLS)
        self.uc.reg_write(arm.UC_ARM64_REG_LR, RETURN)
        self.write(TLS+40, 0x12345678, 8)
        self.cursor = HEAP
        self.events = []
        self.stubs = {}
        self.redirects = {}
        self.allowed = []
        self.stops = {}
        self.visited = set()
        self.done = False
        self.empty = self.alloc(24)
        self.stubs[0xc09f90] = lambda m: None  # Log
        self.stubs[0xc118a0] = lambda m: None  # SDK diagnostic output
        self.stubs[0xc0dd40] = lambda m: m.reg(0, m.empty)  # NameOfEnum
        self.uc.hook_add(UC_HOOK_CODE, self.hook)

    def alloc(self, size):
        result = self.cursor
        self.cursor += (size+15) & ~15
        if self.cursor >= HEAP+0x200000:
            raise ValueError('synthetic heap exhausted')
        return result

    def reg(self, index, value=None):
        name = getattr(arm, 'UC_ARM64_REG_X'+str(index))
        if value is None:
            return self.uc.reg_read(name)
        self.uc.reg_write(name, value & 0xffffffffffffffff)

    def read(self, address, size=4):
        return int.from_bytes(self.uc.mem_read(address, size), 'little')

    def write(self, address, value, size=4):
        self.uc.mem_write(address, (value % (1 << (size*8))).to_bytes(size, 'little'))

    def string(self, value):
        obj = self.alloc(24)
        self.set_string(obj, value)
        return obj

    def set_string(self, obj, value):
        if len(value) <= 22:
            self.uc.mem_write(obj, bytes([len(value)*2])+value+b'\0')
        else:
            pointer = self.alloc(len(value)+1)
            self.uc.mem_write(pointer, value+b'\0')
            self.uc.mem_write(obj, struct.pack('<QQQ', ((len(value)+8) & ~7) | 1,
                                               len(value), pointer))

    def get_string(self, obj):
        if self.read(obj, 1) & 1:
            return bytes(self.uc.mem_read(self.read(obj+16, 8), self.read(obj+8, 8)))
        return bytes(self.uc.mem_read(obj+1, self.read(obj, 1) >> 1))

    def hook(self, uc, pc, size, user):
        self.visited.add(pc)
        if pc == RETURN:
            self.done = True
            uc.emu_stop()
        elif pc in self.stops:
            self.events.append(self.stops[pc])
            self.done = True
            uc.emu_stop()
        elif pc in self.stubs:
            self.stubs[pc](self)
            uc.reg_write(arm.UC_ARM64_REG_PC, uc.reg_read(arm.UC_ARM64_REG_LR))
        elif pc in self.redirects:
            uc.reg_write(arm.UC_ARM64_REG_PC, self.redirects[pc])
        elif not any(start <= pc < end for start, end in self.allowed):
            raise ValueError('unmodeled call/control flow at '+hex(pc))

    def run(self, start, end, *args, budget=20000):
        self.done = False
        self.allowed.append((start, end))
        for index, value in enumerate(args):
            self.reg(index, value)
        self.uc.emu_start(start, RETURN+4, count=budget)
        if not self.done:
            raise ValueError('instruction budget exhausted')

    def buffers(self):
        def ensure(m):
            obj, count = m.reg(0), m.reg(1)
            if m.read(obj+8) < count:
                old = m.read(obj, 8)
                fresh = m.alloc(max(count, 512))
                if old:
                    m.uc.mem_write(fresh, bytes(m.uc.mem_read(old, m.read(obj+20))))
                m.write(obj, fresh, 8)
                m.write(obj+8, max(count, 512))

        def put(m):
            obj, source, count = m.reg(0), m.reg(1), m.reg(2)
            position = m.read(obj+20)
            m.reg(1, position+count+1)
            ensure(m)
            m.uc.mem_write(m.read(obj, 8)+position, bytes(m.uc.mem_read(source, count)))
            m.write(obj+20, position+count)

        self.stubs.update({
            0xc0a290: lambda m: m.uc.mem_write(m.reg(0), bytes(48)),
            0xc0a200: ensure,
            0xc0a210: put,
            0xc0a120: lambda m: None,
            0xc09990: lambda m: None,
            0xbff250: lambda m: None,
            0xbff420: lambda m: m.reg(0, m.alloc(m.reg(0))),
            0xbff3d0: lambda m: m.uc.mem_write(m.reg(0), bytes(m.uc.mem_read(m.reg(1), m.reg(2)))),
        })


def common_manager(m, state=5, request_id=123):
    manager, address = m.alloc(8192), m.alloc(32)
    m.write(manager+8, state)
    m.write(manager+512, request_id)
    m.write(manager+496, 0x1234, 8)
    m.stubs[0xc0da90] = lambda m: m.events.append(('stop', m.reg(1)))
    return manager, address


def streaming(elf, result, expected, old=False, decode=True, zero=False):
    m = Machine(elf)
    manager, address = common_manager(m)
    msg = m.alloc(80)
    m.write(msg+48, 0 if zero else 122 if old else 123)
    m.write(msg+52, result)
    for off in (24, 32, 40):
        m.write(msg+off, m.empty, 8)
    record, entries = m.alloc(40), m.alloc(24)
    m.write(entries+8, record, 8)
    m.write(manager+1152, entries, 8)
    m.stubs.update({
        0xc022d0: lambda m: m.reg(0, 0),
        0xc09c30: lambda m: None,
        0xc0d8b0: lambda m: None,
        0xc0d950: lambda m: m.reg(0, 0),
        0xc0dba0: lambda m: m.reg(0, 0),
        0xc0dca0: lambda m: m.reg(0, int(decode)),
        0xc0da50: lambda m: m.events.append(('authorize',)),
        0xc02260: lambda m: m.uc.mem_write(m.reg(0), bytes(32)),
        0xc02620: lambda m: None,
        0xc0dae0: lambda m: m.events.append(('cancel', m.reg(1), m.read(m.reg(2)+24))),
    })
    m.run(0x79e828, 0x79eb40, manager, address, 0x1234, msg)
    if expected == 'ready':
        assert m.read(manager+8) == 6 and not m.events
    else:
        assert m.events == expected, (result, old, zero, m.events, expected)


def authorization(elf, state, result, auth_key, expected, foreign=False, exchange_ok=True):
    m = Machine(elf)
    manager, address = common_manager(m, state)
    msg = m.alloc(64)
    # Container contents and key-exchange result are synthetic external inputs.
    m.write(msg+16, int(auth_key))
    m.write(msg+24, m.string(b'synthetic-auth-key'), 8)
    m.write(msg+48, result)
    record, entries = m.alloc(40), m.alloc(24)
    m.write(entries+8, record, 8)
    m.write(manager+1152, entries, 8)
    m.buffers()
    m.stubs[0xc022b0] = lambda m: m.reg(0, 0)
    m.stubs[0xc0d8b0] = lambda m: None
    m.stubs[0xc0d950] = lambda m: m.reg(0, 0)
    m.stubs[0xc0d4f0] = lambda m: m.reg(0, 0xffffffff)
    m.stubs[0xc0dab0] = lambda m: m.events.append(('save_legacy_secret',))
    m.stubs[0xc021f0] = lambda m: m.uc.mem_write(m.reg(0), bytes(40))
    m.stubs[0xc02500] = lambda m: None
    m.stubs[0xc0dae0] = lambda m: m.events.append(('confirmation', m.read(m.reg(2)+24)))
    m.stubs[0xc0da40] = lambda m: m.events.append(('stream_request',))

    def exchange(m):
        m.events.append(('key_exchange',))
        m.write(m.reg(4), 0)
        m.reg(0, int(exchange_ok))

    m.stubs[0xc0dd30] = exchange
    m.run(0x79d680, 0x79dbfc, manager, address, 0x5678 if foreign else 0x1234, msg)
    assert m.events == expected, (state, result, auth_key, foreign, m.events, expected)
    if expected and expected[-1] == ('stream_request',):
        assert m.read(manager+8) == 5


def authorization_cache(elf, same, attempts, cached_result=0, different_length=False):
    m = Machine(elf)
    manager, _ = common_manager(m, 3)
    previous = b'previous-auth-key'
    incoming = previous if same else b'different-key' if different_length else b'changed-auth-key!'
    assert (incoming == previous) == same
    cache, msg, result = m.alloc(64), m.alloc(64), m.alloc(4)
    m.uc.mem_write(cache, previous)
    m.write(manager+720, attempts)
    m.write(manager+728, cache, 8)
    m.write(manager+748, len(previous))
    m.write(manager+792, cached_result)
    m.write(msg+24, m.string(incoming), 8)
    m.write(result, 0xdeadbeef)

    def compare(m):
        left = bytes(m.uc.mem_read(m.reg(0), m.reg(2)))
        right = bytes(m.uc.mem_read(m.reg(1), m.reg(2)))
        m.reg(0, 0 if left == right else 1 if left > right else -1)

    m.stubs[0xc0a110] = compare
    # The cache/attempt guard is executed; fresh cryptographic exchange is not.
    m.stops[0x79dcb0] = ('fresh_exchange',)
    m.run(0x79dbfc, 0x79df80, manager, 0x1234, 0x5678, msg, result)
    assert m.read(manager+720) == attempts+int(not same)
    if same:
        assert not m.events and m.read(result) == cached_result and m.reg(0) == 0
    elif attempts < 3:
        assert m.events == [('fresh_exchange',)] and m.read(result) == 0xdeadbeef
    else:
        assert m.events == [('stop', 2)] and m.read(result) == 1 and m.reg(0) == 0


def proof(elf, update, already=False, request_id=123, has_id=True, foreign=False,
          encrypt_ok=True):
    m = Machine(elf)
    manager, address = common_manager(m)
    msg = m.alloc(48)
    secret, challenge = bytes(range(32)), b'synthetic-challenge'
    keyptr = m.alloc(64)
    m.uc.mem_write(keyptr, secret)
    m.write(manager+536, keyptr, 8)
    m.write(manager+544, 64)
    m.write(manager+556, 32)
    m.write(manager+528, int(already), 1)
    m.write(msg+16, 2 if has_id else 0)
    m.write(msg+24, m.string(challenge), 8)
    m.write(msg+32, request_id)
    m.write(msg+36, int(update), 1)
    m.buffers()

    def constructor(m):
        obj = m.reg(0)
        m.uc.mem_write(obj, bytes(48))
        m.write(obj+24, m.string(b''), 8)

    def sha(m):
        raw = bytes(m.uc.mem_read(m.reg(0), m.reg(1)))
        assert raw == secret+challenge
        m.events.append(('hash',))
        m.uc.mem_write(m.reg(2), hashlib.sha256(raw).digest())

    def persist(m):
        buf = m.reg(3)
        stored = bytes(m.uc.mem_read(m.read(buf, 8), m.read(buf+20)))
        assert stored == hashlib.sha256(secret+challenge).digest()
        m.events.append(('persist',))

    def encrypt(m):
        assert bytes(m.uc.mem_read(m.reg(0), m.reg(1))) == challenge
        expected = hashlib.sha256(secret+challenge).digest() if update and not already else secret
        assert bytes(m.uc.mem_read(m.reg(4), m.reg(5))) == expected
        m.events.append(('encrypt',))
        m.uc.mem_write(m.reg(2), b'fake-enc')
        m.write(m.reg(3), 8)
        m.reg(0, int(encrypt_ok))

    def send(m):
        obj = m.reg(2)
        assert m.reg(1) == 8
        m.events.append(('send', m.read(obj+16), m.read(obj+32), m.read(obj+36, 1),
                         len(m.get_string(m.read(obj+24, 8)))))

    m.stubs.update({
        0xc02240: constructor,
        0xc026d0: lambda m: None,
        0xc0dd60: lambda m: m.write(m.reg(0)+16, 1),
        0xc09830: sha,
        0xc0dab0: persist,
        0xc097b0: lambda m: m.reg(0, 64),
        0xc09950: encrypt,
        0xc0dae0: send,
    })
    m.run(0x79e1c0, 0x79e614, manager, address, 0x5678 if foreign else 0x1234, msg)
    if foreign:
        expected = [('send', 1, 0, 0, 0)]
    elif has_id and request_id != 123:
        expected = []
    else:
        expected = [('hash',), ('persist',)] if update and not already else []
        expected += [('encrypt',)]
        if encrypt_ok:
            expected += [('send', 7, 123, int(update), 8)]
    assert m.events == expected, (update, already, request_id, foreign, m.events, expected)


def transport(elf, *, best=20, current=50, best_max=20, current_min=50, buckets=15,
              sticky=True, controlling=True, nominated=True, current_exists=True,
              need_confirm=False, count=2, age=2000000, expected_switch=True):
    m = Machine(elf)
    connection = m.alloc(8192)
    candidates = [m.alloc(640), m.alloc(640)]
    old, new = candidates
    vt = m.alloc(64)
    m.write(vt, UPDATE_METRICS, 8)
    m.write(connection+6848, 3)
    m.write(connection+6856, NOW-age, 8)
    m.write(connection+7240, count, 8)
    m.write(connection+7264, new if count == 1 else old, 8)
    m.write(connection+7272, new, 8)
    m.write(connection+7288, old if current_exists else 0, 8)
    m.write(connection+7296, new if nominated else 0, 8)
    m.write(connection+7320, int(sticky), 1)
    m.write(connection+344, int(controlling), 1)
    for obj, score, minimum, maximum in [(old, current, current_min, current),
                                        (new, best, best, best_max)]:
        m.write(obj, vt, 8)
        m.write(obj+560, score)
        m.write(obj+564, minimum)
        m.write(obj+568, maximum)
        m.write(obj+576, buckets)
        m.write(obj+528, NOW+10000, 8)  # outstanding probe avoids fake network calls
        m.write(obj+592, NOW+10000, 8)
    m.write(new+24, int(need_confirm), 1)

    def select(m):
        m.events.append(('select', m.reg(1)))
        m.write(connection+7288, m.reg(1), 8)

    m.stubs.update({UPDATE_METRICS: lambda m: None,
                    0xc13f80: select,
                    0xc11df0: lambda m: None,
                    0xc13340: lambda m: None})
    m.run(0x8755a4, 0x875c08, connection, NOW)
    assert (m.read(connection+7288, 8) == new) == expected_switch, m.events


def relay_penalty(elf, seconds, gap=0, failures=0, alternate=0):
    m = Machine(elf)
    base, relay, metrics, alt = [m.alloc(1024) for _ in range(4)]
    m.write(base+68, -1)
    m.write(relay+760, relay, 8)
    m.write(relay+800, seconds)
    m.write(relay+256, failures)
    m.write(relay+248, NOW-gap, 8)
    if alternate:
        m.write(relay+792, alt, 8)
        m.write(alt+28, alternate)
    m.stubs[0xc125e0] = lambda m: m.reg(0, 1)
    m.run(0x81c3f0, 0x81c55c, base, relay, metrics, NOW)
    if alternate > 8190:
        assert m.reg(0) == 0
    else:
        expected = 1000 if seconds <= 0 else (30-seconds)*1000//30 if seconds < 30 else 0
        expected += alternate + (100 if failures and gap >= 1750001 else 0)
        assert m.read(metrics+48) == expected, (seconds, gap, m.read(metrics+48), expected)
        assert m.read(metrics+64, 8) == (gap if failures and gap >= 500001 else 0)


def packet_length(elf, length, valid):
    m = Machine(elf)
    m.reg(8, length)
    m.stops = {0x8163a0: ('accept',), 0x816350: ('reject',)}
    m.run(0x816344, 0x816350)
    assert m.events == [('accept' if valid else 'reject',)], (length, m.events)


def relay_data(elf, gap=16000, same_previous=True, counter=0x12345):
    m = Machine(elf)
    transport, conn, session, relay, ctx = [m.alloc(8192) for _ in range(5)]
    payload = bytes(range(32))  # Already-encrypted synthetic data, no crypto claim.
    data = m.alloc(len(payload))
    m.uc.mem_write(data, payload)
    m.write(transport+8, conn, 8)
    m.write(ctx, NOW, 8)
    m.write(ctx+160, session, 8)
    m.write(session, relay, 8)
    m.write(conn+2528, counter, 8)
    m.write(session+2248, 0x23456, 8)
    m.write(conn+384, 0x11223344)
    m.write(conn+2584, NOW-gap, 8)
    m.write(session+2304, NOW-gap if same_previous else NOW-gap-1, 8)
    m.write(conn+4832, 1)
    m.write(conn+4836, 1)
    m.stubs[0xc12d90] = lambda m: None  # Inline stats absent in these cases.

    def gather(m):
        assert (m.reg(0), m.reg(1), m.reg(4)) == (relay, 2, session)
        iov = m.reg(2)
        packet = b''.join(bytes(m.uc.mem_read(m.read(iov+i*16, 8), m.read(iov+i*16+8, 8)))
                          for i in range(2))
        timestamp = same_previous and 0 <= gap <= 250000
        expected = struct.pack('<BHHI', 0xa2 if timestamp else 0xa0,
                               counter & 65535, 0x3456, 0x11223344)
        if timestamp:
            expected += struct.pack('<H', gap >> 4)
        expected += payload
        assert packet == expected, (gap, same_previous, packet.hex(), expected.hex())
        assert m.reg(3) == len(packet)
        m.events.append(('gather', len(packet)))
        m.reg(0, 1)

    m.stubs[0xc12380] = gather
    m.run(0x83ed9c, 0x83f0a8, transport, data, len(payload), ctx)
    assert m.events and m.reg(0) == m.events[0][1]
    assert m.read(conn+2528, 8) == counter+1
    assert m.read(session+2248, 8) == 0x23457


def relay_ping(elf, age=5000000, ping=-1, pending=0):
    m = Machine(elf)
    relay, cluster, config, logging = [m.alloc(1024) for _ in range(4)]
    cookie, ip, port, version = 0xa1b2c3d4, 0x0a010203, 27031, 0x33445566
    m.write(relay+32, cluster, 8)
    m.write(relay+760, relay, 8)
    m.write(relay+104, cookie)
    m.write(relay+8, ip)
    m.write(relay+28, 3, 2)
    m.write(relay+30, port, 2)
    m.write(relay+136, pending, 8)
    m.write(cluster+76, ping)
    m.write(cluster+768, NOW-age, 8)
    # These are fixed-sample GOT data references, not SDK API constants.
    m.write(0xc80000+2816, config, 8)
    m.write(config, version)
    m.write(0xc80000+2880, logging, 8)
    m.stubs[0xc09980] = lambda m: m.uc.mem_write(m.reg(0), bytes([m.reg(1) & 255])*m.reg(2))
    m.stubs[0xc123c0] = lambda m: m.reg(0, ping)

    def gather(m):
        iov = m.reg(2)
        packet = bytes(m.uc.mem_read(m.read(iov, 8), m.read(iov+8, 8)))
        short = age < 5000000
        expected = struct.pack('<BB6sIIIIIHHB', 1, 0x82 if short else 2, b'sdping',
                               NOW & 0xffffffff, cookie, 0, version,
                               ip ^ cookie, port ^ (cookie & 65535), 13, 0)
        expected += bytes((100 if short else 1300)-len(expected))
        assert packet == expected
        assert (m.reg(1), m.reg(3)) == (1, len(packet))
        m.events.append(('ping', len(packet)))
        m.reg(0, 1)

    m.stubs[0xc12380] = gather
    m.run(0x8176d8, 0x817a88, relay, NOW, m.empty+1, 5, 0, 0)
    timeout = 1250000 if ping < 0 else min(ping*2000, 1000000)+250000
    assert m.read(relay+136, 8) == (pending or NOW+timeout)
    assert m.events == [('ping', 100 if age < 5000000 else 1300)]


def bridge(elf, cloud_state, wants, queued, new_signal=False):
    m = Machine(elf)
    bridge, backend, session, vt = [m.alloc(256) for _ in range(4)]
    m.write(bridge+8, backend, 8)
    m.write(bridge+88, session, 8)
    m.write(bridge+100, 0 if queued else -1)
    m.write(session+24, cloud_state)
    m.write(backend, vt, 8)
    for offset, func in [(24, BACKEND_UPDATE), (32, POP_SIGNAL), (48, WANTS_CLOUD)]:
        m.write(vt+offset, func, 8)
    left = [int(new_signal)]

    def pop(m):
        m.reg(0, left[0])
        left[0] = 0

    def send(m):
        if cloud_state != 5:
            m.write(bridge+100, 0)

    m.stubs.update({
        BACKEND_UPDATE: lambda m: None,
        POP_SIGNAL: pop,
        WANTS_CLOUD: lambda m: m.reg(0, int(wants)),
        0xc04140: lambda m: None,
        0xc05aa0: lambda m: None,
        0xc10170: send,
        0xc0d420: lambda m: m.events.append(('update',)),
        0xc0d310: lambda m: m.events.append(('connect',)),
        0xc0d2f0: lambda m: m.events.append(('disconnect',)),
    })
    m.run(0x7d44fc, 0x7d4610, bridge)
    need = wants or queued or (new_signal and cloud_state != 5)
    if cloud_state in (0, 4):
        expected = [('connect',), ('update',)] if need else []
    else:
        expected = [('update',)] if need else [('disconnect',)]
    assert m.events == expected, (cloud_state, wants, queued, new_signal, m.events)


def pairing(elf, cloud_state, manager_state, cancel):
    m = Machine(elf)
    manager, _ = common_manager(m, manager_state)
    if cloud_state is not None:
        session = m.alloc(64)
        m.write(manager+24, session, 8)
        m.write(session+24, cloud_state)
    m.stubs[0xc0d3d0] = lambda m: m.events.append(('start_pairing',))
    m.stubs[0xc0d3f0] = lambda m: m.events.append(('cancel_pairing',))
    start, end = (0x79c540, 0x79c594) if cancel else (0x79c514, 0x79c540)
    m.run(start, end, manager)
    if cancel:
        expected = [('cancel_pairing',), ('stop', 0)] if cloud_state == 5 and manager_state in (2, 3) else []
    else:
        expected = [('start_pairing',)] if cloud_state == 5 else [('stop', 18)]
        assert m.read(manager+8) == 2  # Before the mocked StopStreaming body.
    assert m.events == expected, (cloud_state, manager_state, cancel, m.events)


def cloud_update(elf, state, underlying, expected, now=100.0, deadline=100.0):
    m = Machine(elf)
    session, request, delegate, vt, dvt = [m.alloc(256) for _ in range(5)]
    m.write(session, delegate, 8)
    m.write(session+24, state)
    m.uc.mem_write(session+28, struct.pack('<f', deadline))
    m.write(session+40, request, 8)
    m.write(session+72, request, 8)
    m.write(request, vt, 8)
    m.write(vt+16, QUERY_STATE, 8)
    m.write(delegate, dvt, 8)
    m.write(dvt+8, NOTIFY_DISCONNECT, 8)
    m.stubs[QUERY_STATE] = lambda m: m.reg(0, underlying)
    m.stubs[NOTIFY_DISCONNECT] = lambda m: m.events.append('notify_disconnected')
    m.stubs[0xc0d360] = lambda m: m.uc.reg_write(
        arm.UC_ARM64_REG_D0, int.from_bytes(struct.pack('<d', now), 'little'))
    for target, event in [(0xc0d2f0, 'disconnect'), (0xc0d310, 'connect'),
                          (0xc0d340, 'finish_resolving'), (0xc0d350, 'next_endpoint'),
                          (0xc0d380, 'create_session'), (0xc0d3b0, 'consume_packets')]:
        m.stubs[target] = lambda m, event=event: m.events.append(event)
    m.run(0x791bdc, 0x791d24, session)
    assert m.events == expected, (state, underlying, now, deadline, m.events, expected)


def manager_update(elf, state=1, now=100, next_round=200, extra=200, sent=3,
                   age=None, cloud_online=False, reentrant=False):
    m = Machine(elf)
    manager, _ = common_manager(m, state)
    m.write(manager+48, next_round, 8)
    m.write(manager+80, sent)
    m.write(manager+88, extra, 8)
    m.write(manager+520, 100, 8)
    m.write(manager+376, int(reentrant), 1)
    m.stubs[0xc0a5b0] = lambda m: m.reg(0, now)
    m.stubs[0xc0da20] = lambda m: m.events.append('discover')
    m.stubs[0xc0da40] = lambda m: m.events.append('stream_request')
    m.stubs[0xc0da50] = lambda m: m.events.append('authorize_request')

    def random(m):
        low, high = m.reg(0), m.reg(1)
        assert (low, high) in ((1, 5), (1, 3), (4, 7))
        m.reg(0, low)  # Controlled RNG provider; test scheduling, not RNG.

    m.stubs[0xc0da10] = random
    if age is not None:
        records = m.alloc(104)
        m.write(manager+144, records, 8)
        m.write(manager+168, 1)
        m.write(records+8, 0x1234, 8)
        m.write(records+40, now-age, 8)
        m.stubs[0xc0da30] = lambda m: m.reg(0, 0 if cloud_online else -1)
        m.stubs[0xc0d4f0] = lambda m: m.reg(0, 0)
        m.stubs[0xc0d910] = lambda m: m.events.append('remove_visible')

        def grow(m):
            m.write(m.reg(0), m.alloc(64), 8)
            m.write(m.reg(0)+8, 8)

        m.stubs[0xc0d6d0] = grow
        m.stubs[0xc09990] = lambda m: None
    m.run(0x79890c, 0x798d10, manager)
    expected = []
    active = state != 0 and not reentrant
    if active:
        if now >= next_round:
            expected.append('discover')
            assert m.read(manager+48, 8) == now+13
            assert m.read(manager+80) == 1 and m.read(manager+88, 8) == now+1
        elif sent <= 2 and now >= extra:
            expected.append('discover')
            assert m.read(manager+80) == sent+1 and m.read(manager+88, 8) == now+4
        if age is not None and not cloud_online and age >= 30:
            expected.append('remove_visible')
        if now >= 100 and state in (4, 5):
            expected.append('authorize_request' if state == 4 else 'stream_request')
    assert m.events == expected, (state, now, age, cloud_online, m.events, expected)
    assert m.read(manager+376, 1) == int(reentrant)


def sns_send(elf, state, handle, sdk_result, packet_flags=0):
    m = Machine(elf)
    transport, packet, header, data, sdk, vt = [m.alloc(256) for _ in range(6)]
    m.write(transport+20, state)
    m.write(transport+48, handle)
    m.write(transport+56, sdk, 8)
    m.write(sdk, vt, 8)
    m.write(vt+88, SDK_SEND, 8)
    m.write(packet+40, header, 8)
    m.write(packet+52, 32)
    m.write(packet+56, data, 8)
    m.write(header, packet_flags, 1)

    def send(m):
        assert tuple(m.reg(i) for i in range(6)) == (
            sdk, handle, data, 36 if packet_flags & 128 else 32, 0x15, 0)
        m.events.append('send')
        m.reg(0, sdk_result)

    m.stubs[SDK_SEND] = send
    m.run(0x800224, 0x8002c0, transport, packet)
    if not handle:
        expected = 3
    elif state < 2:
        expected = 1
    elif state == 3:
        expected = 4
    elif state != 2:
        expected = 3
    else:
        expected = 0 if sdk_result == 1 else 1 if sdk_result in (25, 41) else 3
    assert m.reg(0) == expected
    assert m.events == (['send'] if handle and state == 2 else [])


def sns_check(elf, state, handle=True, sns_state=3, info_ok=True, quick_ok=True,
              elapsed=1000000):
    m = Machine(elf)
    transport, sdk, utils, vt, uvt, tvt = [m.alloc(512) for _ in range(6)]
    m.write(transport, tvt, 8)
    m.write(tvt+120, 0x800f94, 8)  # Execute original SDR close, not a state-changing stub.
    m.allowed.append((0x800f94, 0x801084))
    m.write(transport+20, state)
    m.write(transport+48, int(handle))
    m.write(transport+56, sdk, 8)
    m.write(transport+64, utils, 8)
    m.write(transport+264, NOW-elapsed, 8)
    m.write(sdk, vt, 8)
    m.write(utils, uvt, 8)
    m.write(uvt+96, UTIL_TIME, 8)
    m.write(vt+120, CONNECTION_INFO, 8)
    m.write(vt+128, QUICK_STATUS, 8)
    m.write(vt+40, SDK_CLOSE, 8)
    m.stubs[UTIL_TIME] = lambda m: m.reg(0, NOW)
    for address in (0xc09c30, 0xc0a680, 0xc11620, 0xc11630, 0xc11640):
        m.stubs[address] = lambda m: None  # Diagnostic string operations only.
    m.stubs[0xc09b00] = lambda m: m.reg(0, 1)  # Assert handler: no debugger trap.

    def info(m):
        m.events.append('info')
        m.uc.mem_write(m.reg(2), bytes(512))
        m.write(m.reg(2)+176, sns_state)
        m.reg(0, int(info_ok))

    def quick(m):
        m.events.append('quick')
        m.uc.mem_write(m.reg(2), bytes(128))
        m.write(m.reg(2)+4, -1)
        for offset in (16, 20, 24, 28):
            m.uc.mem_write(m.reg(2)+offset, struct.pack('<f', -1.0))
        m.reg(0, int(quick_ok))

    def close(m):
        assert (m.reg(1), m.reg(4)) == (1, 0)  # handle, linger=false
        m.events.append(('close', m.reg(2)))
        m.reg(0, 1)

    m.stubs.update({CONNECTION_INFO: info, QUICK_STATUS: quick, SDK_CLOSE: close})
    m.run(0x800348, 0x800960, transport)
    expected_events = []
    expected_handle = int(handle)
    if not handle:
        expected_state, expected_return = (3 if state == 3 else 4), 0
    elif state == 2 and elapsed < 1000000:
        expected_state, expected_return = 2, 1
    else:
        expected_events.append('info')
        if not info_ok:
            expected_state, expected_handle, expected_return = 3, 0, 0
        elif sns_state in (1, 2):
            expected_state, expected_return = 1, 1
        elif sns_state == 3:
            expected_events.append('quick')
            expected_state, expected_return = (2, 1) if quick_ok else (3, 0)
            if not quick_ok:
                expected_handle = 0
        else:
            reason = 0 if sns_state in (4, 5) else 2001
            expected_events.append(('close', reason))
            expected_state = 3 if sns_state == 5 or state == 3 else 4
            expected_handle, expected_return = 0, 0
    assert m.read(transport+20) == expected_state, (state, handle, sns_state, m.read(transport+20))
    assert m.read(transport+48) == expected_handle and m.reg(0) == expected_return
    assert m.events == expected_events, (m.events, expected_events)


def address_lookup(elf, verified, count):
    m = Machine(elf)
    manager, _ = common_manager(m)
    record, entries, addresses, out = [m.alloc(128) for _ in range(4)]
    m.write(manager+1152, entries, 8)
    m.write(entries+8, record, 8)
    m.write(record+32, addresses, 8)
    m.write(record+48, count)
    m.write(addresses, int(verified), 1)
    value = bytes(range(24))
    m.uc.mem_write(addresses+16, value)
    m.stubs[0xc0d8b0] = lambda m: None
    m.stubs[0xc0d950] = lambda m: m.reg(0, 0)
    m.reg(8, out)  # AAPCS indirect aggregate return.
    m.run(0x79c25c, 0x79c308, manager, 0x1234)
    expected = value if verified and count else bytes(20)+struct.pack('<HH', 3, 0)
    assert bytes(m.uc.mem_read(out, 24)) == expected


def address_compare(elf, left, right, expected):
    m = Machine(elf)
    entries = [m.alloc(64), m.alloc(64)]
    strings = {}
    for obj, (verified, remote, kind, timestamp, ip) in zip(entries, (left, right)):
        m.write(obj, verified, 1)
        m.write(obj+1, remote, 1)
        m.write(obj+8, timestamp, 8)
        m.write(obj+36, kind, 2)
        if kind == 3:
            m.write(obj+16, ip)
        else:
            strings[obj+16] = ip.encode()+b'\0'

    def to_string(m):
        m.uc.mem_write(m.reg(1), strings[m.reg(0)])

    def compare_strings(m):
        def read_string(address):
            return bytes(m.uc.mem_read(address, 48)).split(b'\0')[0]
        a, b = read_string(m.reg(0)), read_string(m.reg(1))
        m.reg(0, (a > b)-(a < b))

    m.stubs.update({0xc0de90: lambda m: m.reg(0, m.read(m.reg(0))),
                    0xc0da00: to_string, 0xc09fb0: compare_strings})
    m.run(0x7a3140, 0x7a3260, *entries)
    assert m.reg(0) == int(expected), (left, right, expected, m.reg(0))


def initial_routing(elf, expected, *, age=0, pending=True, sdr=False,
                    config_ready=True, route_state=3, peer_clusters=0,
                    relay_ready=False, ice=False, ice_ready=False,
                    permitted=0, gathered=0, ice_failed=False):
    m = Machine(elf)
    connection, relay, candidate, vt, config = [m.alloc(8192) for _ in range(5)]
    m.write(connection+6882, int(pending), 1)
    m.write(connection+6888, relay if sdr else 0, 8)
    m.write(connection+6848, route_state)
    m.write(connection+6856, NOW-age, 8)
    m.write(relay+56, int(relay_ready))
    m.write(relay+928, peer_clusters)
    m.write(0xc80000+3016, config, 8)
    m.write(config, int(config_ready), 1)
    m.write(connection+6984, candidate if ice else 0, 8)
    m.write(connection+7072, int(ice_failed))
    m.write(connection+7088, permitted)
    m.write(connection+7048, gathered)
    m.write(candidate, vt, 8)
    m.write(vt+32, QUERY_STATE, 8)
    m.stubs[QUERY_STATE] = lambda m: m.reg(0, int(ice_ready))
    m.run(0x875c08, 0x875d5c, connection, NOW)
    assert m.reg(0) == (1 if expected == 0 else NOW+expected), (age, expected, m.reg(0))
    assert m.read(connection+6882, 1) == (int(pending) if expected else 0)


def reliable_receive(elf, first, count, last, expected_delivery, *, ack=0,
                     has_first=True, existing_deadline=0):
    m = Machine(elf)
    connection, msg, queue, repeated, ice, vt = [m.alloc(8192) for _ in range(6)]
    m.write(connection+6848, 3)
    m.write(connection+6984, ice, 8)
    m.write(connection+7380, last)
    m.write(connection+7328, queue, 8)
    m.write(connection+7336, queue+3*48, 8)
    if existing_deadline:
        m.write(connection+7352, m.empty, 8)
        m.write(connection+7360, existing_deadline, 8)
    for index in range(3):
        m.write(queue+index*48, index+1)
    m.write(ice, vt, 8)
    m.write(vt+144, RELIABLE_DELIVER, 8)
    m.write(msg+16, (1 << 12) if has_first else 0)
    m.write(msg+136, 1, 1)  # ICE enabled; bypass no-ICE teardown.
    m.write(msg+144, ack)
    m.write(msg+148, first)
    m.write(msg+32, count)
    m.write(msg+40, repeated, 8)
    for index in range(count):
        item, payload = m.alloc(32), m.alloc(32)
        m.write(repeated+8+index*8, item, 8)
        m.write(item+16, 1, 1)
        m.write(item+24, payload, 8)
        m.write(payload, first+index)

    def swap(m):
        a, b = m.reg(0), m.reg(1)
        av, bv = bytes(m.uc.mem_read(a, 32)), bytes(m.uc.mem_read(b, 32))
        m.uc.mem_write(a, bv)
        m.uc.mem_write(b, av)

    m.stubs.update({0xc09420: swap, 0xc093b0: lambda m: None,
                    0xc119d0: lambda m: m.reg(0, NOW),
                    0xc11df0: lambda m: m.events.append(('think', m.reg(1))),
                    RELIABLE_DELIVER: lambda m: m.events.append(('deliver', m.read(m.reg(1))))})
    m.run(0x877614, 0x877c30, connection, msg, NOW)
    assert m.reg(0) == 1
    assert [event[1] for event in m.events if event[0] == 'deliver'] == expected_delivery
    assert m.read(connection+7380) == (expected_delivery[-1] if expected_delivery else last)
    remaining = (m.read(connection+7336, 8)-queue)//48
    assert [m.read(queue+i*48) for i in range(remaining)] == [i for i in (1, 2, 3) if i > ack]
    think = [event for event in m.events if event[0] == 'think']
    if has_first:
        deadline = min(existing_deadline or NOW+10000, NOW+10000)
        assert think == [('think', deadline)] and m.read(connection+7360, 8) == deadline
    else:
        assert not think


def sns_wait_receive(elf, wait_ms, batches, handle=True, queued=False):
    m = Machine(elf)
    transport, sdk, utils, vt, uvt, pending = [m.alloc(4096) for _ in range(6)]
    m.write(transport+48, int(handle))
    m.write(transport+56, sdk, 8)
    m.write(transport+64, utils, 8)
    m.write(transport+244, 0 if queued else -1)
    m.write(sdk, vt, 8)
    m.write(utils, uvt, 8)
    m.write(uvt+224, 0x82244c, 8)
    m.allowed.append((0x82244c, 0x822454))  # Original Poll(int) argument adapter.
    m.write(vt+112, CONNECTION_INFO, 8)
    m.stubs[0xc128d0] = lambda m: m.events.append(('poll', m.reg(0)))
    m.stubs[0xbff420] = lambda m: m.reg(0, m.alloc(m.reg(0)))
    m.stubs[0xc10fd0] = lambda m: None
    m.stubs[0xc110e0] = lambda m: m.events.append(('wrap',))
    remaining = list(batches)

    def receive(m):
        assert (m.reg(1), m.reg(3)) == (1, 128)
        count = remaining.pop(0)
        m.events.append(('receive', count))
        for index in range(max(0, count)):
            m.write(m.reg(2)+8*index, m.empty, 8)
        m.reg(0, count)

    def enqueue(m):
        m.write(transport+244, 0)
        m.write(m.reg(1), m.empty, 8)
        m.reg(0, pending)

    m.stubs.update({CONNECTION_INFO: receive, 0xc09e50: enqueue, 0xc09e60: lambda m: None})
    m.run(0x80010c, 0x800224, transport, wait_ms)
    actual_batches = [e[1] for e in m.events if e[0] == 'receive']
    assert m.events[0] == ('poll', wait_ms)
    assert actual_batches == (batches if handle else []) and (not remaining if handle else True)
    assert sum(e[0] == 'wrap' for e in m.events) == sum(max(0, n) for n in actual_batches)
    assert m.reg(0) == int(queued or any(n > 0 for n in actual_batches))


def sns_recv_queue(elf, handle, count, output=True):
    m = Machine(elf)
    transport, entries, out = [m.alloc(512) for _ in range(3)]
    m.write(transport+48, int(handle))
    m.write(transport+240, 3)  # Queue index mask.
    m.write(transport+244, 0 if count else -1)
    m.write(transport+248, count-1)
    m.write(transport+256, entries, 8)
    m.write(entries, 0x12345678, 8)
    m.run(0x8002c0, 0x800328, transport, out if output else 0)
    assert m.reg(0) == (2 if not handle else 1 if not count else 0)
    if handle and count:
        assert m.read(transport+244) == (0xffffffff if count == 1 else 1)
        assert m.read(transport+248) == (0xffffffff if count == 1 else count-1)
        assert m.read(out, 8) == (0x12345678 if output else 0)
    else:
        assert m.read(transport+244) == (0 if count else 0xffffffff)


def poll_wait_budget(elf, wait_ms, next_delta, expected):
    m = Machine(elf)
    m.stubs[0xc13c30] = lambda m: m.reg(0, (1 << 63)-1 if next_delta is None else NOW+next_delta)
    m.stubs[0xc119d0] = lambda m: m.reg(0, NOW)
    m.stops[0x86e2a4] = ('wait_computed',)
    m.run(0x86e200, 0x86e2a4, wait_ms, 1)
    assert m.reg(20) == expected, (wait_ms, next_delta, expected, m.reg(20))


def ice_route_metrics(elf, smooth, minimum, maximum, kind, penalty, ready=True):
    m = Machine(elf)
    route, connection, vt = [m.alloc(8192) for _ in range(3)]
    m.write(route, vt, 8)
    m.write(route+8, connection, 8)
    m.write(route+100, smooth)
    m.write(route+676, kind)
    m.write(vt+32, QUERY_STATE, 8)
    m.write(connection+5008, 1)
    m.write(connection+5012, penalty)
    m.write(connection+5488, NOW, 8)
    m.stubs[QUERY_STATE] = lambda m: m.reg(0, int(ready))

    def ping_range(m):
        m.write(m.reg(1), minimum)
        m.write(m.reg(2), maximum)
        m.reg(0, 15)

    m.stubs[0xc125f0] = ping_range
    m.run(0x87e4c4, 0x87e734, route, NOW)
    metrics = [m.read(route+offset) for offset in (576, 580, 584, 588, 592)]
    if not ready or smooth < 0:
        expected = [268435455]*3+[0, 0]
    elif minimum <= 4 and kind == 4:
        expected = [smooth, minimum, maximum, penalty, 15]
    else:
        expected = [value+value//10 for value in (smooth, minimum, maximum)]+[10+penalty, 15]
    assert metrics == expected, (smooth, minimum, maximum, kind, penalty, metrics, expected)


def start_stream_guard(elf, state, same):
    m = Machine(elf)
    manager, _ = common_manager(m, state)
    records = m.alloc(104)
    m.write(manager+144, records, 8)
    m.write(manager+168, 1)
    m.write(records+8, 0x1234, 8)
    m.write(records+16, 0x5678, 8)
    m.write(manager+528, 1, 1)
    m.stubs[0xc0d4f0] = lambda m: m.reg(0, 0)
    m.stubs[0xc0da10] = lambda m: m.reg(0, 456)
    m.stubs[0xc0da70] = lambda m: None
    m.stubs[0xc0da80] = lambda m: m.reg(0, 1)
    m.stops[0x798ec8] = ('new_transaction',)
    m.run(0x798d94, 0x798f5c, manager, 0x1234 if same else 0x9999, m.empty)
    duplicate = state == 5 and same
    assert m.events == ([] if duplicate else [('new_transaction',)])
    assert m.read(manager+512) == (123 if duplicate else 456)
    assert m.read(manager+528, 1) == int(duplicate)


def network_changed(elf, state):
    m = Machine(elf)
    manager, _ = common_manager(m, state)
    records = m.alloc(208)
    m.write(manager+144, records, 8)
    m.write(manager+168, 2)
    m.write(records+40, 123, 8)
    m.write(records+104+40, 456, 8)
    m.write(records+104+96, -2)  # A vacant hash-map slot must not be touched.
    m.write(manager+48, 789, 8)
    m.stubs[0xc0d9e0] = lambda m: m.events.append('update')
    m.run(0x79a614, 0x79a668, manager)
    assert m.events == (['update'] if state == 1 else [])
    assert m.read(records+40, 8) == (0 if state == 1 else 123)
    assert m.read(records+104+40, 8) == 456
    assert m.read(manager+48, 8) == (0 if state == 1 else 789)


def control_route(elf, has_ip, port, local, cloud, *, socket=True, start_ok=True,
                  steamid=True, udp_ok=True):
    m = Machine(elf)
    manager, address = common_manager(m)
    session, record, identities, packet = [m.alloc(128) for _ in range(4)]
    m.write(manager+12, int(local), 1)
    m.write(manager+32, m.empty if socket else 0, 8)
    m.write(address+22, port, 2)
    if cloud is not None:
        m.write(manager+24, session, 8)
        m.write(session+24, cloud)
    m.write(record+8, identities, 8)
    m.write(record+24, int(steamid))
    m.write(identities, 0x5678, 8)
    sp = m.uc.reg_read(arm.UC_ARM64_REG_SP)
    m.write(sp+8, packet, 8)
    m.write(sp+28, 32)
    m.reg(19, manager)
    m.reg(20, 0x1234)
    m.reg(21, address)
    m.stubs[0xc0dba0] = lambda m: m.reg(0, int(has_ip))
    m.stubs[0xc0db60] = lambda m: m.reg(0, record)

    def start(m):
        m.events.append('start_socket')
        if start_ok:
            m.write(manager+32, m.empty, 8)
        m.reg(0, int(start_ok))

    def udp(m):
        m.events.append('udp')
        m.reg(0, int(udp_ok))

    def send_cloud(m):
        assert tuple(m.reg(i) for i in range(4)) == (session, 0x5678, packet, 32)
        m.events.append('cloud')

    m.stubs.update({0xc0d9c0: start, 0xc0d770: udp, 0xc0d410: send_cloud})
    m.stops[0x79b024] = 'done'
    m.run(0x79b118, 0x79b1a4)
    expected = []
    use_udp = has_ip and port and local
    if use_udp and not socket:
        expected.append('start_socket')
    if use_udp and (socket or start_ok):
        expected.append('udp')
    elif cloud == 5 and steamid:
        expected.append('cloud')
    expected.append('done')
    assert m.events == expected, (has_ip, port, local, cloud, m.events, expected)


def relay_cipher_context(elf, context, challenge):
    m = Machine(elf)
    private = bytes(range(32))
    peer = X25519PrivateKey.from_private_bytes(bytes(range(32, 64))).public_key()
    public = peer.public_bytes(Encoding.Raw, PublicFormat.Raw)
    raw_shared = X25519PrivateKey.from_private_bytes(private).exchange(peer)
    vt = m.alloc(64)
    m.write(vt+16, KEY_VALID, 8)
    m.write(vt+32, KEY_RAW, 8)
    keys = []
    for raw in (private, public):
        obj, data = m.alloc(64), m.alloc(32)
        m.uc.mem_write(data, raw)
        m.write(obj, vt, 8)
        m.write(obj+16, data, 8)
        keys.append(obj)
    cipher, nonce = m.alloc(64), m.alloc(16)
    digests = []

    def get_raw(m):
        m.uc.mem_write(m.reg(1), bytes(m.uc.mem_read(m.read(m.reg(0)+16, 8), 32)))
        m.reg(0, 32)

    def sha(m):
        raw = bytes(m.uc.mem_read(m.reg(0), m.reg(1)))
        digests.append(raw)
        m.uc.mem_write(m.reg(2), hashlib.sha256(raw).digest())

    def init(m):
        expected_key = hashlib.sha256(hashlib.sha256(raw_shared).digest()+context).digest()
        assert bytes(m.uc.mem_read(m.reg(1), m.reg(2))) == expected_key
        assert tuple(m.reg(i) for i in (2, 3, 4, 5)) == (32, 12, 16, 1)
        m.reg(0, 1)

    m.buffers()
    m.stubs.update({KEY_VALID: lambda m: m.reg(0, 1), KEY_RAW: get_raw,
                    0xc09830: sha, 0xc09b30: init})
    m.redirects.update({0xc09810: 0x74610c, 0xc09820: 0x8b88fc})
    m.allowed.extend([(0x74610c, 0x7463dc), (0x8b88fc, 0x8bdbcc)])
    m.run(0x8a094c, 0x8a0ac4, *keys, challenge, m.string(context), cipher, nonce, 1,
          budget=1000000)
    assert m.reg(0) == 1
    assert digests == [raw_shared, hashlib.sha256(raw_shared).digest()+context]
    assert bytes(m.uc.mem_read(nonce, 12)) == struct.pack('<QI', challenge, 0)


def gcm_output_layout(elf, aad):
    m = Machine(elf)
    key, nonce, plaintext = bytes(range(32)), bytes(range(12)), b'synthetic-peer-identity'
    encrypted = AESGCM(key).encrypt(nonce, plaintext, aad)
    obj, provider, iv, data, out, length, aad_ptr = [m.alloc(128) for _ in range(7)]
    m.write(obj+8, provider, 8)
    m.write(obj+16, 12)
    m.write(obj+20, 16)
    m.uc.mem_write(iv, nonce)
    m.uc.mem_write(data, plaintext)
    m.write(length, 128)
    if aad:
        m.uc.mem_write(aad_ptr, aad)

    def init(m):
        assert bytes(m.uc.mem_read(m.reg(4), 12)) == nonce
        m.reg(0, 1)

    def update(m):
        if m.reg(1):
            assert bytes(m.uc.mem_read(m.reg(3), m.reg(4))) == plaintext
            m.uc.mem_write(m.reg(1), encrypted[:-16])
            m.write(m.reg(2), len(plaintext))
        else:
            assert bytes(m.uc.mem_read(m.reg(3), m.reg(4))) == aad
            m.write(m.reg(2), 0)
        m.reg(0, 1)

    def final(m):
        m.write(m.reg(2), 0)
        m.reg(0, 1)

    def tag(m):
        assert (m.reg(0), m.reg(1), m.reg(2), m.reg(3)) == (provider, 16, 16, out+len(plaintext))
        m.uc.mem_write(m.reg(3), encrypted[-16:])
        m.reg(0, 1)

    # Mock the fixed sample's EVP provider calls, execute the whole C++ wrapper.
    m.stubs.update({0xb76558: init, 0xb75ec8: update, 0xb761bc: final, 0xb75e14: tag})
    m.run(0x74b6dc, 0x74b9f0, obj, data, len(plaintext), iv, out, length,
          aad_ptr if aad else 0, len(aad))
    assert m.reg(0) == 1 and m.read(length) == len(encrypted)
    assert bytes(m.uc.mem_read(out, len(encrypted))) == encrypted


def audit(elf):
    counts = {}

    def case(group, fn, *args, **kwargs):
        try:
            fn(elf, *args, **kwargs)
        except Exception as error:
            raise RuntimeError('audit group='+group+' function='+fn.__name__) from error
        counts[group] = counts.get(group, 0)+1

    stops = {2: 11, 3: 16, 6: 7, 7: 9, 8: 8, 9: 12, 10: 13, 11: 14,
             12: 15, 13: 1, 14: 17, 15: 10, 16: 1, 0xffffffff: 1}
    for result in range(16):
        expected = 'ready' if result == 0 else [('authorize',)] if result == 1 else [] if result in (4, 5) else [('stop', stops[result])]
        case('streaming_result', streaming, result, expected)
    for result in (16, 0xffffffff):
        case('streaming_result', streaming, result, [('stop', 1)])
    case('streaming_result', streaming, 0, [('stop', 1)], decode=False)
    for result in (0, 1, 4, 5, 11):
        case('stale_streaming', streaming, result, [('cancel', 10, 122)] if result == 5 else [], old=True)
    case('stale_streaming', streaming, 5, [('cancel', 10, 0)], zero=True)
    for state in (3, 4):
        for result in range(1, 9):
            error = {1: 2, 2: 3, 3: 4, 4: 5, 6: 6}.get(result, 1)
            expected = [] if state == 4 and result == 5 else [('stop', error)]
            for auth_key in (False, True):
                case('authorization_result', authorization, state, result, auth_key, expected)
        for auth_key in (False, True):
            expected = [('key_exchange',), ('confirmation', 0)] if auth_key else [('save_legacy_secret',)] if state == 3 else []
            if state == 4:
                expected += [('stream_request',)]
            case('authorization_result', authorization, state, 0, auth_key, expected)
    case('authorization_result', authorization, 4, 4, True, [('confirmation', 8)], foreign=True)
    case('authorization_result', authorization, 4, 0, True,
         [('key_exchange',), ('confirmation', 0), ('confirmation', 8)], foreign=True)
    case('authorization_result', authorization, 4, 0, True,
         [('key_exchange',), ('confirmation', 0)], exchange_ok=False)
    for state in (3, 4):
        for result in (9, 0xffffffff):
            for auth_key in (False, True):
                case('authorization_result', authorization, state, result, auth_key, [('stop', 1)])
    for state in (0, 1, 2, 5, 6):
        for result in (0, 4):
            for auth_key in (False, True):
                case('authorization_out_of_context', authorization, state, result, auth_key,
                     [('confirmation', 8)] if auth_key else [])
    for attempts in (0, 3):
        for result in (0, 1):
            case('authorization_cache', authorization_cache, True, attempts, result)
    for attempts in range(4):
        case('authorization_cache', authorization_cache, False, attempts)
    case('authorization_cache', authorization_cache, False, 3, different_length=True)
    for update in (False, True):
        for already in (False, True):
            case('proof', proof, update, already=already)
        case('proof', proof, update, request_id=122)
        case('proof', proof, update, has_id=False, request_id=999)
        case('proof', proof, update, foreign=True)
    case('proof', proof, True, encrypt_ok=False)
    for kw in [{}, {'buckets': 14, 'expected_switch': False},
               {'best_max': 60, 'buckets': 0}, {'best': 41, 'expected_switch': False},
               {'best': 40}, {'sticky': False, 'best': 49},
               {'sticky': False, 'best': 50, 'expected_switch': False},
               {'current_exists': False, 'controlling': False, 'nominated': False,
                'age': 1000000, 'expected_switch': False},
               {'current_exists': False, 'controlling': False, 'nominated': False,
                'age': 1000001},
               {'current_exists': False, 'controlling': False, 'nominated': True},
               {'need_confirm': True, 'expected_switch': False},
               {'need_confirm': True, 'count': 1}]:
        case('transport_selection', transport, **kw)
    for seconds in (-1, 0, 1, 15, 29, 30, 0x7fffffff):
        case('relay_penalty', relay_penalty, seconds)
    for gap in (500000, 500001, 1750000, 1750001):
        case('relay_penalty', relay_penalty, 30, gap=gap, failures=1)
    for alternate in (1, 8190, 8191):
        case('relay_penalty', relay_penalty, 30, alternate=alternate)
    for length in (0, 4, 5, 8, 9, 1299, 1300, 1301, 0xffffffff):
        case('packet_length_guard', packet_length, length, 5 <= length <= 1300)
    for gap in (0, 15, 16, 16000, 250000, 250001):
        case('relay_data_header', relay_data, gap=gap)
    case('relay_data_header', relay_data, same_previous=False)
    case('relay_data_header', relay_data, counter=0xffff)
    for age in (0, 4999999, 5000000, 5000001):
        case('relay_ping', relay_ping, age=age)
    for ping in (0, 30, 500, 650):
        case('relay_ping', relay_ping, ping=ping)
    case('relay_ping', relay_ping, pending=NOW+12345)
    for state in range(6):
        for wants in (False, True):
            for queued in (False, True):
                case('bridge_cloud_dispatch', bridge, state, wants, queued)
    for state in (0, 4, 5):
        case('bridge_cloud_dispatch', bridge, state, False, False, new_signal=True)
    for cloud in (None, 0, 1, 2, 3, 4, 5):
        case('pairing_dispatch', pairing, cloud, 1, False)
        for state in range(7):
            case('pairing_dispatch', pairing, cloud, state, True)
    for state in range(6):
        for underlying in range(5):
            expected = []
            if state == 1 and underlying != 1:
                expected = ['finish_resolving']
            elif state == 2 and underlying != 2:
                expected = ['create_session' if underlying == 3 else 'next_endpoint']
            elif state == 3:
                expected = ['consume_packets' if underlying == 3 else 'next_endpoint']
            elif state == 4:
                expected = ['connect']
            elif state == 5:
                expected = ['consume_packets'] if underlying == 3 else ['notify_disconnected', 'disconnect', 'connect']
            case('cloud_session_update', cloud_update, state, underlying, expected)
    for now, expected in [(99.999, []), (100.0, ['connect']), (100.001, ['connect'])]:
        case('cloud_session_update', cloud_update, 4, 0, expected, now=now)
    for state in range(7):
        for now in (99, 100):
            case('manager_update', manager_update, state, now=now)
    for kw in [{'next_round': 100}, {'next_round': 99},
               {'extra': 100, 'sent': 1}, {'extra': 100, 'sent': 2},
               {'extra': 100, 'sent': 3}, {'extra': 101, 'sent': 1},
               {'state': 0, 'next_round': 0}, {'reentrant': True, 'next_round': 0}]:
        case('manager_update', manager_update, **kw)
    for age in (29, 30, 31):
        for online in (False, True):
            case('manager_expiration', manager_update, age=age, cloud_online=online)
    for state in range(5):
        for handle in (0, 1):
            case('sns_send', sns_send, state, handle, 1)
    for result in (0, 2, 25, 41, 42, 0xffffffff):
        case('sns_send', sns_send, 2, 1, result)
    case('sns_send', sns_send, 2, 1, 1, packet_flags=128)
    for state in range(5):
        case('sns_connection_state', sns_check, state, handle=False)
    for state in (1, 2, 3):
        for sns_state in range(6):
            case('sns_connection_state', sns_check, state, sns_state=sns_state)
    for kw in [{'info_ok': False}, {'quick_ok': False}, {'elapsed': 999999},
               {'elapsed': 1000000}, {'elapsed': 1000001}]:
        case('sns_connection_state', sns_check, 2, **kw)
    for verified in (False, True):
        for count in (0, 1):
            case('address_lookup', address_lookup, verified, count)
    address_cases = [
        ((1, 1, 4, 100, '::2'), (0, 0, 3, 200, 1), True),
        ((0, 0, 3, 200, 1), (1, 1, 4, 100, '::2'), False),
        ((1, 1, 3, 100, 2), (1, 0, 4, 200, '::1'), True),
        ((1, 1, 4, 200, '::1'), (1, 0, 3, 100, 2), False),
        ((1, 0, 3, 100, 2), (1, 1, 3, 200, 1), True),
        ((1, 1, 3, 200, 1), (1, 0, 3, 100, 2), False),
        ((1, 0, 3, 104, 3), (1, 0, 3, 100, 1), True),
        ((1, 0, 3, 100, 1), (1, 0, 3, 104, 3), False),
        ((1, 0, 3, 103, 3), (1, 0, 3, 100, 1), False),
        ((1, 0, 3, 100, 1), (1, 0, 3, 103, 3), True),
        ((1, 0, 3, 100, 1), (1, 0, 3, 102, 2), True),
        ((1, 0, 3, 102, 2), (1, 0, 3, 104, 3), True),
        ((1, 0, 4, 100, '::1'), (1, 0, 4, 100, '::2'), True),
        ((1, 0, 4, 100, '::2'), (1, 0, 4, 100, '::1'), False),
        ((1, 0, 3, 100, 1), (1, 0, 3, 100, 1), False),
    ]
    for left, right, expected in address_cases:
        case('address_comparator', address_compare, left, right, expected)
    for kw, expected in [({}, 0), ({'pending': False}, 0),
                         ({'sdr': True, 'config_ready': False}, 20000),
                         ({'sdr': True, 'config_ready': False, 'age': 1999999}, 1),
                         ({'sdr': True, 'config_ready': False, 'age': 2000000}, 0),
                         ({'sdr': True, 'route_state': 2, 'peer_clusters': 1}, 20000),
                         ({'sdr': True, 'route_state': 2, 'peer_clusters': 1, 'age': 99999}, 1),
                         ({'sdr': True, 'route_state': 2, 'peer_clusters': 1, 'age': 100000}, 0),
                         ({'sdr': True, 'route_state': 2, 'peer_clusters': 1, 'relay_ready': True}, 0),
                         ({'ice': True, 'permitted': 0x808}, 10000),
                         ({'ice': True, 'permitted': 0x808, 'age': 99999}, 1),
                         ({'ice': True, 'permitted': 0x808, 'age': 100000}, 0),
                         ({'ice': True, 'permitted': 0x606}, 10000),
                         ({'ice': True, 'permitted': 0x606, 'age': 9999}, 1),
                         ({'ice': True, 'permitted': 0x606, 'age': 10000}, 0),
                         ({'ice': True, 'permitted': 0x808, 'gathered': 8}, 0),
                         ({'ice': True, 'permitted': 0x606, 'gathered': 2}, 0),
                         ({'ice': True, 'permitted': 0x808, 'ice_ready': True}, 0),
                         ({'ice': True, 'permitted': 0x808, 'ice_failed': True}, 0)]:
        case('initial_routing_wait', initial_routing, expected, **kw)
    for first, count, last, delivery in [(1, 3, 0, [1, 2, 3]), (1, 4, 2, [3, 4]),
                                         (1, 2, 2, []), (4, 2, 2, []), (3, 0, 2, [])]:
        for ack in (0, 1, 2, 3, 4):
            case('reliable_receive', reliable_receive, first, count, last, delivery, ack=ack)
    case('reliable_receive', reliable_receive, 1, 3, 0, [], has_first=False)
    for deadline in (NOW+9999, NOW+10000, NOW+10001):
        case('reliable_receive', reliable_receive, 4, 2, 2, [], existing_deadline=deadline)
    for wait_ms in (0, 1, 7, 1000, 0xffffffff):
        case('sns_wait_receive', sns_wait_receive, wait_ms, [0])
    for batches in ([1], [127], [128, 0], [128, 1], [-1]):
        case('sns_wait_receive', sns_wait_receive, 7, batches)
    for queued in (False, True):
        case('sns_wait_receive', sns_wait_receive, 7, [], handle=False, queued=queued)
    for handle in (False, True):
        for count in (0, 1, 2):
            for output in (False, True):
                case('sns_recv_queue', sns_recv_queue, handle, count, output)
    for wait_ms, delta, expected in [(0, None, 0), (7, None, 7), (1000, None, 1000),
                                     (1500, None, 1000), (7, 0, 0), (7, -1, 0),
                                     (7, 1, 1), (7, 499, 1), (7, 500, 1),
                                     (7, 1499, 1), (7, 1500, 2), (7, 100000, 7),
                                     (0xffffffff, None, 0xffffffff), (0xffffffff, 0, 0)]:
        case('poll_wait_budget', poll_wait_budget, wait_ms, delta, expected)
    for smooth, minimum, maximum, kind, penalty in [(20, 4, 30, 4, 0), (20, 5, 30, 4, 0),
                                                   (20, 4, 30, 3, 0), (19, 9, 29, 3, 7),
                                                   (20, 4, 30, 4, 7), (-1, 4, 30, 4, 0)]:
        case('ice_route_metrics', ice_route_metrics, smooth, minimum, maximum, kind, penalty)
    case('ice_route_metrics', ice_route_metrics, 20, 4, 30, 4, 0, ready=False)
    for state in range(7):
        for same in (False, True):
            case('start_stream_guard', start_stream_guard, state, same)
        case('network_changed', network_changed, state)
    for has_ip in (False, True):
        for port in (0, 27036):
            for local in (False, True):
                for cloud in (None, 4, 5):
                    case('control_route', control_route, has_ip, port, local, cloud)
    for kw in [{'socket': False}, {'socket': False, 'start_ok': False},
               {'udp_ok': False}, {'steamid': False}]:
        case('control_route', control_route, True, 27036, True, 5, **kw)
    case('control_route', control_route, False, 0, True, 5, steamid=False)
    for context, challenge in [(b'', 0), (b'x'*22, 1), (b'x'*23, 1),
                               (b'identity:test', 0), (b'identity:test', 1),
                               (b'long-synthetic-identity:'*3, 0x0123456789abcdef),
                               (b'identity\0tail', 0xffffffffffffffff)]:
        case('relay_key_derivation', relay_cipher_context, context, challenge)
    for aad in (b'', b'additional-data'):
        case('gcm_output_layout', gcm_output_layout, aad)
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', required=True, type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    if not __debug__:
        parser.error('assertions are required; run without Python -O')
    elf = descriptors.SampleELF(args.elf.read_bytes())
    counts = audit(elf)
    report = {'sample_sha256': descriptors.SAMPLE_SHA256,
              'method': 'offline AArch64 emulation with explicit external-call stubs',
              'network_interoperability': False, 'passed': sum(counts.values()), 'groups': counts}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
