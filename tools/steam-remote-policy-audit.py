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
        fn(elf, *args, **kwargs)
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
    for context, challenge in [(b'identity:test', 0), (b'identity:test', 1),
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
