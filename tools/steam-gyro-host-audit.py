#!/usr/bin/env python3
"""Execute the pinned Windows host's gyro input paths offline.

Requires pefile and unicorn. No Steam process, network or Switch is touched.
Original instructions: remote full/delta decoding + CRC, Generic RAW builder,
sensor timing, postprocessor gates, quaternion integration, gyro source rate
copy, SDL sensor quantization/timestamp and sensor enable settings.
Explicit substitutes: object lookup, buffer/container/RC operations, memcpy,
locks, elapsed-clock provider, and SDL producer's state allocation. Synthetic
source/config objects do NOT prove real action configuration or mouse output.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import struct
import subprocess
import zlib

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn import x86_const as x86

SHA256 = 'e9045710ec7ee47d7b7488d1c5dda2d933dec7e251e965967a5c48f4df68eb4e'
RETURN = 0x4ff000


class Machine:
    def __init__(self, pe):
        self.u = Uc(UC_ARCH_X86, UC_MODE_64)
        base = pe.OPTIONAL_HEADER.ImageBase
        self.u.mem_map(base, (pe.OPTIONAL_HEADER.SizeOfImage + 4095) & ~4095)
        for section in pe.sections:
            self.u.mem_write(base + section.VirtualAddress, section.get_data())
        self.u.mem_map(0x100000, 0x400000)
        self.cursor = 0x100000
        self.stubs, self.stops, self.allowed = {}, set(), []
        self.visited = set()
        self.u.hook_add(UC_HOOK_CODE, self.hook)

    def alloc(self, size=4096):
        address = self.cursor
        self.cursor += (size + 15) & ~15
        if self.cursor >= 0x400000:
            raise ValueError('synthetic heap exhausted')
        return address

    def write(self, address, value, size=8):
        self.u.mem_write(address, (value % (1 << (8 * size))).to_bytes(size, 'little'))

    def read(self, address, size=8):
        return int.from_bytes(self.u.mem_read(address, size), 'little')

    def reg(self, name, value=None):
        register = getattr(x86, 'UC_X86_REG_' + name.upper())
        if value is not None:
            self.u.reg_write(register, value)
        return self.u.reg_read(register)

    def ret(self, value=0):
        self.reg('rax', value)
        sp = self.reg('rsp')
        self.reg('rip', self.read(sp))
        self.reg('rsp', sp + 8)

    def hook(self, uc, address, size, userdata):
        self.visited.add(address)
        if address in self.stops:
            uc.emu_stop()
        elif address in self.stubs:
            self.stubs[address]()
        elif not any(lo <= address < hi for lo, hi in self.allowed):
            raise ValueError(f'unexpected instruction address {address:#x}')

    def run(self, address, *args, stops=()):
        self.reg('rsp', 0x4f0008)  # Windows x64 entry alignment and shadow space
        self.write(0x4f0008, RETURN)
        for name, value in zip(('rcx', 'rdx', 'r8', 'r9'), args):
            self.reg(name, value)
        self.stops = {RETURN, *stops}
        self.visited = set()
        self.u.emu_start(address, 0, count=100000)
        if self.reg('rip') not in self.stops:
            raise ValueError('instruction budget exhausted')

    def memcpy(self):
        self.u.mem_write(self.reg('rcx'), bytes(self.u.mem_read(self.reg('rdx'), self.reg('r8'))))
        self.ret(self.reg('rcx'))


def remote_decode(pe, previous, report):
    """Real ProcessInputReport, delta reconstruction and CRC, synthetic queue."""
    m = Machine(pe)
    m.write(0x13918e480, m.alloc())  # imported profiler-enabled integer = 0
    obj, msg, string, buf, storage, queue, client, cell = [m.alloc() for _ in range(8)]
    m.write(obj + 0x18, 1, 4)
    m.write(obj + 0x20, 73, 4)  # actual StartInputReports length in device logs
    m.write(obj + 0x50, queue)  # recycle queue contains one buffer
    m.write(queue, buf)
    m.write(buf, storage)
    baseline = m.alloc()
    m.write(obj + 0x58, baseline)
    m.u.mem_write(baseline, previous + bytes(73 - len(previous)))
    delta = report['kind'] == 'delta'
    payload = bytes.fromhex(report['payload'])
    m.write(msg + 0x10, 2 if delta else 1, 4)
    m.write(msg + (0x20 if delta else 0x18), string)
    if delta:
        m.write(msg + 0x28, report['size'], 4)
        m.write(msg + 0x2c, report['crc'], 4)
    data = m.alloc()
    if len(payload) > 15:
        m.u.mem_write(data, payload)
        m.write(string, data)
    else:
        m.u.mem_write(string, payload)
    m.write(string + 0x10, len(payload))
    m.write(string + 0x18, max(15, len(payload)))

    def lookup():
        m.write(m.reg('rdx'), client)
        m.ret()

    def set_length():
        m.write(m.reg('rcx') + 0x10, m.reg('r8'), 4)
        m.ret()

    m.stubs = {
        0x1386cf4a0: lookup, 0x1391663e0: m.memcpy,
        0x138cf6930: set_length, 0x138cf9760: lambda: m.ret(cell),
        0x138cf97d0: lambda: m.ret(), 0x1380ed4a0: lambda: m.ret(),
    }
    m.allowed = [(0x1386cfd80, 0x1386d007f), (0x1386cef00, 0x1386ceff0),
                 (0x138cfa3e0, 0x138cfa407), (0x138cf9c90, 0x138cf9e20)]
    # Stop at the original bad-CRC branch before its external RPC allocation.
    m.run(0x1386cfd80, obj, msg, stops=[0x1386cff64])
    if m.reg('rip') == 0x1386cff64:
        return None
    assert m.read(cell) == buf, 'report was not queued'
    if delta:
        assert 0x138cfa3e0 in m.visited, 'original CRC wrapper was not executed'
    return bytes(m.u.mem_read(storage, 72))


def wire_report(previous, current, delta=False):
    if not delta:
        return {'kind': 'full', 'payload': current.hex()}
    mask, values = bytearray(10), bytearray()
    for index, (old, new) in enumerate(zip(previous, current)):
        if old != new:
            mask[index // 8] |= 1 << (index % 8)
            values.append(new)
    return {'kind': 'delta', 'payload': (mask + values).hex(),
            'size': len(current), 'crc': zlib.crc32(current)}


def build_state(pe, wire):
    m = Machine(pe)
    obj, out = m.alloc(), m.alloc()
    m.u.mem_write(obj + 0x18, wire)
    m.write(obj + 0x61, 1, 1)
    m.write(obj + 0xb0, 0x66, 4)  # exercise explicit fresh bits (no 0xff fallback)
    m.write(obj + 0xd4, 4000, 4)
    # Synthetic timing context: previous sample 4ms earlier, known nominal 4ms.
    tick = struct.unpack_from('<I', wire, 52)[0]
    for offset in (0x5f8, 0x648):
        m.write(obj + offset + 0x44, int(offset == 0x5f8), 4)
        m.write(obj + offset + 0x10, 4000, 4)
        m.write(obj + offset + 0x14, 4000, 4)
        m.write(obj + offset + 0x18, tick - 40000, 4)
    # No forced rate; debug off; sample-time policy=1; 50% nominal tolerance.
    for pointer, value in ((0x13980f0f0, 0), (0x13980f010, 0),
                           (0x13980f1d0, 1), (0x13980f2b0, 50)):
        config = m.alloc()
        m.write(pointer, config)
        m.write(config + 0x7c, value, 4)
    m.write(0x13918e1b8, RETURN + 16)
    m.stubs[RETURN + 16] = lambda: m.ret(4000)  # elapsed-clock function only
    m.allowed = [(0x1386793e0, 0x1386798ed), (0x13863bc00, 0x13863bf52)]
    m.run(0x1386793e0, obj, out, stops=[0x1386798ed])  # touch processing excluded
    state = bytes(m.u.mem_read(out, 0xb0))
    accepted = []
    for slot in (0, 1):
        source = m.alloc()
        m.write(source + 0xc0, slot, 4)
        m.allowed = [(0x1386702d0, 0x138670335)]
        m.run(0x1386702d0, source, out, stops=[0x138670335, 0x138670788])
        accepted.append(m.reg('rip') == 0x138670335)
    return state, accepted


def original_sensor(pe, sensor_type, values, event_ns, sensor_ns):
    """Original OnSensorEvent; only state lookup/locks substituted."""
    m = Machine(pe)
    obj, event, state = m.alloc(), m.alloc(), m.alloc()
    m.write(event + 8, event_ns)
    m.write(event + 0x14, sensor_type, 4)
    m.u.mem_write(event + 0x18, struct.pack('<3f', *values))
    m.write(event + 0x28, sensor_ns)
    m.write(0x13918d978, RETURN + 16)
    m.write(0x13918d970, RETURN + 16)
    m.stubs[RETURN + 16] = lambda: m.ret()
    m.stubs[0x1386d2a80] = lambda: m.ret(state)
    m.allowed = [(0x1386d30e0, 0x1386d3414)]
    m.run(0x1386d30e0, obj, event)
    return bytes(m.u.mem_read(state, 72))


def postprocess_gate(pe, state, caps=0x834bff, enabled=True):
    """Original settings/enable and postprocessor up to calibration entry.

    Lock and HID Write only are substituted. Run all 30 warmup iterations;
    no calibration result is fabricated and the calibration call is a stop.
    """
    m = Machine(pe)
    obj, out, setting, device, vtable = [m.alloc() for _ in range(5)]
    m.write(obj + 8, 30, 4)  # Generic device kind
    m.write(obj + 0x10, device)
    m.write(obj + 0x80, caps)
    m.write(obj + 0xb0, 0x66, 4)
    m.write(obj + 0xb8, 1, 1)
    m.write(obj + 0x588, 1, 1)  # enhanced reporting already initialized
    m.write(device, vtable)
    m.write(vtable + 0x20, RETURN + 24)
    m.write(0x13980d070, 1, 4)  # SDL write support enabled
    m.u.mem_write(setting, bytes((0x57, 0, 0xaa if enabled else 0xbb)))
    writes = []

    def hid_write():
        writes.append(bytes(m.u.mem_read(m.reg('rdx'), m.reg('r8'))))
        m.ret(m.reg('r8'))

    m.stubs[RETURN + 24] = hid_write
    m.allowed = [(0x13867c110, 0x13867c634), (0x138673310, 0x13867332f)]
    m.run(0x13867c1d0, obj, setting, 1)
    assert m.read(obj + 0x1f4, 1) == enabled
    assert writes == [bytes((8, int(enabled))) + bytes(19)]
    m.u.mem_write(out, state)
    for pointer in (0x13918d978, 0x13918d970):
        m.write(pointer, RETURN + 16)
    m.stubs[RETURN + 16] = lambda: m.ret()
    m.allowed = [(0x13867d830, 0x13867dac4), (0x1386731d0, 0x1386731ef)]
    for sample in range(1, 33):
        m.write(out + 8, sample, 4)
        m.run(0x13867d830, obj, out, stops=[0x13863d430])
        if m.reg('rip') == 0x13863d430:
            assert m.reg('rdx') == out + 0x58, 'wrong sensor slot'
            return sample
    return None


def integrate_and_consume(pe, state, zero_dt=False, zero_gyro=False):
    """Original integrator + source update through the angular-rate copy.

    Deliberately isolated from calibration: use a synthetic, already initialized
    unit orientation with no calibration/filter bias. All quaternion/CRT math
    instructions run unmodified. This does not exercise action dispatch.
    """
    m = Machine(pe)
    ctx, out, source = [m.alloc() for _ in range(3)]
    m.u.mem_write(out, state)
    if zero_gyro:
        m.u.mem_write(out + 0x5e, bytes(6))
    m.write(ctx + 4, 30, 4)
    m.u.mem_write(ctx + 8, struct.pack('<4f', 0, 0, 0, 1))
    m.write(0x139828430, 1, 1)  # host math subsystem initialized
    dt = 0 if zero_dt else struct.unpack_from('<I', state, 0xa0)[0] / 1e6
    m.reg('xmm2', int.from_bytes(struct.pack('<d', dt), 'little'))
    m.allowed = [(0x13863d990, 0x13863dc61), (0x138673780, 0x138673792),
                 (0x138cd6ed0, 0x138cd7021), (0x138cd7e80, 0x138cd80c3),
                 (0x138cd8210, 0x138cd8370), (0x138cd72a0, 0x138cd7399),
                 (0x138fccd80, 0x138fccd85), (0x138febe40, 0x138febee0),
                 (0x138fd5180, 0x138fd5d00)]
    m.run(0x13863d990, ctx, out + 0x58)
    q = struct.unpack('<4f', m.u.mem_read(out + 0x64, 16))  # w,x,y,z
    assert all(math.isfinite(v) for v in q)
    assert abs(sum(v*v for v in q) - 1) < 1e-5
    if zero_dt or zero_gyro:
        assert q == (1, 0, 0, 0)
    else:
        assert any(abs(v) > 1e-6 for v in q[1:]), 'orientation did not change'
    m.write(source, 0x1392e5218)  # actual gyro vtable
    for offset, value in ((0xc0, 1), (0xbc, 1), (0xe0, 1), (0xa8, 1)):
        m.write(source + offset, value, 1 if offset != 0xc0 else 4)
    threshold = m.alloc()
    m.write(0x13980f630, threshold)  # no angular-rate quantization filter
    m.allowed = [(0x1386702d0, 0x13867058c), (0x13866f660, 0x13866f735),
                 (0x13866fc00, 0x13866fc1a), (0x13866eea0, 0x13866ef02)]
    # Negative control: raw IMU alone is insufficient without postprocessed q.
    saved_q = bytes(m.u.mem_read(out + 0x64, 16))
    m.u.mem_write(out + 0x64, bytes(16))
    m.run(0x1386702d0, source, out, stops=[0x138670780, 0x13867058c])
    assert m.reg('rip') == 0x138670780
    m.u.mem_write(out + 0x64, saved_q)
    m.run(0x1386702d0, source, out, stops=[0x138670780, 0x13867058c])
    assert m.reg('rip') == 0x13867058c
    assert m.u.mem_read(source + 8, 6) == m.u.mem_read(out + 0x5e, 6)
    return q


def audit(pe, native=None):
    results = []
    neutral = bytearray(72)
    neutral[27] = 3
    controls = None
    for flags, version, expected in ((6, 3, [False, False]),
                                     (0x406, 3, [False, True]),
                                     (6, 2, [False, True]),
                                     (0x806, 3, [False, False]),
                                     (0xa06, 3, [True, False])):
        wire = bytearray(neutral)
        wire[27] = version
        struct.pack_into('<6hII', wire, 0, 1234, -2345, 3456, -4567, 0, 0, flags, 1)
        struct.pack_into('<6h', wire, 28, 100, 200, 300, 1000, 2000, 3000)
        if flags & 0x200:
            struct.pack_into('<6h', wire, 56, 400, 500, 600, 4000, 5000, 6000)
        wire = bytes(wire)
        for delta in (False, True):
            decoded = remote_decode(pe, bytes(neutral), wire_report(neutral, wire, delta))
            assert decoded == wire
            state, accepted = build_state(pe, decoded)
            assert accepted == expected, (flags, accepted)
            actual_controls = state[:8] + state[0x18:0x24]
            if controls is None:
                controls = actual_controls
            assert controls == actual_controls, 'flags changed buttons or axes'
            results.append({'flags': hex(flags), 'version': version,
                            'transport': 'delta' if delta else 'full', 'source_gate': accepted})
        bad = wire_report(neutral, wire, True)
        bad['crc'] ^= 1
        assert remote_decode(pe, bytes(neutral), bad) is None, 'bad CRC accepted'
    for sensor_type, expected_flag, offset in ((2, 0x402, 28), (4, 0xa00, 56)):
        produced = original_sensor(pe, sensor_type, [1.0, -2.0, 3.0], 100000000, 100000000)
        assert struct.unpack_from('<I', produced, 12)[0] == expected_flag
        assert struct.unpack_from('<I', produced, 52 if sensor_type == 2 else 68)[0] == 1000000
        assert all(struct.unpack_from('<3h', produced, offset))
        results.append({'original_sensor_type': sensor_type, 'flags': hex(expected_flag)})
    # Factory table and actual branches choose normal source(10)->1, left(16)->0.
    for kind, target, code in ((10, 0x66ede4, bytes.fromhex('ba01000000')),
                                (16, 0x66ee10, bytes.fromhex('33d2'))):
        assert struct.unpack('<I', pe.get_data(0x66ee48 + (kind - 1) * 4, 4))[0] == target
        assert pe.get_data(target + 15, len(code)) == code
    if native:
        # The C oracle uses production packer AND production report holder.
        output = subprocess.run([str(Path(native).resolve())], check=True,
                                capture_output=True, text=True).stdout
        previous = bytes(neutral)
        for line in output.splitlines():
            item = json.loads(line)
            wire = bytes.fromhex(item['wire'])
            decoded = remote_decode(pe, previous, item)
            assert decoded == wire, item['name']
            state, accepted = build_state(pe, decoded)
            assert accepted == [False, item['motion']], (item['name'], accepted)
            if item['motion']:
                gx, gy, gz, ax, ay, az = struct.unpack_from('<6h', wire, 28)
                assert struct.unpack_from('<6h', state, 0x58) == (ax, -az, ay, gx, gz, gy)
                assert state[0xac] & 1
                assert struct.unpack_from('<I', state, 0xa0)[0] == 4000
                assert postprocess_gate(pe, state) == 31
                assert postprocess_gate(pe, state, caps=0x8343ff) is None
                assert postprocess_gate(pe, state, enabled=False) is None
                stale = bytearray(state)
                stale[0xac] = 0
                assert postprocess_gate(pe, bytes(stale)) is None
                q = integrate_and_consume(pe, state)
                integrate_and_consume(pe, state, zero_dt=True)
                integrate_and_consume(pe, state, zero_gyro=True)
                results.append({'native': item['name'], 'postprocess_warmup': 30,
                                'isolated_quaternion_wxyz': q,
                                'source_angular_rate_copy': True})
            results.append({'native': item['name'], 'transport': item['kind'], 'source_gate': accepted})
            previous = wire
    return {'binary_sha256': SHA256, 'passed': True, 'cases': results,
            'limits': 'Synthetic objects/config/clock/containers. Postprocessor gates and isolated '
                      'quaternion integration/source rate copy; no calibration convergence, '
                      'action/mouse/network/lifecycle proof.'}


def main():
    if not __debug__:
        raise SystemExit('Python -O is not supported: assertions are required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--native', type=Path, help='production C oracle executable')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    raw = args.binary.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA256:
        raise SystemExit('refusing unpinned host binary')
    result = audit(pefile.PE(data=raw), args.native)
    encoded = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.write_text(encoded)
    print(encoded, end='')


if __name__ == '__main__':
    main()
