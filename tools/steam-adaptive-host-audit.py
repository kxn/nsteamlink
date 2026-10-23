#!/usr/bin/env python3
"""Execute pinned official Windows x86 host adaptive-bitrate boundaries offline.

Requires pefile/unicorn. No Steam process, network, Switch or production code is
modified. Loss-function branches/arithmetic, float min/max helpers, actual host
virtual getters, mode branches, preset table and cap getter execute original
instructions. Explicit providers: clock/logging, platform ID/FPS interface and
thread start/stop effect endpoints. Synthetic objects are not real negotiation,
encoder changes, a full estimator lifetime or proof of another host version.
"""
import pefile, struct, hashlib, json, math, argparse
from pathlib import Path
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_EIP,
    UC_X86_REG_ESP,
    UC_X86_REG_ECX,
    UC_X86_REG_EAX,
)

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--binary", type=Path, required=True)
p = parser.parse_args().binary
b = p.read_bytes()
sha = hashlib.sha256(b).hexdigest()
assert sha == "0cad7c69ace13e802be17beb06df299f7f733f01b4450a74bc68709494b21ddb"
pe = pefile.PE(data=b)
base = pe.OPTIONAL_HEADER.ImageBase
image = pe.get_memory_mapped_image()
results = []
for name, now, initial, floor, expected in [
    ("early", 2.999, 10.0, 1.0, 10.0),
    ("boundary", 3.0, 10.0, 1.0, 9.0),
    ("late", 4.0, 10.0, 1.0, 9.0),
    ("floor", 4.0, 1.0, 1.0, 1.0),
]:
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    u.mem_map(base, (len(image) + 4095) & ~4095)
    u.mem_write(base, image)
    u.mem_map(0x100000, 0x10000)
    u.mem_map(0x70000000, 0x10000)
    u.mem_map(0x4FF000, 4096)
    obj = 0x101000
    tm = 0x102000
    res = 0x102010
    timefn = 0x103000
    stop = 0x4FF000

    def wf(addr, x):
        u.mem_write(addr, struct.pack("<f", x))

    def wd(addr, x):
        u.mem_write(addr, struct.pack("<d", x))

    wf(obj + 0x68, initial)
    wf(obj + 0x6C, initial)
    wf(obj + 0x70, floor)
    wd(obj + 8, 0)
    wd(obj + 0x60, 0)
    wd(tm, now)
    u.mem_write(0x3A9F1964, struct.pack("<I", timefn))
    u.mem_write(timefn, b"\xdd\x05" + struct.pack("<I", tm) + b"\xc3")
    u.mem_write(0x3A12FEF0, b"\xc3")
    stack = 0x7000F000
    u.mem_write(stack, struct.pack("<I", stop))
    u.reg_write(UC_X86_REG_ESP, stack)
    u.reg_write(UC_X86_REG_ECX, obj)
    # Initialize the x87 environment without changing the original function.
    u.mem_write(0x103100, b"\xdb\xe3")
    u.emu_start(0x103100, 0x103102, count=2)
    u.emu_start(0x3A10ADD0, stop, count=10000)
    value = struct.unpack("<f", u.mem_read(obj + 0x68, 4))[0]
    assert math.isclose(value, expected, rel_tol=1e-6), (name, value)
    results.append(
        {
            "name": name,
            "now_seconds": now,
            "before": initial,
            "floor": floor,
            "after": value,
            "loss_counter": struct.unpack("<I", u.mem_read(obj + 0x80, 4))[0],
        }
    )

for desired, quality, expected in [
    (6000, 2, 6000),
    (-1, 1, 5000),
    (-1, 2, 10000),
    (-1, 3, 15000),
    (0, 2, 100000),
]:
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    u.mem_map(base, (len(image) + 4095) & ~4095)
    u.mem_write(base, image)
    u.mem_map(0x100000, 0x10000)
    u.mem_map(0x70000000, 0x10000)
    u.mem_map(0x4FF000, 4096)
    obj = 0x101000
    stop = 0x4FF000

    def wi(a, n):
        u.mem_write(a, struct.pack("<I", n & 0xFFFFFFFF))

    wi(obj, 0x3AA19F14)
    wi(obj + 0x18C, desired)
    wi(obj + 0x168, quality)
    wi(obj + 0x4000, -1)
    wi(obj + 0x3FFC, -1)
    wi(obj + 0x3FCC, 1280)
    wi(obj + 0x3FD0, 720)
    # Platform ID and FPS interface are explicit providers. The source getters,
    # selection branches, preset table and cap getter execute their original code.
    u.mem_write(0x3A6ECAF0, b"\x31\xc0\xc3")
    fake = 0x10A000
    fps = 0x103000
    wi(obj + 0x3F68, fake)
    wi(fake + 0x10, fps)
    u.mem_write(fps, b"\x31\xc0\xc2\x08\x00")
    actions = []
    for entry in [0x3A10B480, 0x3A10B450]:
        u.mem_write(entry, b"\xc3")

    # Bounds/FPS setters execute original instructions; thread start/stop is an effect endpoint.
    def hook(uc, pc, size, data):
        if pc in [0x3A10B480, 0x3A10B450]:
            actions.append("stop" if pc == 0x3A10B480 else "start")

    u.hook_add(UC_HOOK_CODE, hook)
    sp = 0x7000F000
    wi(sp, stop)
    u.reg_write(UC_X86_REG_ESP, sp)
    u.reg_write(UC_X86_REG_ECX, obj)
    u.mem_write(0x103100, b"\xdb\xe3")
    u.emu_start(0x103100, 0x103102, count=2)
    u.emu_start(0x3A11FF60, stop, count=20000)
    actual = u.reg_read(UC_X86_REG_EAX)
    assert actual == expected, (desired, quality, actual)
    assert actions == (["start"] if desired == 0 else ["stop"]), actions
    results.append(
        {
            "desired": desired,
            "quality": quality,
            "selected_ceiling_kbps": actual,
            "estimator_actions": actions,
        }
    )
print(
    json.dumps(
        {
            "sha256": sha,
            "scope": "Original loss function and mode-selection branches; clock/log and mode start-stop/platform/FPS are explicit effect providers, not real host execution",
            "cases": results,
        },
        indent=2,
    )
)
