#!/usr/bin/env python3
"""Execute pinned Android packet ctor/SNS attachment/reset instructions.

Only heap deletion and SteamNetworkingMessage_t::Release are adapters. This
observes ownership, pointers and lengths, not SDK wire validation or producer
MTU policy; no sockets, media or actual SDK is run.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import (
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X30,
    UC_ARM64_REG_SP, UC_ARM64_REG_PC, UC_ARM64_REG_CPACR_EL1,
)

SHA = '50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e'
CTOR, ATTACH, RESET = 0x7F6D90, 0x7F6F30, 0x7F6DD0
STOP, RELEASE, DELETE = 0x40000000, 0x40000100, 0xC09AC0
PACKET, MESSAGE, OLD, HEAP = 0x20010000, 0x20020000, 0x20030000, 0x20040000


class Machine:
    def __init__(self, binary):
        self.u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.u.mem_map(0, 0x2000000)
        self.u.mem_map(0x20000000, 0x100000)
        self.u.mem_map(0x30000000, 0x100000)
        self.u.mem_map(STOP, 0x1000)
        elf = ELFFile(io.BytesIO(binary))
        for segment in elf.iter_segments():
            if segment['p_type'] == 'PT_LOAD':
                self.u.mem_write(segment['p_vaddr'], segment.data())
        self.u.reg_write(UC_ARM64_REG_CPACR_EL1, 3 << 20)
        self.actions = []
        self.u.hook_add(UC_HOOK_CODE, self.hook)

    def hook(self, uc, address, size, unused):
        if address == STOP:
            uc.emu_stop()
        elif address in (RELEASE, DELETE):
            self.actions.append(('release' if address == RELEASE else 'delete',
                                 uc.reg_read(UC_ARM64_REG_X0)))
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))

    def q(self, address):
        return struct.unpack('<Q', self.u.mem_read(address, 8))[0]

    def i(self, address):
        return struct.unpack('<I', self.u.mem_read(address, 4))[0]

    def wq(self, address, value):
        self.u.mem_write(address, struct.pack('<Q', value))

    def wi(self, address, value):
        self.u.mem_write(address, struct.pack('<I', value))

    def call(self, address, a=PACKET, b=0):
        self.u.reg_write(UC_ARM64_REG_SP, 0x300FF000)
        self.u.reg_write(UC_ARM64_REG_X0, a)
        self.u.reg_write(UC_ARM64_REG_X1, b)
        self.u.reg_write(UC_ARM64_REG_X30, STOP)
        self.u.emu_start(address, STOP + 4, count=1000)
        assert self.u.reg_read(UC_ARM64_REG_PC) == STOP

    def view(self):
        return dict(data=self.q(PACKET + 40), capacity=self.i(PACKET + 48),
                    size=self.i(PACKET + 52), storage=self.q(PACKET + 56),
                    owner=self.q(PACKET + 2336), actions=self.actions[:])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == SHA, 'wrong official sample'
    m = Machine(binary)
    rows = []
    for owner in ('inline', 'heap', 'message'):
        for length in (0, 1, 2048, 2049, 2272, 2273, 3000, 65536, 524288):
            m.call(CTOR)
            assert m.i(PACKET + 48) == 2272 and m.i(PACKET + 52) == 13
            if owner == 'heap':
                m.wq(PACKET + 56, HEAP)
            elif owner == 'message':
                m.wq(PACKET + 2336, OLD)
                m.wq(OLD + 184, RELEASE)
            m.wq(MESSAGE, HEAP + 0x1000)
            m.wi(MESSAGE + 8, length)
            m.wq(MESSAGE + 184, RELEASE)
            m.actions = []
            m.call(ATTACH, PACKET, MESSAGE)
            observed = m.view()
            assert observed['size'] == length and observed['capacity'] == length
            assert observed['data'] == HEAP + 0x1000 and observed['storage'] == HEAP + 0x1000
            assert observed['owner'] == MESSAGE
            expected = [] if owner == 'inline' else [('delete', HEAP)] if owner == 'heap' else [('release', OLD)]
            assert observed['actions'] == expected
            m.actions = []
            m.call(RESET)
            reset = m.view()
            assert reset['owner'] == 0 and reset['data'] == PACKET + 64
            assert reset['capacity'] == 2272 and reset['size'] == 13
            assert reset['actions'] == [('release', MESSAGE)]
            rows.append(dict(previous=owner, length=length, attached=observed, reset=reset))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(dict(sample_sha256=SHA,
        scope='Original packet ctor/SNS message attach/reset; SDK validation and producer MTU not exercised',
        cases=rows), indent=2) + '\n')
    print(f'PASS: {len(rows)} original-instruction SNS packet ownership/length cases')


if __name__ == '__main__':
    main()
