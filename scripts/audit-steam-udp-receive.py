#!/usr/bin/env python3
"""Original UDP wait/recv/packet constructor -> Socket -> Connection/windows.

Final select/recvfrom, address conversion, allocator/refcounts and the media
delegate are explicit adapters. The syscall adapter copies min(wire, capacity),
as recvfrom(flags=0) does for a short datagram buffer; native loopback verifies
that boundary independently. errno is not modeled: the original receive path
never reads it. No genuine Steam peer, kernel-error incidence or Switch claim.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import types

ROOT = Path(__file__).resolve().parents[1]
SHA = "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"
spec = importlib.util.spec_from_file_location(
    "cycle", ROOT / "scripts/audit-steam-receive-cycle.py"
)
cycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cycle)


def helpers():
    found = {}

    def visit(module):
        path = Path(getattr(module, "__file__", "")).resolve()
        if path.parent != ROOT / "scripts" or str(path) in found:
            return
        found[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        for value in vars(module).values():
            if isinstance(value, types.ModuleType):
                visit(value)

    visit(cycle)
    return {str(Path(p).relative_to(ROOT)): h for p, h in sorted(found.items())}


class UDP(cycle.Cycle):
    def __init__(self, binary, crc):
        super().__init__(binary, crc)
        self.wi(self.transport + 20, 7)
        self.b(self.transport + 16, 1)
        self.wq(self.transport + 24, 0)
        vt = self.q(self.transport)
        self.wq(vt + 64, 0x802664)  # actual TransportUDP::BWait
        self.wq(vt + 80, 0x80286C)  # actual TransportUDP::Recv
        self.wi(self.connection + 52, 1000000)
        self.wi(self.connection + 56, 1000000)
        self.reads, self.selects, self.packet_allocations = [], [], []
        self.pending, self.select_result, self.clear_sets = [], 1, False
        self.callbacks.update(
            {
                0xBFF420: self.allocate,
                0xC10FD0: lambda: self.jump(0x7F6D90),  # actual packet constructor
                0xC0D7E0: self.recvfrom,
                0xC0D7F0: self.address,
                0xC0D800: lambda: self.ret(1),
                0xC11720: self.fd_set,
                0xC11730: self.fd_isset,
                0xC10F10: self.select,
            }
        )

    def allocate(self):
        self.packet_allocations.append(self.r(0))
        self.ret(self.alloc(self.r(0)))

    def fd_set(self):
        fd, address = self.r(0), self.r(1)
        target = address + 8 * (fd // 64)
        self.wq(target, self.q(target) | (1 << (fd % 64)))
        self.ret()

    def fd_isset(self):
        fd, address = self.r(0), self.r(1)
        self.ret(bool(self.q(address + 8 * (fd // 64)) & (1 << (fd % 64))))

    def select(self):
        self.selects.append(
            dict(
                result=self.select_result,
                clear_sets=self.clear_sets,
                nfds=self.r(0),
                sec=self.q(self.r(4)),
                usec=self.q(self.r(4) + 8),
            )
        )
        if self.clear_sets:
            self.u.mem_write(self.r(1), bytes(128))
            self.u.mem_write(self.r(2), bytes(128))
        self.ret(self.select_result)

    def recvfrom(self):
        item = self.pending.pop(0) if self.pending else -1
        capacity, pointer = self.r(2), self.r(1)
        if isinstance(item, str):
            wire = bytes.fromhex(item)
            received = wire[:capacity]
            self.u.mem_write(pointer, received)
            result = len(received)
        else:
            wire, received, result = b"", b"", item
        self.reads.append(
            dict(
                capacity=capacity,
                flags=self.r(3),
                result=result,
                wire_bytes=len(wire),
                received_sha256=hashlib.sha256(received).hexdigest(),
            )
        )
        self.ret(result)

    def address(self):
        self.u.mem_write(self.r(0) + 20, struct.pack("<H", 3))
        self.u.mem_write(self.r(3), struct.pack("<H", 27036))
        self.ret(1)

    def step(self, reads, tick, selected=1, clear=False):
        self.pending = reads.copy()
        self.select_result, self.clear_sets, self.now = selected, clear, tick
        self.delivered.clear()
        wait = self.call(0x7FEB7C, self.sock)
        self.call(0x7FEB90, self.sock, wait)
        wait_ready = self.u.mem_read(self.sock + 56, 1)[0]
        self.call(0x7FECD4, self.sock)
        assert not self.pending
        return dict(
            update_tick=self.i(self.connection + 48),
            last_receive=self.i(self.connection + 52),
            read_ready=self.u.mem_read(self.sock + 56, 1)[0],
            wait_ready=wait_ready,
            cached_packet=bool(self.q(self.transport + 24)),
            delivered=[
                dict(
                    bytes=len(bytes.fromhex(v)),
                    sha256=hashlib.sha256(bytes.fromhex(v)).hexdigest(),
                )
                for v in self.delivered
            ],
        )

    def wire(self, size, crc, packet_id=0):
        data = struct.pack(
            "<BBBBBHHI", 3 | (128 if crc else 0), 0, 34, 12, 3, 0, packet_id, 900000
        )
        data += bytes((i * 37 + 11) & 255 for i in range(size - len(data) - 4 * crc))
        if crc:
            pointer = self.alloc(len(data))
            self.u.mem_write(pointer, data)
            data += struct.pack("<I", self.call(0x8E1610, pointer, len(data)))
        assert len(data) == size
        return data.hex()


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == SHA
    cases = []
    for crc in (False, True):
        for size in (1472, 2048, 2049, 2200, 2201, 2272, 2273, 3000):
            r = UDP(binary, crc)
            wire = r.wire(size, crc)
            state = r.step([wire], 1000000)
            cases.append(
                dict(
                    input=dict(name=f"size_{size}_{int(crc)}", wire=wire, crc=crc),
                    observed=dict(
                        cycles=[state],
                        reads=r.reads,
                        selects=r.selects,
                        allocations=r.packet_allocations,
                    ),
                )
            )
        for label, result, clear, reads in (
            ("negative_read", 1, False, [-1]),
            ("empty_read", 1, False, [0]),
            ("negative_wait_keeps_sets", -1, False, [-1]),
            ("negative_wait_clears_sets", -1, True, []),
            ("timeout", 0, True, []),
        ):
            r = UDP(binary, crc)
            states = [r.step(reads, 1000000, result, clear)]
            wire = r.wire(40, crc)
            states.append(r.step([wire], 1000001))
            assert (
                states[0]["update_tick"] == 1000000
                and states[1]["update_tick"] == 1000001
            )
            assert not states[0]["delivered"] and len(states[1]["delivered"]) == 1
            assert all(v["read_ready"] == 0 for v in states)
            cases.append(
                dict(
                    input=dict(name=f"{label}_{int(crc)}", crc=crc),
                    observed=dict(
                        cycles=states,
                        reads=r.reads,
                        selects=r.selects,
                        allocations=r.packet_allocations,
                    ),
                )
            )
        for ending in (-1, 0):
            r = UDP(binary, crc)
            states = [
                r.step([r.wire(40, crc), ending], 1000000),
                r.step([r.wire(40, crc, 1)], 1000001),
            ]
            assert all(len(v["delivered"]) == 1 for v in states)
            cases.append(
                dict(
                    input=dict(name=f"after_packet_{ending}_{int(crc)}", crc=crc),
                    observed=dict(
                        cycles=states,
                        reads=r.reads,
                        selects=r.selects,
                        allocations=r.packet_allocations,
                    ),
                )
            )
    assert all(
        row["capacity"] == 2272 and row["flags"] == 0
        for case in cases
        for row in case["observed"]["reads"]
    )
    return dict(binary_sha256=SHA, helpers=helpers(), scope=__doc__, cases=cases)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--refresh-reference", action="store_true")
    args = p.parse_args()
    report = audit(args.binary.read_bytes())
    reference = ROOT / "scripts/fixtures/steam-udp-receive-reference.json"
    if args.refresh_reference:
        assert not reference.exists()
        reference.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert json.loads(reference.read_text()) == report
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"Original UDP receive: {len(report['cases'])} constructor/size/wait/read recovery cases"
    )


if __name__ == "__main__":
    main()
