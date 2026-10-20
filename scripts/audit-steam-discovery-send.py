#!/usr/bin/env python3
"""Execute original discovery sending, startup and broadcast socket recovery.

Pinned Core and Qt-shell SendMessage/BSend/BStart/BInit/Update/RequestStatus,
broadcast enable/trigger, CUtlBuffer and generated protobuf instructions run.
Manager storage/identity and empty host tables are controlled inputs, not an
original manager-constructor proof. Initial resource-empty Stop, OS calls,
allocation/libc/libc++ string storage are adapters. Invalid-address cases stop
at an explicitly unavailable remote-token terminal; full auth is excluded.
Two read-order programs use an opaque BProcess terminal, not valid wire admission.
Socket syscalls capture full
wire/address bytes; no actual OS network, Qt event, Steam host or Switch claim.
SendMessage has no checked delivery return; only original BSend is observed.
"""
import argparse
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import struct
from collections import Counter
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn.arm64_const import UC_ARM64_REG_X30

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("config", ROOT / "scripts/audit-steam-client-config.py")
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)
IDENTITIES = {"core": config.SHA, "shell": config.BASE["SHA"]}
FUNCTIONS = {
    "send": "_ZN14CServerManager11SendMessageE25ERemoteClientBroadcastMsgPN6google8protobuf7MessageE10CIPAndPorty",
    "start": "_ZN14CServerManager6BStartEv",
    "update": "_ZN14CServerManager6UpdateEv",
    "status": "_ZN14CServerManager13RequestStatusEv",
    "enable": "_ZN14CServerManager24EnableBroadcastDiscoveryEv",
    "trigger": "_ZN14CServerManager25TriggerBroadcastDiscoveryEv",
    "socket_init": "_ZN16CDiscoverySocket5BInitEv",
    "socket_send": "_ZN16CDiscoverySocket5BSendEPK10CUtlBufferRK10CIPAndPort",
    "socket_receive": "_ZN16CDiscoverySocket8BReceiveEP10CIPAndPortP10CUtlBuffer",
    "socket_destroy": "_ZN16CDiscoverySocketD1Ev",
    "identity": "_ZN14CServerManager11GetDeviceIDEv",
    "header_ctor": "_ZN31CMsgRemoteClientBroadcastHeaderC1Ev",
    "discovery_ctor": "_ZN34CMsgRemoteClientBroadcastDiscoveryC1Ev",
}


class Sender(config.Core):
    def __init__(self, binary):
        self.ready, self.allocations = False, {}
        # Reuse the symbol-based memory/string support without constructing the
        # unrelated streaming-client fixture or installing fixed Core callbacks.
        config.Shell.__init__(self, binary)
        self.ready = True
        self.manager = self.alloc(2048)
        self.wq(self.manager + 16, 42)  # original GetDeviceID cached branch
        self.b(self.manager + 12, 1)
        self.wq(self.manager + 48, 2000)
        self.wq(self.manager + 88, 2000)
        self.peer = self.alloc(24)
        self.wi(self.peer, 0x7f000001)
        self.u.mem_write(self.peer + 20, struct.pack("<HH", 3, 27036))
        self.socket_result, self.wall_time = -1, 1000
        self.random_upper = False
        self.socket_plan, self.send_plan, self.receive_plan = [], [], []
        self.trace, self.sends, self.send_returns, self.return_points = [], [], [], []
        self.calls = Counter()
        self.entries = {self.symbols[name]: key for key, name in FUNCTIONS.items()}
        self.errno_slot = self.alloc(4)
        self.wi(self.errno_slot, 5)
        self.message = self.alloc(256)
        self.parse(self.message, b"\x08\x11", "CMsgRemoteClientBroadcastDiscovery")

    def alloc(self, size):
        assert 0 <= size < 0x100000
        pointer = super().alloc(max(1, size))
        self.allocations[pointer] = size
        return pointer

    def hook(self, u, pc, size, data):
        if not self.ready:
            return super().hook(u, pc, size, data)
        if self.return_points and pc == self.return_points[-1]:
            self.return_points.pop()
            value = self.r(0)
            assert value in (0, 1)
            self.send_returns.append(value)
            self.trace.append(["BSend_return", value])
        if pc in self.entries:
            key = self.entries[pc]
            self.calls[key] += 1
            self.trace.append(["original", key])
            if key == "socket_send":
                self.return_points.append(self.u.reg_read(UC_ARM64_REG_X30))
        name = self.plts.get(pc, "")
        args = [self.r(i) for i in range(6)]
        if name == "_ZN14CServerManager4StopEv":
            assert self.i(self.manager + 8) == 0
            assert self.q(self.manager + 24) == self.q(self.manager + 32) == 0
            self.trace.append(["initial_empty_Stop"])
            self.ret()
        elif name == "_ZN10CUtlBufferC1Ev":
            self.jump(self.symbols[name])
        elif name == "socket":
            result = self.socket_plan.pop(0) if self.socket_plan else self.socket_result
            self.trace.append(["socket", args[0], result])
            self.ret(result & ((1 << 64) - 1))
        elif name in ("setsockopt", "bind", "fcntl", "close"):
            if name == "close":
                assert args[0] < 0x80000000
            self.trace.append([name, *args[:3]])
            self.ret(0)
        elif name == "recvfrom":
            result = self.receive_plan.pop(0) if self.receive_plan else -1
            self.trace.append(["recvfrom", args[0], result])
            if result > 0:
                assert result <= args[2]
                u.mem_write(args[1], b"X" * result)
                address = struct.pack("<H", 2) + struct.pack(">H", 27036) + bytes([127, 0, 0, 1]) + bytes(8)
                u.mem_write(args[4], address)
                self.wi(args[5], len(address))
            self.ret(result & ((1 << 64) - 1))
        elif name == "_ZN14CServerManager8BProcessEP10CIPAndPortP10CUtlBufferb":
            self.trace.append(["opaque_BProcess_terminal", self.i(args[2] + 20)])
            self.ret(1)
        elif name == "time":
            self.ret(self.wall_time)
        elif name == "WeakRandomInt":
            value = args[1] if self.random_upper else args[0]
            self.trace.append(["random_boundary_fixture", args[0], args[1], value])
            self.ret(value)
        elif "basic_string" in name and "6resizeEmc" in name:
            target, length, fill = args[:3]
            tag = u.mem_read(target, 1)[0]
            old_length = self.q(target + 8) if tag & 1 else tag >> 1
            old_pointer = self.q(target + 16) if tag & 1 else target + 1
            value = bytes(u.mem_read(old_pointer, min(old_length, length)))
            value += bytes([fill & 255]) * max(0, length - old_length)
            capacity = (length + 2) & ~1
            pointer = self.alloc(capacity)
            u.mem_write(pointer, value + b"\0")
            self.wq(target, capacity | 1)
            self.wq(target + 8, length)
            self.wq(target + 16, pointer)
            self.ret()
        elif name == "realloc":
            pointer = self.alloc(args[1])
            assert not args[0] or args[0] in self.allocations
            if args[0]:
                u.mem_write(pointer, bytes(u.mem_read(args[0], min(self.allocations[args[0]], args[1]))))
            self.ret(pointer)
        elif name == "sendto":
            wire = bytes(u.mem_read(args[1], args[2]))
            result, error = self.send_plan.pop(0) if self.send_plan else ("full", 0)
            result = args[2] if result == "full" else result
            self.wi(self.errno_slot, error)
            row = dict(fd=args[0] if args[0] < 0x80000000 else args[0] - (1 << 32),
                       size=args[2], result=result, errno=error, flags=args[3],
                       sockaddr=bytes(u.mem_read(args[4], args[5])).hex(), wire=wire.hex())
            self.trace.append(["sendto", row])
            self.sends.append(row)
            self.ret(result & ((1 << 64) - 1))
        elif name == "_ZN14CServerManager15BGetDeviceTokenER10CUtlBuffer":
            self.trace.append(["remote_token_unavailable_terminal"])
            self.ret(0)
        elif name == "__errno":
            self.ret(self.errno_slot)
        else:
            try:
                return super().hook(u, pc, size, data)
            except Exception:
                print("Source diagnostic", hex(pc), hex(self.u.reg_read(UC_ARM64_REG_X30)), self.trace[-6:], flush=True)
                raise

    def run(self, key):
        self.call(self.symbols[FUNCTIONS[key]], self.manager)
        assert not self.return_points

    def send(self):
        self.call(self.symbols[FUNCTIONS["send"]], self.manager, 0, self.message, self.peer, 0)
        assert not self.return_points

    def snapshot(self):
        socket = self.q(self.manager + 32)
        fd = self.i(socket + 4) if socket else None
        if fd is not None and fd >= 0x80000000:
            fd -= 1 << 32
        return copy.deepcopy(dict(state=self.i(self.manager + 8), socket=socket, fd=fd,
            ipv6=self.i(socket) & 255 if socket else None, broadcast_owners=self.i(self.manager + 40),
            sequence=self.i(self.manager + 44), next_status=self.q(self.manager + 48),
            fast_status=self.q(self.manager + 88), status_tries=self.i(self.manager + 80),
            calls=dict(sorted(self.calls.items())), sends=self.sends, returns=self.send_returns, trace=self.trace))


def started(binary, ipv6):
    machine = Sender(binary)
    machine.socket_result = 37
    if not ipv6:
        machine.socket_plan = [-1, 37]
    machine.run("start")
    assert machine.i(machine.manager + 8) == 1
    assert bool(machine.i(machine.q(machine.manager + 32)) & 255) == ipv6
    assert not machine.sends
    return machine


def audit_one(binary, identity):
    assert hashlib.sha256(binary).hexdigest() == IDENTITIES[identity]
    cases = []
    machine = Sender(binary)
    machine.send()
    rows = [machine.snapshot()]
    assert rows[-1]["state"] == 0 and not rows[-1]["socket"] and not rows[-1]["sends"]
    machine.socket_result = 37
    machine.send()
    rows.append(machine.snapshot())
    machine.send()
    rows.append(machine.snapshot())
    assert [row["calls"].get("start", 0) for row in rows] == [1, 2, 2]
    assert [len(row["sends"]) for row in rows] == [0, 1, 2]
    assert rows[-1]["socket"] == rows[-2]["socket"] and rows[-1]["state"] == 1
    assert all(row["wire"] == "ffffffff214c5fa004000000082a1000020000000811" for row in rows[-1]["sends"])
    cases.append(dict(name="send_retriggers_failed_initial_start", stages=rows))
    for disabled in ("local", "ip", "port"):
        machine = Sender(binary)
        if disabled == "local":
            machine.b(machine.manager + 12, 0)
        elif disabled == "ip":
            machine.wi(machine.peer, 0)
        else:
            machine.u.mem_write(machine.peer + 22, b"\0\0")
        machine.send()
        row = machine.snapshot()
        assert not row["calls"].get("start", 0) and not row["sends"]
        cases.append(dict(name="send_disabled_" + disabled, stages=[row]))
    # Android/Linux ABI errno values belong to the pinned originals, not to
    # Switch's libc numbering. Native comparisons must map symbolic names.
    errors = dict(EIO=5, EINTR=4, EAGAIN=11, EHOSTUNREACH=113, ENETUNREACH=101,
                  ENOBUFS=105, EBADF=9, ECONNREFUSED=111)
    for name, error in errors.items():
        machine = started(binary, False)
        before = machine.snapshot()
        machine.send_plan = [(-1, error)]
        machine.send()
        failed = machine.snapshot()
        machine.send()
        recovered = machine.snapshot()
        assert failed["returns"] == [int(name == "EHOSTUNREACH")]
        assert recovered["returns"] == failed["returns"] + [1]
        assert before["socket"] == failed["socket"] == recovered["socket"]
        assert recovered["calls"]["socket_init"] == 1 and recovered["fd"] == 37
        cases.append(dict(name="unicast_" + name, stages=[before, failed, recovered]))
    for ipv6 in (False, True):
        targets = 2 if ipv6 else 1
        for plan in ("recover", "all_fail", "host_unreachable", "short_host_errno"):
            machine = started(binary, ipv6)
            original_socket = machine.q(machine.manager + 32)
            machine.socket_plan = [38, 39]
            if plan == "recover":
                machine.send_plan = [(-1, 5)] * targets + [("full", 0)] * targets
                attempts, final_fd, result, initializations = 2 * targets, 38, 1, 2
            elif plan == "all_fail":
                machine.send_plan = [(-1, 5)] * (3 * targets)
                attempts, final_fd, result, initializations = 3 * targets, 39, 0, 3
            elif plan == "host_unreachable":
                machine.send_plan = [(-1, 113)] * targets
                attempts, final_fd, result, initializations = targets, 37, 1, 1
            else:
                machine.send_plan = [(21, 113)] * (3 * targets)
                attempts, final_fd, result, initializations = 3 * targets, 39, 0, 3
            machine.run("enable")
            row = machine.snapshot()
            assert not machine.send_plan
            assert len(row["sends"]) == attempts and row["returns"] == [result]
            assert row["fd"] == final_fd and row["calls"]["socket_init"] == initializations
            assert row["state"] == 1 and row["socket"] == original_socket and row["broadcast_owners"] == 1
            assert all(send["wire"] == "ffffffff214c5fa004000000082a1000020000000802" for send in row["sends"])
            cases.append(dict(name=f"broadcast_{'ipv6' if ipv6 else 'ipv4'}_{plan}", stages=[row]))
    for plan in ("one_success", "one_host_unreachable"):
        machine = started(binary, True)
        machine.send_plan = [(-1, 5), ("full", 0) if plan == "one_success" else (-1, 113)]
        machine.run("enable")
        row = machine.snapshot()
        assert len(row["sends"]) == 2 and row["returns"] == [1]
        assert row["calls"]["socket_init"] == 1 and row["fd"] == 37
        cases.append(dict(name="broadcast_" + plan, stages=[row]))
    machine = started(binary, False)
    original_socket = machine.q(machine.manager + 32)
    machine.socket_result = -1
    machine.send_plan = [(-1, 5), (-1, 9), (-1, 9)]
    machine.run("enable")
    failed = machine.snapshot()
    assert failed["fd"] == -1 and failed["returns"] == [0]
    assert failed["calls"]["socket_init"] == 3 and failed["calls"]["start"] == 1
    machine.socket_result = 38
    machine.send_plan = [(-1, 9), ("full", 0)]
    machine.wall_time = failed["fast_status"]
    machine.run("update")
    recovered = machine.snapshot()
    assert recovered["fd"] == 38 and recovered["socket"] == original_socket and recovered["state"] == 1
    assert recovered["returns"] == [0, 1] and recovered["calls"]["start"] == 1
    assert len(recovered["sends"]) == 5 and not machine.send_plan
    cases.append(dict(name="broadcast_reopen_failure_next_fast_update_recovers", stages=[failed, recovered]))
    for upper in (False, True):
        machine = Sender(binary)
        machine.socket_result, machine.socket_plan, machine.random_upper = 37, [-1, 37], upper
        machine.run("start")
        machine.run("enable")
        times = [1002, 1003, 1010, 1016, 1017] if upper else [1000, 1001, 1005, 1009, 1013]
        rows = [machine.snapshot()]
        for now in times:
            machine.wall_time = now
            machine.run("update")
            rows.append(machine.snapshot())
        assert [len(row["sends"]) for row in rows] == [1, 1, 2, 3, 3, 4]
        assert [row["status_tries"] for row in rows] == [1, 1, 2, 3, 3, 1]
        assert [row["sequence"] for row in rows] == [2, 2, 2, 2, 2, 3]
        full = 1017 if upper else 1013
        assert [row["next_status"] for row in rows] == [full] * 5 + [1034 if upper else 1026]
        assert [row["wire"][-4:] for row in rows[-1]["sends"]] == ["0802", "0802", "0802", "0803"]
        cases.append(dict(name="broadcast_schedule_" + ("upper" if upper else "lower"),
                          wall_times=[1000] + times, stages=rows))
    for count in (1, 2):
        machine = started(binary, False)
        machine.receive_plan = [9] * count + [-1]
        machine.send_plan = [(-1, 5), ("full", 0)]
        machine.socket_plan = [38]
        machine.run("enable")
        row = machine.snapshot()
        consumed = [i for i, event in enumerate(row["trace"]) if event[0] == "opaque_BProcess_terminal"]
        closed = [i for i, event in enumerate(row["trace"]) if event[0] == "close"]
        assert len(consumed) == count and len(closed) == 1 and max(consumed) < closed[0]
        assert row["fd"] == 38 and row["returns"] == [1] and not machine.receive_plan
        cases.append(dict(name=f"opaque_read_dispatch_before_broadcast_reopen_{count}", stages=[row]))
    elf = ELFFile(io.BytesIO(binary))
    symbols = {symbol.name: symbol for symbol in elf.get_section_by_name(".dynsym").iter_symbols()}
    functions = {key: dict(symbol=name, address=hex(symbols[name]["st_value"]), size=symbols[name]["st_size"])
                 for key, name in FUNCTIONS.items()}
    return dict(binary_sha256=IDENTITIES[identity], cases=cases, functions=functions)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-binary", required=True, type=Path)
    parser.add_argument("--shell-binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--refresh-reference", action="store_true")
    args = parser.parse_args()
    result = dict(scope=__doc__, binaries={name: audit_one(path.read_bytes(), name) for name, path in
        [("core", args.core_binary), ("shell", args.shell_binary)]}, helpers={path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (Path(__file__), ROOT / "scripts/audit-steam-client-config.py", ROOT / "scripts/audit-steam-client-fec-policy.py")})
    encoded = (json.dumps(result, indent=2) + "\n").encode()
    reference = ROOT / "scripts/fixtures/steam-discovery-send-reference.json.gz"
    if args.refresh_reference:
        assert not reference.exists()
        reference.write_bytes(gzip.compress(encoded, mtime=0))
    else:
        assert result == json.loads(gzip.decompress(reference.read_bytes()))
    args.output.write_bytes(encoded)
    print("Official complete discovery send:", {k: len(v["cases"]) for k, v in result["binaries"].items()}, "programs passed")


if __name__ == "__main__":
    main()
