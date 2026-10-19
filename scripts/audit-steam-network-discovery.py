#!/usr/bin/env python3
"""Execute official Android shell discovery scheduling/error branches.

Original watcher constructor/slots, BStart, discovery ctor/BInit/BReceive and
manager Update/HandleNetworkChanged execute. Qt/OS/socket calls, empty CUtlBuffer
storage and remote-session APIs are declared terminals. Stop is a terminal on
initially empty managers only. BProcess is a terminal: the successful datagram is
opaque, not a valid protocol/host-discovery proof. No Qt event loop, natural
network-change producer, DNS, Steam connection, physical network or device proof.
"""
import argparse
import hashlib
import importlib.util
import io
import json
from collections import Counter
from pathlib import Path

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "shell_policy", ROOT / "scripts/audit-steam-client-fec-policy.py"
)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

FUNCTIONS = {
    "watcher_ctor": "_ZN28CServerManagerNetworkWatcherC1EP14CServerManager",
    "network_slot": "_ZN28CServerManagerNetworkWatcher21OnNetworkStateChangedEN21QNetworkAccessManager20NetworkAccessibilityE",
    "timer_slot": "_ZN28CServerManagerNetworkWatcher8OnUpdateEv",
    "meta_dispatch": "_ZN28CServerManagerNetworkWatcher11qt_metacallEN11QMetaObject4CallEiPPv",
    "start": "_ZN14CServerManager6BStartEv",
    "update": "_ZN14CServerManager6UpdateEv",
    "network_api": "_ZN14CServerManager20HandleNetworkChangedEv",
    "socket_ctor": "_ZN16CDiscoverySocketC1Ev",
    "socket_init": "_ZN16CDiscoverySocket5BInitEv",
    "socket_receive": "_ZN16CDiscoverySocket8BReceiveEP10CIPAndPortP10CUtlBuffer",
    "socket_destroy": "_ZN16CDiscoverySocketD1Ev",
}


class Discovery(policy.Shell):
    def __init__(self, binary, state=0):
        self.ready = False
        super().__init__(binary)
        self.manager = self.alloc(1024)
        self.watcher = self.alloc(64)
        self.wq(self.watcher + 16, self.manager)
        self.wi(self.manager + 8, state)
        # Suppress unrelated status/expiry branches unless explicitly tested.
        self.wq(self.manager + 48, 2000)
        self.wq(self.manager + 88, 2000)
        self.access = 1
        self.socket_result = 37
        self.socket_plan = []
        self.bind_result = self.option_result = self.fcntl_result = 0
        self.remote_result = 1
        self.reads = []
        self.calls = Counter()
        self.trace = []
        self.addresses = {self.symbols[v]: k for k, v in FUNCTIONS.items()}
        self.ready = True

    def hook(self, u, pc, size, data):
        if not self.ready:
            return super().hook(u, pc, size, data)
        if pc in self.addresses:
            self.calls[self.addresses[pc]] += 1
        name = self.plts.get(pc)
        if name is None:
            return super().hook(u, pc, size, data)
        args = [self.r(i) for i in range(6)]
        if name == "_ZN14CServerManager4StopEv":
            # Only initial BStart fixtures use this adapter. It must never
            # manufacture cleanup of an already live socket/session.
            assert self.i(self.manager + 8) == 0
            assert self.q(self.manager + 24) == self.q(self.manager + 32) == 0
            self.trace.append(["initial_empty_stop"])
            self.ret()
        elif name == "_ZN7QObject7connectEPKS_PKcS1_S3_N2Qt14ConnectionTypeE":
            self.trace.append(["connect", self.cstring(args[1]), self.cstring(args[3]), args[4]])
            self.ret()
        elif name == "_ZNK21QNetworkAccessManager17networkAccessibleEv":
            self.trace.append(["network_accessible", self.access])
            self.ret(self.access)
        elif name == "_ZN6QTimer5startEi":
            self.trace.append(["timer_start_ms", args[1]])
            self.ret()
        elif name == "_ZN7QObject11qt_metacallEN11QMetaObject4CallEiPPv":
            self.ret(args[2])  # base QObject has already resolved inherited IDs
        elif name in ("_ZN7QObjectC2EPS_", "_ZN21QNetworkAccessManagerC1EP7QObject", "_ZN6QTimerC1EP7QObject", "_ZN11QMetaObject10ConnectionD1Ev"):
            self.ret()
        elif name == "socket":
            result = self.socket_plan.pop(0) if self.socket_plan else self.socket_result
            self.trace.append(["socket", args[0], args[1], args[2], result])
            self.ret(result & 0xFFFFFFFFFFFFFFFF)
        elif name in ("setsockopt", "bind", "fcntl", "close"):
            self.trace.append([name, args[0], args[1], args[2] if name in ("fcntl", "setsockopt") else 0])
            result = {"bind": self.bind_result, "setsockopt": self.option_result,
                      "fcntl": self.fcntl_result}.get(name, 0)
            self.ret(result & 0xFFFFFFFFFFFFFFFF)
        elif name == "_ZN20CRemoteClientSessionC1EP28IRemoteClientSessionDelegate9EUniverse11ESteamRealm":
            assert args[1:4] == [self.manager, 1, 0]
            self.trace.append(["remote_ctor", args[2], args[3]])
            self.ret()
        elif name == "_ZN20CRemoteClientSession8BConnectEv":
            self.trace.append(["remote_connect", self.remote_result])
            self.ret(self.remote_result)
        elif name == "_ZN20CRemoteClientSession6UpdateEv":
            self.trace.append(["remote_update"])
            self.ret()
        elif name == "_ZN10CUtlBufferC1Ev":
            self.u.mem_write(args[0], bytes(64))
            self.wi(args[0] + 12, -1)  # externally managed fixture storage
            self.ret()
        elif name == "_ZN10CUtlBuffer18AddNullTerminationEv":
            self.ret()
        elif name == "_ZN10CUtlBuffer14EnsureCapacityEi":
            if not self.q(args[0]):
                self.wq(args[0], self.alloc(args[1]))
                self.wi(args[0] + 8, args[1])
            self.ret()
        elif name == "_ZN10CUtlBuffer7SeekPutENS_10SeekType_tEi":
            self.wi(args[0] + 20, args[2])
            self.ret()
        elif name == "recvfrom":
            assert self.reads, "unplanned extra receive"
            result = self.reads.pop(0)
            self.trace.append(["recvfrom", args[0], args[2], args[3], result])
            if result > 0:
                self.u.mem_write(args[1], b"X" * result)
            self.ret(result & 0xFFFFFFFFFFFFFFFF)
        elif name in ("_ZN10CIPAddress14SetFromSockadrEPKvmPt", "_ZN10CIPAddress20BConvertMappedToIPv4Ev"):
            self.trace.append(["address_terminal", name])
            self.ret(1)
        elif name == "_ZN14CServerManager8BProcessEP10CIPAndPortP10CUtlBufferb":
            self.trace.append(["opaque_datagram", self.i(args[2] + 20)])
            self.ret(1)
        elif name == "time":
            self.ret(1000)
        elif name == "WeakRandomInt":
            self.trace.append(["random_range", args[0], args[1]])
            self.ret(args[0])  # explicit lower-bound time fixture
        elif name == "_ZN14CServerManager13RequestStatusEv":
            self.trace.append(["request_status_terminal"])
            self.ret()
        elif name == "_ZNK11CUtlHashMapIyb10CDefEqualsIyE11HashFunctorIyEyE4FindERKy":
            self.ret(0)  # explicitly present: don't exercise host expiry here
        elif name == "Log":
            self.trace.append(["log", self.cstring(args[0])])
            self.ret()
        else:
            return super().hook(u, pc, size, data)

    def run(self, which, *args):
        return self.call(self.symbols[FUNCTIONS[which]], *args)

    def snapshot(self):
        return dict(state=self.i(self.manager + 8),
                    socket=self.q(self.manager + 32),
                    remote=self.q(self.manager + 24),
                    updating=self.i(self.manager + 376) & 255,
                    next_status=self.q(self.manager + 48),
                    calls=dict(sorted(self.calls.items())), trace=self.trace.copy())


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == policy.SHA
    cases = []
    for state in (0, 1, 4, 5):
        for access in (-1, 0, 1):
            d = Discovery(binary, state)
            d.access = access
            d.run("watcher_ctor", d.watcher, d.manager)
            assert d.calls["start"] == (state == 0)
            assert ["timer_start_ms", 100] in d.trace
            assert sum(t[0] == "connect" for t in d.trace) == 2
            cases.append(dict(input=dict(kind="constructor", state=state, access=access), observed=d.snapshot()))
            d = Discovery(binary, state)
            d.run("network_slot", d.watcher, access & 0xFFFFFFFF)
            assert d.calls["start"] == (state == 0)
            assert not d.calls["network_api"]
            cases.append(dict(input=dict(kind="network_slot", state=state, access=access), observed=d.snapshot()))
            d = Discovery(binary, state)
            argv = d.alloc(16)
            value = d.alloc(4)
            d.wi(value, access)
            d.wq(argv + 8, value)
            d.run("meta_dispatch", d.watcher, 0, 1, argv)
            assert d.calls["network_slot"] == 1 and d.calls["start"] == (state == 0)
            assert not d.calls["network_api"]
            cases.append(dict(input=dict(kind="meta_network_slot", state=state, access=access), observed=d.snapshot()))
    for local, remote, socket_result, remote_result in (
        (1, 0, 37, 1), (1, 1, -1, 1), (0, 1, 37, 0),
        (0, 1, 37, 1), (1, 1, 37, 0),
    ):
        d = Discovery(binary)
        d.b(d.manager + 12, local)
        d.b(d.manager + 13, remote)
        d.socket_result, d.remote_result = socket_result, remote_result
        d.reads = [-1] if local and socket_result >= 0 else []
        result = d.run("start", d.manager)
        failed = local and socket_result < 0
        assert bool(result) == (not failed)
        assert d.i(d.manager + 8) == (not failed)
        assert bool(d.q(d.manager + 24)) == (bool(remote) and not failed)
        assert d.calls["update"] == (not failed)
        assert d.calls["socket_destroy"] == bool(failed)
        cases.append(dict(input=dict(kind="start", local=local, remote=remote,
                                     socket_result=socket_result, remote_result=remote_result),
                          result=result, observed=d.snapshot()))
    for ending in (-1, 0):
        for prefix in ([], [7]):
            d = Discovery(binary, 1)
            sock = d.alloc(8)
            d.wi(sock + 4, 37)
            d.wq(d.manager + 32, sock)
            snapshots = []
            for reads in (prefix + [ending], [9, -1]):
                d.reads = reads.copy()
                argv = d.alloc(16)
                d.run("meta_dispatch", d.watcher, 0, 0, argv)
                assert not d.reads
                snapshots.append(d.snapshot())
            assert all(s["state"] == 1 and s["socket"] == sock and s["updating"] == 0 for s in snapshots)
            assert not d.calls["start"] and not d.calls["socket_destroy"]
            assert ["opaque_datagram", 9] in d.trace
            cases.append(dict(input=dict(kind="receive_cycles", prefix=prefix, ending=ending), observed=snapshots))
    for plan, bind, option, fcntl in (
        ([37], 0, 0, 0), ([-1, 37], 0, 0, 0), ([-1, -1], 0, 0, 0),
        ([37], -1, 0, 0), ([37], 0, -1, 0), ([37], 0, 0, -1),
    ):
        d = Discovery(binary)
        d.socket_plan = plan.copy()
        d.bind_result, d.option_result, d.fcntl_result = bind, option, fcntl
        sock = d.alloc(8)
        d.run("socket_ctor", sock)
        result = d.run("socket_init", sock)
        assert result == (plan[-1] >= 0) and not d.socket_plan
        cases.append(dict(input=dict(kind="socket_init", socket_plan=plan, bind=bind,
                                     option=option, fcntl=fcntl), result=result, observed=d.snapshot()))
    for state in (0, 1, 4, 5):
        d = Discovery(binary, state)
        rows = d.alloc(104 * 4)
        d.wq(d.manager + 144, rows)
        d.wi(d.manager + 168, 4)
        for n, discriminator in enumerate((-2, -1, 0, 4)):
            d.wi(rows + n * 104 + 96, discriminator)
            d.wq(rows + n * 104 + 40, 900 + n)
        d.run("network_api", d.manager)
        stamps = [d.q(rows + n * 104 + 40) for n in range(4)]
        assert stamps == ([900, 0, 0, 0] if state == 1 else [900, 901, 902, 903])
        assert d.calls["update"] == (state == 1)
        cases.append(dict(input=dict(kind="explicit_network_api", state=state),
                          observed=d.snapshot(), row_field_40=stamps))
    elf = ELFFile(io.BytesIO(binary))
    syms = {s.name: s for s in elf.get_section_by_name(".dynsym").iter_symbols()}
    identities = []
    for label, name in FUNCTIONS.items():
        sym = syms[name]
        address, size = sym["st_value"], sym["st_size"]
        # Hash the original file bytes, without dynamic relocation.
        text = elf.get_section_by_name(".text")
        offset = address - text["sh_addr"]
        identities.append(dict(label=label, name=name, address=address, size=size,
                               sha256=hashlib.sha256(text.data()[offset:offset + size]).hexdigest()))
    helpers = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (
        Path(__file__), ROOT / "scripts/audit-steam-client-fec-policy.py")}
    return dict(binary_sha256=policy.SHA, scope=__doc__, functions=identities, helpers=helpers, cases=cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--refresh-reference", action="store_true")
    args = parser.parse_args()
    result = audit(args.binary.read_bytes())
    reference = ROOT / "scripts/fixtures/steam-network-discovery-reference.json"
    if args.refresh_reference:
        assert not reference.exists()
        reference.write_text(json.dumps(result, indent=2) + "\n")
    else:
        assert result == json.loads(reference.read_text())
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"Official discovery: {len(result['cases'])} trigger/start/read cases")


if __name__ == "__main__":
    main()
