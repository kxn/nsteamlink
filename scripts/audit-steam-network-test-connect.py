#!/usr/bin/env python3
"""Official dedicated-test Run -> BConnect -> receiver budget and first wire.

Original thread-body state selection, BConnect, Connection Create/constructor,
SetChannelMaxRecvDelay/GetChannel, Connect, packet constructor/CRC/SocketSend,
Cancel and Reset execute. Backend constructor/activation, socket storage, endpoint,
thread scheduling, final I/O/close and transport-client storage are explicit
adapters. The first global-network boundary records state then enters original
Cancel; this is not a naturally scheduled OS thread or a real Steam connection.
Only the Switch-supported UDP transport is exercised, with supplied mode/address.
"""
import argparse
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
from elftools.elf.elffile import ELFFile
from unicorn.arm64_const import UC_ARM64_REG_X0

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "flow", ROOT / "scripts/audit-steam-network-test-fec-flow.py"
)
flow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flow)
STOP, TEST = flow.config.STOP, flow.TEST
REFERENCE = ROOT / "scripts/fixtures/steam-network-test-connect-reference.json.gz"


class Connect(flow.Flow):
    def __init__(self, binary, inp, patch=None):
        self.inp, self.chain, self.wires, self.at_network = inp, [], [], []
        self.entered, self.entries, self.budget_writes = set(), {}, []
        super().__init__(binary, patch)
        for name, addr in self.symbols.items():
            if addr and (
                name.startswith("_ZN12CNetworkTest")
                or name.startswith("_ZN17CStreamConnection")
                or name.startswith("_ZN14CStreamChannel")
                or name.startswith("_ZN13CStreamSocket")
                or name.startswith("_ZN13CStreamPacket")
            ):
                self.entries.setdefault(addr, []).append(name)
        self.call(0xCCEC98)
        self.now = inp["start"]
        self.callbacks[STOP + 0x900] = self.activate
        self.callbacks[STOP + 0x904] = lambda: self.ret()
        self.callbacks[STOP + 0x908] = self.send

    def activate(self):
        self.chain.append("activate")
        self.ret(int(self.inp["activate"]))

    def send(self):
        packet = self.r(1)
        self.wires.append(
            bytes(self.u.mem_read(self.q(packet + 56), self.i(packet + 52))).hex()
        )
        self.ret(self.inp["send_result"])

    def hook(self, u, pc, size, unused):
        self.entered.update(self.entries.get(pc, []))
        name = self.plts.get(pc, "")
        if name == "_ZN19CStreamTransportUDPC1Eb":
            self.chain.append("udp_constructor")
            vt = self.alloc(128)
            self.wq(self.r(0), vt)
            for offset, callback in [
                (8, STOP + 0x904),
                (16, STOP + 0x900),
                (72, STOP + 0x908),
            ]:
                self.wq(vt + offset, callback)
            self.ret()
        elif (
            name
            == "_ZN22CStreamTransportClientC1EP16IStreamTransport9EUniverse11ESteamRealmyRK10CUtlBuffer"
        ):
            self.chain.append("transport_client_storage")
            vt = self.alloc(128)
            self.wq(self.r(0), vt)
            self.wq(vt + 56, STOP + 0x904)
            self.ret()
        elif name == "_ZN13CStreamSocketC1EP16IStreamTransport":
            self.chain.append("socket_storage")
            self.wq(self.r(0), self.r(1))
            self.ret()
        elif name == "_ZN17CStreamConnection22SetChannelMaxRecvDelayEhi":
            self.budget_writes.append([self.r(1), self.r(2)])
            super().hook(u, pc, size, unused)
        elif name == "_Z20StreamProcessNetworkv":
            connection = self.q(TEST + 0x128)
            channel = self.q(connection + 112 + 3 * 8) if connection else 0
            self.at_network.append(
                dict(
                    status=self.i(TEST + 12),
                    phase=self.i(TEST + 0x114),
                    delay=self.i(channel + 28) if channel else None,
                )
            )
            if len(self.at_network) == 1 and connection:
                # Explicit network-driver cancellation, original Cancel body.
                u.reg_write(UC_ARM64_REG_X0, TEST)
                self.jump(self.symbols["_ZN12CNetworkTest6CancelEv"])
            else:
                self.ret()
        elif name in ["__cxa_atexit", "Log", "_ZN22CStreamTransportClient6UpdateEv"]:
            self.ret(0)
        elif name == "_ZNK10CIPAndPort8ToStringEPcjb":
            self.u.mem_write(self.r(1), b"fixture-endpoint\0")
            self.ret()
        else:
            super().hook(u, pc, size, unused)

    def result(self):
        return dict(
            chain=self.chain,
            wires=self.wires,
            budget_writes=self.budget_writes,
            at_network=self.at_network,
            status=self.i(TEST + 12),
            phase=self.i(TEST + 0x114),
            connection_cleared=self.q(TEST + 0x128) == 0,
            transport_cleared=self.q(TEST + 0x120) == 0,
            source_assertions=self.assertions,
            patch_hits=self.patch_hits,
            executed=sorted(self.entered),
        )


def run(binary, inp, patch=None):
    r = Connect(binary, inp, patch)
    # Supplied test-mode/UDP metadata and running status. The original thread
    # body itself moves the session to Connecting before entering BConnect.
    r.wi(TEST + 8, inp["mode"])
    r.wi(TEST + 12, 1)
    r.wi(TEST + 0x118, 1)
    r.call(r.symbols["_ZN12CNetworkTest14RunNetworkTestEv"], TEST)
    return dict(input=inp, observed=r.result())


def inventory(binary, cases):
    elf = ELFFile(io.BytesIO(binary))
    names = set().union(*(set(c["observed"]["executed"]) for c in cases))
    rows = []
    for s in elf.get_section_by_name(".dynsym").iter_symbols():
        if s.name not in names:
            continue
        address, size = s["st_value"], s["st_size"]
        for seg in elf.iter_segments():
            if (
                seg["p_type"] == "PT_LOAD"
                and seg["p_vaddr"] <= address < seg["p_vaddr"] + seg["p_filesz"]
            ):
                start = address - seg["p_vaddr"]
                rows.append(
                    dict(
                        name=s.name,
                        address=address,
                        size=size,
                        sha256=hashlib.sha256(
                            seg.data()[start : start + size]
                        ).hexdigest(),
                    )
                )
                break
    assert len(rows) == len(names)
    return sorted(rows, key=lambda x: x["name"])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--refresh-reference", action="store_true")
    args = p.parse_args()
    binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == flow.SHA
    inputs = [
        dict(mode=mode, start=start, activate=activate, send_result=result)
        for mode in (1, 2)
        for start in (0, 1000000, 0xFFFFFFF0)
        for activate, result in [(True, 0), (True, 1), (True, 2), (False, 0)]
    ]
    cases = [run(binary, i) for i in inputs]
    for c in cases:
        o = c["observed"]
        assert not o["source_assertions"]
        assert o["status"] == (3 if c["input"]["activate"] else 4) and o["phase"] == 0
        assert o["connection_cleared"] and o["transport_cleared"]
        if c["input"]["activate"]:
            assert o["budget_writes"] == [[3, 6553]] and o["at_network"][0] == dict(
                status=1, phase=1, delay=6553
            )
            assert len(o["wires"]) == 1 and bytes.fromhex(o["wires"][0])[
                13:
            ] == bytes.fromhex("c73d8f3c")
        else:
            assert not o["wires"] and not o["budget_writes"]
    before = struct.unpack_from(
        "<I", flow.config.BASE["load_image"](binary)[0], 0xCAA018
    )[0]
    after = 0x52800002 | (65 << 5)  # MOVZ W2,65, replacing original 6553.
    mutant = run(binary, inputs[4], (0xCAA018, before, after))
    assert mutant["observed"]["patch_hits"] == [0xCAA018]
    assert not mutant["observed"]["source_assertions"]
    assert mutant["observed"]["at_network"][0]["delay"] == 65
    report = dict(
        binary_sha256=flow.SHA,
        scope=__doc__,
        cases=cases,
        functions=inventory(binary, cases),
        mutation=dict(
            original=cases[4], mutant=mutant, pc=0xCAA018, before=before, after=after
        ),
    )
    if args.refresh_reference:
        assert not REFERENCE.exists()
        REFERENCE.write_bytes(
            gzip.compress((json.dumps(report, indent=2) + "\n").encode(), mtime=0)
        )
    else:
        assert json.loads(gzip.decompress(REFERENCE.read_bytes())) == report
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        "Original network-test connect:",
        len(cases),
        "cases,",
        len(report["functions"]),
        "function identities, 1 executed delay counterfactual",
    )


if __name__ == "__main__":
    main()
