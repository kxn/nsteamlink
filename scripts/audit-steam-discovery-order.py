#!/usr/bin/env python3
"""Original Update receives a pending ticket before checking due retries.

Original Start/request producer, Update, generated response parser/handler/AES
execute. BReceive and BProcess dispatch are explicit adapters; BProcess jumps
to the actual parsed response handler, then returns to the original Update.
No claim of original wire-envelope admission, Qt scheduling or physical network.
All other terminals inherit the transaction audit's documented boundaries.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X30

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("transaction", ROOT / "scripts/audit-steam-streaming-transaction.py")
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
SHA = "15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2"


class Order(t.Transaction):
    def __init__(self, binary, reply):
        self.pending = reply
        self.order = []
        super().__init__(binary)
        self.wq(self.manager + 48, 0x7FFFFFFFFFFFFFFF)
        self.wi(self.manager + 80, 3)
        self.wq(self.manager + 32, self.alloc(8))
        self.peer, self.response_obj, self.shim = self.alloc(24), self.alloc(512), self.alloc(4)
        self.u.mem_write(self.peer, bytes(range(1, 25)))
        self.callbacks[self.shim] = self.return_process

    def return_process(self):
        self.u.reg_write(UC_ARM64_REG_X30, self.process_return)
        self.ret(1)

    def hook(self, u, pc, size, data):
        name = self.plts.get(pc, "")
        if name == "_ZN16CDiscoverySocket8BReceiveEP10CIPAndPortP10CUtlBuffer":
            self.order.append(["read", self.wall_time, int(self.pending)])
            self.ret(int(self.pending))
        elif name == "_ZN14CServerManager8BProcessEP10CIPAndPortP10CUtlBufferb":
            assert self.pending
            self.pending = False
            self.order.append(["response_handler", self.wall_time])
            self.process_return = self.u.reg_read(UC_ARM64_REG_X30)
            self.u.reg_write(UC_ARM64_REG_X30, self.shim)
            for index, value in enumerate((self.manager, self.peer, 123, self.response_obj)):
                self.u.reg_write(UC_ARM64_REG_X0 + index, value)
            self.jump(self.symbols["_ZN14CServerManager28HandleStartStreamingResponseERK10CIPAndPortyPK33CMsgRemoteDeviceStreamingResponse"])
        else:
            if name == "_ZN14CServerManager25SendStartStreamingRequestEv":
                self.order.append(["send_request", self.wall_time])
            super().hook(u, pc, size, data)


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == SHA
    cases = []
    for reply in (False, True):
        machine = Order(binary, reply)
        machine.start(False)
        rid = machine.i(machine.manager + 0x200)
        v = t.discovery.varint
        cipher = t.discovery.encrypted()
        response = b"\x08" + v(rid) + b"\x10\x00\x18" + v(61024) + b"\x22" + v(len(cipher)) + cipher
        assert machine.parse(machine.response_obj, response, t.discovery.RESPONSE)
        rows = [machine.observe("initial")]
        machine.wall_time = 1001
        rows.append(machine.observe("idle_without_update"))
        for label in ("due_update", "same_wall_next_update"):
            machine.call(machine.symbols["_ZN14CServerManager6UpdateEv"], machine.manager)
            rows.append(machine.observe(label))
        counts = [sum(m["tag"] == 5 for m in row["messages"]) for row in rows]
        assert counts == ([1, 1, 1, 1] if reply else [1, 1, 2, 2]), counts
        assert rows[-1]["state"] == (6 if reply else 5)
        assert not machine.assertions
        cases.append(dict(reply=reply, response=response.hex(), request_id=rid,
                          steps=rows, request_counts=counts, order=machine.order,
                          executed=sorted(machine.executed)))
    return dict(binary_sha256=SHA, scope=__doc__, cases=cases,
                functions=t.inventory(binary, cases),
                helper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--refresh-reference", action="store_true")
    args = parser.parse_args()
    result = audit(args.binary.read_bytes())
    reference = ROOT / "scripts/fixtures/steam-discovery-order-reference.json"
    if args.refresh_reference:
        assert not reference.exists()
        reference.write_text(json.dumps(result, indent=2) + "\n")
    else:
        assert result == json.loads(reference.read_text())
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print("Official Update order: pending-ticket and empty-input due branches passed")


if __name__ == "__main__":
    main()
