#!/usr/bin/env python3
"""Execute official Frame/Connection send gates and control caller error policy.

Frame constructor, Frame::Send, Connection::Send/SendUnreliable and the client
caller execute pinned ARM64 instructions. Protobuf Put, packet allocation,
channel lookup/send result, destructor and ordinary encryption are adapters.
Crypto-fault cases execute original BEncrypt with HMAC/AES failure adapters;
they expose an unsafe official failure path, not a production-equivalence claim.
No packet window, final wire, real Steam host or decoder is exercised here.
"""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "outgoing", ROOT / "scripts/audit-steam-outgoing.py"
)
outgoing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(outgoing)


def audit(base):
    Run, STOP = base["Run"], base["STOP"]

    class Sender(Run):
        def __init__(self, state=1, result=0):
            super().__init__()
            self.conn, self.channel, self.client, self.frame, self.message, self.key = (
                0x20000000 + i * 4096 for i in range(6)
            )
            self.result = result
            self.message_type = 6
            self.actions = []
            self.frame_result = None
            self.crypto_result = None
            self.packet_ptr = 0
            self.w32(self.conn + 16, state)
            self.wq(self.client + 280, self.conn)
            self.w32(self.client + 256, 6)
            self.wq(self.client + 64, self.key)
            self.w32(self.client + 84, 16)
            self.wq(self.client + 128, 7)
            self.callbacks.update(
                {
                    0xC0E2D0: lambda: self.jump(0x7F2AF4),
                    0xC0E2E0: self.put,
                    0xC0E2F0: lambda: self.jump(0x7F3078),
                    0xC10FF0: lambda: self.jump(0x7FB9B4),
                    0xC11000: lambda: self.jump(0x7FBB58),
                    0xC0E390: self.lookup,
                    0xC111F0: lambda: self.send("reliable"),
                    0xC11210: lambda: self.send("unreliable"),
                    0xC0E3A0: self.encrypt,
                    0xC0E120: self.destroy,
                    0xC0E030: lambda: self.action("disconnect"),
                    0x7A7E08: self.plain_result,
                    0x7A7E78: self.encrypted_result,
                    0x7A7E68: self.encryption_result,
                    0xBFF3D0: self.memcpy,
                }
            )

        def jump(self, address):
            self.u.reg_write(base["UC_ARM64_REG_PC"], address)

        def call(self, address, *params):
            self.u.reg_write(base["UC_ARM64_REG_SP"], 0x300FF000)
            self.u.reg_write(base["UC_ARM64_REG_X30"], STOP)
            self.run(address, *params)
            return self.r(0) & 0xFFFFFFFF

        def put(self):
            self.packet_ptr = p = self.alloc(4096)
            self.packet(p, typ=0, stamp=0, received=0, retry=0, id=0)
            self.w32(p + 52, 16)
            self.u.mem_write(p + 77, bytes.fromhex("00aabb"))
            self.wq(self.r(0) + 8, p)
            self.action("put")

        def lookup(self):
            self.actions.append(dict(action="lookup", channel=self.r(1)))
            self.ret(self.channel)

        def send(self, kind):
            p = self.r(1)
            self.actions.append(
                dict(
                    action="channel_send",
                    kind=kind,
                    body=bytes(
                        self.u.mem_read(self.q(p + 56) + 13, self.i(p + 52) - 13)
                    ).hex(),
                )
            )
            self.ret(self.result)

        def action(self, name):
            self.actions.append(dict(action=name))
            self.ret()

        def encrypt(self):
            self.actions.append(dict(action="encrypt", sequence=self.r(1)))
            self.ret(1)

        def destroy(self):
            self.action("destroy")
            self.w(
                0, 0xFEED
            )  # Caller must not interpret a destructor's x0 as Send's result.

        def plain_result(self):
            if self.message_type in (1, 2, 6, 7):
                self.frame_result = self.r(0) & 0xFFFFFFFF

        def encrypted_result(self):
            self.frame_result = self.r(0) & 0xFFFFFFFF

        def encryption_result(self):
            self.crypto_result = self.r(0) & 0xFFFFFFFF

        def memcpy(self):
            dest, source, count = self.r(0), self.r(1), self.r(2)
            if count:
                self.u.mem_write(dest, bytes(self.u.mem_read(source, count)))
            self.ret(dest)

        def frame_send(self, reliable, present=True):
            self.call(0x7F2AF4, self.frame, 1, 6)
            self.w(0, self.frame)
            self.put()
            self.actions = []
            self.frame_result = self.call(
                0x7F3078, self.frame, self.conn if present else 0, reliable
            )

        def control_send(self, message):
            self.message_type = message
            self.call(0x7A7D90, self.client, message, self.message)

        def observed(self):
            return dict(
                frame_result=self.frame_result,
                state=self.i(self.conn + 16),
                client_state=self.i(self.client + 256),
                sequence=self.q(self.client + 128),
                actions=self.actions,
            )

    cases = []

    def record(name, group, inputs, observed):
        cases.append(dict(case=name, group=group, input=inputs, observed=observed))

    for state in range(4):
        for reliable in (False, True):
            for result in range(5):
                r = Sender(state, result)
                r.frame_send(reliable)
                assert r.frame_result == (result if state == 1 else 3)
                assert sum(a["action"] == "channel_send" for a in r.actions) == int(
                    state == 1
                )
                record(
                    f"frame_state{state}_reliable{int(reliable)}_channel{result}",
                    "frame_gate",
                    dict(
                        state=state,
                        reliable=reliable,
                        channel_result=result,
                        connection=True,
                    ),
                    r.observed(),
                )
    for reliable in (False, True):
        r = Sender()
        r.frame_send(reliable, False)
        assert r.frame_result == 3 and not r.actions
        record(
            f"frame_null_reliable{int(reliable)}",
            "frame_gate",
            dict(state=1, reliable=reliable, channel_result=0, connection=False),
            r.observed(),
        )
    for state in range(4):
        for message in (1, 2, 6, 7, 8, 106):
            for result in range(5):
                r = Sender(state, result)
                r.control_send(message)
                assert r.frame_result == (result if state == 1 else 3)
                assert not any(a["action"] == "disconnect" for a in r.actions)
                assert r.i(r.conn + 16) == state and r.i(r.client + 256) == 6
                assert r.q(r.client + 128) == (7 if message in (1, 2, 6, 7) else 8)
                assert r.crypto_result == (None if message in (1, 2, 6, 7) else 1)
                record(
                    f"control_state{state}_type{message}_channel{result}",
                    "control_caller",
                    dict(state=state, message=message, channel_result=result),
                    r.observed(),
                )
    for state in range(4):
        for stage in ("hmac", "aes"):
            r = Sender(state)
            r.callbacks[0xC0E3A0] = lambda: r.jump(0x7F342C)
            r.callbacks[0xC09A70] = lambda: r.ret(int(stage == "aes"))
            r.callbacks[0xC099A0] = lambda: r.ret(0)
            r.control_send(106)
            assert r.crypto_result == 0
            sent = [a for a in r.actions if a["action"] == "channel_send"]
            assert (sent[0]["body"] == "6aaabb") if sent else state != 1
            assert not any(a["action"] == "disconnect" for a in r.actions)
            record(
                f"crypto_fault_state{state}_{stage}",
                "crypto_fault",
                dict(state=state, stage=stage),
                r.observed(),
            )
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--refresh-reference", action="store_true")
    args = parser.parse_args()
    base = outgoing.load(args.binary, args.output.with_name("official-branches.json"))
    report = dict(binary_sha256=outgoing.SHA, scope=__doc__, cases=audit(base))
    reference = ROOT / "scripts/fixtures/steam-send-admission-reference.json"
    if args.refresh_reference:
        if reference.exists():
            previous = {
                c["case"]: c for c in json.loads(reference.read_text())["cases"]
            }
            for case in report["cases"]:
                if case["case"] in previous:
                    assert case == previous[case["case"]], case["case"]
        reference.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert report == json.loads(reference.read_text()), (
            "official send contract changed"
        )
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"Official Android send admission: {len(report['cases'])} original-instruction cases passed"
    )


if __name__ == "__main__":
    main()
