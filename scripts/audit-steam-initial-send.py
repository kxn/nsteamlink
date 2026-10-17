#!/usr/bin/env python3
"""Execute official reliable frame admission, failed initial scan and continuations.

Real client stats/Frame/Connection/Channel/window/Socket/CRC instructions execute.
Serializer output, channel construction, window release, timestamp feedback,
allocation/refcount/mutex/stats and final UDP are adapters. New Frame triggers
execute the real producer again; Update triggers call its actual reliable sender
component, not the full receive/update loop. ACK uses the actual ACK handler with
a window-advance storage adapter. No real host, encryption or decoder is used.
"""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "wire", ROOT / "scripts/audit-steam-control-wire.py"
)
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)


def audit(base):
    wire.audit(base)

    class Sender(wire.audit.Sender):
        def __init__(self, crc, fail_index, error):
            self.attempts = 0
            self.fail_index, self.error = fail_index, error
            super().__init__(crc, 512, b"\x12" + wire.varint(1000) + b"x" * 1000)
            self.callbacks[0x7A8C14] = self.capture_result
            self.callbacks[0xC112A0] = lambda: self.ret()

        def send(self):
            self.transport_result = (
                self.error if self.attempts == self.fail_index else 0
            )
            self.attempts += 1
            super().send()

        def observe(self):
            ch = self.channels[2]
            value = dict(
                wire=list(self.sent),
                outstanding=self.h(ch + 122) - self.h(ch + 120),
                next_id=self.h(ch + 122),
                result=self.frame_result,
            )
            self.sent.clear()
            return value

        def stats(self):
            self.call(0x7A8BBC, self.client, 3, self.message)

    cases = []
    for crc in (0, 1):
        for fail_index in range(3):
            for error in range(1, 5):
                for trigger in ("update", "new_frame", "ack_update"):
                    if trigger == "ack_update" and fail_index == 0:
                        continue  # only ACK the successfully sent prefix
                    r = Sender(crc, fail_index, error)
                    r.stats()
                    first = r.observe()
                    assert (
                        len(first["wire"]) == fail_index + 1
                        and first["outstanding"] == 3
                    )
                    assert first["result"] == (0 if error == 1 else error)
                    r.now += 1
                    if trigger == "new_frame":
                        r.payload = b"\x12\x00"
                        r.stats()
                    else:
                        if trigger == "ack_update":
                            p = r.alloc(4096)
                            r.packet(p, typ=7, stamp=r.now, id=fail_index - 1)
                            r.w32(p + 52, 17)
                            r.w32(p + 77, r.now - 1)
                            ch = r.channels[2]
                            r.call(0x7F94B8, ch, ch + 40, p, r.now)
                        r.frame_result = r.call(0x7F8AC4, r.channels[2], r.now)
                    second = r.observe()
                    assert len(second["wire"]) == 3 - fail_index + int(
                        trigger == "new_frame"
                    )
                    cases.append(
                        dict(
                            input=dict(
                                crc=crc,
                                fail_index=fail_index,
                                error=error,
                                trigger=trigger,
                            ),
                            observed=[first, second],
                        )
                    )
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--refresh-reference", action="store_true")
    args = parser.parse_args()
    base = wire.outgoing.load(args.binary, args.output.with_name("initial-base.json"))
    report = dict(binary_sha256=wire.outgoing.SHA, scope=__doc__, cases=audit(base))
    reference = ROOT / "scripts/fixtures/steam-initial-send-reference.json"
    if args.refresh_reference:
        if reference.exists():
            assert report == json.loads(reference.read_text())
        reference.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert report == json.loads(reference.read_text())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"Official initial reliable transactions: {len(report['cases'])} cases passed"
    )


if __name__ == "__main__":
    main()
