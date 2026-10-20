#!/usr/bin/env python3
"""Replay official Linux DecodeFrame/key-mark FlushPendingData and queued output.

Same pinned Valve client as the AVCodec/player audits. Original default Frame
construction/reset runs; a legal already-parsed plaintext Frame descriptor and
externally owned carrier are explicit received-frame boundary inputs. Original
DecodeFrame, FlushPendingData, OnThink and FinalDecode run, followed by original
player consumption. Codec APIs, OS/UI/SDL terminals inherit the player audit;
no Socket/CRC/crypto, full frame parser, natural SDK or hardware/loader proof.
Carrier external references remain fixture-owned; this is not a full receiver
or packet lifetime audit. SDK flush calls are observed, never inferred from the
method name. AU bytes are copied from actual original parser/send arguments.
"""

import argparse
import gzip
import importlib.util
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "player", ROOT / "scripts/audit-steam-client-avcodec-player.py"
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
m.codec.FUNCTIONS = {
    0x1942F0: "frame_default_constructor",
    0x1942C0: "frame_reset",
    0x3260D0: "decode_frame",
    0x325EC0: "flush_pending_data",
    0x326F30: "on_think",
    0x324190: "final_decode",
}


class Keys(m.Player):
    def hook(self, u, a, z, d):
        if a == 0x325EC0:
            self.events.append(["flush_pending"])
        name = self.names.get(a, "")
        if name == "avcodec_flush_buffers":
            self.events.append(["sdk_flush"])
            self.ret()
        else:
            if name == "avcodec_send_packet":
                p = self.arg(1)
                self.events.append(
                    ["au", bytes(self.u.mem_read(self.q(p + 24), self.i(p + 32))).hex()]
                )
            super().hook(u, a, z, d)

    def feed(self, fid, sequence, flags, offset, size):
        self.events = []
        self.assertions = []
        if fid not in self.slots:
            self.slots[fid] = self.seed(fid)
        body = (
            struct.pack("<HBHH", sequence, flags, 0, 0)
            + self.payload[offset : offset + size]
        )
        frame, packet, storage = (
            self.alloc(64),
            self.alloc(256),
            self.alloc(len(body) + 13),
        )
        self.call(0x1942F0, frame)
        self.u.mem_write(storage + 13, body)
        self.wi(packet, 2)
        self.wi(packet + 52, len(body) + 13)
        self.wq(packet + 56, storage)
        self.wq(frame + 8, packet)
        self.u.mem_write(frame + 26, struct.pack("<H", fid))
        self.wi(frame + 28, 1000000)
        self.call(0x3260D0, self.dec, frame)
        self.call(0x326F30, self.dec)
        assert not self.assertions, self.assertions
        return self.state()


def scenarios():
    return [
        dict(name="complete_mark", actions=[["P", 1, 0, 24, 0, 2204], ["D"]]),
        dict(
            name="split_mark",
            actions=[["P", 1, 0, 16, 0, 1100], ["P", 1, 1, 8, 1100, 1104], ["D"]],
        ),
        dict(
            name="replace_incomplete",
            actions=[["P", 1, 0, 16, 0, 1100], ["P", 2, 1, 24, 0, 2204], ["D"]],
        ),
        dict(
            name="queued_then_mark",
            actions=[
                ["P", 1, 0, 24, 0, 2204],
                ["P", 2, 1, 16, 0, 1100],
                ["D"],
                ["P", 2, 2, 8, 1100, 1104],
                ["D"],
            ],
        ),
    ]


def run(binary, case, mutate=False):
    r = Keys(binary)
    if mutate:
        assert bytes(r.u.mem_read(0x326225, 3)) == b"\xff\x50\x78"
        r.u.mem_write(0x326225, b"\x90" * 3)
        r.u.ctl_remove_cache(0x326225, 0x326228)
    states = [r.feed(*a[1:]) if a[0] == "P" else r.present() for a in case["actions"]]
    return dict(
        case,
        states=states,
        entries={m.codec.FUNCTIONS[a]: v for a, v in sorted(r.entered.items())},
    )


def audit(binary):
    cases = [run(binary, c) for c in scenarios()]
    assert all(
        not any(row[0] == "sdk_flush" for row in s["events"])
        for c in cases
        for s in c["states"]
    )
    payload = (
        (ROOT / "app/tests/fixtures/video/sequential.h264").read_bytes()[:2204].hex()
    )
    for c in cases:
        aus = [row[1] for s in c["states"] for row in s["events"] if row[0] == "au"]
        assert aus and all(au == payload for au in aus), c["name"]
    queued = cases[-1]["states"]
    assert queued[2]["stats"] == {"1": 1, "2": 0} and queued[-1]["stats"] == {
        "1": 1,
        "2": 1,
    }
    assert queued[2]["previous"] == [1, 1000000]
    base = cases[2]
    changed = run(binary, base, True)
    before = [row[1] for s in base["states"] for row in s["events"] if row[0] == "au"]
    after = [row[1] for s in changed["states"] for row in s["events"] if row[0] == "au"]
    assert before != after and len(bytes.fromhex(after[-1])) == 3304
    assert all(
        any(name in c["entries"] for c in cases) for name in m.codec.FUNCTIONS.values()
    )
    return dict(
        scope=__doc__,
        binary_sha256=m.codec.SHA,
        functions=m.codec.inventory(binary),
        cases=cases,
        mutation_checks=["omit_marked_flush_changes_actual_au"],
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    report = audit(a.binary.read_bytes())
    data = (json.dumps(report, indent=2) + "\n").encode()
    ref = ROOT / "scripts/fixtures/steam-client-avcodec-key-reference.json.gz"
    if a.refresh_reference:
        if ref.exists():
            assert json.loads(gzip.decompress(ref.read_bytes())) == report
        ref.write_bytes(gzip.compress(data, mtime=0))
    else:
        assert json.loads(gzip.decompress(ref.read_bytes())) == report
    a.output.write_bytes(data)
    print(
        "Official Linux AVCodec key:",
        len(report["cases"]),
        "cases,",
        sum(len(c["states"]) for c in report["cases"]),
        "states, 6 functions, 1 mutation",
    )


if __name__ == "__main__":
    main()
