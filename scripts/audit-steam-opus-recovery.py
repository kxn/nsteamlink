#!/usr/bin/env python3
"""Execute official Opus gap recovery and the embedded original Opus decoder.

Original StartDecoding/DecodeFrame/StopDecoding, multistream decoder creation and
decode execute from the SHA-pinned Android client. Frame IDs/timestamps and input
payloads are controlled at the decoder-worker boundary. Player creation/submit,
Frame storage, allocation, assertion presentation and libc storage are adapters.
No transport/UI/OS-thread reachability, jitter-buffer output or device is proved.
Malformed codec output records the original unsafe Resize request without
allocating or reading that size; it is not claimed as safe native behavior.
"""

import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import zlib

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "config", ROOT / "scripts/audit-steam-client-config.py"
)
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class Opus(c.Core):
    def __init__(self, binary, channels):
        super().__init__(binary)
        self.decoder, self.player, vt = (self.alloc(4096) for _ in range(3))
        self.frames, self.decodes, self.submitted, self.assertions = {}, [], [], []
        self.force_plc = False
        self.decoder_config = None
        self.wq(self.decoder + 16, self.player)
        self.wi(self.decoder + 392, 48000)
        self.wi(self.decoder + 396, channels)
        self.wq(self.player, vt)
        self.wq(vt + 24, c.STOP + 0x300)
        self.wq(vt + 48, c.STOP + 0x310)
        self.callbacks.update(
            {
                c.STOP + 0x300: lambda: self.ret(),
                c.STOP + 0x310: self.submit,
                0xC0BA20: self.create,
                0xC0BA50: self.area,
                0xC0BA60: self.resize,
            }
        )

    def call(self, entry, *params):
        self.u.reg_write(c.SP, 0x300FF000)
        self.u.reg_write(c.LR, c.STOP)
        for i, value in enumerate(params):
            self.u.reg_write(c.X0 + i, value)
        self.u.emu_start(entry, c.STOP + 4, count=10000000)
        assert self.u.reg_read(c.BASE["UC_ARM64_REG_PC"]) == c.STOP
        return self.r(0)

    def create(self):
        p = self.alloc(4096)
        self.frames[p] = dict(id=self.r(1), timestamp=self.r(2), size=0)
        self.active = p
        self.ret(p)

    def area(self):
        f = self.frames[self.r(0) - 24]
        f["size"] = self.r(1)
        assert f["size"] <= 1024 * 1024
        f["data"] = self.alloc(f["size"] + 64)
        f["capacity"] = f["size"]
        self.ret(f["data"])

    def resize(self):
        self.frames[self.r(0) - 24]["size"] = self.r(1)
        self.ret()

    def submit(self):
        f = self.frames[self.r(1)]
        out = {k: f[k] for k in ("id", "timestamp", "size")}
        out["decoder_result"] = self.decodes[-1]["result"]
        if out["decoder_result"] < 0 or (
            self.decodes[-1]["max_samples"] == 480 and out["decoder_result"] != 480
        ):
            out["invalid_codec_output"] = True
        elif f["size"] <= f["capacity"]:
            raw = bytes(self.u.mem_read(f["data"], f["size"]))
            values = struct.unpack("<" + "f" * (len(raw) // 4), raw)
            # Decoder arithmetic is original; this only formats an observation.
            pcm = struct.pack(
                "<" + "h" * len(values),
                *(max(-32768, min(32767, round(v * 32768))) for v in values),
            )
            out["s16_sha256"] = hashlib.sha256(pcm).hexdigest()
            out["s16_zlib_base64"] = base64.b64encode(zlib.compress(pcm)).decode()
            out["peak"] = max((abs(v) for v in values), default=0)
        else:
            out["unsafe_resize"] = True
        self.submitted.append(out)
        self.ret()

    def hook(self, uc, address, size, data):
        name = self.plts.get(address, "")
        if address in (0x7B15B4, 0x7B168C):
            self.decodes[-1]["result"] = struct.unpack(
                "<i", struct.pack("<I", self.r(0) & 0xFFFFFFFF)
            )[0]
        if name == "calloc":
            self.ret(self.alloc(self.r(0) * self.r(1)))
        elif name == "__memset_chk":
            assert self.r(2) <= self.r(3)
            self.u.mem_write(self.r(0), bytes([self.r(1) & 255]) * self.r(2))
            self.ret(self.r(0))
        elif name == "opus_multistream_decoder_create":
            self.decoder_config = [self.r(i) for i in range(4)] + list(
                self.u.mem_read(self.r(4), self.r(1))
            )
            self.jump(self.symbols[name])
        elif name == "opus_multistream_decode_float":
            if self.force_plc and self.r(5):
                # Explicit codec counterfactual; never a product-policy case.
                self.u.reg_write(c.X0 + 1, 0)
                self.u.reg_write(c.X0 + 2, 0)
                self.u.reg_write(c.X0 + 5, 0)
            f = self.frames[self.active]
            self.decodes.append(
                dict(
                    id=f["id"],
                    timestamp=f["timestamp"],
                    payload=bytes(self.u.mem_read(self.r(1), self.r(2))).hex()
                    if self.r(2)
                    else "",
                    max_samples=self.r(4),
                    fec=self.r(5),
                )
            )
            self.jump(self.symbols[name])
        elif name.startswith("_ZN15AssertMsgHelper"):
            self.assertions.append(self.r(1))
            self.ret(1)  # Record failed checks, no debug break/unsafe allocation.
        else:
            super().hook(uc, address, size, data)

    def start(self):
        self.call(0x7B134C, self.decoder, self.alloc(64))
        assert self.q(self.decoder + 400)

    def feed(self, fid, timestamp, payload):
        f, p, raw = (self.alloc(4096) for _ in range(3))
        self.wq(f + 8, p)
        self.wq(p + 56, raw)
        self.wi(p + 52, 13 + len(payload))
        self.u.mem_write(raw, bytes(13) + payload)
        self.u.mem_write(f + 26, struct.pack("<HI", fid, timestamp))
        self.call(0x7B1414, self.decoder, f)

    def snapshot(self):
        result = dict(
            first=bool(self.u.mem_read(self.decoder + 408, 1)[0]),
            next=struct.unpack("<H", self.u.mem_read(self.decoder + 410, 2))[0],
            decodes=list(self.decodes),
            submitted=list(self.submitted),
            assertions=list(self.assertions),
        )
        self.decodes.clear()
        self.submitted.clear()
        self.assertions.clear()
        return result


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == c.SHA
    schedules = {
        "sequential": [10, 11, 12],
        "one_gap": [10, 12, 13],
        "three_gap": [10, 14, 15],
        "old_duplicate": [10, 10, 9, 11],
        "out_of_order": [20, 22, 21, 23],
        "wrap": [65534, 0, 65535, 1],
        "first_high": [65000, 65001],
        "restart": [10, 14, "R", 123, 125],
    }
    cases = []
    for channels in (1, 2):
        for duration, payload in ((10, "f0fffe"), (20, "f8fffe")):
            for name, sequence in schedules.items():
                r = Opus(binary, channels)
                r.start()
                actions, observed = [], []
                for index, fid in enumerate(sequence):
                    if fid == "R":
                        r.call(0x7B16FC, r.decoder)
                        assert not r.q(r.decoder + 400)
                        r.start()
                        actions.append(["R"])
                    else:
                        timestamp = 1100000 + index * 1000
                        r.feed(fid, timestamp, bytes.fromhex(payload))
                        actions.append(["F", fid, timestamp, payload])
                    state = r.snapshot()
                    if duration == 10:
                        assert not state["assertions"], (
                            channels,
                            duration,
                            name,
                            fid,
                            state,
                        )
                    observed.append(state)
                cases.append(
                    dict(
                        name=f"{name}_{channels}_{duration}",
                        channels=channels,
                        frequency=48000,
                        decoder_config=r.decoder_config,
                        actions=actions,
                        observed=observed,
                    )
                )
    # Actual invalid Opus output and a missing decoder are source-only bounds.
    for mode in ("invalid", "missing"):
        r = Opus(binary, 2)
        r.start()
        if mode == "missing":
            r.call(0x7B16FC, r.decoder)
        r.feed(10, 1100000, b"\xff")
        cases.append(dict(name=mode, source_only=True, observed=[r.snapshot()]))
    stimulus = json.loads(
        (ROOT / "scripts/fixtures/steam-opus-recovery-input.json").read_text()
    )
    for inp in stimulus["cases"]:
        for gap in (1, 3):
            ids = [0, 1, 2, 3 + gap, 4 + gap]
            r = Opus(binary, inp["channels"])
            r.start()
            actions, observed = [], []
            for fid in ids:
                payload = inp["packets"][fid]
                stamp = 1100000 + fid * 655
                r.feed(fid, stamp, bytes.fromhex(payload))
                state = r.snapshot()
                assert not state["assertions"], (inp["channels"], gap, fid, state)
                actions.append(["F", fid, stamp, payload])
                observed.append(state)
            case = dict(
                name=f"silk_fec_gap{gap}_{inp['channels']}",
                channels=inp["channels"],
                frequency=48000,
                decoder_config=r.decoder_config,
                actions=actions,
                observed=observed,
            )
            if gap == 1:
                control = Opus(binary, inp["channels"])
                control.start()
                control.force_plc = True
                states = []
                for _, fid, stamp, payload in actions:
                    control.feed(fid, stamp, bytes.fromhex(payload))
                    states.append(control.snapshot())
                fec_hash = observed[3]["submitted"][-2]["s16_sha256"]
                plc_hash = states[3]["submitted"][-2]["s16_sha256"]
                case["codec_counterfactual"] = dict(
                    scope="Force packet=NULL/fec=0 only at the codec API, not a product strategy",
                    fec_sha256=fec_hash,
                    plc_sha256=plc_hash,
                    distinguishes=fec_hash != plc_hash,
                )
            cases.append(case)
    for channels in (1, 2):
        r = Opus(binary, channels)
        r.start()
        actions, observed = [], []
        for fid, timestamp in ((65535, 0xFFFFFFF0), (1, 0), (2, 0xFFFFFF9C)):
            r.feed(fid, timestamp, bytes.fromhex("f0fffe"))
            actions.append(["F", fid, timestamp, "f0fffe"])
            observed.append(r.snapshot())
        cases.append(
            dict(
                name=f"timestamp_zero_wrap_{channels}",
                channels=channels,
                frequency=48000,
                decoder_config=r.decoder_config,
                actions=actions,
                observed=observed,
            )
        )
    return cases


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    binary = a.binary.read_bytes()
    cases = audit(binary)
    identity = c.Core(binary)
    version = identity.cstring(
        identity.call(identity.symbols["opus_get_version_string"])
    )
    assert version == "libopus unknown-fixed"
    report = dict(
        binary_sha256=c.SHA, scope=__doc__, cases=cases, codec_identity=version
    )
    ref = ROOT / "scripts/fixtures/steam-opus-recovery-reference.json"
    if a.refresh_reference:
        if ref.exists():
            old = json.loads(ref.read_text())
            assert old["cases"] == report["cases"][: len(old["cases"])]
            assert old["binary_sha256"] == report["binary_sha256"]
            if "codec_identity" in old:
                assert old["codec_identity"] == version
        ref.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert json.loads(ref.read_text()) == report
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Official embedded Opus gap recovery: {len(report['cases'])} cases")


if __name__ == "__main__":
    main()
