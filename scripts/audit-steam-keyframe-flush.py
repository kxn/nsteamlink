#!/usr/bin/env python3
"""Execute official key-fragment flush through H264 assembly and SDK submission.

SHA-pinned original constructors/virtual FlushPendingData, DecodeFrame/OnThink,
AppendBuffer/data-buffer Read, FinalDecode/AndroidAccel/BSubmitFrame and packet
reference release execute. SDK, JNI/platform, allocator/primitives, NAL metadata
and profiler formatting are declared terminals inherited from the decoder audit.
SDK input bytes are read only at queueInputBuffer after original Read/copy. No
real decode output, GPU, all factories/producers or FFmpeg error mapping is proved.
Initial strict/soft and pending-owner states are explicit decoder-boundary inputs.
With a backend, frame zero is primed through the same original decode chain;
its original CAndroidFrame is retained in the player queue across key flush.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "reset", ROOT / "scripts/audit-steam-decoder-reset.py"
)
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
c = r.c


class Key(r.Reset):
    def __init__(self, binary, inp):
        self.flow = []
        self.action = -1
        self.decode_id = 0
        self.flush_cuts = []
        super().__init__(
            binary,
            dict(
                threads=True,
                old_backend=inp["backend"],
                init_success=True,
                flush_result=inp.get("flush_result", 0),
            ),
        )
        self.b(self.video + 404, 0)
        self.b(self.video + 405, 0)
        if inp["backend"]:
            payload = (ROOT / "app/tests/fixtures/video/sequential.h264").read_bytes()[
                :2204
            ]
            self.feed(0, 0, 24, payload)
            assert self.snapshot()["player_queue"]["ids"] == [0]
            assert not self.assertions
        if inp["pending"] != "none":
            self.feed(
                1,
                int(inp["backend"]),
                2 if inp["pending"] == "encoded" else 0,
                b"old-partial",
                False,
            )
            if inp["pending"] != "linked":
                self.call(0x7B24DC, self.video)
        self.b(self.video + 404, inp["strict"])
        self.b(self.video + 405, inp["soft"])
        self.flow = []
        self.trace = []
        self.effects = []
        self.sdk = []
        self.assertions = []
        self.initial = self.state()
        self.tracing = True

    def hook(self, u, a, size, context):
        name = self.plts.get(a, "")
        if a == 0x7B1088:
            self.decode_id = self.r(1) & 65535
        if name == "vsnprintf":
            if self.r(1):
                self.u.mem_write(self.r(0), b"\0")
            self.ret(0)
            return
        if self.tracing and name == "AMediaCodec_flush":
            cut = self.snapshot()
            self.flow.append(["flush", self.action, cut["strict"], cut["soft"]])
            assert (
                cut["pending"][0] == 0xFFFFFFFF
                and not cut["encoded"]
                and not cut["packet_buffers"]
            )
            self.flush_cuts.append(
                dict(
                    action=self.action,
                    old_refs=dict(cut["refs"]),
                    player=cut["player_queue"]["ids"],
                    held=cut["held"],
                )
            )
        if self.tracing and name == "AMediaCodec_queueInputBuffer":
            body = bytes(self.u.mem_read(self.input + self.r(2), self.r(3)))
            self.flow.append(["decode", self.action, self.decode_id, body.hex()])
        super().hook(u, a, size, context)

    def feed(self, fid, seq, flags, payload, think=True):
        body = (
            b"\x01"
            + struct.pack("<HIHI", fid, 1000000, 0, 0)
            + struct.pack("<HBHH", seq, flags, 0, 0)
            + payload
        )
        packet = self.packet(5, 3, False, 12, 34, len(body))
        self.labels[packet] = f"input_{fid}_{seq}"
        self.u.mem_write(self.q(packet + 40) + 13, body)
        frame = self.alloc(64)
        self.call(self.symbols["_ZN12CStreamFrameC1EP13CStreamPacket"], frame, packet)
        self.call(0x7B2000, self.video, frame)
        self.call(self.symbols["_ZN12CStreamFrameD1Ev"], frame)
        self.refs[f"input_{fid}_{seq}"] = packet
        if think:
            self.call(0x7B24DC, self.video)

    def state(self):
        s = self.snapshot()
        return dict(
            strict=s["strict"],
            soft=s["soft"],
            request=s["request"],
            flow=list(self.flow),
            player=s["player_queue"]["ids"],
            held=s["held"],
            refs=s["refs"],
            pending=s["pending"],
            encoded=s["encoded"],
            packet_buffers=s["packet_buffers"],
        )


def case(binary, inp, actions):
    x = Key(binary, inp)
    states = []
    for index, (fid, seq, flags, body) in enumerate(actions):
        x.action = index
        x.feed(fid, seq, flags, bytes.fromhex(body))
        states.append(x.state())
        assert not x.assertions, (inp, index, x.assertions)
    if inp["backend"]:
        assert len(x.flush_cuts) == sum(bool(a[2] & 16) for a in actions)
        assert all(0 in cut["player"] for cut in x.flush_cuts)
        assert all(not v for cut in x.flush_cuts[:1] for v in cut["old_refs"].values())
    assert not any(
        e[0] in ("player_flush", "accel_quit", "codec_delete", "standalone_start")
        for e in x.trace
    )
    return dict(
        input=inp,
        initial=x.initial,
        actions=actions,
        states=states,
        flush_cuts=x.flush_cuts,
        sdk=x.sdk,
        effects=x.effects,
        trace=x.trace,
    )


def static_audit(binary):
    from elftools.elf.elffile import ELFFile
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    from capstone.arm64 import ARM64_OP_MEM, ARM64_OP_REG
    import io

    sp = importlib.util.spec_from_file_location(
        "entries", ROOT / "scripts/audit-steam-client-fec-entry.py"
    )
    entries = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(entries)
    entries.TARGETS = (
        "_ZN19CStreamDecoderVideo16FlushPendingDataEv",
        "_ZN28CStreamDecoderH264Standalone16FlushPendingDataEv",
    )
    direct = entries.static(binary)
    elf = ELFFile(io.BytesIO(binary))
    text = elf.get_section_by_name(".text")
    base = text["sh_addr"]
    data = text.data()
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    decoder.detail = True
    scope = {}
    for symbol in elf.get_section_by_name(".dynsym").iter_symbols():
        if symbol["st_info"]["type"] == "STT_FUNC" and symbol.name.startswith(
            (
                "_ZN19CStreamDecoderVideo",
                "_ZN28CStreamDecoderH264Standalone",
                "_ZN18CStreamDecoderH264",
            )
        ):
            scope.setdefault((symbol["st_value"], symbol["st_size"]), []).append(
                symbol.name
            )
    candidates = []
    for (start, size), names in sorted(scope.items()):
        if not size:
            continue
        ins = list(decoder.disasm(data[start - base : start - base + size], start))
        for n, i in enumerate(ins):
            if (
                i.mnemonic != "ldr"
                or len(i.operands) != 2
                or i.operands[1].type != ARM64_OP_MEM
                or i.operands[1].mem.disp != 120
            ):
                continue
            if i.operands[0].type != ARM64_OP_REG:
                continue
            reg = i.operands[0].reg
            for call in ins[n + 1 : n + 4]:
                if call.mnemonic == "blr" and call.operands[0].reg == reg:
                    candidates.append(
                        dict(
                            load=i.address,
                            call=call.address,
                            owners=sorted(names),
                            instructions=[
                                [a.address, a.mnemonic, a.op_str, a.bytes.hex()]
                                for a in ins[max(n - 2, 0) : n + 4]
                            ],
                        )
                    )
                    break
    assert [c["load"] for c in candidates] == [0x7B1FDC, 0x7B20BC]
    return dict(
        direct=direct,
        virtual_scope=[
            dict(address=a, size=z, names=sorted(v))
            for (a, z), v in sorted(scope.items())
        ],
        slot120_candidates=candidates,
        scope_boundary="Selected Video/H264/Standalone methods only; indirect aliases, other classes/platforms and all reset producers remain independent.",
    )


def negative_checks(binary, baseline):
    """Each omitted original operation must change observations or assert.

    Invalidate Unicorn translations after patching: priming/pending assembly
    already executed these addresses, so writing bytes alone is insufficient.
    """
    constructor = Key.__init__
    rejected = []
    mutations = (
        ("skip_key_virtual_flush", 0x7B20C0, 0xD503201F),
        ("skip_protocol_purge", 0x7B125C, 0xD503201F),
        ("skip_sdk_flush", 0x7B1278, 0xD65F03C0),
        ("skip_wait_clear", 0x7B20D0, 0xD503201F),
        ("skip_append", 0x7B2580, 0xD503201F),
    )
    try:
        for name, pc, word in mutations:

            def mutated(self, *args, **kwargs):
                constructor(self, *args, **kwargs)
                self.u.mem_write(pc, struct.pack("<I", word))
                self.u.ctl_remove_cache(pc, pc + 4)

            Key.__init__ = mutated
            try:
                result = case(binary, baseline["input"], baseline["actions"])
            except (AssertionError, ValueError):
                rejected.append(name)
            else:
                assert result != baseline, ("undetected official mutation", name)
                rejected.append(name)
    finally:
        Key.__init__ = constructor
    return rejected


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == c.SHA
    clip = (ROOT / "app/tests/fixtures/video/sequential.h264").read_bytes()
    # ffprobe and the real parser tests identify the first AU as 2204 bytes.
    payload = clip[:2204]
    half = len(payload) // 2
    shapes = {
        "single": [[2, 2, 24, payload.hex()]],
        "split": [[2, 2, 16, payload[:half].hex()], [2, 3, 8, payload[half:].hex()]],
        "replace": [
            [2, 2, 16, payload[:half].hex()],
            [3, 3, 16, payload[:half].hex()],
            [3, 4, 8, payload[half:].hex()],
        ],
        "repeat_mark": [[2, 2, 16, payload[:half].hex()], [2, 3, 24, payload.hex()]],
    }
    cases = []
    for backend in (False, True):
        for strict, soft in ((0, 0), (1, 0), (0, 1), (1, 1)):
            for pending in ("none", "linked", "packets", "encoded"):
                for shape, actions in shapes.items():
                    inp = dict(
                        backend=backend,
                        strict=strict,
                        soft=soft,
                        pending=pending,
                        shape=shape,
                    )
                    cases.append(case(binary, inp, actions))
    for result in (-10000,):
        cases.append(
            case(
                binary,
                dict(
                    backend=True,
                    strict=1,
                    soft=1,
                    pending="encoded",
                    shape="split",
                    flush_result=result,
                ),
                shapes["split"],
            )
        )
    return dict(
        binary_sha256=c.SHA,
        boundary=__doc__,
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        cases=cases,
        static=static_audit(binary),
        mutation_checks=negative_checks(
            binary,
            next(
                item
                for item in cases
                if item["input"]
                == dict(
                    backend=True, strict=1, soft=1, pending="encoded", shape="split"
                )
            ),
        ),
    )


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--write", type=Path)
    p.add_argument("--check", type=Path)
    args = p.parse_args()
    result = audit(args.binary.read_bytes())
    if args.write:
        args.write.write_text(json.dumps(result, indent=2) + "\n")
    if args.check:
        assert result == json.loads(args.check.read_text())
    print("Official keyframe flush:", len(result["cases"]), "cases")
