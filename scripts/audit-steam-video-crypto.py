#!/usr/bin/env python3
"""Execute official AES-CBC/padding, video bit5 handling and original frame resize.

Original CCrypto::SymmetricDecryptWithIV, software AES key schedule/decrypt and
CBC/padding/copy instructions execute without a crypto-result adapter. Python
crypto only constructs ciphertext inputs. Original decoder/frame/packet/assembly,
FinalDecode and Android SDK input chain execute. SDK/JNI/NAL metadata/platform,
libc/ref primitives, network/control and OS scheduling inherit declared terminals
from the mode audit. All output, including failed-decrypt mutation, is observed.
No host producer, physical decode, all factories or SDK/FFmpeg error mapping proof.
"""

import argparse
import hashlib
import importlib.util
import json
import struct
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "mode", ROOT / "scripts/audit-steam-video-content-mode.py"
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
c = m.c


def encrypt(raw, key, iv=bytes(16)):
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return e.update(raw) + e.finalize()


def padded(raw):
    pad = 16 - len(raw) % 16
    return raw + bytes([pad]) * pad


class Crypto(m.Mode):
    def __init__(self, binary, inp):
        self.operations, self.protection, self.current = [], [], None
        self.visits = dict(
            key_schedule=0, decrypt_block=0, enable_terminal=0, disable_terminal=0
        )
        super().__init__(
            binary,
            dict(
                threads=inp.get("threads", True),
                backend=inp.get("backend", False),
                initial=0 if inp.get("backend") else None,
            ),
        )
        # The inherited audio harness replaces shared Frame::SetSize. Video
        # must execute its original resize against owned packet storage instead.
        self.callbacks.pop(0xC0BA60, None)
        key = bytes(range(inp["keylen"]))
        storage = self.alloc(len(key))
        self.u.mem_write(storage, key)
        self.wq(c.CLIENT + 64, storage)
        self.wi(c.CLIENT + 84, len(key))

    def hook(self, u, address, size, ctx):
        sites = {
            0xAAE31C: "key_schedule",
            0xAAE894: "decrypt_block",
            0x9090C4: "enable_terminal",
            0x9090C8: "disable_terminal",
        }
        if address in sites:
            self.visits[sites[address]] += 1
        if address == 0x747640:
            self.current = dict(
                input_len=self.r(1),
                capacity=self.i(self.r(5)),
                size_ptr=self.r(5),
                out=self.r(4),
                keylen=self.r(7),
                iv=bytes(self.u.mem_read(self.r(2), 16)).hex(),
            )
        if address == 0x747880 and self.current:
            op = self.current
            self.operations.append(
                dict(
                    action=self.action,
                    input_len=op["input_len"],
                    capacity=op["capacity"],
                    keylen=op["keylen"],
                    iv=op["iv"],
                    ok=bool(self.r(0) & 1),
                    out_len=self.i(op["size_ptr"]),
                    out=bytes(self.u.mem_read(op["out"], op["capacity"])).hex(),
                )
            )
            self.current = None
        if self.tracing and address in (0x7B11EC, 0x7B1204):
            self.protection.append([self.action, address == 0x7B11EC])
        super().hook(u, address, size, ctx)

    def observe(self):
        s = super().observe()
        s.update(
            crypto=list(self.operations),
            protected=bool(self.u.mem_read(self.video + 395, 1)[0]),
            protection=list(self.protection),
            assertions=list(self.assertions),
            visits=dict(self.visits),
        )
        return s


def direct(binary, inp):
    x = Crypto(binary, dict(keylen=inp["keylen"]))
    body, iv = bytes.fromhex(inp["cipher"]), bytes.fromhex(inp["iv"])
    room = max(len(body), inp["capacity"], 1)
    source = x.alloc(room + 16)
    x.u.mem_write(source, bytes([165]) * (room + 16))
    if body:
        x.u.mem_write(source, body)
    dest = source if inp["inplace"] else x.alloc(room + 16)
    if dest != source:
        x.u.mem_write(dest, bytes([165]) * (room + 16))
    ivptr, keyptr, sizeptr = x.alloc(16), x.alloc(inp["keylen"]), x.alloc(4)
    x.u.mem_write(ivptr, iv)
    x.u.mem_write(keyptr, bytes(range(inp["keylen"])))
    x.wi(sizeptr, inp["capacity"])
    # Ninth ABI parameter is bVerifyPadding=true on the caller stack. Video's
    # real call at 7b2238 also writes this byte; it is not an AES-result stub.
    x.u.mem_write(0x300FF000, b"\1")
    ok = x.call(
        0x747640, source, len(body), ivptr, 16, dest, sizeptr, keyptr, inp["keylen"]
    )
    result = dict(
        ok=bool(ok),
        out_len=x.i(sizeptr),
        out=bytes(x.u.mem_read(dest, room)).hex(),
        input_after=bytes(x.u.mem_read(source, len(body))).hex(),
        guard=bytes(x.u.mem_read(dest + room, 16)).hex(),
    )
    assert result["guard"] == "a5" * 16
    return dict(
        input=inp,
        result=result,
        assertions=x.assertions,
        crypto=x.operations,
        visits=x.visits,
    )


def video(binary, inp, actions):
    x = Crypto(binary, inp)
    states = []
    for n, a in enumerate(actions):
        x.action = n
        if a[0] == "F":
            x.feed(*a[1:4], bytes.fromhex(a[4]))
        elif a[0] == "Q":
            x.call(0x7AD394, c.CLIENT, 0)
        elif a[0] == "R":
            x.call(0x7A5FF8, c.CLIENT)
        else:
            raise ValueError(a)
        states.append(x.observe())
        if not inp.get("source_only"):
            assert not x.assertions, (inp, n, x.assertions)
    return dict(input=inp, actions=actions, states=states)


def protected_slots(binary):
    import io
    from elftools.elf.elffile import ELFFile
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

    elf = ELFFile(io.BytesIO(binary))
    dyn = list(elf.get_section_by_name(".dynsym").iter_symbols())
    text = elf.get_section_by_name(".text")
    data, base = text.data(), text["sh_addr"]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    result = []
    for name, slots in (
        ("_ZTV28CStreamDecoderH264Standalone", (88, 96)),
        ("_ZTV13CAndroidAccel", (80, 88)),
    ):
        vt = next(s["st_value"] for s in dyn if s.name == name)
        for rel in elf.get_section_by_name(".rela.dyn").iter_relocations():
            if rel["r_offset"] - vt - 16 in slots:
                symbol = dyn[rel["r_info_sym"]]
                start, size = symbol["st_value"], symbol["st_size"]
                ins = [
                    [i.address, i.mnemonic, i.op_str, i.bytes.hex()]
                    for i in md.disasm(data[start - base : start - base + size], start)
                ]
                if name == "_ZTV13CAndroidAccel":
                    assert size == 4 and ins[0][1] == "ret"
                result.append(
                    dict(
                        vtable=name,
                        slot=rel["r_offset"] - vt - 16,
                        symbol=symbol.name,
                        instructions=ins,
                    )
                )
    assert len(result) == 4
    return result


def negative_checks(binary, helpers, videos):
    constructor = Crypto.__init__
    hzero = next(
        c
        for c in helpers
        if c["input"]["name"] == "zero_pad"
        and c["input"]["keylen"] == 16
        and c["input"]["iv"] == "00" * 16
        and c["input"]["inplace"]
    )
    hvalid = next(
        c
        for c in helpers
        if c["input"]["name"] == "pad2"
        and c["input"]["keylen"] == 16
        and c["input"]["iv"] == "00" * 16
        and c["input"]["inplace"]
    )
    vvalid = next(
        c
        for c in videos
        if c["input"] == dict(keylen=16, backend=True, request=False, shape="valid")
    )
    rejected = []
    mutations = (
        (
            "skip_padding_verification",
            0x747428,
            0x14000000 | ((0x747570 - 0x747428) // 4),
            hzero,
            False,
        ),
        ("omit_success_nul", 0x7475FC, 0xD503201F, hvalid, False),
        ("omit_video_decrypt", 0x7B223C, 0xD503201F, vvalid, True),
        ("omit_video_resize", 0x7B224C, 0xD503201F, vvalid, True),
    )
    try:
        for name, pc, word, baseline, is_video in mutations:

            def modified(self, *args, **kwargs):
                constructor(self, *args, **kwargs)
                self.u.mem_write(pc, struct.pack("<I", word))
                self.u.ctl_remove_cache(pc, pc + 4)

            Crypto.__init__ = modified
            try:
                got = (
                    video(binary, baseline["input"], baseline["actions"])
                    if is_video
                    else direct(binary, baseline["input"])
                )
            except (AssertionError, ValueError):
                rejected.append(name)
            else:
                assert got != baseline, ("undetected official mutation", name)
                rejected.append(name)
    finally:
        Crypto.__init__ = constructor
    return rejected


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == c.SHA
    helpers = []
    for keylen in (16, 32):
        key = bytes(range(keylen))
        for nonzero_iv in (False, True):
            iv = bytes(range(16)) if nonzero_iv else bytes(16)
            raw_cases = {
                f"pad{pad}": bytes(range(32 - pad)) + bytes([pad]) * pad
                for pad in range(1, 17)
            }
            raw_cases.update(
                zero_pad=b"A" * 31 + b"\0",
                large_pad=b"A" * 31 + b"\x11",
                pad255=b"A" * 31 + b"\xff",
                unequal=b"A" * 30 + b"\1\2",
                empty_plain=bytes([16]) * 16,
            )
            ciphers = {name: encrypt(raw, key, iv) for name, raw in raw_cases.items()}
            ciphers.update(
                short1=b"\x31",
                short15=b"\x32" * 15,
                length17=b"\x33" * 17,
                length33=b"\x34" * 33,
            )
            for name, body in ciphers.items():
                for inplace in (False, True):
                    inp = dict(
                        keylen=keylen,
                        iv=iv.hex(),
                        cipher=body.hex(),
                        capacity=len(body),
                        inplace=inplace,
                        name=name,
                    )
                    helpers.append(direct(binary, inp))
            for cap in (1, 15, 16, 17, 29, 30, 31, 33, 48):
                for inplace in (False, True):
                    helpers.append(
                        direct(
                            binary,
                            dict(
                                keylen=keylen,
                                iv=iv.hex(),
                                cipher=ciphers["pad2"].hex(),
                                capacity=cap,
                                inplace=inplace,
                                name="bounded_capacity",
                            ),
                        )
                    )
    assert all(not x["assertions"] for x in helpers)
    videos, source_only = [], []
    payload = m.PAYLOAD
    for keylen in (16, 32):
        key = bytes(range(keylen))
        variants = {
            "valid": encrypt(padded(payload), key),
            "pad_zero": encrypt(b"A" * 31 + b"\0", key),
            "unequal": encrypt(b"A" * 30 + b"\1\2", key),
            "empty_plain": encrypt(bytes([16]) * 16, key),
            "short": b"123",
        }
        for backend in (False, True):
            for request in (False, True):
                for name, body in variants.items():
                    inp = dict(
                        keylen=keylen, backend=backend, request=request, shape=name
                    )
                    seq = int(backend)
                    ops = ([["Q"]] if request else []) + [
                        ["F", 1, seq, 56, body.hex()],
                        ["F", 2, seq + 1, 8, payload.hex()],
                        ["F", 3, seq + 2, 24, payload.hex()],
                        ["R"],
                        ["F", 4, seq + 3, 56, variants["valid"].hex()],
                    ]
                    videos.append(video(binary, inp, ops))
            half = len(payload) // 2
            for finish_encrypted in (False, True):
                ops = [
                    [
                        "F",
                        1,
                        int(backend),
                        48,
                        encrypt(padded(payload[:half]), key).hex(),
                    ],
                    [
                        "F",
                        1,
                        int(backend) + 1,
                        40 if finish_encrypted else 8,
                        (
                            encrypt(padded(payload[half:]), key)
                            if finish_encrypted
                            else payload[half:]
                        ).hex(),
                    ],
                ]
                videos.append(
                    video(
                        binary,
                        dict(
                            keylen=keylen,
                            backend=backend,
                            shape="split",
                            finish_encrypted=finish_encrypted,
                        ),
                        ops,
                    )
                )
        for flags in (56, 58):
            videos.append(
                video(
                    binary,
                    dict(keylen=keylen, backend=True, shape="empty_flags", flags=flags),
                    [["F", 1, 1, flags, variants["empty_plain"].hex()]],
                )
            )
        for flags, body in ((59, variants["empty_plain"]), (56, b"")):
            inp = dict(keylen=keylen, backend=True, source_only=True, flags=flags)
            item = video(binary, inp, [["F", 1, 1, flags, body.hex()]])
            assert item["states"][0]["assertions"]
            source_only.append(item)
    return dict(
        binary_sha256=c.SHA,
        boundary=__doc__,
        helpers=helpers,
        videos=videos,
        source_only=source_only,
        protected_slots=protected_slots(binary),
        mutation_checks=negative_checks(binary, helpers, videos),
    )


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--write", type=Path)
    p.add_argument("--check", type=Path)
    a = p.parse_args()
    result = audit(a.binary.read_bytes())
    if a.write:
        a.write.write_text(json.dumps(result, indent=2) + "\n")
    if a.check:
        assert result == json.loads(a.check.read_text())
    print(
        "Official video crypto:",
        len(result["helpers"]),
        "helper cases;",
        len(result["videos"]),
        "video cases/",
        sum(len(c["states"]) for c in result["videos"]),
        "states",
    )
