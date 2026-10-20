#!/usr/bin/env python3
"""Official client network-test discovery producer and response credentials.

Pinned Android SetPanelStateConnecting, full request producer/serializer, response
parser/handler, BSaveEncryptedSessionKey, original AES decrypt and buffer writes
execute. UI settings/display/controller inputs, persistent server lookup/token,
Qt presentation/storage, time, allocation and final SendMessage are adapters.
StartStreaming is a recorded boundary between UI configuration and the request
producer; the latter receives the exact manager fields left by the UI caller.
The Unauthorized authorization producer and enum log metadata are adapters.
Valid 32-byte responses continue through original Panel OnUpdate/NetworkTest
entry/SetAuthToken, with thread start/join adapted. The response's peer/identity
table is explicit input, not real Steam identity. No OS discovery, real host,
Qt event loop, natural test thread, decoder or device runs in this audit.
"""
import argparse
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from elftools.elf.elffile import ELFFile
from unicorn.arm64_const import UC_ARM64_REG_D0

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "lifecycle", ROOT / "scripts/audit-steam-network-test-lifecycle.py"
)
lifecycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifecycle)
REFERENCE = ROOT / "scripts/fixtures/steam-network-test-discovery-reference.json.gz"
PANEL, APP, CONFIG = lifecycle.media.PANEL, lifecycle.media.APP, lifecycle.media.CONFIG
REQUEST = "CMsgRemoteDeviceStreamingRequest"
RESPONSE = "CMsgRemoteDeviceStreamingResponse"
SECRET = bytes(range(32, 64))
PLAIN = bytes(range(32))


def encrypted(plain=PLAIN):
    iv = bytes(range(16))
    pad = 16 - len(plain) % 16
    ecb = Cipher(algorithms.AES(SECRET), modes.ECB()).encryptor()
    cbc = Cipher(algorithms.AES(SECRET), modes.CBC(iv)).encryptor()
    return (
        ecb.update(iv)
        + ecb.finalize()
        + cbc.update(plain + bytes([pad]) * pad)
        + cbc.finalize()
    )


def varint(value):
    return lifecycle.media.flow.varint(value)


def fields(wire):
    def read(pos):
        value = shift = 0
        while True:
            byte = wire[pos]
            pos += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value, pos
            shift += 7
            assert shift < 70

    pos, result = 0, {}
    while pos < len(wire):
        tag, pos = read(pos)
        if tag & 7 == 0:
            value, pos = read(pos)
        else:
            assert tag & 7 == 2
            size, pos = read(pos)
            value = wire[pos : pos + size].hex()
            pos += size
        result.setdefault(str(tag >> 3), []).append(value)
    return result


class Discovery(lifecycle.Lifecycle):
    def __init__(self, binary, settings=None, patch=None):
        self.messages, self.boundaries, self.starts, self.errors = [], [], [], []
        self.auth_tokens = []
        self.crypto_hits = {}
        self.wall_time = 1000
        self.settings = settings or {}
        self.has_ip = True
        super().__init__(binary, {}, patch)
        for name, address in self.symbols.items():
            if address and (
                name.startswith("_ZN14CServerManager")
                or name.startswith("_ZN7CCrypto")
                or name.startswith("_ZN13CPanelConnect")
            ):
                self.function_entries.setdefault(address, []).append(name)
        self.manager, self.server = self.alloc(2048), self.alloc(1024)
        self.wq(self.manager + 0x120, self.server)
        self.wi(self.manager + 8, 5)
        self.wq(self.manager + 0x1F0, 123)
        self.wi(self.manager + 0x200, 17)
        for offset in (0x218, 0x398):
            self.call(self.symbols["_ZN10CUtlBufferC1Ev"], self.manager + offset)
        pointer = self.alloc(len(SECRET))
        self.u.mem_write(pointer, SECRET)
        self.call(
            self.symbols["_ZN10CUtlBuffer3PutEPKvi"],
            self.manager + 0x218,
            pointer,
            len(SECRET),
        )
        table, identity, accounts = self.alloc(24), self.alloc(32), self.alloc(8)
        self.wq(self.manager + 0x480, table)
        self.wq(table + 8, identity)
        self.wq(identity + 8, accounts)
        self.wi(identity + 0x18, 1)
        self.wq(accounts, 76561198000000001)
        observer, vtable, observers = self.alloc(64), self.alloc(64), self.alloc(8)
        self.wq(observer, vtable)
        self.wq(vtable + 0x30, lifecycle.RETURN + 0x40)
        self.wq(observers, observer)
        self.wq(self.manager + 0x180, observers)
        self.wi(self.manager + 0x190, 1)
        self.callbacks[lifecycle.RETURN + 0x40] = self.notify_error
        self.config(CONFIG, False, 2)
        self.loaded = CONFIG
        # Core's unrelated client-delegate fixture aliases PANEL+48. Restore
        # the shell-app input before exercising the real panel caller.
        self.wq(PANEL + 0x30, APP)
        self.wq(PANEL + 0xC8, self.manager)
        self.wq(PANEL + 728, self.empty)

    def notify_error(self):
        self.errors.append(self.r(1))
        self.ret()

    def byte_array(self, value):
        p = self.alloc(32 + len(value))
        self.wi(p, -1)
        self.wi(p + 4, len(value))
        self.wq(p + 16, 24)
        self.u.mem_write(p + 24, value + b"\0")
        return p

    def hook(self, u, pc, size, data):
        if pc in (0xCDC27C, 0xCDC2B4, 0x102F05C, 0x102F5D4, 0xCDC558):
            key = hex(pc)
            self.crypto_hits[key] = self.crypto_hits.get(key, 0) + 1
        name = self.plts.get(pc, "")
        if name == "_ZN12CNetworkTest12SetAuthTokenEPKvi":
            self.auth_tokens.append(bytes(u.mem_read(self.r(1), self.r(2))).hex())
            super().hook(u, pc, size, data)
        elif "CUtlHashMap" in name and "4Find" in name:
            self.boundaries.append(name)
            self.ret(0 if "PersistentClientInfo_t" in name else 0xFFFFFFFF)
        elif name == "_ZN14CServerManager15BGetDeviceTokenER10CUtlBuffer":
            self.boundaries.append(name)
            buf, p = self.r(1), self.alloc(8)
            u.mem_write(p, b"TOKEN123")
            self.wq(buf, p)
            self.wi(buf + 8, 8)
            self.wi(buf + 20, 8)
            self.ret(1)
        elif (
            name
            == "_ZN14CServerManager11SendMessageE25ERemoteClientBroadcastMsgPN6google8protobuf7MessageE10CIPAndPorty"
        ):
            self.messages.append((self.r(1), self.freeze(self.r(2), 256)))
            self.ret()
        elif name == "_ZN14CServerManager24LoadPersistentClientInfoEy":
            self.boundaries.append(name)
            self.ret()
        elif name == "_ZN14CServerManager26SendAuthorizeDeviceRequestEv":
            # Unauthorized enters the separately documented pairing producer.
            # Do not pretend this credential audit executes that new request.
            self.boundaries.append(name)
            self.ret()
        elif name == "_ZNK10CIPAddress5HasIPEv":
            self.boundaries.append(name)
            self.ret(int(self.has_ip))
        elif name == "_ZN14CServerManager14StartStreamingEyPKc":
            self.starts.append(
                dict(
                    manager=self.r(0), client_id=self.r(1), pin=self.cstring(self.r(2))
                )
            )
            self.ret()
        elif name == "_ZN13CPanelConnect20SetUIStateConnectingEv":
            self.ret()
        elif name == "_ZNK15QGuiApplication16devicePixelRatioEv":
            self.u.reg_write(
                UC_ARM64_REG_D0, struct.unpack("<Q", struct.pack("<d", 1.0))[0]
            )
            self.ret()
        elif name == "_ZN12CShellSystem21GetDisplayRefreshRateEPiS0_":
            self.wi(self.r(1), 60)
            self.wi(self.r(2), 1)
            self.ret()
        elif name == "_ZN12CShellSystem14BCanDisplayHDREbb":
            self.ret(0)
        elif name == "_ZN12CShellSystem23GetSpeakerConfigurationEv":
            self.ret(2)
        elif name == "_ZN18CControllerManager23GetNumMappedControllersEv":
            self.ret(self.settings.get("gamepads", 0))
        elif name in (
            "_ZN9QSettingsC1EP7QObject",
            "_ZN9QSettingsD1Ev",
            "_ZN8QVariantD1Ev",
        ):
            self.ret()
        elif name == "_ZNK9QSettings5valueERK7QStringRK8QVariant":
            self.ret()
        elif name == "_ZNK8QVariant6toUIntEPb":
            self.ret(2)
        elif name == "_ZN7QString16fromAscii_helperEPKci":
            self.ret(self.qstring(self.cstring(self.r(0))))
        elif name == "_ZN7QString13toUtf8_helperERKS_":
            self.wq(self.r(8), self.byte_array(b"4321"))
            self.ret()
        elif name == "_ZN10CUtlString8SetValueEPKc":
            value = self.cstring(self.r(1)) if self.r(1) else ""
            p = self.alloc(len(value) + 1)
            u.mem_write(p, value.encode() + b"\0")
            self.wq(self.r(0), p)
            self.ret()
        elif name == "strlen":
            self.ret(len(self.cstring(self.r(0)).encode()))
        elif "ERemoteDeviceStreamingResult_descriptor" in name:
            # This descriptor is only an argument to the inherited enum-name
            # formatting adapter. Required response parsing still runs.
            self.boundaries.append(name)
            self.ret()
        elif name == "time":
            self.ret(self.wall_time)
        elif name == "Log":
            self.ret()
        else:
            super().hook(u, pc, size, data)

    def message_wires(self):
        names = {5: REQUEST, 10: "CMsgRemoteDeviceStreamingCancelRequest"}
        return [
            dict(tag=tag, body=self.serialize(msg, names[tag]).hex())
            for tag, msg in self.messages
        ]


def request_case(binary, test, restricted, gamepads, patch=None):
    r = Discovery(binary, dict(gamepads=gamepads), patch)
    r.config(CONFIG, False, 2)
    r.loaded = CONFIG
    r.wq(PANEL + 0xC8, r.manager)
    r.wq(PANEL + 0xE8, 123)
    r.b(PANEL + 0xD4, int(test))
    r.wi(APP + 0x38, 1280)
    r.wi(APP + 0x3C, 720)
    r.wi(r.manager + 0x1BC, 4)
    r.b(r.manager + 0x1E4, int(restricted))
    r.call(r.symbols["_ZN13CPanelConnect23SetPanelStateConnectingEv"], PANEL)
    assert r.i(PANEL + 0xD8) == 4 and len(r.starts) == 1
    assert r.starts[0] == dict(manager=r.manager, client_id=123, pin="4321")
    # StartStreaming's identity/auth acquisition remains the documented boundary.
    # The complete producer below uses the manager the original UI just wrote.
    r.call(r.symbols["_ZN14CServerManager25SendStartStreamingRequestEv"], r.manager)
    wires = r.message_wires()
    assert len(wires) == 1 and wires[0]["tag"] == 5 and not r.assertions
    decoded = fields(bytes.fromhex(wires[0]["body"]))
    assert (patch or decoded["12"] == [int(test)]) and decoded["15"] == [
        int(restricted)
    ]
    assert "6" not in decoded
    return dict(
        input=dict(network_test=test, restricted=restricted, gamepads=gamepads),
        messages=wires,
        fields=decoded,
        starts=[{k: v for k, v in s.items() if k != "manager"} for s in r.starts],
        source_assertions=r.assertions,
        executed=sorted(r.executed),
        boundaries=r.boundaries,
        patch_hits=r.patch_hits,
    )


def response_case(binary, options):
    r = Discovery(binary)
    r.has_ip = options.get("has_ip", True)
    peer = r.alloc(24)
    r.u.mem_write(peer, bytes(range(1, 25)))
    r.u.mem_write(peer + 22, struct.pack("<H", options.get("peer_port", 27036)))
    body = (
        b"\x08"
        + varint(options.get("request_id", 17))
        + b"\x10"
        + varint(options.get("result", 0))
    )
    body += b"\x18" + varint(options.get("port", 27031))
    cipher = encrypted(bytes(range(options.get("key_length", 32))))
    if options.get("bad_padding"):
        # Deterministic corruption of a padding byte in the preceding block.
        cipher = bytearray(cipher)
        cipher[-17] ^= 0x80
        cipher = bytes(cipher)
    if "cipher_length" in options:
        cipher = cipher[: options["cipher_length"]]
    body += b"\x22" + varint(len(cipher)) + cipher
    if "raw" in options:
        body = bytes.fromhex(options["raw"])
    obj = r.alloc(512)
    parsed = r.parse(obj, body, RESPONSE)
    if parsed:
        for _ in range(options.get("repeat", 1)):
            r.call(
                r.symbols[
                    "_ZN14CServerManager28HandleStartStreamingResponseERK10CIPAndPortyPK33CMsgRemoteDeviceStreamingResponse"
                ],
                r.manager,
                peer,
                123,
                obj,
            )
    length = r.i(r.manager + 0x3AC)
    value = bytes(r.u.mem_read(r.q(r.manager + 0x398), length)).hex() if length else ""
    # Malformed optional cipher can reach official diagnostics (e.g. empty
    # output buffer). Preserve them as observations rather than suppressing or
    # counting them as a successful, assertion-free protocol case.
    if r.i(r.manager + 8) == 6 and length == 32:
        r.b(PANEL + 0xD4, 1)
        r.wi(PANEL + 0xD8, 4)
        r.call(r.symbols["_ZN13CPanelConnect8OnUpdateEv"], PANEL)
        assert r.auth_tokens == [value]
    return dict(
        input=options,
        parsed=parsed,
        response=body.hex(),
        state=r.i(r.manager + 8),
        request_id=r.i(r.manager + 0x200),
        key=value,
        key_length=length,
        test_auth_tokens=r.auth_tokens,
        crypto_hits=r.crypto_hits,
        endpoint=bytes(r.u.mem_read(r.manager + 0x32C, 24)).hex(),
        port=struct.unpack("<H", r.u.mem_read(r.manager + 0x342, 2))[0],
        steamid=r.q(r.manager + 0x320),
        messages=r.message_wires(),
        errors=r.errors,
        source_assertions=r.assertions,
        executed=sorted(r.executed),
        boundaries=r.boundaries,
    )


def retry_case(binary):
    r = Discovery(binary)
    r.wq(r.manager + 0x30, 0x7FFFFFFFFFFFFFFF)
    r.wi(r.manager + 0x50, 3)
    r.wi(r.manager + 0x1BC, 4)
    r.b(r.manager + 0x1E5, 1)
    r.wi(PANEL + 0xD8, 4)
    r.call(r.symbols["_ZN14CServerManager25SendStartStreamingRequestEv"], r.manager)
    observations = []
    for tick in (1000, 1001, 1001, 1002, 1015, 1300, 86400):
        r.wall_time = tick
        r.call(r.symbols["_ZN14CServerManager6UpdateEv"], r.manager)
        r.call(r.symbols["_ZN13CPanelConnect8OnUpdateEv"], PANEL)
        observations.append(
            dict(
                time=tick,
                next=r.q(r.manager + 0x208),
                state=r.i(r.manager + 8),
                sends=len(r.messages),
                errors=list(r.errors),
            )
        )
    assert not r.assertions
    assert [s["sends"] for s in observations] == [1, 2, 2, 3, 4, 5, 6]
    assert all(s["state"] == 5 and not s["errors"] for s in observations)
    return dict(
        observations=observations,
        messages=r.message_wires(),
        source_assertions=r.assertions,
        executed=sorted(r.executed),
        boundaries=r.boundaries,
    )


def inventory(binary, cases):
    names = {n for c in cases for n in c["executed"]}
    elf = ELFFile(io.BytesIO(binary))
    text = elf.get_section_by_name(".text")
    result = {}
    for s in elf.get_section_by_name(".dynsym").iter_symbols():
        if s.name in names and s["st_size"]:
            offset = s["st_value"] - text["sh_addr"]
            code = text.data()[offset : offset + s["st_size"]]
            result[s.name] = dict(
                address=s["st_value"],
                size=len(code),
                sha256=hashlib.sha256(code).hexdigest(),
            )
    assert set(result) == names
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    binary = a.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == lifecycle.media.flow.SHA
    requests = [
        request_case(binary, t, r, g)
        for t in (False, True)
        for r in (False, True)
        for g in (0, 1)
    ]
    response_inputs = [dict(name="success"), dict(name="bad_padding", bad_padding=True)]
    response_inputs += [
        dict(name=f"short_{n}", cipher_length=n) for n in (0, 1, 15, 16, 17, 31, 32, 63)
    ]
    response_inputs += [
        dict(name=f"key_length_{n}", key_length=n) for n in (0, 16, 31, 33)
    ]
    response_inputs += [dict(name=f"result_{n}", result=n) for n in range(1, 16)]
    response_inputs += [
        dict(
            name=f"mismatch_{result}_{request_id}", result=result, request_id=request_id
        )
        for result in (0, 5)
        for request_id in (0, 16, 18)
    ]
    response_inputs += [
        dict(name="no_ip", has_ip=False),
        dict(name="zero_peer_port", peer_port=0),
        dict(name="response_port_zero", port=0),
        dict(name="response_port_truncate", port=65537),
    ]
    response_inputs += [
        dict(name=f"malformed_{wire}", raw=wire) for wire in ("08", "08111080")
    ]
    response_inputs += [dict(name="missing_cipher", raw="08111000")]
    response_inputs += [dict(name="mismatch_twice", result=5, request_id=16, repeat=2)]
    responses = []
    for options in response_inputs:
        responses.append(response_case(binary, options))
        print(
            options["name"], responses[-1]["state"], responses[-1]["errors"], flush=True
        )
    retry = retry_case(binary)
    original = next(
        c
        for c in requests
        if c["input"] == dict(network_test=True, restricted=False, gamepads=0)
    )
    r = Discovery(binary)
    pc = 0xC6E28C
    before = r.i(pc)
    assert before == 0x39079708
    after = (before & ~31) | 31
    mutant = request_case(binary, True, False, 0, (pc, before, after))
    assert mutant["patch_hits"] == [pc] and mutant["fields"]["12"] == [0]
    report = dict(
        binary_sha256=lifecycle.media.flow.SHA,
        scope=__doc__,
        functions=inventory(binary, requests + responses + [retry]),
        requests=requests,
        responses=responses,
        retry=retry,
        mutation=dict(
            pc=pc, before=before, after=after, original=original, mutant=mutant
        ),
    )
    if a.refresh_reference:
        if REFERENCE.exists():
            assert json.loads(gzip.decompress(REFERENCE.read_bytes())) == report
        REFERENCE.write_bytes(
            gzip.compress((json.dumps(report, indent=2) + "\n").encode(), mtime=0)
        )
    else:
        assert json.loads(gzip.decompress(REFERENCE.read_bytes())) == report
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        "Official discovery:",
        len(requests),
        "UI/request producers;",
        len(responses),
        "response/decrypt cases",
    )


if __name__ == "__main__":
    main()
