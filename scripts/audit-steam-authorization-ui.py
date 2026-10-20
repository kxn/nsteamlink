#!/usr/bin/env python3
"""Official automatic authorization UI, real save callers and failure continuation.

Original Start/keypair, Unauthorized, Panel OnUpdate/Authorizing/PIN label input,
full response crypto, SavePersistentClientKey/hex/paired-list/SaveFile, 14/5 sends
and original cancel execute. Low-level SDL mkdir/open/write/close are explicit
controlled providers with readback; Qt/QString/widgets/layout, random/identity,
clock, request RSA and final send/Pop/ordinary launcher are adapters. The request
producer, parsers and all response crypto are original. No actual Qt pixels,
Steam identity, filesystem durability, natural threads or Switch is proved.
Constructor defaults now execute on A5-filled independent storage; paired-ID loading
and client-ID migration are explicit identity/file providers (§130).
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "exchange", ROOT / "scripts/audit-steam-authorization-exchange.py"
)
e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e)
PANEL, APP = e.p.m.PANEL, e.p.m.discovery.APP
REFERENCE = ROOT / "scripts/fixtures/steam-authorization-ui-reference.json.gz"
SAVE = "_ZN14CServerManager23SavePersistentClientKeyEyyR10CUtlBuffer"
SEND = "_ZN14CServerManager11SendMessageE25ERemoteClientBroadcastMsgPN6google8protobuf7MessageE10CIPAndPorty"


class AuthorizationUI(e.Exchange):
    def __init__(self, binary, mode="ok", patch=None, random_values=None, pin="9876"):
        self.io, self.file_bytes, self.handles, self.timeline = [], {}, {}, []
        self.labels, self.ui_calls = [], []
        self.mode = mode
        self.connect_pin = pin.encode()
        self.random_values = iter(random_values or [42])
        self.pin_random = []
        self.next_handle = 0x9000
        self.ordinary_launches = []
        super().__init__(binary, patch)
        for name in (
            SAVE,
            "_ZN14CServerManager12BSaveHexDataEPKcPKvi",
            "_ZN14CServerManager17SavePairedSteamIDEy",
            "_ZN14CServerManager18SavePairedSteamIDsEv",
            "_Z9BSaveFilePKcS0_RK10CUtlBuffer",
            "V_binarytohex",
        ):
            self.function_entries.setdefault(self.symbols[name], []).append(name)
        self.wq(PANEL + 0xE8, 123)
        self.wi(APP + 0x38, 1280)
        self.wi(APP + 0x3C, 720)
        paired = self.alloc(64)
        self.wq(self.manager + 0x3D8, paired)
        self.wi(self.manager + 0x3E0, 8)

    def hook(self, u, pc, size, data):
        name = self.plts.get(pc, "")
        if name:
            self.ui_calls.append(name)
        if name == "_ZN13CPanelConnect23SetPanelStateConnectingEv":
            self.jump(self.symbols[name])
        elif name == "_ZN7QString13toUtf8_helperERKS_":
            self.wq(self.r(8), self.byte_array(self.connect_pin))
            self.ret()
        elif name == SAVE:
            buf = self.r(3)
            self.timeline.append(
                dict(
                    op="save_key",
                    client=self.r(1),
                    steamid=self.r(2),
                    secret=bytes(u.mem_read(self.q(buf), self.i(buf + 20))).hex(),
                )
            )
            self.jump(self.symbols[name])
        elif name == "_ZN7CCrypto19GenerateRandomBlockEPvm" and self.r(1) == 4:
            value = next(self.random_values)
            self.pin_random.append(value)
            u.mem_write(self.r(0), struct.pack("<I", value))
            self.ret(1)
        elif name == "_Z17BCreateDirsInPath10StringView":
            self.io.append(dict(op="mkdir", path=self.cstring(self.r(0))))
            self.ret(int(self.mode != "mkdir"))
        elif name == "SDL_IOFromFile":
            path = self.cstring(self.r(0))
            self.io.append(dict(op="open", path=path, mode=self.cstring(self.r(1))))
            if self.mode == "open":
                self.ret(0)
            else:
                self.next_handle += 1
                self.handles[self.next_handle] = path
                self.file_bytes[path] = b""
                self.ret(self.next_handle)
        elif name == "SDL_WriteIO":
            n = self.r(2)
            count = (
                0
                if self.mode == "zero"
                else max(1, n // 2) if self.mode == "short" else n
            )
            path = self.handles[self.r(0)]
            self.file_bytes[path] += bytes(u.mem_read(self.r(1), count))
            self.io.append(dict(op="write", path=path, requested=n, written=count))
            self.ret(count)
        elif name == "SDL_CloseIO":
            path = self.handles.pop(self.r(0))
            self.io.append(dict(op="close", path=path))
            self.ret(int(self.mode != "close"))
        elif name == SEND:
            self.timeline.append(dict(op="send", tag=self.r(1), io_count=len(self.io)))
            super().hook(u, pc, size, data)
        elif name == "_ZN13CPanelConnect14StartStreamingEv":
            self.ordinary_launches.append(
                bytes(
                    u.mem_read(
                        self.q(self.manager + 0x398), self.i(self.manager + 0x3AC)
                    )
                ).hex()
            )
            self.ret()
        elif name == "_ZN10CPanelBase11LayoutPanelEP7QWidgetP9CPanelNav":
            self.ret()
        elif name in (
            "_ZN8QVariantC1ERK7QString",
            "_ZN8QVariantC1EPKc",
            "_ZN11QBasicTimer4stopEv",
            "_ZN10QBoxLayout10addStretchEi",
        ):
            self.ret()
        elif name == "_ZNK7QWidget6layoutEv":
            self.ret(0)
        elif name == "_ZN6QLabel7setTextERK7QString":
            text = self.qt_strings.get(self.q(self.r(1)))
            assert text is not None
            self.labels.append(text)
            self.ret()
        elif name == "_ZN7QObject11setPropertyEPKcRK8QVariant":
            self.ret(1)
        elif name == "_ZN7QStringaSERKS_":
            self.wq(self.r(0), self.q(self.r(1)))
            self.ret(self.r(0))
        else:
            super().hook(u, pc, size, data)

    def update(self):
        self.call(self.symbols["_ZN13CPanelConnect8OnUpdateEv"], PANEL)

    def observe(self, label):
        state = self.snapshot(label)
        state.update(
            panel=self.i(PANEL + 0xD8),
            labels=list(self.labels),
            io=list(self.io),
            files={k: v.hex() for k, v in self.file_bytes.items()},
            timeline=list(self.timeline),
            ordinary_launches=list(self.ordinary_launches),
            network_tokens=list(self.auth_tokens),
            pin_random=list(self.pin_random),
        )
        return state

    def credentials(self, secret, length):
        iv = bytes(range(16))
        raw = bytes(range(length))
        pad = 16 - len(raw) % 16
        a = e.Cipher(e.algorithms.AES(secret), e.modes.ECB()).encryptor()
        b = e.Cipher(e.algorithms.AES(secret), e.modes.CBC(iv)).encryptor()
        cipher = (
            a.update(iv)
            + a.finalize()
            + b.update(raw + bytes([pad]) * pad)
            + b.finalize()
        )
        v = e.p.m.discovery.varint
        body = b"\x08\x11\x10\0\x18" + v(61024) + b"\x22" + v(len(cipher)) + cipher
        obj, peer = self.alloc(512), self.alloc(24)
        self.u.mem_write(peer, bytes(range(1, 25)))
        self.u.mem_write(peer + 22, struct.pack("<H", 27036))
        assert self.parse(obj, body, e.p.m.discovery.RESPONSE)
        self.call(
            self.symbols[
                "_ZN14CServerManager28HandleStartStreamingResponseERK10CIPAndPortyPK33CMsgRemoteDeviceStreamingResponse"
            ],
            self.manager,
            peer,
            123,
            obj,
        )


def run(binary, inp, patch=None):
    r = AuthorizationUI(
        binary, inp.get("io", "ok"), patch, inp.get("random"), inp.get("pin", "9876")
    )
    r.b(PANEL + 0xD4, int(inp.get("test", False)))
    r.call(r.symbols["_ZN13CPanelConnect23SetPanelStateConnectingEv"], PANEL)
    assert r.i(PANEL + 0xD8) == 4
    r.response(1)
    assert r.i(PANEL + 0xD8) == 4
    r.update()
    steps = [r.observe("pin")]
    r.update()
    steps.append(r.observe("same_pin"))
    if inp["path"] == "cancel":
        r.call(r.symbols["_ZN13CPanelConnect14OnActionCancelEv"], PANEL)
        steps.append(r.observe("cancelled"))
    else:
        key, token, secret = e.material(pin=r.labels[0].encode())
        r.auth_response(key=key, token=token)
        steps.append(r.observe("authorized"))
        r.update()
        steps.append(r.observe("connecting"))
        if inp["path"] == "credentials":
            r.credentials(secret, inp["length"])
            steps.append(r.observe("credentials"))
            r.update()
            steps.append(r.observe("consumer"))
    assert not r.assertions
    return dict(
        input=inp,
        steps=steps,
        actions=r.actions,
        ui_calls=r.ui_calls,
        source_assertions=r.assertions,
        executed=sorted(r.executed),
        patch_hits=r.patch_hits,
    )


def verify(c):
    i = c["input"]
    first, last = c["steps"][0], c["steps"][-1]
    label = f"{i.get('random',[42])[-1]%10000:04d}"
    assert first["panel"] == 3 and first["state"] == 4 and first["labels"] == [label]
    assert c["steps"][1]["labels"] == [label]
    if i["path"] == "cancel":
        assert last["state"] == 1 and last["rid"] == 0
        assert [m["tag"] for m in last["messages"]] == [5, 3, 9] and c["actions"] == [
            dict(pop=True)
        ]
        return
    authorized = c["steps"][2]
    assert authorized["state"] == 5 and authorized["rid"] == 17
    assert [m["tag"] for m in authorized["messages"]] == [5, 3, 14, 5]
    # Full-body equality here depends on the TOKEN123 identity adapter. The PIN
    # comparator projects field8 only; this is not a real-token retry contract.
    assert authorized["messages"][0] == authorized["messages"][3]
    assert [x.get("tag", x["op"]) for x in authorized["timeline"]] == [
        5,
        3,
        "save_key",
        14,
        5,
    ]
    assert next(x for x in authorized["timeline"] if x.get("tag") == 14)[
        "io_count"
    ] == len(authorized["io"])
    assert (
        c["steps"][3]["state"] == 5
        and c["steps"][3]["rid"] == 17
        and c["steps"][3]["panel"] == 4
    )
    assert (
        c["ui_calls"].count(
            "_ZN7CCrypto26GenerateKeyExchangeKeyPairEP23CECKeyExchangePublicKeyP24CECKeyExchangePrivateKey"
        )
        == 1
    )
    if i.get("io", "ok") == "ok":
        expected = e.material()[2].hex().encode() + b"\n"
        assert (
            bytes.fromhex(
                authorized["files"][
                    "/fixture/7b00000000000000/014c5e0201001001/secret_key.txt"
                ]
            )
            == expected
        )
        assert (
            bytes.fromhex(authorized["files"]["/fixture/paired_steamid.txt"])
            == b"014c5e0201001001\n"
        )
    if i["path"] == "credentials":
        assert last["state"] == 6
        raw = bytes(range(i["length"])).hex()
        assert last["network_tokens"] == ([raw] if i["test"] else [])
        assert last["ordinary_launches"] == ([] if i["test"] else [raw])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    args = p.parse_args()
    binary = args.binary.read_bytes()
    sha = e.p.m.discovery.lifecycle.media.flow.SHA
    assert hashlib.sha256(binary).hexdigest() == sha
    inputs = [dict(path="cancel", test=t) for t in (False, True)]
    inputs += [
        dict(path="success", test=t, io=io)
        for t in (False, True)
        for io in ("ok", "mkdir", "open", "zero", "short", "close")
    ]
    inputs += [
        dict(path="credentials", test=t, length=n)
        for t in (False, True)
        for n in (16, 32)
    ]
    inputs += [
        dict(path="success", pin=pin)
        for pin in ("", "0", "987654321012345", "9876543210123456")
    ]
    inputs += [
        dict(path="success", random=values)
        for values in ([0, 10000, 10042], [0, 10000, 1])
    ]
    cases = [run(binary, i) for i in inputs]
    for c in cases:
        verify(c)
    pc = 0xCB4D6C
    image = e.p.m.discovery.lifecycle.media.flow.config.BASE["load_image"](binary)[0]
    before = struct.unpack_from("<I", image, pc)[0]
    original = run(binary, dict(path="success"))
    mutant = run(binary, dict(path="success"), (pc, before, 0xD503201F))
    assert mutant["patch_hits"] == [pc] and not mutant["source_assertions"]
    assert len(original["steps"][2]["files"]) == 2 and not mutant["steps"][2]["files"]
    report = dict(
        binary_sha256=sha,
        scope=__doc__,
        functions=e.p.m.inventory(binary, cases),
        cases=cases,
        negative=dict(
            site=pc, before=before, after=0xD503201F, original=original, mutant=mutant
        ),
    )
    if args.refresh_reference:
        if REFERENCE.exists():
            assert report == json.loads(gzip.decompress(REFERENCE.read_bytes()))
        REFERENCE.write_bytes(
            gzip.compress(json.dumps(report, sort_keys=True).encode(), mtime=0)
        )
    else:
        assert report == json.loads(gzip.decompress(REFERENCE.read_bytes()))
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"Official authorization UI/storage: {len(cases)} cases, original save callers/file failure branches and credential consumer"
    )


if __name__ == "__main__":
    main()
