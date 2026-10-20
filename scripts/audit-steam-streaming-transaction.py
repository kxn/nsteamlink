#!/usr/bin/env python3
"""Official request replacement, ticket ownership and failed-test acknowledgement.

Original StartStreaming/state guards, request producer/serializer, response parser/
handler/AES, StopStreaming/cancel serializer and Panel OnUpdate/test Start/Run/
CheckFailed/failed-dialog wiring/OnActionCancel run. Server lookup, authorized
secret/token/account, supplied randomness/keypair/PIN inputs, clock, thread start,
BConnect bool failure, Qt storage/presentation/formatting and final SendMessage/
PopState are explicit adapters. Qt finished delivery is a supplied user action;
no natural Steam identity, Qt scheduling, OS test thread or Switch is proved.
Native comparisons project request-id/test flag/state/target/cancel bytes, not
all platform-dependent request metadata or the adapted keypair implementation.
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

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "discovery", ROOT / "scripts/audit-steam-network-test-discovery.py"
)
discovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(discovery)
PANEL, TEST = discovery.PANEL, discovery.lifecycle.TEST
REFERENCE = ROOT / "scripts/fixtures/steam-streaming-transaction-reference.json.gz"


class Transaction(discovery.Discovery):
    def __init__(self, binary, patch=None):
        self.ids = iter([17, 19, 23, 29])
        self.actions, self.destinations = [], []
        self.failed_run = False
        super().__init__(binary, patch=patch)
        self.wi(self.manager + 8, 1)
        self.wi(self.manager + 0x200, 0)
        self.wq(self.manager + 0x1F0, 0)
        self.wq(PANEL + 0xF0, self.qstring("Fixture Host"))
        self.wq(PANEL + 0xF8, self.empty)
        self.wq(discovery.APP + 0x18, self.manager)

    def hook(self, u, pc, size, unused):
        name = self.plts.get(pc, "")
        if name == "_ZN14CServerManager14StartStreamingEyPKc":
            self.jump(self.symbols[name])
        elif name == "WeakRandomInt":
            assert (self.r(0), self.r(1)) == (1, 0x7FFFFFF)
            self.ret(next(self.ids))
        elif name == "_ZN14CServerManager23LoadPersistentClientKeyEyyR10CUtlBuffer":
            self.ret()  # Known authorized secret already in the real CUtlBuffer.
        elif name == "_ZN7CCrypto19GenerateRandomBlockEPvm":
            assert self.r(1) == 4
            u.mem_write(self.r(0), struct.pack("<I", 42))
            self.ret(1)
        elif (
            name
            == "_ZN7CCrypto26GenerateKeyExchangeKeyPairEP23CECKeyExchangePublicKeyP24CECKeyExchangePrivateKey"
        ):
            self.ret(1)  # Keypair boundary; not a key-agreement proof.
        elif name == "_ZN10CUtlString6FormatEPKcz":
            assert self.cstring(self.r(1)) == "%4.4u" and self.r(2) == 42
            p = self.alloc(16)
            u.mem_write(p, b"0042\0")
            self.wq(self.r(0), p)
            self.ret()
        elif name == "_ZN17CShellApplication8PopStateEv":
            self.actions.append(dict(pop=True))
            self.ret()
        elif name == "_ZN12CNetworkTest8BConnectEv" and self.failed_run:
            self.ret(0)  # Original Run body then reaches actual status Failed.
        elif name.startswith("_ZN12CPanelDialogC"):
            self.actions.append(
                dict(
                    dialog_style=self.r(4), title=self.qt_strings.get(self.q(self.r(2)))
                )
            )
            self.ret()
        elif name == "_ZN7QObject7connectEPKS_PKcS1_S3_N2Qt14ConnectionTypeE":
            self.actions.append(
                dict(signal=self.cstring(self.r(1)), slot=self.cstring(self.r(3)))
            )
            self.ret()
        else:
            if (
                name
                == "_ZN14CServerManager11SendMessageE25ERemoteClientBroadcastMsgPN6google8protobuf7MessageE10CIPAndPorty"
            ):
                self.destinations.append(self.r(4))
            super().hook(u, pc, size, unused)

    def start(self, test, host=123):
        self.b(self.manager + 0x1E5, int(test))
        empty = self.alloc(1)
        self.call(
            self.symbols["_ZN14CServerManager14StartStreamingEyPKc"],
            self.manager,
            host,
            empty,
        )

    def response(self, result=0, request_id=None, host=123):
        peer = self.alloc(24)
        self.u.mem_write(peer, bytes(range(1, 25)))
        self.u.mem_write(peer + 22, struct.pack("<H", 27036))
        rid = self.i(self.manager + 0x200) if request_id is None else request_id
        body = b"\x08" + discovery.varint(rid) + b"\x10" + discovery.varint(result)
        if result == 0:
            cipher = discovery.encrypted()
            body += (
                b"\x18"
                + discovery.varint(61024)
                + b"\x22"
                + discovery.varint(len(cipher))
                + cipher
            )
        obj = self.alloc(512)
        assert self.parse(obj, body, discovery.RESPONSE)
        self.call(
            self.symbols[
                "_ZN14CServerManager28HandleStartStreamingResponseERK10CIPAndPortyPK33CMsgRemoteDeviceStreamingResponse"
            ],
            self.manager,
            peer,
            host,
            obj,
        )

    def stop(self):
        self.call(
            self.symbols["_ZN14CServerManager13StopStreamingE12EServerError"],
            self.manager,
            0,
        )

    def observe(self, label):
        messages = self.message_wires()
        for m, host in zip(messages, self.destinations):
            fields = discovery.fields(bytes.fromhex(m["body"]))
            m.update(target=host, request_id=fields["1"][0])
            if m["tag"] == 5:
                m["network_test"] = bool(fields["12"][0])
        return dict(
            label=label,
            state=self.i(self.manager + 8),
            request_id=self.i(self.manager + 0x200),
            target=self.q(self.manager + 0x1F0),
            messages=messages,
            actions=list(self.actions),
            test_status=self.i(TEST + 12),
        )


def run(binary, inp, patch=None):
    r = Transaction(binary, patch)
    r.start(inp["test"])
    steps = [r.observe("requested")]
    path = inp["path"]
    ticket = path in (
        "cancel_ticket",
        "replace_ticket",
        "replace_ticket_host",
        "failure_dialog",
    )
    if ticket:
        r.response()
        steps.append(r.observe("ticket"))
        r.response(5)
        steps.append(r.observe("matching_progress"))
    if path == "duplicate_pending":
        r.start(inp["test"])
        steps.append(r.observe("duplicate"))
    if path.startswith("replace"):
        different_host = path.endswith("_host")
        r.start(False, 456 if different_host else 123)
        steps.append(r.observe("replaced"))
        r.response(5, 17, 123)
        steps.append(r.observe("old_progress"))
        r.response(5, None, 456 if different_host else 123)
        steps.append(r.observe("new_progress"))
    if path == "failure_dialog":
        r.wi(PANEL + 0xD0, inp["action"])
        r.b(PANEL + 0xD4, 1)
        r.wi(PANEL + 0xD8, 4)
        r.call(r.symbols["_ZN13CPanelConnect8OnUpdateEv"], PANEL)
        r.failed_run = True
        r.call(r.symbols["_ZN12CNetworkTest14RunNetworkTestEv"], TEST)
        r.call(r.symbols["_ZN13CPanelConnect21CheckNetworkTestStateEv"], PANEL)
        steps.append(r.observe("failed_dialog"))
        # QObject connects finished(int) to the zero-argument slot. The supplied
        # result is discarded at that boundary; the original slot is executed.
        r.call(r.symbols["_ZN13CPanelConnect14OnActionCancelEv"], PANEL)
        steps.append(r.observe("acknowledged"))
    else:
        r.stop()
        steps.append(r.observe("cancelled"))
        if inp.get("repeat_cancel", True):
            r.stop()
            steps.append(r.observe("cancelled_again"))
    assert not r.assertions
    return dict(
        input=inp,
        steps=steps,
        source_assertions=r.assertions,
        executed=sorted(r.executed),
        patch_hits=r.patch_hits,
    )


def inventory(binary, cases):
    elf = ELFFile(io.BytesIO(binary))
    names = set().union(*(set(c["executed"]) for c in cases))
    rows = []
    for s in elf.get_section_by_name(".dynsym").iter_symbols():
        if s.name not in names:
            continue
        a, n = s["st_value"], s["st_size"]
        for seg in elf.iter_segments():
            if (
                seg["p_type"] == "PT_LOAD"
                and seg["p_vaddr"] <= a < seg["p_vaddr"] + seg["p_filesz"]
            ):
                off = a - seg["p_vaddr"]
                rows.append(
                    dict(
                        name=s.name,
                        address=a,
                        size=n,
                        sha256=hashlib.sha256(seg.data()[off : off + n]).hexdigest(),
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
    a = p.parse_args()
    binary = a.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == discovery.lifecycle.media.flow.SHA
    inputs = [
        dict(path=path, test=test)
        for test in (False, True)
        for path in (
            "cancel_pending",
            "cancel_ticket",
            "duplicate_pending",
            "replace_pending_host",
            "replace_ticket",
            "replace_ticket_host",
        )
    ]
    inputs += [
        dict(path="failure_dialog", test=True, action=action, finished_result=finished)
        for action in (2, 3)
        for finished in (0, 1)
    ]
    cases = [run(binary, i) for i in inputs]
    for c in cases:
        assert c["steps"][0]["state"] == 5 and c["steps"][0]["request_id"] == 17
        assert c["steps"][-1]["state"] == 1 and c["steps"][-1]["request_id"] == 0
        for step in c["steps"]:
            if step["label"] in ("ticket", "matching_progress", "failed_dialog"):
                assert (
                    step["state"] == 6
                    and step["request_id"] == 17
                    and len(step["messages"]) == 1
                )
        if c["input"]["path"] == "failure_dialog":
            failed = next(s for s in c["steps"] if s["label"] == "failed_dialog")
            assert failed["test_status"] == 4
            assert (
                dict(signal="2finished( int )", slot="1OnActionCancel()")
                in failed["actions"]
            )
            assert failed["actions"][0] == dict(
                dialog_style=0, title="Network Test Failed"
            )
            assert c["steps"][-1]["actions"][-1] == dict(pop=True)
    inp = dict(path="cancel_ticket", test=True, repeat_cancel=False)
    pc = 0xCB0F1C
    before = struct.unpack_from(
        "<I", discovery.lifecycle.media.flow.config.BASE["load_image"](binary)[0], pc
    )[0]
    original = run(binary, inp)
    mutant = run(binary, inp, (pc, before, before + (5 << 10)))
    assert mutant["patch_hits"] == [pc] and not mutant["source_assertions"]
    assert (
        original["steps"][-1]["request_id"] == 0
        and mutant["steps"][-1]["request_id"] == 17
    )
    report = dict(
        binary_sha256=discovery.lifecycle.media.flow.SHA,
        scope=__doc__,
        cases=cases,
        functions=inventory(binary, cases),
        mutation=dict(
            original=original,
            mutant=mutant,
            pc=pc,
            before=before,
            after=before + (5 << 10),
        ),
    )
    if a.refresh_reference:
        assert not REFERENCE.exists()
        REFERENCE.write_bytes(
            gzip.compress((json.dumps(report, indent=2) + "\n").encode(), mtime=0)
        )
    else:
        assert json.loads(gzip.decompress(REFERENCE.read_bytes())) == report
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        "Official streaming transactions:",
        len(cases),
        "cases,",
        len(report["functions"]),
        "function identities, 1 executed stop counterfactual",
    )


if __name__ == "__main__":
    main()
