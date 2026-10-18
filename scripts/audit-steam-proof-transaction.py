#!/usr/bin/env python3
"""Original Proof transaction trace and selected-server identity input.

Extends §133 without changing its frozen 56 cases. Runs original StartStreaming
copy from selected fallback record+8 into manager+1f8, not post-Start injection.
Selected record, identity/key loading, Qt, SDL files, time/IV, final Send and
ordinary launcher remain §133 providers. This proves the copy/save contract,
not the natural server/account selector or real Steam/OS/Switch behavior.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "proof", ROOT / "scripts/audit-steam-streaming-proof.py"
)
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
REFERENCE = ROOT / "scripts/fixtures/steam-proof-transaction-reference.json.gz"
Original = p.Proof


class Trace(Original):
    def __init__(self, binary, inp, patch=None):
        self.tracing = False
        super().__init__(binary, inp, patch)
        self.wire_events = []
        self.event_host = 123
        self.first_start = True
        self.server_account = inp.get("server_account", 0)
        self.wq(self.manager + 0x128, self.server_account)
        self.tracing = True

    def call(self, address, *args):
        if self.tracing:
            kind = None
            if address in (
                self.symbols[p.life.START],
                self.symbols["_ZN14CServerManager14StartStreamingEyPKc"],
            ):
                if self.first_start:
                    self.first_start = False
                else:
                    kind = "start"
            elif (
                address
                == self.symbols["_ZN14CServerManager13StopStreamingE12EServerError"]
            ):
                kind = "cancel"
            elif address == self.symbols["_ZN14CServerManager6UpdateEv"]:
                kind = "update"
            if kind:
                self.wire_events.append(dict(kind=kind, wall=self.wall_time))
        return super().call(address, *args)

    def parse(self, address, body, name):
        tags = {
            "CMsgRemoteDeviceStreamingResponse": 6,
            "CMsgRemoteDeviceAuthorizationResponse": 4,
            "CMsgRemoteDeviceProofRequest": 7,
        }
        if self.tracing and name in tags:
            self.wire_events.append(
                dict(
                    kind="packet",
                    tag=tags[name],
                    body=body.hex(),
                    host=self.event_host,
                    wall=self.wall_time,
                    encrypt_failure=self.fail_encrypt if tags[name] == 7 else False,
                )
            )
        return super().parse(address, body, name)

    def proof(self, *args, **kwargs):
        self.event_host = kwargs.get("host", 123)
        result = super().proof(*args, **kwargs)
        self.event_host = 123
        return result

    def observe(self, label):
        row = super().observe(label)
        row.update(
            event_count=len(self.wire_events),
            server_account=self.q(self.manager + 0x128),
            launcher_account=self.q(self.manager + 0x320),
        )
        self.final_events = list(self.wire_events)
        return row


def verify(case):
    p.verify(case)
    inp = case["input"]
    if "server_account" in inp:
        assert all(s["account"] == inp["server_account"] for s in case["steps"])
        saves = [x for x in case["steps"][-1]["timeline"] if x["op"] == "save_key"]
        proof_saves = [x for x in case["steps"][-1]["proof_ops"] if x["op"] == "save"]
        assert proof_saves and all(
            x["steamid"] == inp["server_account"] for x in proof_saves
        )
        if inp.get("phase") == "authorized":
            assert saves[0]["steamid"] == 76561198000000001
            assert saves[-1]["steamid"] == inp["server_account"]
        if inp["path"] == "reauthorize":
            assert saves[-1]["steamid"] == 76561198000000001


def main():
    if not __debug__:
        raise SystemExit("Assertions required")
    a = argparse.ArgumentParser(description=__doc__)
    a.add_argument("--binary", type=Path, required=True)
    a.add_argument("--output", type=Path, required=True)
    a.add_argument("--refresh-reference", action="store_true")
    args = a.parse_args()
    binary = args.binary.read_bytes()
    sha = p.life.m.e.p.m.discovery.lifecycle.media.flow.SHA
    assert hashlib.sha256(binary).hexdigest() == sha
    traced = []

    class Recorded(Trace):
        def __init__(self, *args, **kw):
            super().__init__(*args, **kw)
            traced.append(self)

    p.Proof = Recorded
    cases = []
    inputs = p.inputs() + [
        dict(server_account=i, path=path)
        for i in (123, 76561198000000002)
        for path in ("requests", "reauthorize")
    ]
    inputs += [dict(requests=[dict(challenge=(bytes(range(256)) * 5).hex())])]
    inputs += [
        dict(server_account=i, path="requests", phase="authorized")
        for i in (123, 76561198000000002)
    ]
    for index, inp in enumerate(inputs):
        case = p.run(binary, inp)
        verify(case)
        case["events"] = traced[-1].final_events
        cases.append(case)
        print(
            index,
            inp.get("path", "requests"),
            "original transaction verified",
            flush=True,
        )
    import struct

    image = p.life.m.e.p.m.discovery.lifecycle.media.flow.config.BASE["load_image"](
        binary
    )[0]
    pc = 0xCB03C0
    before = struct.unpack_from("<I", image, pc)[0]
    original = p.run(binary, dict(server_account=123, path="requests"))
    verify(original)
    mutant = p.run(
        binary, dict(server_account=123, path="requests"), (pc, before, 0xD503201F)
    )
    assert mutant["patch_hits"] == [pc] and not mutant["source_assertions"]
    try:
        verify(mutant)
    except AssertionError:
        pass
    else:
        raise AssertionError("Selected identity copy regression not detected")
    negative = dict(
        site=pc, before=before, after=0xD503201F, original=original, mutant=mutant
    )
    report = dict(
        binary_sha256=sha,
        scope=__doc__,
        cases=cases,
        negative_identity=negative,
        functions=p.life.m.e.p.m.inventory(binary, cases),
    )
    if args.refresh_reference and not REFERENCE.exists():
        REFERENCE.write_bytes(
            gzip.compress(json.dumps(report, sort_keys=True).encode(), mtime=0)
        )
    assert report == json.loads(gzip.decompress(REFERENCE.read_bytes()))
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Original Proof transactions: {len(cases)}", flush=True)


if __name__ == "__main__":
    main()
