#!/usr/bin/env python3
"""Official original-request authorization transitions and matching-ID packet order.

Original Stream/Authorization parsers, producers, token/PIN/response crypto,
keypair/cache/save callers, Update and Panel execute with §131 providers. Input
packets enter the parsed handler boundary; OS socket admission is not claimed.
Qt, identity/IV, request RSA, low-level files and final Send/ordinary launcher
remain explicit boundaries. No Native automatic completion is inferred here.
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
    "token", ROOT / "scripts/audit-steam-device-token.py"
)
token = importlib.util.module_from_spec(spec)
spec.loader.exec_module(token)
life = token.life
PANEL, START = life.m.PANEL, life.START
REFERENCE = ROOT / "scripts/fixtures/steam-auto-authorization-reference.json.gz"


class Automatic(token.Token):
    def __init__(self, binary, inp, patch=None):
        self.events, self.event_host, self.record_events = [], 123, False
        super().__init__(
            binary, dict(path="reauthorize", pin="9876", test=inp["test"]), patch
        )
        self.record_events = True

    def parse(self, address, body, name):
        if self.record_events and name in (
            "CMsgRemoteDeviceStreamingResponse",
            "CMsgRemoteDeviceAuthorizationResponse",
        ):
            self.events.append(
                dict(
                    kind="packet",
                    tag=6 if name == "CMsgRemoteDeviceStreamingResponse" else 4,
                    body=body.hex(),
                    host=self.event_host,
                    wall=self.wall_time,
                )
            )
        return super().parse(address, body, name)

    def observe(self, label):
        row = super().observe(label)
        row["event_count"] = len(self.events)
        return row

    def advance(self, wall):
        self.wall_time = wall
        self.events.append(dict(kind="update", wall=wall))
        self.call(self.symbols["_ZN14CServerManager6UpdateEv"], self.manager)


def run(binary, inp, patch=None):
    r = Automatic(binary, inp, patch)
    r.b(PANEL + 0xD4, int(inp["test"]))
    r.call(r.symbols[START], PANEL)
    steps = [r.observe("requested")]
    r.response(1)
    r.update()
    steps.append(r.observe("authorization"))
    path = inp["path"]
    if path == "duplicate_unauthorized":
        r.wall_time = 1001
        r.response(1)
        r.update()
        steps.append(r.observe("duplicate"))
        for wall in (1003, 1004):
            r.advance(wall)
            steps.append(r.observe(str(wall)))
    elif path == "success_repeat_then_new_key":
        r.answer()
        r.update()
        steps.append(r.observe("first_success"))
        r.wall_time = 1001
        r.response(1)
        r.update()
        steps.append(r.observe("authorization_again"))
        r.answer()
        steps.append(r.observe("cached_success"))
        r.answer(index=1)
        r.update()
        steps.append(r.observe("new_key_success"))
    elif path in ("stream_success_while_authorizing", "credentials_after_auth"):
        secret = bytes(range(32, 64))
        if path == "credentials_after_auth":
            r.answer()
            r.update()
            steps.append(r.observe("authorized"))
            secret = bytes.fromhex(steps[-1]["secret"])
        r.credentials(secret, inp["length"])
        steps.append(r.observe("credentials"))
        r.update()
        steps.append(r.observe("after_ui_update"))
        r.answer()
        steps.append(r.observe("late_authorization"))
    elif path in ("busy_while_authorizing", "progress_while_authorizing"):
        r.wall_time = 1001
        r.response(4 if path.startswith("busy") else 5)
        steps.append(r.observe("waiting"))
        r.advance(1003)
        steps.append(r.observe("auth_retry"))
    elif path == "compat_success":
        r.auth_response()
        r.update()
        steps.append(r.observe("compat_success"))
    elif path.startswith("cancel"):
        if path == "cancel_after_auth_success":
            r.answer()
            r.update()
            steps.append(r.observe("authorized"))
        r.events.append(dict(kind="cancel", wall=r.wall_time))
        r.call(r.symbols[life.STOP], PANEL)
        steps.append(r.observe("cancelled"))
        r.answer()
        steps.append(r.observe("late_authorization"))
    elif path == "auth_result":
        key, device_token, _ = life.m.e.material()
        r.auth_response(result=inp["result"], key=key, token=device_token)
        r.update()
        steps.append(r.observe("result"))
    else:
        assert path in ("third_success", "exhausted")
        for index in range(3 if path == "third_success" else 4):
            r.answer(index=index, valid=index == (2 if path == "third_success" else 3))
            r.update()
            steps.append(r.observe(str(index)))
    assert not r.assertions
    return dict(
        input=inp,
        events=r.events,
        steps=steps,
        source_assertions=r.assertions,
        executed=sorted(r.executed),
        patch_hits=r.patch_hits,
    )


def verify(case):
    inp, steps = case["input"], case["steps"]
    last = steps[-1]
    path = inp["path"]
    assert steps[0]["state"] == 5 and steps[1]["state"] == 4 and steps[1]["rid"] == 17
    assert all(step["keypair_generations"] == 1 for step in steps)
    if path == "duplicate_unauthorized":
        assert [s["next"] for s in steps[1:]] == [1003, 1004, 1004, 1007]
        assert [len(s["messages"]) for s in steps] == [1, 2, 3, 3, 4]
    elif path == "success_repeat_then_new_key":
        assert [s["state"] for s in steps] == [5, 4, 5, 4, 4, 5]
        assert [s["attempts"] for s in steps] == [0, 0, 1, 1, 1, 2]
    elif path in ("stream_success_while_authorizing", "credentials_after_auth"):
        assert last["state"] == 6 and last["messages"][-1]["body"] == "0808"
        raw = bytes(range(inp["length"])).hex()
        assert (
            last["network_tokens"] if inp["test"] else last["ordinary_launches"]
        ) == [raw]
    elif path in ("busy_while_authorizing", "progress_while_authorizing"):
        assert (
            steps[-2]["state"] == 4
            and steps[-2]["next"] == 1003
            and last["messages"][-1]["tag"] == 3
        )
    elif path == "compat_success":
        assert (
            last["state"] == 5
            and last["attempts"] == 0
            and [m["tag"] for m in last["messages"]] == [5, 3, 5]
        )
    elif path.startswith("cancel"):
        assert (
            last["state"] == 1
            and last["rid"] == 0
            and last["messages"][-1]["body"] == "0808"
        )
        assert last["messages"][-2]["tag"] == (
            9 if path == "cancel_authorization" else 10
        )
    elif path == "auth_result":
        result = inp["result"]
        assert last["state"] == (4 if result == 5 else 1) and last["attempts"] == 0
        assert not any(m["tag"] == 14 for m in last["messages"])
    else:
        assert last["state"] == (5 if path == "third_success" else 1)
        assert last["attempts"] == (3 if path == "third_success" else 4)
        assert [m["body"] for m in last["messages"] if m["tag"] == 14] == (
            ["0801", "0801", "0800"] if path == "third_success" else ["0801"] * 4
        )
    assert not last["errors"] or last["state"] == 1


def main():
    if not __debug__:
        raise SystemExit("This source audit requires assertions; do not use python -O")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    binary = a.binary.read_bytes()
    sha = life.m.e.p.m.discovery.lifecycle.media.flow.SHA
    assert hashlib.sha256(binary).hexdigest() == sha
    paths = (
        "duplicate_unauthorized",
        "success_repeat_then_new_key",
        "busy_while_authorizing",
        "progress_while_authorizing",
        "compat_success",
        "cancel_authorization",
        "cancel_after_auth_success",
        "third_success",
        "exhausted",
    )
    inputs = [dict(path=path, test=t) for t in (False, True) for path in paths]
    inputs += [
        dict(path=path, length=n, test=t)
        for t in (False, True)
        for path in ("stream_success_while_authorizing", "credentials_after_auth")
        for n in (16, 32)
    ]
    inputs += [
        dict(path="auth_result", result=n, test=t)
        for t in (False, True)
        for n in range(1, 9)
    ]
    cases = []
    for inp in inputs:
        case = run(binary, inp)
        verify(case)
        cases.append(case)
        print(inp, "verified", flush=True)
    image = life.m.e.p.m.discovery.lifecycle.media.flow.config.BASE["load_image"](
        binary
    )[0]
    pc = 0xCB1CCC
    before = struct.unpack_from("<I", image, pc)[0]
    # add x8,x0,#3 -> add x8,x0,#1, actual authorization deadline writer.
    after = (before & ~(0xFFF << 10)) | (1 << 10)
    original = run(binary, dict(path="duplicate_unauthorized", test=False))
    mutant = run(
        binary, dict(path="duplicate_unauthorized", test=False), (pc, before, after)
    )
    assert original["patch_hits"] == []
    assert mutant["patch_hits"] == [pc] * 4 and not mutant["source_assertions"]
    assert (
        len(original["steps"][-2]["messages"]) == 3
        and len(mutant["steps"][-2]["messages"]) == 4
    )
    report = dict(
        binary_sha256=sha,
        scope=__doc__,
        cases=cases,
        functions=life.m.e.p.m.inventory(binary, cases),
        negative=dict(
            site=pc, before=before, after=after, original=original, mutant=mutant
        ),
    )
    if a.refresh_reference:
        if REFERENCE.exists():
            assert report == json.loads(gzip.decompress(REFERENCE.read_bytes()))
        REFERENCE.write_bytes(
            gzip.compress(json.dumps(report, sort_keys=True).encode(), mtime=0)
        )
    else:
        assert report == json.loads(gzip.decompress(REFERENCE.read_bytes()))
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"Official auto authorization: {len(cases)} complete owner/packet-order/UI traces",
        flush=True,
    )


if __name__ == "__main__":
    main()
