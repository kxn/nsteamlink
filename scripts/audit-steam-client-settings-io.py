#!/usr/bin/env python3
"""Replay original Android SetSettingsFile/Load/Save instructions.

C++ protobuf parsing, copy and serialization execute. BLoadFile/BSaveFile and
CUtlBuffer/libc++ storage are explicit adapters; this does not exercise Android
filesystem durability. Malformed loads record original partial mutation.
"""
import argparse
import hashlib
import json
import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = runpy.run_path(str(Path(__file__).with_name("audit-steam-client-config.py")))
CLIENT, INPUT, SHA = BASE["CLIENT"], BASE["INPUT"], BASE["SHA"]


class Files(BASE["Core"]):
    def __init__(self, binary):
        super().__init__(binary)
        self.callbacks.pop(0xC0A7A0)
        self.file = None
        self.write_success = True
        self.path = "/fixture/streaming_settings.bin"
        self.filename(self.path)

    def filename(self, name):
        pointer = 0
        if name is not None:
            pointer = self.alloc(len(name) + 1)
            self.u.mem_write(pointer, name.encode() + b"\0")
        self.wq(CLIENT + 144, pointer)

    def hook(self, uc, address, size, data):
        name = self.plts.get(address, "")
        if "BLoadFile" in name:
            self.actions.append({"file_read": self.cstring(self.r(0))})
            if self.file is None:
                self.ret(0)
            else:
                pointer = self.alloc(len(self.file) + 1)
                if self.file:
                    self.u.mem_write(pointer, self.file)
                self.wq(self.r(1), pointer)
                self.wi(self.r(1) + 20, len(self.file))
                self.ret(1)
        elif "CUtlBuffer3PutEPKvi" in name:
            value = bytes(self.u.mem_read(self.r(1), self.r(2)))
            pointer = self.alloc(len(value) + 1)
            if value:
                self.u.mem_write(pointer, value)
            self.wq(self.r(0), pointer)
            self.wi(self.r(0) + 20, len(value))
            self.ret()
        elif "BSaveFile" in name:
            buffer = self.r(1)
            value = bytes(self.u.mem_read(self.q(buffer), self.i(buffer + 20)))
            self.actions.append(
                {
                    "file_write": self.cstring(self.r(0)),
                    "bytes": value.hex(),
                    "success": self.write_success,
                }
            )
            self.ret(int(self.write_success))
        elif "CUtlString8SetValueEPKc" in name:
            value = self.cstring(self.r(1)) if self.r(1) else ""
            pointer = self.alloc(len(value) + 1)
            self.u.mem_write(pointer, value.encode() + b"\0")
            self.wq(self.r(0), pointer)
            self.ret()
        elif "basic_string" in name and "6resizeEmc" in name:
            dest, length = self.r(0), self.r(1)
            tag = self.u.mem_read(dest, 1)[0]
            old_length = self.q(dest + 8) if tag & 1 else tag >> 1
            old_ptr = self.q(dest + 16) if tag & 1 else dest + 1
            value = bytes(self.u.mem_read(old_ptr, min(old_length, length)))
            value += bytes([self.r(2) & 255]) * max(0, length - old_length)
            pointer = self.alloc(length + 1)
            self.u.mem_write(pointer, value + b"\0")
            self.wq(dest, (length + 1) | 1)
            self.wq(dest + 8, length)
            self.wq(dest + 16, pointer)
            self.ret(dest)
        elif name == "Warning":
            self.actions.append({"warning": True})
            self.ret()
        else:
            super().hook(uc, address, size, data)


def audit(binary):
    references = json.loads(
        (ROOT / "scripts/fixtures/steam-client-config-reference.json").read_text()
    )["cases"]
    rich = next(
        c["observed"]["config"] for c in references if c["case"] == "incoming_s6_rich"
    )
    large = next(
        c["observed"]["config"]
        for c in references
        if c["case"] == "incoming_s6_large_string"
    )
    initial = "5800c80101"
    cases = []
    for name, value in (
        ("missing", None),
        ("empty", ""),
        ("fec_false", "c80100"),
        ("rich", rich),
        ("large", large),
        ("bad_tag", "80"),
        ("partial_failure", "c8010080"),
    ):
        core = Files(binary)
        assert core.parse(INPUT, bytes.fromhex(initial))
        core.call(
            core.symbols["_ZN22CStreamingClientConfig8CopyFromERKS_"],
            CLIENT + 456,
            INPUT,
        )
        core.file = bytes.fromhex(value) if value is not None else None
        core.actions.clear()
        core.call(0x7A5A50, CLIENT)
        observed = core.result()
        assert not any(
            "notify" in event or "send" in event for event in observed["events"]
        )
        if name == "missing":
            assert BASE["Core"].serialize(core, CLIENT + 456).hex() == initial
        elif name == "bad_tag":
            assert observed["config"] == ""
        elif name == "partial_failure":
            assert observed["config"] == "c80100"
        cases.append(
            {
                "case": "load_" + name,
                "operation": "load",
                "input": {"initial": initial, "file": value},
                "observed": observed,
            }
        )
    for name in (None, "", "/fixture/streaming_settings.bin"):
        for value in ("", rich, large):
            for success in (False, True):
                core = Files(binary)
                assert core.parse(INPUT, bytes.fromhex(value))
                core.call(
                    core.symbols["_ZN22CStreamingClientConfig8CopyFromERKS_"],
                    CLIENT + 456,
                    INPUT,
                )
                core.filename(name)
                core.write_success = success
                core.actions.clear()
                core.call(0x7A5B34, CLIENT)
                observed = core.result()
                writes = [
                    event for event in observed["events"] if "file_write" in event
                ]
                assert bool(writes) == bool(name)
                assert observed["config"] == value
                if writes:
                    assert writes[0]["bytes"] == value
                    assert any("warning" in event for event in observed["events"]) == (
                        not success
                    )
                cases.append(
                    {
                        "case": f"save_{len(cases)}",
                        "operation": "save",
                        "input": {
                            "filename": name,
                            "config": value,
                            "write_success": success,
                        },
                        "observed": observed,
                    }
                )
    for present in (False, True):
        core = Files(binary)
        core.filename("/old/path")
        core.file = bytes.fromhex(rich) if present else None
        address = core.alloc(128)
        core.u.mem_write(address, core.path.encode() + b"\0")
        core.call(0x7A5A28, CLIENT, address)
        observed = core.result()
        observed["filename"] = core.cstring(core.q(CLIENT + 144))
        assert observed["filename"] == core.path
        assert observed["events"] == [{"file_read": core.path}]
        cases.append(
            {
                "case": f"set_filename_present{int(present)}",
                "operation": "set_filename",
                "input": {"file": rich if present else None},
                "observed": observed,
            }
        )
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--refresh-reference", action="store_true")
    args = parser.parse_args()
    binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == SHA
    cases = audit(binary)
    report = {"binary_sha256": SHA, "scope": __doc__, "cases": cases}
    reference = ROOT / "scripts/fixtures/steam-client-settings-io-reference.json"
    if args.refresh_reference:
        if reference.exists():
            previous = {
                case["case"]: case
                for case in json.loads(reference.read_text())["cases"]
            }
            for case in cases:
                if case["case"] in previous:
                    assert (
                        case == previous[case["case"]]
                    ), "existing original observation changed"
        reference.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert report == json.loads(reference.read_text())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"Official Android settings I/O: {len(cases)} original-instruction cases passed"
    )


if __name__ == "__main__":
    main()
