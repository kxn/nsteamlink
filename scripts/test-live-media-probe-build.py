#!/usr/bin/env python3
"""Exercise the observer gate on actual Switch artifacts; never execute mutants."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "probe_build", ROOT / "scripts/check-live-media-probe-build.py"
)
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def overlay(source, destination):
    for name in (
        "CMakeCache.txt",
        "generated/build_identity.json",
        "app/CMakeFiles/nsl-live-media-probe.dir/link.txt",
        "app/nsl-live-media-probe.map",
        "app/nsl-live-media-probe.elf",
        "app/nsl-live-media-probe.nro",
    ):
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(source / name)


def replace(path, data):
    path.unlink()
    path.write_bytes(data)


def remove_edge(build, source, target):
    elf, nro = (
        build / "app/nsl-live-media-probe.elf",
        build / "app/nsl-live-media-probe.nro",
    )
    cache = (build / "CMakeCache.txt").read_text()
    objdump = re.search(r"^CMAKE_OBJDUMP:FILEPATH=(.+)$", cache, re.M)[1]
    dump = subprocess.check_output([objdump, "-d", str(elf)], text=True)
    addresses, function = [], ""
    for line in dump.splitlines():
        header = re.match(r"^[0-9a-f]+ <([^>]+)>:", line)
        if header:
            function = header[1].split(".")[0]
        branch = re.search(
            r"^\s*([0-9a-f]+):.*\b(?:b|bl)\s+[0-9a-f]+\s+<([^>]+)>", line
        )
        if function == source and branch and branch[2] == target:
            addresses.append(int(branch[1], 16))
    if not addresses:
        raise ValueError("No actual branch to mutate: " + source + " -> " + target)
    data, image = bytearray(elf.read_bytes()), bytearray(nro.read_bytes())
    phoff = struct.unpack_from("<Q", data, 32)[0]
    stride, count = struct.unpack_from("<HH", data, 54)
    for address in addresses:
        patched = False
        for i in range(count):
            kind, _, pos, start, _, size, _, _ = struct.unpack_from(
                "<IIQQQQQQ", data, phoff + i * stride
            )
            if kind == 1 and start <= address and address + 4 <= start + size:
                offset = pos + address - start
                data[offset : offset + 4] = image[address : address + 4] = (
                    b"\x1f\x20\x03\xd5"  # AArch64 NOP
                )
                patched = True
                break
        if not patched:
            raise ValueError("Branch outside ELF load segments")
    replace(elf, data)
    replace(nro, image)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--ordinary-build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build, ordinary = args.build.resolve(), args.ordinary_build.resolve()
    report = CHECKER.check(ROOT, build, ordinary)
    checks = ["actual probe accepted"]

    def rejected(tree, normal, reason):
        try:
            CHECKER.check(ROOT, tree, normal)
        except ValueError as error:
            if reason not in str(error):
                raise
        else:
            raise RuntimeError("Fault was accepted: " + reason)
        checks.append(reason)

    rejected(build, build, "NSL_DIAGNOSTICS must be OFF")
    with tempfile.TemporaryDirectory(prefix="nsl-live-probe-faults-") as temp:
        base = Path(temp)
        changed = base / "nro"
        overlay(build, changed)
        path = changed / "app/nsl-live-media-probe.nro"
        data = bytearray(path.read_bytes())
        data[0x100] ^= 1
        replace(path, data)
        rejected(changed, ordinary, "probe NRO differs from audited ELF")
        changed = base / "link"
        overlay(build, changed)
        path = changed / "app/CMakeFiles/nsl-live-media-probe.dir/link.txt"
        replace(
            path,
            path.read_bytes().replace(b"-Wl,--wrap=IHS_SessionChannelControlSend", b""),
        )
        rejected(changed, ordinary, "missing/duplicate wrap option")
        changed = base / "producer"
        overlay(build, changed)
        remove_edge(
            changed, "OnNegotiationInit", "__wrap_IHS_SessionChannelControlSend"
        )
        rejected(changed, ordinary, "production call missing")
        changed = base / "delegate"
        overlay(build, changed)
        remove_edge(
            changed,
            "__wrap_IHS_SessionQueuePacketResult",
            "IHS_SessionQueuePacketResult",
        )
        rejected(changed, ordinary, "observer does not call original")
    report["counterexamples"] = checks
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("PASS: actual observer build and five artifact/call-path fault cases")


if __name__ == "__main__":
    main()
