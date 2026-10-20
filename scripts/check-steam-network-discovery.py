#!/usr/bin/env python3
"""Compare actual Native discovery continuation with official receive cycles.

The official BReceive does not read errno. Named errno values below belong to
the Native POSIX adapter, not a claim that an Android/Switch network emitted
those errors. Default includes all fourteen inputs; --controls-only preserves
the original control subset for independent comparisons.
"""
import argparse
import errno
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTROLS = ("NONE", "EAGAIN", "ETIMEDOUT", "EINTR", "ECONNREFUSED",
            "ECONNRESET", "ENETUNREACH", "EHOSTUNREACH")
ERRORS = CONTROLS + ("ENETDOWN", "EIO", "EINVAL", "EBADF", "ENOMEM", "ENOBUFS")


def require(value, reason):
    if not value:
        raise ValueError(reason)


def compare(receiver, reference, names):
    source = json.loads(reference.read_text())
    require(source["binary_sha256"] == "15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2", "official binary identity")
    plans = [c for c in source["cases"] if c["input"]["kind"] == "receive_cycles"]
    require(len(plans) == 4, "four official receive plans required")
    for plan in plans:
        first, second = plan["observed"]
        require(first["state"] == second["state"] == 1, "official manager continuation")
        require(first["socket"] == second["socket"] != 0, "official socket retention")
        require(["opaque_datagram", 9] in second["trace"], "official next-cycle delivery")
        require(second["calls"].get("socket_destroy", 0) == 0, "official socket not destroyed")
    results = []
    for name in names:
        number = 0 if name == "NONE" else getattr(errno, name)
        process = subprocess.run([str(receiver.resolve()), str(number)],
                                 capture_output=True, text=True, timeout=7)
        require(process.returncode == 0, f"{name}: fixture exit {process.returncode}: {process.stderr}")
        native = json.loads(process.stdout)
        require(native["errno"] == number and native["joined_closed_destroyed"] is True,
                f"{name}: input/cleanup evidence")
        compatible = (native["delivered"] == 1 and native["socket_live_before_stop"] is True
                      and native["nonblocking"] is True
                      and native["signals"] == native["joins"] == native["destroys"] == 1)
        results.append(dict(name=name, observed=native, compatible=compatible))
    return dict(scope=__doc__, source_binary_sha256=source["binary_sha256"],
                compatible=all(r["compatible"] for r in results), cases=results)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", required=True, type=Path)
    parser.add_argument("--reference", type=Path, default=ROOT / "scripts/fixtures/steam-network-discovery-reference.json")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--controls-only", action="store_true")
    args = parser.parse_args()
    result = compare(args.receiver, args.reference, CONTROLS if args.controls_only else ERRORS)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    gaps = [c["name"] for c in result["cases"] if not c["compatible"]]
    print(f"Discovery receive: {len(result['cases']) - len(gaps)}/{len(result['cases'])} compatible; gaps={','.join(gaps) or 'none'}")
    raise SystemExit(0 if result["compatible"] else 1)


if __name__ == "__main__":
    main()
