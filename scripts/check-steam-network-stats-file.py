#!/usr/bin/env python3
"""Compare production real-file I/O and auto-test selection with official bytes.

Original filesystem endpoints/Qt/printf are adapters; Native uses real temporary
files. Source buffer-tail variants have no filesystem counterpart and are checked
for invariance. Full product UI/real Steam/Switch are not exercised.
"""
import argparse
import gzip
import json
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
INITIAL = struct.pack("<fff", 11.5, 22.5, 33.5).hex()


def run(receiver, *args):
    p = subprocess.run(
        [str(receiver.resolve()), *map(str, args)],
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert p.returncode == 0, (args, p.returncode, p.stdout[-1000:], p.stderr[-1000:])
    return json.loads(p.stdout)


def put(directory, body):
    path = directory / "streaming_stats.bin"
    if path.exists():
        path.unlink()
    if body is not None:
        path.write_bytes(bytes.fromhex(body))
    return path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    a = p.parse_args()
    report = json.loads(
        gzip.decompress(
            (
                ROOT / "scripts/fixtures/steam-network-stats-file-reference.json.gz"
            ).read_bytes()
        )
    )
    assert (
        report["binary_sha256"]
        == "15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2"
    )
    assert len(report["functions"]) == 32
    assert [len(report[k]) for k in ("saves", "loads", "triggers", "completions")] == [
        7,
        104,
        32,
        4,
    ]
    assert all(
        not c["source_assertions"]
        for k in ("saves", "loads", "triggers", "completions")
        for c in report[k]
    )
    for m in report["mutations"]:
        assert m["mutant"]["patch_hits"] == [m["pc"]]
        assert not m["mutant"]["source_assertions"]
        assert m["original"]["test_starts"] != m["mutant"]["test_starts"]
    with tempfile.TemporaryDirectory(prefix="nsl-stats-") as folder:
        directory = Path(folder)
        loads = saves = actions = 0
        for c in report["loads"]:
            peers = [
                r
                for r in report["loads"]
                if (r["name"], r["output"]) == (c["name"], c["output"])
            ]
            assert len(peers) == 2 and peers[0]["average"] == peers[1]["average"]
            if c["tail"]:
                continue
            path = put(directory, c["body"])
            result = run(a.receiver, "load", directory, INITIAL, int(c["output"]))
            assert result == dict(ok=c["readable"], average=c["average"]), (
                c["name"],
                result,
                c["average"],
            )
            if c["body"] is not None:
                assert path.read_bytes().hex() == c["body"]
            loads += 1
        for c in report["saves"]:
            path = put(directory, "70726576696f7573")
            if not c["write"]["success"]:
                (directory / "streaming_stats.tmp").mkdir()
            samples = b"".join(struct.pack("<II", *row) for row in c["samples"]).hex()
            result = run(a.receiver, "save", directory, c["average"], samples or "-")
            assert result["ok"] == c["write"]["success"], c["name"]
            assert path.read_bytes().hex() == (
                c["write"]["body"] if result["ok"] else "70726576696f7573"
            ), c["name"]
            if not result["ok"]:
                (directory / "streaming_stats.tmp").rmdir()
            saves += 1
        for c in report["triggers"]:
            i = c["input"]
            put(directory, i["body"])
            result = run(a.receiver, "action", directory, i["action"], int(i["video"]))
            assert result == dict(action=c["action"], test=c["test"]), (i, result)
            assert c["network_flag"] == int(c["test"]) and c["test_starts"] == [
                c["test"]
            ]
            actions += 1
        # Official completion saves statistics even when accepted=false.
        # Runtime request continuation is Source evidence here, not a fake
        # local helper that claims to have implemented the product UI.
        for c in report["completions"]:
            assert c["before_state"] == 5 and c["panel_state"] == 4
            assert c["test_starts"] == [True, False] and not c["test"]
            assert len(c["writes"]) == 1
            assert c["warning_count"] == int(not c["input"]["write_ok"])
        for fault in (
            "alloc1",
            "alloc2",
            "alloc3",
            "close",
            "rename",
            "rollback",
            "overflow",
        ):
            path = put(directory, "70726576696f7573")
            result = run(a.receiver, "guard", directory, fault)
            assert result == dict(ok=False), (fault, result)
            assert path.read_bytes() == b"previous", fault
            assert not (directory / "streaming_stats.tmp").exists(), fault
        # Real read failure is distinct from readable malformed bytes.
        path = put(directory, None)
        path.mkdir()
        result = run(a.receiver, "load", directory, INITIAL, 1)
        assert result == dict(ok=False, average=INITIAL)
        path.rmdir()
        for count in (1, 640):
            put(directory, None)
            result = run(a.receiver, "session", directory, count)
            assert result["ok"]
            wire = (directory / "streaming_stats.bin").read_bytes()
            # Explicit float presence/order plus full samples across public
            # API's 256-item copy bound. Session-finish trigger is controlled.
            average = bytes.fromhex(result["average"])
            assert (
                wire[:15]
                == b"\x0d"
                + average[:4]
                + b"\x15"
                + average[4:8]
                + b"\x1d"
                + average[8:]
            )
            assert b"15000:" in wire and b"1000.00" in wire
            if count == 640:
                assert b";100000:" in wire
                assert wire.count(b"1000.00") == 640
            else:
                assert struct.unpack("<f", average[:4])[0] > 99.9
    print(
        f"Stats real files: {loads} load, {saves} save, {actions} action vectors; 2 actual Session collector/public-copy integrations; 4 source-only continuation cases"
    )


if __name__ == "__main__":
    main()
