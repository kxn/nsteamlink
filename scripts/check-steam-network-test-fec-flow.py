#!/usr/bin/env python3
"""Official test recommendation -> exact settings file -> real Native negotiation.

The official shell phase is a controlled instruction audit; it is not a native
network-test UI implementation. Distinct resulting settings are then loaded by
actual Native settings/UDP/crypto workers, against original Linux client wire.
Platform capabilities remain explicit test inputs, not Switch declarations.
"""

import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "config_check", ROOT / "scripts/check-steam-client-config.py"
)
config = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(config)
fields = config.fields


def load(name):
    return json.loads(gzip.decompress((ROOT / "scripts/fixtures" / name).read_bytes()))


def verify_flow(report):
    assert (
        report["client_sha256"]
        == "15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2"
    )
    assert len(report["cases"]) == 64 and len(report["functions"]) == 61
    assert sum(len(c["observed"]["states"]) for c in report["cases"]) == 616
    for case in report["cases"]:
        i, o = case["input"], case["observed"]
        states = {s["label"]: s for s in o["states"]}
        mode = 2 if i["bitrate"] <= 0 else 1
        previous = i["targets"][-2] if len(i["targets"]) > 1 else i["targets"][-1]
        rec = 0
        if mode == 2:
            rec = (
                (1 if i["quality"] != 1 else 0)
                if previous < 100000
                else (2 if i["quality"] != 3 else 0)
            )
        assert states["ui_start"]["mode"] == mode and states["ui_start"]["status"] == 1
        assert states["connected"]["state"] == 2
        assert states["authenticated_response"]["state"] == 4
        assert (
            states["timeout_equal"]["state"] == 4
            and states["timeout_after"]["state"] == 5
        )
        assert states["complete"]["status"] == 2 and states["complete"]["state"] == 0
        assert states["result_page"]["previous_kbps"] == previous
        assert states["result_page"]["current_kbps"] == i["targets"][-1]
        assert states["result_page"]["recommendation"] == rec
        assert all(s["gate"] == 0 for s in o["states"][1:])
        assert o["gate_writes"] == [dict(pc=0xCCB64C, offset=8, size=4, value=0)]
        assert not o["source_assertions"]
        assert all(v[2] == 0 for s in o["states"] for v in s["channels"])
        assert [f["body"] for f in o["frames"][:4]] == ["060a021001", "09", "09", "09"]
        request = bytes.fromhex(o["frames"][4]["body"])
        assert request[0] == 8 and o["frames"][4]["channel"] == 1
        requested = fields(request[1:], "test")
        target = (
            (10000, 15000, 30000)[i["quality"] - 1]
            if i["bitrate"] == -1
            else 250000
            if i["bitrate"] == 0
            else i["bitrate"]
        )
        assert requested == {
            1: [(0, 600)],
            2: [(0, 60)],
            3: [(0, target)],
            4: [(0, 0)],
            5: [(0, int(mode == 2))],
        }
        initial, final = (
            fields(bytes.fromhex(case["initial"])),
            fields(bytes.fromhex(o["final"])),
        )
        assert initial[25] == [(0, int(i["before"]))]
        should_save = bool(i["accepted"] and rec)
        assert len(o["saved"]) == int(should_save)
        if should_save:
            assert final[25] == [(0, 1)] and final[1] == [(0, 1 if rec == 1 else 3)]
        else:
            assert o["final"] == case["initial"]
        assert states["user_result"]["saves"] == int(should_save)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    p.add_argument("--flow-report", type=Path)
    p.add_argument("--negotiation-report", type=Path)
    args = p.parse_args()
    flow = (
        json.loads(args.flow_report.read_text())
        if args.flow_report
        else load("steam-network-test-fec-flow-reference.json.gz")
    )
    verify_flow(flow)
    source = (
        json.loads(args.negotiation_report.read_text())
        if args.negotiation_report
        else load("steam-network-test-fec-negotiation-reference.json.gz")
    )
    assert (
        hashlib.sha256((json.dumps(flow, indent=2) + "\n").encode()).hexdigest()
        == source["flow_report_sha256"]
    )
    baseline = load("steam-client-negotiation-process-reference.json.gz")
    for key in (
        "client_sha256",
        "source_functions",
        "qt_dependency_sha256",
        "helper_sha256",
        "udp_helper_sha256",
        "bootstrap_helper_sha256",
    ):
        assert source[key] == baseline[key], key
    for key, name in (
        ("helper_sha256", "steam-client-negotiation-gdb.py"),
        ("udp_helper_sha256", "steam-client-udp-gdb.py"),
        ("bootstrap_helper_sha256", "steam-client-sdk-gdb.py"),
    ):
        assert (
            source[key]
            == hashlib.sha256((ROOT / "scripts" / name).read_bytes()).hexdigest()
        )
    configs = {c["observed"]["final"] for c in flow["cases"]}
    assert len(configs) == 12 and len(source["cases"]) == 24
    assert {(c["settings"], c["crc"]) for c in source["cases"]} == {
        (s, crc) for s in configs for crc in (False, True)
    }
    for case in source["cases"]:
        r = case["process"]
        assert (
            r["exit_code"] == 0 and r["cleanup_complete"] and not r["source_assertions"]
        )
        assert r["settings_reads"] == [dict(loaded=True, bytes=case["settings"])]
        assert r["connected_state"] == dict(
            client_phase=6,
            transport_state=1,
            crc=int(case["crc"]),
            outgoing_fec=0,
            receive_sequence=2,
            send_sequence=2,
        )
        assert [
            (e["value"], e["phase"])
            for e in r["module_events"]
            if e["name"].startswith("module_force")
        ] == [(5, "original_exit"), (0, "original_exit")]
        assert any(e[0] == "join_completed" and e[2] == 0 for e in r["trace"])
        assert not {
            pid
            for pid, value in r["tasks_after_shutdown"].items()
            if value not in ("X", "Z")
        } - set(r["tasks_before"])
        with tempfile.TemporaryDirectory(
            prefix="native-test-result-settings-"
        ) as directory:
            filename = Path(directory) / "streaming_settings.bin"
            data = bytes.fromhex(case["settings"])
            filename.write_bytes(data)
            result = subprocess.run(
                [
                    str(args.receiver.resolve()),
                    "--negotiate",
                    str(int(case["crc"])),
                    directory,
                    "080010031804",
                    "0",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert result.returncode == 0, (
                case["name"],
                result.returncode,
                result.stderr[-2000:],
            )
            native = json.loads(result.stdout)
            assert filename.read_bytes() == data
        expected = dict(
            phase=6,
            closed=False,
            mtu=1472,
            goodbyes=0,
            receive_sequence=2,
            send_sequence=2,
            frames=case["native_projection"],
        )
        assert {k: native[k] for k in expected} == expected, (
            case["name"],
            native,
            expected,
        )
        envelope = fields(
            bytes.fromhex(native["frames"][0]["plain"])[1:], "negotiation"
        )
        assert fields(envelope[2][0][1]) == fields(data)
        # Product request constraints are separate from official Android/Linux
        # capability values. Exercise the real limited application path too.
        with tempfile.TemporaryDirectory(prefix="native-switch-request-") as directory:
            filename = Path(directory) / "streaming_settings.bin"
            filename.write_bytes(data)
            result = subprocess.run(
                [
                    str(args.receiver.resolve()),
                    "--negotiate-limited",
                    str(int(case["crc"])),
                    directory,
                    "080010031804",
                    "0",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert result.returncode == 0, (case["name"], result.stderr[-2000:])
            bounded = json.loads(result.stdout)
            assert filename.read_bytes() == data
        assert {k: bounded[k] for k in expected if k != "frames"} == {
            k: v for k, v in expected.items() if k != "frames"
        }
        envelope = fields(
            bytes.fromhex(bounded["frames"][0]["plain"])[1:], "negotiation"
        )
        wanted = fields(data)
        wanted.update({2: [(0, 1280)], 3: [(0, 720)], 4: [(0, 60)], 5: [(0, 1)]})
        if wanted.get(13, [(0, 0)])[-1][1]:
            wanted[13] = [(0, 0)]
        actual = fields(envelope[2][0][1])
        assert actual == wanted and actual.get(25) == fields(data).get(25), (
            case["name"],
            actual,
            wanted,
        )

    print(
        "Official network-test/FEC: 64 source flows/616 states, 12 exact settings, 24 original/Native encrypted UDP negotiations and 24 Switch request-limit paths passed"
    )


if __name__ == "__main__":
    main()
