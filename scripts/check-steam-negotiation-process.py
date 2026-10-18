#!/usr/bin/env python3
"""Real Native settings-file/UDP/crypto/stage comparison with original processes.

Only original mandatory Raw-video capability is removed for the declared Native
platform difference. No other config/caps bytes are filtered. Its deterministic
ciphertext projection is derived with independent crypto, after validating the
original real ciphertext. Native's real transmitted ciphertext is compared too.
This is a controlled loopback peer, not a genuine Steam host/FEC media/device test.
"""

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    p.add_argument("--source-report", type=Path)
    args = p.parse_args()
    source = (
        json.loads(args.source_report.read_text())
        if args.source_report
        else json.loads(
            gzip.decompress(
                (
                    ROOT
                    / "scripts/fixtures/steam-client-negotiation-process-reference.json.gz"
                ).read_bytes()
            )
        )
    )
    assert (
        source["client_sha256"]
        == "95482ca6120f90bb90798b27206b7946ab732e079f008d7fc90ea58a8b0074e1"
    )
    assert len(source["cases"]) == 14 and len(source["source_functions"]) == 35
    for key, name in [
        ("helper_sha256", "steam-client-negotiation-gdb.py"),
        ("udp_helper_sha256", "steam-client-udp-gdb.py"),
        ("bootstrap_helper_sha256", "steam-client-sdk-gdb.py"),
    ]:
        assert (
            source[key]
            == hashlib.sha256((ROOT / "scripts" / name).read_bytes()).hexdigest()
        )
    for case in source["cases"]:
        r = case["process"]
        assert (
            r["exit_code"] == 0 and r["cleanup_complete"] and not r["source_assertions"]
        )
        assert r["settings_reads"] == [dict(loaded=True, bytes=case["settings"])]
        assert [
            (e["value"], e["phase"])
            for e in r["module_events"]
            if e["name"] == "module_force_return"
        ] == [(0, "original_exit")]
        with tempfile.TemporaryDirectory(
            prefix="native-negotiation-settings-"
        ) as directory:
            filename = Path(directory) / "streaming_settings.bin"
            filename.write_bytes(bytes.fromhex(case["settings"]))
            init = "080110031804" if case["reliable"] else "080010031804"
            result = subprocess.run(
                [
                    str(args.receiver.resolve()),
                    "--negotiate",
                    str(int(case["crc"])),
                    directory,
                    init,
                    str(int(case["bad_mac"])),
                ],
                text=True,
                capture_output=True,
                timeout=10,
            )
            assert result.returncode == 0, (
                case["name"],
                result.returncode,
                result.stderr[-3000:],
            )
            native = json.loads(result.stdout)
            assert filename.read_bytes() == bytes.fromhex(case["settings"])
        state = r["connected_state"]
        expected = dict(
            phase=state["client_phase"],
            closed=False,
            mtu=1472,
            goodbyes=0,
            receive_sequence=state["receive_sequence"],
            send_sequence=state["send_sequence"],
            frames=case["native_projection"],
        )
        assert {key: native[key] for key in expected} == expected, (
            case["name"],
            native,
            expected,
        )
    print(
        "Native/original real UDP negotiation: 14 saved-config/FEC/CRC/reliability/crypto/Streaming cases passed"
    )


if __name__ == "__main__":
    main()
