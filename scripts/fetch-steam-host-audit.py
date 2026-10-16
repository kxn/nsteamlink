#!/usr/bin/env python3
"""Fetch pinned official Steam host audit inputs; never redistribute the DLLs."""
import argparse
import hashlib
import json
from pathlib import Path
import urllib.request
import zipfile


PACKAGES = {
    "win32": {
        "manifest_version": "1769731672",
        "manifest_url": "https://client-update.steamstatic.com/steam_client_win32",
        "archive": "bins_win32.zip.23e34a6d4b10596a44561a5100dac5585d2517da",
        "bytes": 59544006,
        "archive_sha256": "8b712b2a3412a9066b7725f4e1c5cef9a7ca5b187b6585a5b92d25d09df0ba62",
        "binary_sha256": "0cad7c69ace13e802be17beb06df299f7f733f01b4450a74bc68709494b21ddb",
    },
    "win64": {
        "manifest_version": "1791918634",
        "manifest_url": "https://client-update.steamstatic.com/steam_client_win64",
        "archive": "bins_win64.zip.0ed643edc3bd395674066241d556cd970f4bdc19",
        "bytes": 64307884,
        "archive_sha256": "2378aa4845fea7b08d3cc33a88db240db20e33cf8bb934f7f4037d89a1bac1e9",
        "binary_sha256": "1b9457943205dc3af0bd53463ba331cbd2a381388699705c02271aac7a2b1252",
    },
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--arch", choices=("win32", "win64", "both"), default="both")
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    records = {}
    for arch, package in PACKAGES.items():
        if args.arch != "both" and arch != args.arch:
            continue
        archive = args.output_dir / package["archive"]
        url = "https://client-update.steamstatic.com/" + package["archive"]
        if not archive.exists():
            temporary = archive.with_name(archive.name + ".partial")
            try:
                with urllib.request.urlopen(url, timeout=90) as source, temporary.open(
                    "wb"
                ) as target:
                    while chunk := source.read(1024 * 1024):
                        target.write(chunk)
                assert (
                    temporary.stat().st_size == package["bytes"]
                ), "Archive length mismatch"
                assert (
                    hashlib.sha256(temporary.read_bytes()).hexdigest()
                    == package["archive_sha256"]
                ), "Archive SHA256 mismatch"
                temporary.replace(archive)
            finally:
                temporary.unlink(missing_ok=True)
        assert (
            archive.stat().st_size == package["bytes"]
        ), "Cached archive length mismatch"
        assert (
            hashlib.sha256(archive.read_bytes()).hexdigest()
            == package["archive_sha256"]
        ), "Cached archive SHA256 mismatch"
        with zipfile.ZipFile(archive) as zipped:
            binary = zipped.read("SteamUI.dll")
        assert (
            hashlib.sha256(binary).hexdigest() == package["binary_sha256"]
        ), "DLL SHA256 mismatch"
        destination = args.output_dir / arch / "SteamUI.dll"
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            assert (
                destination.read_bytes() == binary
            ), "Refusing to replace a different existing DLL"
        else:
            destination.write_bytes(binary)
        records[arch] = dict(
            package, archive_url=url, binary_path=str(destination.resolve())
        )
        print(f"Verified {arch}: {destination}", flush=True)
    (args.output_dir / "audit-inputs.json").write_text(
        json.dumps(records, indent=2) + "\n"
    )


if __name__ == "__main__":
    main()
