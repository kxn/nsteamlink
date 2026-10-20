#!/usr/bin/env python3
"""Check actual capability ELF providers, size guard, wrapper and NRO assets.

Structural evidence only; no hardware launch, capacity or loader claim.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import struct
import subprocess


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check(root, build, ordinary):
    app = build / "app"
    manifest = json.loads((app / "vcl_probe/vcl_probe_manifest.json").read_text())
    source = (root / "app/platforms/common/video_pipeline.c").read_bytes()
    generated = (app / "vcl_probe/video_pipeline_capability.c").read_bytes()
    assert sha(source) == manifest["source_sha256"]
    assert sha(generated) == manifest["copy_sha256"]
    assert generated == (
        b'#if !NSL_DIAGNOSTICS\n#error "VCL capability copy requires diagnostics"\n#endif\n'
        + source.replace(
            b"#define MAX_PACKET   (2u * 1024u * 1024u)",
            b"#define MAX_PACKET   (4u * 1024u * 1024u)",
        )
        + b"\nconst unsigned nsl_vcl_probe_limit_bytes = MAX_PACKET;\n"
    )
    linkmap = (app / "nsl-vcl-probe.map").read_text()
    assert "libnsl_vcl_capability_pipeline.a(video_pipeline_capability.o)" in linkmap
    assert "libnsl_video_pipeline.a(video_pipeline" not in linkmap
    tools = Path("/opt/devkitpro/devkitA64/bin")
    elf = app / "nsl-vcl-probe.elf"
    symbols = subprocess.check_output(
        [str(tools / "aarch64-none-elf-nm"), "-S", str(elf)], text=True
    )
    address = next(
        int(line.split()[0], 16)
        for line in symbols.splitlines()
        if line.split()[-1] == "nsl_vcl_probe_limit_bytes"
    )
    data = elf.read_bytes()
    assert (
        data[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", data, 18)[0] == 183
    )
    phoff = struct.unpack_from("<Q", data, 32)[0]
    stride, count = struct.unpack_from("<HH", data, 54)
    limit = None
    for index in range(count):
        kind, _, offset, vaddr, _, size, _, _ = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + stride * index
        )
        if kind == 1 and vaddr <= address and address + 4 <= vaddr + size:
            limit = struct.unpack_from("<I", data, offset + address - vaddr)[0]
    assert limit == manifest["capability_limit"] == 4194304
    disassembly = {}
    for symbol in (
        "sl_video_submit",
        "ff_nvtegra_decode_slice",
        "__wrap_av_nvtegra_map_realloc",
    ):
        disassembly[symbol] = subprocess.check_output(
            [
                str(tools / "aarch64-none-elf-objdump"),
                "-d",
                "--disassemble=" + symbol,
                str(elf),
            ],
            text=True,
        )
    assert "#0x400, lsl #12" in disassembly["sl_video_submit"]
    assert "<__wrap_av_nvtegra_map_realloc>" in disassembly["ff_nvtegra_decode_slice"]
    assert "<av_nvtegra_map_realloc>" in disassembly["__wrap_av_nvtegra_map_realloc"]
    identity = json.loads((build / "generated/build_identity.json").read_text())
    graphics = json.loads((build / "generated/graphics_manifest.json").read_text())
    sdk_commit = subprocess.check_output(
        ["git", "-C", str(root / "third_party/ihslib"), "rev-parse", "HEAD"], text=True
    ).strip()
    assert graphics["backend"] == "deko"
    assert graphics["application"] == {
        "commit": identity["commit"],
        "dirty": identity["dirty"],
    }
    assert graphics["ihslib"] == {"commit": sdk_commit, "dirty": False}
    libraries = {
        path: sha(Path(path).read_bytes())
        for path in graphics["sha256"]
        if path.endswith(("libavcodec.a", "libavutil.a", "libnx.a"))
    }
    assert len(libraries) == 3
    assert all(value == graphics["sha256"][path] for path, value in libraries.items())
    nro = (app / "nsl-vcl-probe.nro").read_bytes()
    assert nro[0x10:0x14] == b"NRO0" and identity["commit"].encode() in nro
    assert b"VCL_BEGIN build=" in nro
    for row in manifest["cases"]:
        fixture = gzip.decompress(
            (
                root / "app/tests/fixtures/video/vcl" / (row["name"] + ".h264.gz")
            ).read_bytes()
        )
        assert sha(fixture) == row["fixture_sha256"] and fixture in nro
    normal = ordinary.read_bytes()
    assert normal[0x10:0x14] == b"NRO0"
    assert b"VCL_BEGIN build=" not in normal
    for row in manifest["cases"]:
        assert (app / "vcl_probe" / (row["name"] + ".h264")).read_bytes() not in normal
    return dict(
        scope=__doc__,
        identity=identity,
        sdk_commit=sdk_commit,
        library_sha256=libraries,
        capability_limit=limit,
        pipeline_provider="libnsl_vcl_capability_pipeline.a(video_pipeline_capability.o)",
        installed_decode_slice_calls_wrapper=True,
        wrapper_calls_real_sdk=True,
        nro_sha256=sha(nro),
        ordinary_nro_sha256=sha(normal),
        fixtures=manifest["cases"],
        disassembly=disassembly,
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--build", required=True, type=Path)
    p.add_argument("--ordinary", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    result = check(
        Path(__file__).resolve().parents[1],
        args.build.resolve(),
        args.ordinary.resolve(),
    )
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(
        "VCL build: separate 4MiB guard, actual SDK wrapper, pinned embedded fixtures; ordinary NRO excluded"
    )


if __name__ == "__main__":
    main()
