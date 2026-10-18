#!/usr/bin/env python3
"""Audit the pinned official client's AVCodec function-table linkage.

Original Init/Release/ForceRelease instructions execute from their full FDEs.
Imported function addresses are labelled ELF-resolution terminals, not executed
SDK calls. The init writes direct GOT imports; version requirements come from
the original dynamic symbol/version/relocation tables. This path has no internal
ABI conversion. Other writers/startup, full Qt, real SDK open and hardware are
not proven by this bounded table audit. Optional SDK probing allocates/frees an
unopened context and compares its default callback pointer to the real export;
it changes no process name, token, gate, callback or original library bytes.
"""

import argparse
import ctypes as ct
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "codec", ROOT / "scripts/audit-steam-client-avcodec.py"
)
codec = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(codec)
TABLE = 0x13BD3A0
FUNCTIONS = {
    0x173B10: "table_init",
    0x173C40: "table_release",
    0x173C60: "table_force_release",
}
APIS = [
    "avcodec_alloc_context3",
    "avcodec_find_decoder",
    "av_codec_iterate",
    "av_codec_is_decoder",
    "avcodec_free_context",
    "avcodec_open2",
    "avcodec_receive_frame",
    "av_packet_alloc",
    "av_new_packet",
    "av_packet_free",
    "avcodec_send_packet",
    "av_parser_close",
    "av_parser_init",
    "av_parser_parse2",
    "avcodec_get_hw_config",
    "av_get_pix_fmt_name",
    "av_buffer_unref",
    "av_frame_alloc",
    "av_frame_free",
    "av_frame_get_side_data",
    "av_frame_unref",
    "av_hwdevice_ctx_alloc",
    "av_hwdevice_ctx_create",
    "av_hwdevice_ctx_init",
    "av_log_set_callback",
]
SDK_SHA = "c53a7e3d32a986323ec6bedd28df73a6e5842c4753b67b1d2aa0d6e4f524472f"


class Table(codec.Client):
    def __init__(self, binary, patch=None):
        self.patch, self.patch_hits, self.initial = patch, 0, None
        # Only ELF/GOT/TLS storage setup; do not construct/open a decoder.
        codec._ElfReplay.__init__(self, binary)

    def call(self, pc, *args):
        first = self.initial is None
        if first:
            self.initial = self.state()
            if self.patch:
                address, before, after = self.patch
                assert bytes(self.u.mem_read(address, len(before))) == before
                assert len(before) == len(after)
                self.u.mem_write(address, after)
        result = super().call(pc, *args)
        if first:
            self.bootstrap_result = result
        return result

    def hook(self, u, pc, size, data):
        if self.patch and pc == self.patch[0]:
            self.patch_hits += 1
        codec._ElfReplay.hook(self, u, pc, size, data)

    def state(self):
        count = self.i(TABLE + 0xC8)
        return dict(
            refcount=count if count < 0x80000000 else count - 0x100000000,
            slots=[self.names.get(self.q(TABLE + 8 * i)) for i in range(25)],
        )


def run(binary, patch=None):
    t = Table(binary, patch)
    states = [dict(op="bootstrap_init", result=t.bootstrap_result, **t.state())]
    for name, pc in [
        ("init", 0x173B10),
        ("release", 0x173C40),
        ("release", 0x173C40),
        ("release_empty", 0x173C40),
        ("init_again", 0x173B10),
        ("init_again", 0x173B10),
        ("force_release", 0x173C60),
        ("force_empty", 0x173C60),
    ]:
        result = t.call(pc, TABLE)
        states.append(dict(op=name, result=result, **t.state()))
    return dict(initial=t.initial, states=states, patch_hits=t.patch_hits)


def bindings(binary):
    e = ELFFile(io.BytesIO(binary))
    dyn, version = (
        e.get_section_by_name(".dynsym"),
        e.get_section_by_name(".gnu.version"),
    )
    required = {}
    for entry, names in e.get_section_by_name(".gnu.version_r").iter_versions():
        for name in names:
            required[name["vna_other"]] = [entry.name, name.name]
    result = []
    for i, api in enumerate(APIS):
        rows = []
        for rel in e.get_section_by_name(".rela.dyn").iter_relocations():
            index = rel["r_info_sym"]
            if dyn.get_symbol(index).name == api:
                library, symbol_version = required[version.get_symbol(index)["ndx"]]
                rows.append(
                    dict(
                        got=rel["r_offset"],
                        relocation_type=rel["r_info_type"],
                        library=library,
                        symbol_version=symbol_version,
                    )
                )
        assert len(rows) == 1 and rows[0]["relocation_type"] == 6, api
        result.append(dict(slot=i * 8, api=api, **rows[0]))
    return result


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == codec.SHA
    original = run(binary)
    assert original["initial"] == dict(refcount=0, slots=[None] * 25)
    assert [s["refcount"] for s in original["states"]] == [1, 2, 1, 0, 0, 1, 2, 0, 0]
    assert all(s["slots"] == APIS for s in original["states"])
    checks = []
    for name, pc, before, after in [
        ("omit_first_pair", 0x173B2D, "0f1107", "909090"),
        ("omit_ref_increment", 0x173C33, "8987c8000000", "909090909090"),
        ("omit_release_store", 0x173C58, "8987c8000000", "909090909090"),
    ]:
        modified = run(binary, (pc, bytes.fromhex(before), bytes.fromhex(after)))
        assert modified["patch_hits"] and modified["states"] != original["states"], name
        checks.append(name)
    previous = codec.FUNCTIONS
    try:
        codec.FUNCTIONS = FUNCTIONS
        functions = codec.inventory(binary)
    finally:
        codec.FUNCTIONS = previous
    return dict(
        client_sha256=codec.SHA,
        scope=__doc__,
        functions=functions,
        bindings=bindings(binary),
        reference=original,
        mutation_checks=checks,
    )


def sdk_callback(directory):
    path = directory / "libavcodec.so.61"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == SDK_SHA
    util = directory / "libavutil.so.59"
    assert hashlib.sha256(util.read_bytes()).hexdigest() == codec.SDK_SHA
    ct.CDLL(str(util.resolve()), mode=ct.RTLD_GLOBAL)
    sdk = ct.CDLL(str(path.resolve()))
    (
        sdk.avcodec_find_decoder_by_name.argtypes,
        sdk.avcodec_find_decoder_by_name.restype,
    ) = [ct.c_char_p], ct.c_void_p
    sdk.avcodec_alloc_context3.argtypes, sdk.avcodec_alloc_context3.restype = (
        [ct.c_void_p],
        ct.c_void_p,
    )
    sdk.avcodec_free_context.argtypes = [ct.POINTER(ct.c_void_p)]
    sdk.avcodec_free_context.restype = None
    context = ct.c_void_p(
        sdk.avcodec_alloc_context3(sdk.avcodec_find_decoder_by_name(b"h264"))
    )
    assert context.value
    try:
        target = ct.cast(sdk.avcodec_default_get_format, ct.c_void_p).value
        offsets = [
            off
            for off in range(0, 0x400, 8)
            if ct.c_void_p.from_address(context.value + off).value == target
        ]
        assert offsets == [0xC0]
    finally:
        sdk.avcodec_free_context(ct.byref(context))
    assert context.value is None
    return dict(
        sdk_sha256=SDK_SHA,
        default_get_format_offsets=offsets,
        resources_freed=True,
        scope="Unopened real SDK context. No gate/name/token/callback alteration or decoder startup.",
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--sdk-directory", type=Path)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    report = audit(a.binary.read_bytes())
    encoded = (json.dumps(report, indent=2) + "\n").encode()
    fixture = ROOT / "scripts/fixtures/steam-client-sdk-linkage-reference.json.gz"
    if a.refresh_reference:
        if fixture.exists():
            assert json.loads(gzip.decompress(fixture.read_bytes())) == report
        fixture.write_bytes(gzip.compress(encoded, mtime=0))
    else:
        assert json.loads(gzip.decompress(fixture.read_bytes())) == report
    a.output.write_bytes(encoded)
    if a.sdk_directory:
        a.output.with_suffix(".sdk.json").write_text(
            json.dumps(sdk_callback(a.sdk_directory), indent=2) + "\n"
        )
    print(
        "Official SDK linkage:",
        len(report["bindings"]),
        "bindings,",
        len(report["reference"]["states"]),
        "states,",
        len(report["functions"]),
        "FDEs,",
        len(report["mutation_checks"]),
        "mutations",
    )


if __name__ == "__main__":
    main()
