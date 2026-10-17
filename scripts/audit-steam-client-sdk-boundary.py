#!/usr/bin/env python3
"""Inspect the pinned official Linux client's bundled AVCodec startup boundary.

Run the original client StartDecoding under the existing explicitly controlled
codec/OS adapter and capture its raw writes. Independently call the unchanged
bundled SDK in this Python process: availability gate, codec lookup/open and
public parameter/option APIs. No process-name/token alteration, gate patch,
factory bypass or physical decoding is performed. A metadata projection copies
only four observed scalar writes into a separate real SDK context; it is not
the complete original client's startup or its context ownership/callbacks.
"""

import argparse
import ctypes as c
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path

from elftools.dwarf.callframe import FDE
from elftools.elf.elffile import ELFFile


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "client_avcodec", ROOT / "scripts/audit-steam-client-avcodec.py"
)
codec = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(codec)
CODEC_SHA = "c53a7e3d32a986323ec6bedd28df73a6e5842c4753b67b1d2aa0d6e4f524472f"
SDK_FUNCTIONS = {
    0x61970: "find_decoder",
    0x61A80: "find_decoder_by_name",
    0x69F60: "open2",
    0x22579: "h264_init",
    0x258F20: "h264_environment_gate",
    0xB77C0: "parameters_from_context",
}


def inventory(binary, functions):
    elf = ELFFile(io.BytesIO(binary))
    sizes = {
        entry["initial_location"]: entry["address_range"]
        for entry in elf.get_dwarf_info().EH_CFI_entries()
        if isinstance(entry, FDE)
    }
    text = elf.get_section_by_name(".text")
    data, start = text.data(), text["sh_addr"]
    result = {}
    for address, name in functions.items():
        size = sizes[address]
        body = data[address - start : address - start + size]
        assert len(body) == size
        result[name] = dict(
            address=address, size=size, sha256=hashlib.sha256(body).hexdigest()
        )
    return result


class OriginalInitialization(codec.Client):
    def hook(self, u, address, size, data):
        if self.names.get(address) == "avcodec_open2":
            ctx = self.arg(0)
            self.at_open = {
                str(off): self.i(ctx + off)
                for off in (0x44, 0x70, 0x74, 0x78, 0x7C, 0x80)
            }
        super().hook(u, address, size, data)


def bind(library, name, result, arguments):
    function = getattr(library, name)
    function.restype, function.argtypes = result, arguments
    return function


def audit(binary_path, directory):
    binary = binary_path.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == codec.SHA
    library = directory / "libavcodec.so.61"
    libutil = directory / "libavutil.so.59"
    sdk_bytes = library.read_bytes()
    assert hashlib.sha256(sdk_bytes).hexdigest() == CODEC_SHA
    assert hashlib.sha256(libutil.read_bytes()).hexdigest() == codec.SDK_SHA
    sdk_inventory = inventory(sdk_bytes, SDK_FUNCTIONS)
    source = OriginalInitialization(binary)
    assert source.at_open == {
        "68": 1,
        "112": 128,
        "116": 72,
        "120": 128,
        "124": 80,
        "128": 0,
    }

    util = c.CDLL(str(libutil.resolve()), mode=c.RTLD_GLOBAL)
    sdk = c.CDLL(str(library.resolve()))
    ptr, integer = c.c_void_p, c.c_int
    find = bind(sdk, "avcodec_find_decoder", ptr, [integer])
    named = bind(sdk, "avcodec_find_decoder_by_name", ptr, [c.c_char_p])
    alloc = bind(sdk, "avcodec_alloc_context3", ptr, [ptr])
    free = bind(sdk, "avcodec_free_context", None, [c.POINTER(ptr)])
    open2 = bind(sdk, "avcodec_open2", integer, [ptr, ptr, ptr])
    alloc_parameters = bind(sdk, "avcodec_parameters_alloc", ptr, [])
    free_parameters = bind(sdk, "avcodec_parameters_free", None, [c.POINTER(ptr)])
    parameters = bind(sdk, "avcodec_parameters_from_context", integer, [ptr, ptr])
    option = bind(
        util, "av_opt_find", ptr, [ptr, c.c_char_p, c.c_char_p, integer, integer]
    )
    base = c.cast(find, ptr).value - 0x61970
    # Whole library SHA and complete FDE inventory above pin this internal entry.
    gate = c.CFUNCTYPE(integer)(base + 0x258F20)

    def cache():
        return [
            c.c_int.from_address(base + off).value
            for off in (0x3F3AA4, 0x3F3AA8, 0x3F3AAC)
        ]

    before, allowed, after = cache(), gate(), cache()
    h264, decoder = named(b"h264"), find(27)
    assert h264 and c.c_int.from_address(h264 + 20).value == 27
    plain = ptr(alloc(h264))
    assert plain.value
    try:
        plain_opened = open2(plain, h264, None)
    finally:
        free(c.byref(plain))
    assert not plain.value
    context, param = ptr(alloc(h264)), ptr(alloc_parameters())
    assert context.value and param.value
    try:
        offsets = {}
        for name in (b"flags2", b"video_size", b"threads", b"thread_type"):
            opt = option(context, name, None, 0, 0)
            assert opt
            offsets[name.decode()] = c.c_int.from_address(opt + 16).value
        assert offsets == dict(
            flags2=0x44, video_size=0x74, threads=0x290, thread_type=0x294
        )
        # Only the original four raw scalar writes are projected, not pointers,
        # callback addresses, parser state or the rest of the emulated context.
        for off in (0x70, 0x74, 0x78, 0x7C):
            c.c_int.from_address(context.value + off).value = source.at_open[str(off)]
        result = parameters(param, context)
        dims = [c.c_int.from_address(param.value + off).value for off in (0x48, 0x4C)]
        assert result == 0 and dims == [72, 128]
        # This call is the ordinary SDK init, without process-name or token changes.
        opened = open2(context, h264, None)
        if allowed == 0:
            assert decoder is None and opened == -1 and plain_opened == -1
    finally:
        free_parameters(c.byref(param))
        free(c.byref(context))
    assert not context.value and not param.value
    libc = c.CDLL(None)
    getauxval = bind(libc, "getauxval", ptr, [c.c_ulong])
    execfn = getauxval(31)
    process_path = c.string_at(execfn) if execfn else b""
    return dict(
        scope=__doc__,
        archive_url="https://repo.steampowered.com/steamlink/1.3.32.316/steamlink-1.3.32.316.tgz",
        archive_sha256=codec.ARCHIVE_SHA,
        client_sha256=codec.SHA,
        sdk_sha256=CODEC_SHA,
        util_sha256=codec.SDK_SHA,
        sdk_functions=sdk_inventory,
        client_functions=inventory(
            binary, {0x3246D0: "start_decoding", 0x1780C0: "codec_selection"}
        ),
        source_at_open_raw_fields=source.at_open,
        source_start_entries=source.entered[0x3246D0],
        sdk_option_offsets=offsets,
        metadata_projection=dict(status=result, parameter_dimensions=dims),
        this_process=dict(
            execfn_contains_client_name=any(
                x in process_path for x in (b"steamlink", b"streaming_client")
            ),
            token_present="STEAMVIDEOTOKEN" in os.environ,
            gate_cache_before=before,
            gate_return=allowed,
            gate_cache_after=after,
            find_h264_by_id=decoder is not None,
            find_h264_by_name_rva=h264 - base,
            plain_context_open_status=plain_opened,
            projected_context_open_status=opened,
        ),
        resources_freed=True,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--sdk-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = audit(args.binary, args.sdk_directory)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("Official SDK boundary:", json.dumps(report["this_process"]))
    print(
        "Raw client writes → bundled parameter dimensions:",
        report["metadata_projection"],
    )


if __name__ == "__main__":
    main()
