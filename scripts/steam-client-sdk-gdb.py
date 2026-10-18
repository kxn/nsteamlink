#!/usr/bin/env python3
"""GDB-only helper for audit-steam-client-sdk-process.py.

Runs in a genuine, hash-pinned official executable paused before original main.
The client boundary is zeroed/configured storage, not a full Client constructor.
No name/token/gate/callback bypass. SDK-only pixel tests keep its own callback;
default original Start installs the original callback without decoding. The
optional worker extension declares its partial client/transport/media boundary
and exercises real asynchronous decoding. All objects and probe-acquired table refs
are released before resuming the original --version entry.
"""

import hashlib
import json
import os
import struct
from pathlib import Path

import gdb

config = json.loads(Path(os.environ["NSL_OFFICIAL_SDK_PROBE_CONFIG"]).read_text())
inf = gdb.selected_inferior()
base = int(gdb.parse_and_eval("$source_main")) - 0x123920
fixture = Path(config["fixture"])
allocations = []


def call(signature, address, *args):
    value = gdb.parse_and_eval(
        "((%s)%s)(%s)" % (signature, address, ",".join(str(int(x)) for x in args))
    )
    return None if value.type.code == gdb.TYPE_CODE_VOID else int(value)


def symbol(name):
    return int(gdb.parse_and_eval("(void*)" + name))


def read(address, size):
    return inf.read_memory(address, size).tobytes()


def u64(address):
    return struct.unpack("<Q", read(address, 8))[0]


def u32(address):
    return struct.unpack("<I", read(address, 4))[0]


def w32(address, value):
    inf.write_memory(address, struct.pack("<I", value))


def cstring(address):
    data = bytearray()
    while True:
        byte = read(address + len(data), 1)
        if byte == b"\0":
            return bytes(data)
        data += byte
        assert len(data) < 8192


malloc, free = symbol("malloc"), symbol("free")


def alloc(size):
    address = call("void*(*)(unsigned long)", malloc, size)
    assert address
    allocations.append(address)
    inf.write_memory(address, b"\0" * size)
    return address


def cpp_alloc(size):
    address = call("void*(*)(unsigned long)", base + 0xE51B0, size)
    assert address
    inf.write_memory(address, b"\0" * size)
    return address


def string(value):
    address = alloc(len(value) + 1)
    inf.write_memory(address, value + b"\0")
    return address


assert Path(gdb.current_progspace().filename).resolve() == Path(config["binary"])
initial_ref = u32(base + 0x13BD3A0 + 0xC8)
assert call("int(*)(void*)", base + 0x173B10, base + 0x13BD3A0) == 1
table = [u64(base + 0x13BD3A0 + 8 * i) for i in range(25)]
sdk_base = table[1] - 0x61970
execfn = call("void*(*)(unsigned long)", symbol("getauxval"), 31)
token = call("void*(*)(void*)", symbol("getenv"), string(b"STEAMVIDEOTOKEN"))
report = {
    "scope": "Debugger pauses genuine official executable before main. Original factory and real SDK APIs are called explicitly; not a full application/streaming startup. No name/token/gate alteration.",
    "execfn_is_original": cstring(execfn).endswith(b"/bin/steamlink"),
    "token_present": bool(token),
    "sdk_gate": call("int(*)()", sdk_base + 0x258F20),
    "original_factory": {},
    "contexts": [],
    "table_ref_initial": initial_ref,
    "table_ref_after_init": u32(base + 0x13BD3A0 + 0xC8),
}
decoder = call("void*(*)(int)", table[1], 27)
selected = call("void*(*)(int,int,void*)", base + 0x1780C0, 27, 0, 0)
report["table_ref_after_factory"] = u32(base + 0x13BD3A0 + 0xC8)
report["original_factory"] = {
    "sdk_lookup_found": bool(decoder),
    "original_selected_found": bool(selected),
    "same_codec": selected == decoder,
}
assert report["sdk_gate"] == 1 and decoder and selected == decoder

assert not report["token_present"] and report["execfn_is_original"]
for address, filename in [
    (table[0], "libavcodec.so.61"),
    (table[17], "libavutil.so.59"),
]:
    assert (
        Path(gdb.solib_name(address)).resolve()
        == (Path(config["sdk_directory"]) / filename).resolve()
    )
report["mapped_original_sdk_verified"] = True
report["sdk_defaults"] = {}
# Observe actual unopened defaults without setting thread options.
ctx = call("void*(*)(void*)", table[0], selected)
assert ctx
report["sdk_defaults"] = {"threads": u32(ctx + 0x290), "thread_type": u32(ctx + 0x294)}
assert report["sdk_defaults"] == {"threads": 1, "thread_type": 3}
option = call(
    "void*(*)(void*,void*,void*,int,int)",
    symbol("av_opt_find"),
    ctx,
    string(b"thread_type"),
    0,
    0,
    0,
)
assert option
value_slot = alloc(4)
assert (
    call(
        "int(*)(void*,void*,void*,void*)",
        symbol("av_opt_eval_flags"),
        ctx,
        option,
        string(b"slice"),
        value_slot,
    )
    == 0
)
report["sdk_slice_thread_type"] = u32(value_slot)
assert report["sdk_slice_thread_type"] == 2
slot = alloc(8)
inf.write_memory(slot, struct.pack("<Q", ctx))
call("void(*)(void*)", table[4], slot)
assert u64(slot) == 0

expected = [
    line.rsplit(",", 1)[-1].strip()
    for line in fixture.with_suffix(".framemd5").read_text().splitlines()
    if line and not line.startswith("#")
][0]
for projected in [False, True]:
    ctx_slot, packet_slot, frame_slot, param_slot = [alloc(8) for _ in range(4)]
    ctx = call("void*(*)(void*)", table[0], decoder)
    assert ctx
    inf.write_memory(ctx_slot, struct.pack("<Q", ctx))
    param = call("void*(*)()", symbol("avcodec_parameters_alloc"))
    assert param
    inf.write_memory(param_slot, struct.pack("<Q", param))
    case = {
        "source_four_scalars": projected,
        "default_callback_matches_source_slot": u64(ctx + 0xC0)
        == symbol("avcodec_default_get_format"),
    }
    try:
        assert (
            call(
                "int(*)(void*,void*,long long,int)",
                symbol("av_opt_set_int"),
                ctx,
                string(b"threads"),
                1,
                0,
            )
            == 0
        )
        if projected:
            for offset, value in [(0x70, 128), (0x74, 72), (0x78, 128), (0x7C, 80)]:
                w32(ctx + offset, value)
        assert (
            call(
                "int(*)(void*,void*)",
                symbol("avcodec_parameters_from_context"),
                param,
                ctx,
            )
            == 0
        )
        case["before_open_dimensions"] = [u32(param + 0x48), u32(param + 0x4C)]
        case["open_status"] = call(
            "int(*)(void*,void*,void*)", table[5], ctx, decoder, 0
        )
        assert case["open_status"] == 0
        packet = call("void*(*)()", table[7])
        assert packet
        inf.write_memory(packet_slot, struct.pack("<Q", packet))
        payload = fixture.read_bytes()[:2204]
        assert call("int(*)(void*,int)", table[8], packet, len(payload)) == 0
        inf.write_memory(u64(packet + 24), payload)
        frame = call("void*(*)()", table[17])
        assert frame
        inf.write_memory(frame_slot, struct.pack("<Q", frame))
        case["send_status"] = call("int(*)(void*,void*)", table[10], ctx, packet)
        case["receive_status"] = call("int(*)(void*,void*)", table[6], ctx, frame)
        assert case["send_status"] == case["receive_status"] == 0
        case["frame_shape"] = [u32(frame + 104), u32(frame + 108), u32(frame + 116)]
        assert case["frame_shape"] == [128, 72, 0]
        pixels = bytearray()
        for plane, width, height in [(0, 128, 72), (1, 64, 36), (2, 64, 36)]:
            address = u64(frame + 8 * plane)
            stride = u32(frame + 64 + 4 * plane)
            assert address and width <= stride < 65536
            for row in range(height):
                pixels += read(address + row * stride, width)
        case["pixel_md5"] = hashlib.md5(pixels).hexdigest()
        assert case["pixel_md5"] == expected
        assert (
            call(
                "int(*)(void*,void*)",
                symbol("avcodec_parameters_from_context"),
                param,
                ctx,
            )
            == 0
        )
        case["after_decode_dimensions"] = [u32(param + 0x48), u32(param + 0x4C)]
        assert case["after_decode_dimensions"] == [128, 72]
    finally:
        if u64(frame_slot):
            call("void(*)(void*)", table[18], frame_slot)
        if u64(packet_slot):
            call("void(*)(void*)", table[9], packet_slot)
        if u64(ctx_slot):
            call("void(*)(void*)", table[4], ctx_slot)
        if u64(param_slot):
            call("void(*)(void*)", symbol("avcodec_parameters_free"), param_slot)
        case["api_objects_cleared"] = all(
            u64(p) == 0 for p in [ctx_slot, packet_slot, frame_slot, param_slot]
        )
    report["contexts"].append(case)

if config.get("worker_mode"):
    worker_path = config["worker_helper"]
    exec(compile(Path(worker_path).read_text(), worker_path, "exec"))
    start_report = globals()["exercise_worker"](config["worker_mode"])
    report["original_start"] = start_report
else:
    client, player, decoder = cpp_alloc(0x22000), cpp_alloc(0x168), cpp_alloc(0x2E0)
    call("void(*)(void*,void*)", base + 0x2EE0F0, player, client)
    call("void(*)(void*,void*,void*,int)", base + 0x324610, decoder, client, player, 4)
    inf.write_memory(decoder + 0x184, struct.pack("<II", 128, 72))
    call("void(*)(void*,void*)", base + 0x3246D0, decoder, 0)
    ctx = u64(decoder + 0x268)
    start_report = {
        "scope": "Actual original base-player/AVCodec constructors and StartDecoding in official process; zeroed configured client boundary, no complete client ctor/Qt/streaming startup.",
        "callback_deferred": bool(inf.read_memory(decoder + 100, 1)[0]),
        "decoder_active": bool(inf.read_memory(decoder + 24, 1)[0]),
        "context_created": bool(ctx),
        "parser_created": bool(u64(decoder + 0x270)),
    }
    assert ctx
    start_report["source_callback_installed"] = u64(ctx + 0xC0) == base + 0x324D00
    start_report["sdk_threads"] = u32(ctx + 0x290)
    start_report["sdk_thread_type"] = u32(ctx + 0x294)
    start_report["codec_capabilities"] = u32(selected + 24)
    params = call(
        "void*(*)()", int(gdb.parse_and_eval("(void*)avcodec_parameters_alloc"))
    )
    assert (
        call(
            "int(*)(void*,void*)",
            int(gdb.parse_and_eval("(void*)avcodec_parameters_from_context")),
            params,
            ctx,
        )
        == 0
    )
    start_report["parameter_dimensions"] = [u32(params + 0x48), u32(params + 0x4C)]
    slot = cpp_alloc(8)
    inf.write_memory(slot, struct.pack("<Q", params))
    call(
        "void(*)(void*)",
        int(gdb.parse_and_eval("(void*)avcodec_parameters_free")),
        slot,
    )
    call("void(*)(void*)", base + 0x324840, decoder)
    start_report["context_cleared_after_stop"] = u64(decoder + 0x268) == 0
    start_report["parser_cleared_after_stop"] = u64(decoder + 0x270) == 0
    assert u64(u64(decoder) + 8) == base + 0x323FC0
    call("void(*)(void*)", u64(u64(decoder) + 8), decoder)
    call("void(*)(void*)", base + 0x2EE370, player)
    call("void(*)(void*,unsigned long)", base + 0xE3310, client, 0x22000)
    call("void(*)(void*,unsigned long)", base + 0xE3310, slot, 8)

    report["original_start"] = start_report
    assert all(
        start_report[key]
        for key in (
            "context_created",
            "parser_created",
            "source_callback_installed",
            "context_cleared_after_stop",
            "parser_cleared_after_stop",
        )
    )
    assert start_report["parameter_dimensions"] == [72, 128]

report["cpu_info"] = {}
info = call("void*(*)()", base + 0x1A7350)
count = read(info + 8, 1)[0]
report["cpu_info"] = {
    "processor_byte": count,
    "original_thread_count": call("int(*)(void*)", base + 0x326BE0, 0),
}
assert report["cpu_info"]["original_thread_count"] == min(count, 4)
expected_threads = min(count, 4)
if start_report["codec_capabilities"] & 0x2000 and expected_threads > 1:
    assert start_report["sdk_threads"] == expected_threads
    assert start_report["sdk_thread_type"] == 2
else:
    assert start_report["sdk_threads"] == 1
# Balance only references acquired by this explicit probe; do not force-release
# another owner's refs or write the reference counter directly.
report["table_ref_before_cleanup"] = u32(base + 0x13BD468)
assert initial_ref <= report["table_ref_before_cleanup"] <= initial_ref + 8
while u32(base + 0x13BD468) > initial_ref:
    previous = u32(base + 0x13BD468)
    call("void(*)(void*)", base + 0x173C40, base + 0x13BD3A0)
    assert u32(base + 0x13BD468) == previous - 1
report["table_ref_after_cleanup"] = u32(base + 0x13BD468)
assert report["table_ref_after_cleanup"] == initial_ref
for address in reversed(allocations):
    call("void(*)(void*)", free, address)
report["probe_cleanup_complete"] = True
report["sdk_gate_after"] = call("int(*)()", sdk_base + 0x258F20)
assert report["sdk_gate_after"] == 1


def exited(event):
    report["original_process_exit_code"] = getattr(event, "exit_code", None)
    Path(config["result"]).write_text(json.dumps(report, indent=2) + "\n")


gdb.events.exited.connect(exited)
print("Official SDK explicit probe completed; resuming original main.")
