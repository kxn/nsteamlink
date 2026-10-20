"""Observe original real UDP unrepaired gap, key-mark admission and SDK pixels.

The controlled peer uses an explicit file barrier after observed SDK pixels and
returns its actual feedback receipt. Barriers choose fixture input/Stop timing;
they do not alter original packets, methods, state, clocks or SDK results.
"""

# ruff: noqa: F821
from pathlib import Path

_gap_scope = __doc__
_gap_path = Path(config["media_helper"])
_gap_source = _gap_path.read_text()
_gap_marker = (
    "# SDK function-table producer is initialized by real negotiation capability calls."
)
assert _gap_source.count(_gap_marker) == 1
exec(compile(_gap_source.split(_gap_marker, 1)[0], str(_gap_path), "exec"), globals())
report.update(scope=_gap_scope, gap_states=[], gap_sends=[])


def gap_state(decoder):
    return dict(
        strict=read(decoder + 396, 1)[0],
        soft=read(decoder + 397, 1)[0],
        sequence=int.from_bytes(read(decoder + 408, 2), "little"),
    )


class GapDecodeReturn(gdb.FinishBreakpoint):
    def __init__(self, decoder, item):
        super().__init__(gdb.newest_frame(), internal=True)
        self.decoder, self.item = decoder, item

    def stop(self):
        self.item["after"] = gap_state(self.decoder)
        return False


class GapDecode(gdb.Breakpoint):
    def stop(self):
        decoder = int(gdb.parse_and_eval("$rdi"))
        frame = int(gdb.parse_and_eval("$rsi"))
        item = dict(
            id=int.from_bytes(read(frame + 26, 2), "little"),
            before=gap_state(decoder),
        )
        report["gap_states"].append(item)
        GapDecodeReturn(decoder, item)
        return False


class GapSendReturn(gdb.FinishBreakpoint):
    def __init__(self, item):
        super().__init__(gdb.newest_frame(), internal=True)
        self.item = item

    def stop(self):
        self.item["return"] = int(gdb.parse_and_eval("$rax"))
        return False


class GapSend(gdb.Breakpoint):
    def stop(self):
        size = int(gdb.parse_and_eval("$rdx"))
        if not 13 <= size <= 65536:
            return False
        wire = read(int(gdb.parse_and_eval("$rsi")), size)
        kind = wire[0] & 127
        if wire[4] != 3 or not (
            kind in (8, 10) or (kind == 3 and wire[13:14] == b"\x02")
        ):
            return False
        stack, frame = [], gdb.newest_frame()
        for _ in range(16):
            if frame is None:
                break
            pc = int(frame.pc())
            stack.append(
                dict(
                    pc=pc,
                    source_relative=pc - base
                    if base <= pc < base + 0x1000000
                    else None,
                )
            )
            frame = frame.older()
        item = dict(
            wire=wire.hex(),
            thread=gdb.selected_thread().global_num,
            phase=u32(client + 256),
            pictures=len(report["pictures"]),
            sdk_packets=sum(e["name"] == "sdk_send" for e in report["media_events"]),
            stack=stack,
        )
        report["gap_sends"].append(item)
        GapSendReturn(item)
        return False


GapDecode("*" + str(base + 0x3260D0), internal=True)
GapSend("*" + str(symbol("sendto")), internal=True)
_gap_tail = _gap_source.split(_gap_marker, 1)[1]
exec(
    compile(
        _gap_tail.split("for attempt in range(3000):", 1)[0], str(_gap_path), "exec"
    ),
    globals(),
)
_gap_stage_file = Path(config["stage_file"])
_gap_seed = _gap_stop = False
_gap_after_feedback = 0
for _gap_attempt in range(3000):
    call("void(*)(void*)", base + 0x3230A0, client)
    if report["pictures"] and not _gap_seed:
        _gap_stage_file.write_text("seed")
        _gap_seed = True
    if config["reliable"]:
        if Path(str(_gap_stage_file) + ".feedback").exists():
            _gap_after_feedback += 1
        _gap_done = _gap_after_feedback >= 30
    else:
        if len(report["pictures"]) == 2:
            _gap_stage_file.write_text("post_key")
        _gap_done = len(report["pictures"]) >= 3
    if _gap_done and not _gap_stop:
        report["gap_before_stop"] = dict(
            pictures=len(report["pictures"]),
            sdk_packets=sum(e["name"] == "sdk_send" for e in report["media_events"]),
            state=gap_state(u64(client + 40)),
            after_feedback_updates=_gap_after_feedback,
        )
        _gap_stage_file.write_text("stop")
        _gap_stop = True
    if _gap_stop and not u64(client + 40):
        break
    call("int(*)(unsigned int)", symbol("usleep"), 1000)
else:
    raise AssertionError(("gap observation timed out", report))
slot = alloc(8)
while call("int(*)(void*,void*)", base + 0x2EF250, player + 0x40, slot) & 255:
    call("void(*)(void*)", base + 0x323FF0, u64(slot))
report["media_final"] = dict(
    phase=u32(client + 256),
    decoder=u64(client + 40),
    rx=u64(client + 136),
    tx=u64(client + 128),
)
report["mapped_sdk"] = {}
for _gap_index, _gap_name in (
    (0, "libavcodec.so.61"),
    (10, "libavcodec.so.61"),
    (17, "libavutil.so.59"),
):
    _gap_mapped = Path(gdb.solib_name(table[_gap_index])).resolve()
    assert _gap_mapped == (Path(config["sdk_directory"]) / _gap_name).resolve()
    report["mapped_sdk"][str(_gap_index)] = dict(
        path=str(_gap_mapped),
        sha256=hashlib.sha256(_gap_mapped.read_bytes()).hexdigest(),
    )
_gap_cleanup = "exec(\n    compile(\n        media_cleanup_marker"
assert _gap_source.count(_gap_cleanup) == 1
exec(
    compile(
        _gap_cleanup + _gap_source.split(_gap_cleanup, 1)[1], str(_gap_path), "exec"
    ),
    globals(),
)
