"""Observe original client UDP audio, Opus recovery and actual SDL3 submissions.

Only peer inputs and explicit dummy-audio platform init/quit are controlled.
No decoded Frame, codec return, original method or internal state is replaced.
Breakpoints observe original workers; wall scheduling/device acoustics are not
claimed equivalent. Opus is the actual mapped external library, recorded below.
"""

# ruff: noqa: F821
from pathlib import Path

_audio_neg_source = Path(config["negotiation_helper"]).read_text()
_audio_marker = "# Continue the original UDP helper"
exec(
    compile(
        _audio_neg_source.split(_audio_marker, 1)[0],
        config["negotiation_helper"],
        "exec",
    ),
    globals(),
)
report["audio_events"] = []
report["audio_decodes"] = []
report["audio_writes"] = []
report["audio_frame_returns"] = []
_audio_streams = set()
audio_decoder = 0
audio_frame = None


class AudioEvent(gdb.Breakpoint):
    def __init__(self, pc, name):
        super().__init__("*" + str(pc), internal=True)
        self.name = name

    def stop(self):
        global audio_decoder, audio_frame
        e = {"name": self.name, "thread": gdb.selected_thread().global_num}
        if self.name == "start":
            audio_decoder = int(gdb.parse_and_eval("$rdi"))
            e.update(
                rate=u32(audio_decoder + 0x180), channels=u32(audio_decoder + 0x184)
            )
            e["owner_offsets"] = [
                o for o in range(0, 128, 8) if u64(client + o) == audio_decoder
            ]
            report["audio_owner_offsets"] = e["owner_offsets"]
        if self.name == "frame":
            f = int(gdb.parse_and_eval("$rsi"))
            audio_frame = {
                "id": int.from_bytes(read(f + 26, 2), "little"),
                "timestamp": u32(f + 28),
                "offset": u32(connection + 848),
            }
            e.update(audio_frame)
            FrameResult(gdb.newest_frame(), internal=True)
        report["audio_events"].append(e)
        return False


class FrameResult(gdb.FinishBreakpoint):
    def stop(self):
        report["audio_frame_returns"].append(
            {
                "next": int.from_bytes(read(audio_decoder + 0x192, 2), "little"),
                "first": read(audio_decoder + 0x190, 1)[0],
            }
        )
        return False


class AudioResult(gdb.FinishBreakpoint):
    def __init__(self, row, output, channels):
        super().__init__(gdb.newest_frame(), internal=True)
        self.row, self.output, self.channels = row, output, channels

    def stop(self):
        result = int(gdb.parse_and_eval("$eax")) & 0xFFFFFFFF
        if result & 0x80000000:
            result -= 1 << 32
        self.row["result"] = result
        if 0 <= result <= self.row["max_samples"]:
            self.row["pcm_sha256"] = hashlib.sha256(
                read(self.output, result * self.channels * 4)
            ).hexdigest()
        return False


class AudioCall(gdb.Breakpoint):
    def stop(self):
        ptr = int(gdb.parse_and_eval("$rsi"))
        size = int(gdb.parse_and_eval("$edx"))
        limit = int(gdb.parse_and_eval("$r8d"))
        fec = int(gdb.parse_and_eval("$r9d"))
        row = dict(
            id=(
                int.from_bytes(read(audio_decoder + 0x192, 2), "little")
                if limit == 480
                else audio_frame["id"]
            ),
            timestamp=audio_frame["timestamp"],
            offset=audio_frame["offset"],
            max_samples=limit,
            fec=fec,
            payload=read(ptr, size).hex() if size else "",
        )
        report["audio_decodes"].append(row)
        AudioResult(row, int(gdb.parse_and_eval("$rcx")), u32(audio_decoder + 0x184))
        return False


class StreamResult(gdb.FinishBreakpoint):
    def stop(self):
        stream = int(gdb.parse_and_eval("$rax"))
        if stream:
            _audio_streams.add(stream)
        return False


class StreamOpen(gdb.Breakpoint):
    def stop(self):
        spec = int(gdb.parse_and_eval("$rsi"))
        report["audio_spec"] = {
            "format": u32(spec),
            "channels": u32(spec + 4),
            "rate": u32(spec + 8),
        }
        StreamResult(gdb.newest_frame(), internal=True)
        return False


class StreamWriteResult(gdb.FinishBreakpoint):
    def __init__(self, item):
        super().__init__(gdb.newest_frame(), internal=True)
        self.item = item

    def stop(self):
        self.item["accepted"] = bool(int(gdb.parse_and_eval("$al")) & 255)
        return False


class StreamWrite(gdb.Breakpoint):
    def stop(self):
        stream = int(gdb.parse_and_eval("$rdi"))
        count = int(gdb.parse_and_eval("$edx"))
        if stream in _audio_streams:
            assert 0 <= count < 1048576
            item = {
                "bytes": count,
                "sha256": hashlib.sha256(
                    read(int(gdb.parse_and_eval("$rsi")), count)
                ).hexdigest(),
                "thread": gdb.selected_thread().global_num,
            }
            report["audio_writes"].append(item)
            StreamWriteResult(item)
        return False


StreamOpen("*" + str(symbol("SDL_OpenAudioDeviceStream")), internal=True)
StreamWrite("*" + str(symbol("SDL_PutAudioStreamData")), internal=True)


class AudioCreateResult(gdb.FinishBreakpoint):
    def __init__(self, item, error):
        super().__init__(gdb.newest_frame(), internal=True)
        self.item, self.error = item, error

    def stop(self):
        self.item["created"] = bool(int(gdb.parse_and_eval("$rax")))
        self.item["error"] = u32(self.error)
        return False


class AudioCreate(gdb.Breakpoint):
    def stop(self):
        channels = int(gdb.parse_and_eval("$esi"))
        item = dict(
            rate=int(gdb.parse_and_eval("$edi")),
            channels=channels,
            streams=int(gdb.parse_and_eval("$edx")),
            coupled=int(gdb.parse_and_eval("$ecx")),
            mapping=list(read(int(gdb.parse_and_eval("$r8")), channels)),
        )
        report["audio_create"] = item
        AudioCreateResult(item, int(gdb.parse_and_eval("$r9")))
        return False


AudioCreate("*" + str(symbol("opus_multistream_decoder_create")), internal=True)
for pc, name in ((0x3252A0, "start"), (0x3253E0, "frame"), (0x3253A0, "stop")):
    AudioEvent(base + pc, name)
AudioCall("*" + str(symbol("opus_multistream_decode_float")), internal=True)
assert call("int(*)(unsigned int)", symbol("SDL_InitSubSystem"), 16) == 1
assert call("unsigned int(*)(unsigned int)", symbol("SDL_WasInit"), 16) & 16
exec(
    compile(
        _audio_marker
        + _audio_neg_source.split(_audio_marker, 1)[1].split("cleanup = ", 1)[0],
        config["negotiation_helper"],
        "exec",
    ),
    globals(),
)
stop_file = Path(config["stage_file"])
requested_stop = False
_audio_seeded = False
_audio_feedback_updates = 0
for attempt in range(3000):
    call("void(*)(void*)", base + 0x3230A0, client)
    if not _audio_seeded and report["audio_frame_returns"]:
        stop_file.write_text("seed")
        _audio_seeded = True
    if config["blocked"] and Path(str(stop_file) + ".feedback").exists():
        _audio_feedback_updates += 1
    if (
        config["drop"]
        and len(report["audio_frame_returns"]) == 2
        and not requested_stop
    ):
        stop_file.write_text("continuation")
    _audio_done = (
        _audio_feedback_updates >= 30
        if config["blocked"]
        else len(report["audio_frame_returns"]) >= config["expected_frames"]
    )
    if (
        _audio_done
        and len(report["audio_decodes"]) >= config["expected_calls"]
        and (not config["require_output"] or report["audio_writes"])
        and "result" in report["audio_decodes"][-1]
        and not requested_stop
    ):
        report["audio_before_stop"] = dict(
            frames=len(report["audio_frame_returns"]),
            calls=len(report["audio_decodes"]),
            feedback_updates=_audio_feedback_updates,
        )
        stop_file.write_text("stop")
        requested_stop = True
    if (
        requested_stop
        and any(e["name"] == "stop" for e in report["audio_events"])
        and all(u64(client + o) != audio_decoder for o in report["audio_owner_offsets"])
    ):
        break
    call("int(*)(unsigned int)", symbol("usleep"), 1000)
else:
    raise AssertionError(("audio observation timeout", report))
lib = Path(gdb.solib_name(symbol("opus_multistream_decode_float"))).resolve()
report["audio_library"] = {
    "path": str(lib),
    "sha256": hashlib.sha256(lib.read_bytes()).hexdigest(),
    "version": cstring(call("void*(*)()", symbol("opus_get_version_string"))).decode(),
}
report["audio_final"] = {
    "feedback_updates": _audio_feedback_updates,
    "phase": u32(client + 256),
    "rx": u64(client + 136),
    "tx": u64(client + 128),
    "owner_cleared": all(
        u64(client + o) != audio_decoder for o in report["audio_owner_offsets"]
    ),
}
cleanup = _audio_neg_source.split("cleanup = ", 1)[1]
# Keep original negotiated shutdown/ref owner, add matching fixture platform quit
# after original player destruction, before the inherited task readback.
anchor = 'exec(compile(tail, str(udp_path), "exec"), globals())'
assert cleanup.count(anchor) == 1
addition = 'tail=tail.replace(\'call("void(*)(void*)", u64(u64(client) + 8), client)\', \'call("void(*)(void*)", u64(u64(client) + 8), client)\\ncall("void(*)(unsigned int)", symbol("SDL_QuitSubSystem"), 16)\')\n'
cleanup = cleanup.replace(anchor, addition + anchor)
exec(compile("cleanup = " + cleanup, config["negotiation_helper"], "exec"), globals())
