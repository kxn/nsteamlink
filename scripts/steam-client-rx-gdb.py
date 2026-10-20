"""Observe real original Socket batches and ProcessTimestamp without replacement.

The inherited audio fixture controls only peer/initial platform ownership/Stop.
Read-only breakpoints perturb scheduling; recorded batches and measured RTT,
not natural timing, are the observable input to the independent replay.
"""

# ruff: noqa: F821
from pathlib import Path
import struct

_rx_audio_source = Path(config["audio_helper"]).read_text()
_rx_audio_marker = "class AudioEvent(gdb.Breakpoint):"
assert _rx_audio_source.count(_rx_audio_marker) == 1
exec(
    compile(
        _rx_audio_source.split(_rx_audio_marker, 1)[0], config["audio_helper"], "exec"
    ),
    globals(),
)
report["rx_batches"] = []
_rx_contexts = {}
_rx_serial = 0


class _RXFinish(gdb.FinishBreakpoint):
    def __init__(self, thread, ctx):
        super().__init__(gdb.newest_frame(), internal=True)
        self.thread, self.ctx = thread, ctx

    def stop(self):
        if self.ctx["packets"]:
            self.ctx["result"] = int(gdb.parse_and_eval("$eax")) & 255
            self.ctx["frames_at_end"] = len(report["audio_frame_returns"])
            self.ctx["clock"] = dict(
                minimum=u32(connection + 740),
                smooth=u32(connection + 744),
                mean=struct.unpack("<f", read(connection + 732, 4))[0],
                offset=u32(connection + 848),
            )
            self.ctx["tick"] = u32(connection + 48)
            report["rx_batches"].append(self.ctx)
        del _rx_contexts[self.thread]
        return False


class _RXStart(gdb.Breakpoint):
    def stop(self):
        global _rx_serial
        thread = gdb.selected_thread().global_num
        assert thread not in _rx_contexts
        _rx_serial += 1
        ctx = dict(serial=_rx_serial, thread=thread, packets=[], budgets=[])
        _rx_contexts[thread] = ctx
        _RXFinish(thread, ctx)
        return False


class _RXPacket(gdb.Breakpoint):
    def stop(self):
        thread = gdb.selected_thread().global_num
        if thread not in _rx_contexts:
            return False
        p = int(gdb.parse_and_eval("$rsi"))
        size = u32(p + 52)
        assert 13 <= size <= 65536
        raw = read(u64(p + 56), size)
        _rx_contexts[thread]["packets"].append(
            dict(wire=raw.hex(), tick=int(gdb.parse_and_eval("$edx")) & 0xFFFFFFFF)
        )
        return False


_RXStart("*" + str(base + 0x1A0760), internal=True)
_RXPacket("*" + str(base + 0x1A0500), internal=True)

report["rx_clock"] = []


class _RXClockResult(gdb.FinishBreakpoint):
    def __init__(self, p, row):
        super().__init__(gdb.newest_frame(), internal=True)
        self.p, self.row = p, row

    def stop(self):
        self.row["after"] = dict(
            minimum=u32(self.p + 740),
            smooth=u32(self.p + 744),
            mean=struct.unpack("<f", read(self.p + 732, 4))[0],
        )
        return False


class _RXClock(gdb.Breakpoint):
    def stop(self):
        p = int(gdb.parse_and_eval("$rdi"))
        row = {
            n: int(gdb.parse_and_eval(reg)) & 0xFFFFFFFF
            for n, reg in (("echo", "$esi"), ("peer", "$edx"), ("now", "$ecx"))
        }
        report["rx_clock"].append(row)
        _RXClockResult(p, row)
        return False


class _RXBudget(gdb.Breakpoint):
    def stop(self):
        channel = int(gdb.parse_and_eval("$rbx"))
        if read(channel + 16, 1)[0] != 3:
            return False
        thread = gdb.selected_thread().global_num
        if thread in _rx_contexts:
            _rx_contexts[thread]["budgets"].append(
                (int(gdb.parse_and_eval("$r14d")) + int(gdb.parse_and_eval("$r15d")))
                & 0xFFFFFFFF
            )
        return False


_RXClock("*" + str(base + 0x19B0A0), internal=True)
_RXBudget("*" + str(base + 0x19C2EF), internal=True)
_rx_tail = _rx_audio_marker + _rx_audio_source.split(_rx_audio_marker, 1)[1]
_rx_old = 'else len(report["audio_frame_returns"]) >= config["expected_frames"]'
assert _rx_tail.count(_rx_old) == 1
_rx_tail = _rx_tail.replace(
    _rx_old,
    'else audio_frame and audio_frame["id"]==27 and len(report["audio_frame_returns"])==sum(e["name"]=="frame" for e in report["audio_events"])',
)
exec(compile(_rx_tail, config["audio_helper"], "exec"), globals())
