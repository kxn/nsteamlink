"""Read-only decoder consumption/OnThink/SDK order in the actual client loop.

The inherited load helper supplies its declared peer/latency/driver boundaries.
These breakpoints only read registers and original state; they do not schedule
decoder methods, alter input or choose SDK results. Breakpoint overhead still
precludes natural wall-time equivalence.
"""

# ruff: noqa: F821
from pathlib import Path

_pressure_path = Path(config["load_helper"])
_pressure_source = _pressure_path.read_text()
_pressure_marker = 'Path(config["stage_file"]).write_text("start")'
assert _pressure_source.count(_pressure_marker) == 1
exec(
    compile(
        _pressure_source.split(_pressure_marker, 1)[0], str(_pressure_path), "exec"
    ),
    globals(),
)
report["pressure_flow"] = []
pressure_consumed = 0


def pressure_state(decoder):
    return dict(
        strict=read(decoder + 396, 1)[0],
        soft=read(decoder + 397, 1)[0],
        sequence=int.from_bytes(read(decoder + 408, 2), "little"),
    )


class PressureInputReturn(gdb.FinishBreakpoint):
    def __init__(self, decoder):
        super().__init__(gdb.newest_frame(), internal=True)
        self.decoder = decoder

    def stop(self):
        report["pressure_flow"].append(
            dict(
                kind="input_return",
                consumed=pressure_consumed,
                **pressure_state(self.decoder)
            )
        )
        return False


class PressureFlow(gdb.Breakpoint):
    def __init__(self, address, kind):
        super().__init__("*" + str(address), internal=True)
        self.kind = kind

    def stop(self):
        global pressure_consumed
        if self.kind == "input":
            decoder = int(gdb.parse_and_eval("$rdi"))
            frame = int(gdb.parse_and_eval("$rsi"))
            pressure_consumed += 1
            extra = dict(
                id=int.from_bytes(read(frame + 26, 2), "little"),
                timestamp=u32(frame + 28),
            )
            PressureInputReturn(decoder)
        else:
            decoder = (
                int(gdb.parse_and_eval("$rbp"))
                if self.kind.startswith("think")
                else u64(client + 40)
            )
            extra = {}
            if self.kind == "think":
                extra["target"] = int(gdb.parse_and_eval("$rax")) - base
            elif self.kind == "think_return":
                extra["timeout"] = int(gdb.parse_and_eval("$eax")) & 0xFFFFFFFF
        report["pressure_flow"].append(
            dict(
                kind=self.kind,
                consumed=pressure_consumed,
                **pressure_state(decoder),
                **extra
            )
        )
        return False


for _pressure_address, _pressure_kind in (
    (base + 0x3260D0, "input"),
    (base + 0x2EDAE0, "think"),
    (base + 0x2EDAE5, "think_return"),
    (table[10], "sdk"),
):
    PressureFlow(_pressure_address, _pressure_kind)

exec(
    compile(
        _pressure_marker + _pressure_source.split(_pressure_marker, 1)[1],
        str(_pressure_path),
        "exec",
    ),
    globals(),
)
