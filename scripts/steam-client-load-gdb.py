"""Official UDP/client/worker/SDK with a declared slow SDK forwarding adapter.

The function table's send_packet endpoint forwards unchanged arguments to the
pinned SDK after nanosleep; it supplies no decoder outcome. Restored before
module cleanup. Peer pacing and top-level OnThink/picture drain are fixture
inputs. Breakpoint overhead excludes wall-time/performance/device equivalence.
FIFO counters at SDK entry are non-locking snapshots, not linearizable maxima.
"""

# ruff: noqa: F821
from pathlib import Path

_load_path = Path(config["media_helper"])
_load_source = _load_path.read_text()
_load_marker = (
    "# SDK function-table producer is initialized by real negotiation capability calls."
)
exec(
    compile(_load_source.split(_load_marker, 1)[0], str(_load_path), "exec"), globals()
)
exec(
    compile(
        _load_source.split(_load_marker, 1)[1].split("for attempt in range(3000):", 1)[
            0
        ],
        str(_load_path),
        "exec",
    ),
    globals(),
)
report["load_scope"] = (
    "Official client and actual SDK, delayed by explicit SDK endpoint wrapper; no kernel/device performance claim."
)
report["load_sdk_samples"] = []
report["load_frames"] = []
report["load_receive_busy"] = 0
report["load_receive_count"] = 0
report["load_receive_callbacks"] = []


class LoadedFrame(gdb.Breakpoint):
    def stop(self):
        frame = int(gdb.parse_and_eval("$rsi"))
        report["load_frames"].append(int.from_bytes(read(frame + 26, 2), "little"))
        return False


LoadedFrame("*" + str(base + 0x3260D0), internal=True)


# Capture FIFO after the delay, just before the original SDK executes.
class SDKProbe(gdb.Breakpoint):
    def stop(self):
        decoder = u64(client + 40)
        if not decoder:
            return False
        q = decoder + 184
        h, t = u32(q + 172), u32(q + 176)
        count = 0 if h == 0xFFFFFFFF else t - h + 1 if h <= t and t - h < 4096 else None
        report["load_sdk_samples"].append(
            dict(count=count, bytes=u32(q + 192), head=h, tail=t)
        )
        return False


SDKProbe("*" + str(table[10]), internal=True)
handle = call(
    "void*(*)(void*,int)", symbol("dlopen"), string(config["delay_library"].encode()), 2
)
assert handle


def get(n):
    return call("void*(*)(void*,void*)", symbol("dlsym"), handle, string(n.encode()))


configure, wrapped, state = (
    get("nsl_probe_config"),
    get("nsl_probe_submit"),
    get("nsl_probe_state"),
)
assert configure and wrapped and state


class LoadReceive(gdb.Breakpoint):
    def stop(self):
        packet = int(gdb.parse_and_eval("$rdx"))
        wire = read(u64(packet + 56), u32(packet + 52))
        if wire[4] == 3:
            mapped = bool(u64(client + 40))
            busy = int(u64(state) != 0)
            report["load_receive_callbacks"].append(
                [int.from_bytes(wire[14:16], "little"), mapped, busy]
            )
            if mapped:
                report["load_receive_count"] += 1
                report["load_receive_busy"] += busy
        return False


LoadReceive("*" + str(base + 0x31BBD0), internal=True)

call("void(*)(void*,unsigned int)", configure, table[10], config["delay_us"])
inf.write_memory(base + 0x13BD3A0 + 80, struct.pack("<Q", wrapped))
Path(config["stage_file"]).write_text("start")
slot = alloc(8)
stopped = False
for attempt in range(15000):
    call("void(*)(void*)", base + 0x3230A0, client)
    while call("int(*)(void*,void*)", base + 0x2EF250, player + 0x40, slot) & 255:
        call("void(*)(void*)", base + 0x323FF0, u64(slot))
    if (
        report["pictures"]
        and report["pictures"][-1]["id"] == config["last_id"]
        and not stopped
    ):
        report["load_before_stop"] = dict(
            pictures=len(report["pictures"]),
            inputs=len(report["load_frames"]),
            adapter=list(struct.unpack("<QQQQ", read(state, 32))),
        )
        Path(config["stage_file"]).write_text("stop")
        stopped = True
    if stopped and not u64(client + 40):
        break
    call("int(*)(unsigned int)", symbol("usleep"), 1000)
else:
    report["load_failure"] = "drain timeout"
    Path(config["result"] + ".partial").write_text(json.dumps(report, indent=2))
    raise AssertionError(
        ("load timeout", len(report["pictures"]), len(report["load_frames"]))
    )
inf.write_memory(base + 0x13BD3A0 + 80, struct.pack("<Q", table[10]))
report["load_table_restored"] = u64(base + 0x13BD3A0 + 80) == table[10]
report["load_adapter_final"] = list(struct.unpack("<QQQQ", read(state, 32)))
assert call("int(*)(void*)", symbol("dlclose"), handle) == 0
report["load_adapter_closed"] = True
report["media_final"] = dict(
    phase=u32(client + 256),
    decoder=u64(client + 40),
    rx=u64(client + 136),
    tx=u64(client + 128),
)
cleanup = "exec(\n    compile(\n        media_cleanup_marker"
exec(
    compile(cleanup + _load_source.split(cleanup, 1)[1], str(_load_path), "exec"),
    globals(),
)
