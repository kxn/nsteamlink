#!/usr/bin/env python3
"""Map all byte-valued control IDs through original client dispatcher instructions.

Frame construction is injected; the dispatcher stops at the first handler or
protobuf constructor, so payload semantics and downstream actions are excluded.
Also executes MTU clamping, connection deadlines, traffic shaping, channel
scheduling and Connected guards. Parsing, socket I/O and handler actions are
stubbed; this is not a whole-protocol or native-implementation equivalence test.
"""
import argparse
import contextlib
import io
import json
import re
import runpy
import subprocess
import sys
from pathlib import Path
from google.protobuf import descriptor_pb2

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--binary", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
saved_argv = sys.argv
sys.argv = [
    str(Path(__file__).with_name("audit-steam-video-recovery.py")),
    "--binary",
    str(args.binary),
    "--output",
    str(args.output.with_name("official-branches.json")),
]
with contextlib.redirect_stdout(io.StringIO()):
    base = runpy.run_path(sys.argv[0])
sys.argv = saved_argv
Run, STOP = base["Run"], base["STOP"]
schema = descriptor_pb2.FileDescriptorProto.FromString(
    base["BINARY"][0x3E5474 : 0x3E5474 + 21560]
)
enum = next(e for e in schema.enum_type if e.name == "EStreamControlMessage")
names = {v.number: v.name for v in enum.value}
disasm = subprocess.run(
    [
        "aarch64-linux-gnu-objdump",
        "-dC",
        "--start-address=0x7a6368",
        "--stop-address=0x7a6db0",
        str(args.binary),
    ],
    capture_output=True,
    text=True,
    check=True,
).stdout
calls = {
    int(m[0], 16): m[1]
    for m in re.findall(r"\b(?:bl|b)\s+([0-9a-f]+)\s+<(.+)@plt>", disasm)
}


class Dispatch:
    def __init__(self):
        self.r = r = Run()
        self.client, self.queue, self.packet = 0x20000000, 0x20010000, 0x20020000
        self.route = None
        self.message = 0

        def frame():
            p = r.r(0)
            r.b(p + 24, 1)
            r.b(p + 25, self.message)
            r.ret()

        def stop(name):
            self.route = name
            r.u.emu_stop()

        for target, name in calls.items():
            if name.startswith("CStreamClient::On") or (
                "::" in name and name.split("::")[0] + "(" in name
            ):
                r.callbacks[target] = lambda name=name: stop(name)
        r.callbacks[0xC0E130] = frame
        r.stop_at[0x7A6558] = lambda: stop("unhandled")
        r.wq(self.client + 736, self.queue)
        r.wq(self.queue, self.packet)

    def dispatch(self, state, message):
        r = self.r
        self.route = None
        self.message = message
        r.w32(self.client + 256, state)
        r.w32(self.client + 720, 0)
        r.w32(self.client + 724, 0)
        r.w32(self.client + 728, 0)
        r.u.reg_write(base["UC_ARM64_REG_SP"], 0x300FF000)
        r.u.reg_write(base["UC_ARM64_REG_X30"], STOP)
        # Stopping at a deliberately stubbed callee is intentional here.
        r.u.reg_write(base["UC_ARM64_REG_X0"], self.client)
        r.u.emu_start(0x7A6368, STOP + 4, count=10000)
        assert self.route is not None, (
            state,
            message,
            hex(r.u.reg_read(base["UC_ARM64_REG_PC"])),
        )
        return self.route


f = Dispatch()
routes = []
for state in (2, 3, 4, 6):
    for message in range(256):
        routes.append(
            dict(
                state=state,
                message=message,
                name=names.get(message),
                target=f.dispatch(state, message),
            )
        )
active = [r for r in routes if r["state"] == 6 and r["target"] != "unhandled"]
source_root = Path(__file__).resolve().parent.parent / "third_party" / "ihslib"
proto = (source_root / "protobuf/remoteplay.proto").read_text()
local_enum = {
    name: int(value)
    for name, value in re.findall(r"\b(k_EStreamControl\w+)\s*=\s*(\d+)", proto)
}
local = (source_root / "src/session/channels/ch_control.c").read_text()
local = local[
    local.index("void IHS_SessionChannelControlOnMessageReceived(") : local.index(
        "static void OnServerHandshake(",
        local.index("void IHS_SessionChannelControlOnMessageReceived("),
    )
]
local_cases = {
    local_enum[n] for n in re.findall(r"\bcase\s+(k_EStreamControl\w+)\s*:", local)
}
missing = [row for row in active if row["message"] not in local_cases]

# OnStreamPacket has fast paths before the queued dispatcher. We inject a
# successfully decoded control envelope; real crypto/payload handling is excluded.
fast_paths = []
r = Run()
client, p, delegate, vt = 0x20000000, 0x20010000, 0x20020000, 0x20030000
r.wq(client + 48, delegate)
r.wq(delegate, vt)
r.wq(vt + 80, STOP + 0x100)
fast_context = {}
events = []


def envelope():
    f = r.r(0)
    r.b(f + 24, fast_context["channel"])
    r.b(f + 25, fast_context["message"])
    r.ret()


def action(name):
    events.append(name)
    r.ret()


r.callbacks.update(
    {
        0xC0E130: envelope,
        0xC0E120: lambda: r.ret(),
        0xC0E780: lambda: r.ret(1),
        0xC0E790: lambda: action("queue"),
        0xC0A380: lambda: r.ret(2),
        0xC0E770: lambda: action("media"),
        STOP + 0x100: lambda: action("RemoteHID"),
    }
)
for state, channel, message in [(6, 1, n) for n in range(256)] + [
    (0, 1, 50),
    (7, 1, 50),
    (6, 3, 1),
    (5, 3, 1),
    (6, 2, 1),
]:
    fast_context.update(channel=channel, message=message)
    events.clear()
    r.w32(client + 256, state)
    r.u.reg_write(base["UC_ARM64_REG_SP"], 0x300FF000)
    r.u.reg_write(base["UC_ARM64_REG_X30"], STOP)
    r.run(0x7ACFA8, client, 0, p)
    expected = (
        []
        if state in (0, 7) or (channel >= 3 and state != 6)
        else (
            ["media"]
            if channel >= 3
            else (
                ["RemoteHID"]
                if channel == 1 and message == 106
                else ([] if channel == 1 and message == 9 else ["queue"])
            )
        )
    )
    assert events == expected, (state, channel, message, events)
    fast_paths.append(
        dict(state=state, channel=channel, message=message, actions=list(events))
    )

# ServerHandshake path starts at original parse result branch with the protobuf
# info object supplied. Actual clamp and global MTU write execute unchanged.
mtu_cases = []
for present, mtu in [
    (True, -1),
    (True, 0),
    (True, 511),
    (True, 512),
    (True, 1024),
    (True, 1472),
    (True, 1473),
    (True, 1500),
    (True, 9000),
    (False, 0),
]:
    r = Run()
    info = 0x20080000
    r.w32(info + 24, mtu if present else 0)
    r.wq(0xC806C8, 0xF34D48)

    def parsed():
        message = r.r(1)
        r.wq(message + 24, info)
        r.ret(1)

    r.callbacks[0xC03E40] = lambda: r.ret()
    r.callbacks[0xC0E160] = parsed
    r.callbacks[0xC0E170] = lambda: r.ret()
    r.callbacks[0xC043B0] = lambda: r.ret()
    # Required info is present; omitted optional mtu has protobuf default zero.
    r.wq(0xC7E308, info)
    sp = 0x300FF000
    r.u.reg_write(base["UC_ARM64_REG_SP"], sp)
    r.u.reg_write(base["UC_ARM64_REG_X19"], 0x20000000)
    r.u.reg_write(base["UC_ARM64_REG_X30"], STOP)
    r.stop_at[0x7A6504] = lambda: None
    r.run(0x7A649C)
    value = r.i(0xF34D48)
    assert value == max(512, min(mtu if present else 0, 1472)), (present, mtu, value)
    mtu_cases.append(dict(mtu_field_present=present, input=mtu, output=value))


# Execute the original static initializer before auditing its timeout values.
def initialized():
    r = Run()
    r.callbacks[0xC09E30] = lambda: r.ret()
    r.callbacks[0xBFF1A0] = lambda: r.ret()
    r.run(0x7FE284)
    r.u.reg_write(base["UC_ARM64_REG_X30"], STOP)
    return r


r = initialized()
constants = dict(
    connect_retry=r.i(0xF47980),
    normal_timeout=r.i(0xF47990),
    paused_timeout=r.i(0xF47994),
    rto_min=r.i(0xF47984),
    rto_max=r.i(0xF47988),
)
assert constants == dict(
    connect_retry=6553,
    normal_timeout=15 * 65536,
    paused_timeout=180 * 65536,
    rto_min=65,
    rto_max=3276,
)
timeout_cases = []
for paused in (False, True):
    threshold = constants["paused_timeout" if paused else "normal_timeout"]
    for delta in (threshold - 1, threshold, threshold + 1):
        r = initialized()
        conn = 0x20000000
        r.wq(conn, 0x20010000)
        r.w32(conn + 16, 1)
        r.b(conn + 8, int(paused))
        r.w32(conn + 52, (r.now - delta) & 0xFFFFFFFF)
        events = []

        def disconnect():
            events.append("Disconnect")
            r.ret()

        r.callbacks[0xC0E030] = disconnect
        r.run(0x7FC108, conn, r.now)
        assert bool(events) == (delta >= threshold)
        timeout_cases.append(
            dict(paused=paused, elapsed=delta, disconnected=bool(events))
        )
# Resume refreshes both receive/echo timestamps, rather than carrying old age.
r = Run()
conn = 0x20000000
r.w32(conn + 48, 123456)
r.b(conn + 8, 1)
r.run(0x7FB99C, conn)
assert (
    r.i(conn + 52) == 123456
    and r.i(conn + 56) == 123456
    and r.u.mem_read(conn + 8, 1) == b"\0"
)
timeout_cases.append(
    dict(action="resume", last_receive=r.i(conn + 52), last_echo=r.i(conn + 56))
)

# Traffic-shaper admission is separate from reliability. Inspect actual class
# deadline choice; the FEC type does not enter these type-3/4/5/6 deadline slots.
r = Run()
shaper = 0x20000000
r.run(0x7FE348, shaper)
shaper_defaults = dict(unreliable_limit=r.i(shaper), reliable_limit=r.i(shaper + 4))
assert shaper_defaults == dict(unreliable_limit=12500000, reliable_limit=625000)
pacing_cases = []
for kind in (3, 4, 5, 6, 7, 10, 11):
    for stamp in (999, 1000, 1001, 1999, 2000, 2001):
        r = Run()
        shaper, p = 0x20000000, 0x20010000
        r.w32(shaper + 8, 1000)
        r.w32(shaper + 12, 2000)
        r.packet(p, typ=kind, stamp=stamp)
        r.run(0x7FE38C, shaper, p)
        allowed = bool(r.r(0))
        threshold = 2000 if kind in (5, 6) else 1000
        assert allowed == (stamp >= threshold or kind not in (3, 4, 5, 6))
        pacing_cases.append(dict(type=kind, stamp=stamp, allowed=allowed))
# A 100-byte data packet at 65536 bytes/s accounts for 100 stream ticks.
for kind, slot in ((3, 8), (4, 8), (5, 12), (6, 12)):
    r = Run()
    shaper, p = 0x20000000, 0x20010000
    r.w32(shaper, 65536)
    r.w32(shaper + 4, 65536)
    r.w32(shaper + slot, 1000)
    r.packet(p, typ=kind, stamp=1000)
    r.w32(p + 52, 100)
    r.run(0x7FE3F0, shaper, p)
    assert r.i(shaper + slot) == 1100
    pacing_cases.append(
        dict(type=kind, bytes=100, bytes_per_second=65536, deadline=1100)
    )
    for rate, previous, stamp, expected in (
        (0, 1000, 2000, 2000),
        (65536, 1000, 2000, 2035),  # Idle catch-up is capped at 65 ticks.
        (65536, 1900, 2000, 2035),
        (65536, 2100, 2000, 2200),  # Retain existing queued budget.
        (65536, 0xFFFFFFF0, 0xFFFFFFF0, 84),  # uint32 wrap.
    ):
        r = Run()
        r.w32(shaper, rate)
        r.w32(shaper + 4, rate)
        r.w32(shaper + slot, previous)
        r.packet(p, typ=kind, stamp=stamp)
        r.w32(p + 52, 100)
        r.run(0x7FE3F0, shaper, p)
        assert r.i(shaper + slot) == expected
        pacing_cases.append(
            dict(
                type=kind, rate=rate, previous=previous, stamp=stamp, deadline=expected
            )
        )

# Execute the real channel-priority sort and two-phase connection scheduler.
scheduling_cases = []
for rotation in (0, 1, 2):
    r = initialized()
    conn = 0x20000000
    r.wq(conn, 0x20010000)
    r.w32(conn + 16, 1)
    r.w32(conn + 52, r.now)
    r.b(conn + 376, 1)
    r.b(conn + 377, rotation)
    for i, (ident, priority) in enumerate(((2, -1), (3, 0), (1, 2))):
        ch = 0x20020000 + i * 4096
        r.wq(conn + 112 + i * 8, ch)
        r.b(ch + 16, ident)
        r.w32(ch + 20, priority)
    actions = []

    def mark(kind):
        ch = r.r(0)
        ident = r.u.mem_read(ch + 16, 1)[0]
        actions.append([kind, ident, r.r(1) if kind == "unreliable" else None])
        r.ret()

    for addr, kind in (
        (0xC112E0, "receive_reliable"),
        (0xC112F0, "receive_unreliable"),
        (0xC11200, "send_reliable"),
        (0xC11220, "unreliable"),
    ):
        r.callbacks[addr] = lambda kind=kind: mark(kind)
    r.callbacks[0xC11160] = lambda: r.ret()
    r.run(0x7FC108, conn, r.now)
    order = [a[1] for a in actions if a[0] == "send_reliable"]
    assert order == [1, 3, 2], order
    retry = [a[1] for a in actions if a[0] == "unreliable" and a[2] == 1]
    assert retry == order[rotation:] + order[:rotation]
    scheduling_cases.append(
        dict(rotation=rotation, first_phase=order, retry_phase=retry)
    )

# Enumerate official packet type names without relying on the local enum.
r = Run()
packet_names = {}
for value in range(13):
    r.u.reg_write(base["UC_ARM64_REG_X30"], STOP)
    r.run(0x7FE318, value)
    addr = r.r(0)
    name = bytes(r.u.mem_read(addr, 64)).split(b"\0")[0].decode()
    packet_names[value] = name

# Connected's length refers to the wire buffer after Socket stripped any CRC.
# Timestamp processing and the connected delegate are replaced by event hooks.
connected_cases = []
for state in (0, 1):
    for length in (16, 17, 18):
        for crc in (False, True):
            r = Run()
            conn, p, delegate, vt = 0x20000000, 0x20010000, 0x20020000, 0x20030000
            r.w32(conn + 16, state)
            r.wq(conn + 368, delegate)
            r.wq(delegate, vt)
            r.wq(vt + 40, STOP + 0x100)
            r.packet(p, typ=2 | (128 if crc else 0))
            r.w32(p + 52, length)
            r.b(p + 64 + 2, 34)
            r.w32(p + 64 + 13, 8765)
            events = []

            def record(name):
                events.append(name)
                r.ret()

            r.callbacks.update(
                {
                    0xC112A0: lambda: record("timestamp"),
                    0xC0DA00: lambda: r.ret(),
                    STOP + 0x100: lambda: record("connected"),
                }
            )
            r.run(0x7FBEF4, conn, p, r.now)
            accepted = state == 0 and length == 17
            assert events == (["timestamp", "connected"] if accepted else [])
            if accepted:
                assert r.i(conn + 16) == 1 and r.u.mem_read(conn + 10, 1) == bytes(
                    [crc]
                )
                assert r.u.mem_read(conn + 13, 1) == b"\x22"
            connected_cases.append(
                dict(state=state, length=length, crc=crc, accepted=accepted)
            )

# Extend the prior connection/channel audit to every unknown base transport ID.
# This is limited to the two dispatchers, not every possible transport backend.
sys.argv = [
    str(Path(__file__).with_name("audit-steam-transport-dispatch.py")),
    "--binary",
    str(args.binary),
    "--output",
    str(args.output.with_name("transport-dispatch.json")),
]
with contextlib.redirect_stdout(io.StringIO()):
    transport = runpy.run_path(sys.argv[0])
sys.argv = saved_argv
unknown_types = []
for connection in (False, True):
    for kind in range(12, 128):
        events = transport["run"](kind, connection=connection)
        assert events == [], (connection, kind, events)
        unknown_types.append(dict(connection=connection, type=kind, actions=events))

# The checked-in reference contains original-client results only; local source
# gaps are recomputed and intentionally excluded from that reference.
reference = dict(
    routes=[row for row in routes if row["target"] != "unhandled"],
    constants=constants,
    mtu_cases=mtu_cases,
    shaper_defaults=shaper_defaults,
    packet_names=packet_names,
    scheduling_cases=scheduling_cases,
)
reference = json.loads(json.dumps(reference))  # Normalize JSON object key types.
reference_path = Path(__file__).with_name("fixtures") / "steam-protocol-inventory.json"
assert reference == json.loads(
    reference_path.read_text()
), "original-client reference changed"

args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(
    json.dumps(
        dict(
            scope=__doc__,
            binary_sha256="50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e",
            control_enum_values=len(names),
            routes=routes,
            active_state6=active,
            missing_top_level_local_cases=missing,
            fast_paths=fast_paths,
            mtu_cases=mtu_cases,
            constants=constants,
            timeout_cases=timeout_cases,
            pacing_cases=pacing_cases,
            scheduling_cases=scheduling_cases,
            shaper_defaults=shaper_defaults,
            packet_names=packet_names,
            connected_cases=connected_cases,
            unknown_types=unknown_types,
        ),
        indent=2,
    )
    + "\n"
)
print(
    json.dumps(
        dict(
            dispatch_cases=len(routes),
            active_state6=len(active),
            missing=missing,
            fast_path_cases=len(fast_paths),
            mtu_cases=len(mtu_cases),
            timeout_cases=len(timeout_cases),
            pacing_cases=len(pacing_cases),
            scheduling_cases=len(scheduling_cases),
            connected_cases=len(connected_cases),
            unknown_transport_cases=len(unknown_types),
            shaper_defaults=shaper_defaults,
            packet_names=packet_names,
        ),
        ensure_ascii=False,
    )
)
