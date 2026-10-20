"""GDB-only actual UDP ConnectACK -> original client handshake observer.

Reuse only the SDK helper's allocation/read/call definitions before its first
experiment; no SDK init, decoder, parsed Packet/Frame input or method replacement.
The peer provides explicit loopback ConnectACK datagrams and deterministic auth
material goes through the original API. Authentication/Steam/Qt/renderer and
streaming media are outside this transport handshake experiment.
"""
# ruff: noqa: F821

import json
from pathlib import Path

bootstrap = Path(config["bootstrap_helper"])
source = bootstrap.read_text()
marker = "assert Path(gdb.current_progspace().filename)"
assert source.count(marker) == 1
exec(compile(source.split(marker, 1)[0], str(bootstrap), "exec"), globals())
assert Path(gdb.current_progspace().filename).resolve() == Path(config["binary"])
report = dict(scope=__doc__, source_assertions=[], trace=[], states=[])
main_thread = gdb.selected_thread().global_num


def tasks():
    result = {}
    for path in Path(f"/proc/{inf.pid}/task").glob("*/stat"):
        try:
            result[int(path.parent.name)] = (
                path.read_text().rsplit(") ", 1)[1].split()[0]
            )
        except FileNotFoundError:
            pass
    return result


before_tasks = tasks()


class Observe(gdb.Breakpoint):
    def __init__(self, address, name):
        super().__init__("*" + str(address), internal=True)
        self.name = name

    def stop(self):
        name = self.name
        event = [name, gdb.selected_thread().global_num]
        if name == "assert":
            report["source_assertions"].append(
                dict(
                    file=cstring(int(gdb.parse_and_eval("$rdi"))).decode(),
                    line=int(gdb.parse_and_eval("$esi")),
                    expression=cstring(int(gdb.parse_and_eval("$rdx"))).decode(),
                    phase="exit" if report.get("cleanup_complete") else "probe",
                )
            )
        elif name == "connected_handler":
            packet = int(gdb.parse_and_eval("$rsi"))
            owner = int(gdb.parse_and_eval("$rdi"))
            event += [
                read(u64(packet + 56), u32(packet + 52)).hex(),
                u32(owner + 16),
                u32(client + 256),
                read(owner + 10, 1)[0],
                read(owner + 11, 1)[0],
            ]
        elif name == "frame_send":
            frame = int(gdb.parse_and_eval("$rdi"))
            event.append(read(frame + 25, 1)[0])
        elif name == "send_control":
            event.append(int(gdb.parse_and_eval("$esi")))
        elif name == "join_completed":
            if int(gdb.parse_and_eval("$r12")) != base + 0x13BD6A0:
                return False
            event.append(int(gdb.parse_and_eval("$eax")) & 0xFFFFFFFF)
        report["trace"].append(event)
        return False


for pc, name in (
    (0x1A5610, "assert"),
    (0x19B720, "connected_handler"),
    (0x3203B0, "connected_delegate"),
    (0x31AF60, "send_control"),
    (0x1947A0, "frame_send"),
    (0x1A0170, "network_shutdown"),
    (0x1AA2D5, "join_completed"),
):
    Observe(base + pc, name)

client, player = cpp_alloc(0x1F6F8), cpp_alloc(0x10000)
initial_ref = u32(base + 0x13BD468)
call("void(*)(void*)", base + 0x31A6F0, client)
assert u64(client) == base + 0x10FF908 and u32(client + 256) == 0
call("void(*)(void*,void*,int,int)", base + 0x337610, player, client, 0, 0)
assert u64(client + 48) == player and u32(client + 256) == 0
assert call("int(*)(void*,int)", base + 0x317A10, client, 1) == 1
auth = alloc(32)
inf.write_memory(auth, bytes(range(32)))
call("void(*)(void*,void*,int)", base + 0x317B30, client, auth, 32)
assert u32(client + 84) == 32 and read(u64(client + 64), 32) == bytes(range(32))
address = alloc(24)
assert (
    call(
        "int(*)(void*,void*,void*)",
        base + 0x2AED10,
        address,
        string(config["endpoint"].encode()),
        address + 22,
    )
    & 255
)
assert (
    call(
        "int(*)(void*,int,int,int,void*,void*,void*,void*,int)",
        base + 0x3181A0,
        client,
        1,
        1,
        0,
        0,
        address,
        string(b""),
        string(b""),
        0,
    )
    & 255
)
connection = u64(client + 280)
delegate = u64(connection + 0x170)
assert u64(u64(delegate) + 0x28) == base + 0x3203B0
for attempt in range(1500):
    call("void(*)(void*)", base + 0x3230A0, client)
    if u32(client + 256) == 2 and u32(connection + 16) == 1:
        break
    call("int(*)(unsigned int)", symbol("usleep"), 1000)
else:
    raise AssertionError(("No actual connection callback", report))
# Observe duplicates in the original RX handler. OS/GDB timing is not a policy
# assertion; wait for explicit peer input count, not a required retransmit count.
expected_handlers = config["expected_handlers"]
for attempt in range(1500):
    call("int(*)(unsigned int)", symbol("usleep"), 1000)
    call("void(*)(void*)", base + 0x3230A0, client)
    if sum(e[0] == "connected_handler" for e in report["trace"]) >= expected_handlers:
        break
else:
    raise AssertionError(("Missing actual duplicate/bad-length input", report))
report["connected_state"] = dict(
    client_phase=u32(client + 256),
    transport_state=u32(connection + 16),
    crc=read(connection + 10, 1)[0],
    outgoing_fec=read(connection + 11, 1)[0],
    ids=read(connection + 12, 2).hex(),
    callback=0x3203B0,
)
call("void(*)(void*)", base + 0x31AA60, client)
assert u32(client + 256) == 0
call("void(*)(void*,void*)", base + 0x317AB0, client, 0)
assert not u64(client + 48)
call("void(*)(void*)", u64(u64(player) + 8), player)
call("void(*)(void*)", u64(u64(client) + 8), client)
call("unsigned int(*)(void*)", base + 0x1A0C10, base + 0x13BD6A0)
assert u32(base + 0x13BD6A0 + 0x88) == u32(base + 0x13BD6A0 + 0xA0) == 0
call("void(*)()", base + 0x1A0170)
report["module_refs"] = [initial_ref, u32(base + 0x13BD468)]
assert report["module_refs"][0] == report["module_refs"][1]
for address in reversed(allocations):
    call("void(*)(void*)", free, address)
report["tasks_before"] = before_tasks
report["tasks_after_shutdown"] = tasks()
report["main_thread"] = main_thread
report["cleanup_complete"] = True


def exited(event):
    report["exit_code"] = getattr(event, "exit_code", None)
    Path(config["result"]).write_text(json.dumps(report, indent=2) + "\n")


gdb.events.exited.connect(exited)
