"""Original settings file -> real UDP crypto negotiation -> Streaming.

Client/player/threads/network, settings loader, protobuf, SDK capability lookup,
crypto and stages execute. Peer/token/file bytes are explicit fixture inputs;
no parsed Packet/Frame, phase, callback, SDK result or original body is supplied.
The original atexit ForceRelease owns the capability module refs: observe its
actual completion after original main, never force them to zero in the probe.
Qt/SDL renderer, actual Steam identity/host media/FEC policy and device remain out.
"""

# ruff: noqa: F821
from pathlib import Path

negotiation_scope = __doc__
udp_path = Path(config["udp_helper"])
udp_source = udp_path.read_text()
neg_setup_marker = "address = alloc(24)"
assert udp_source.count(neg_setup_marker) == 1
exec(
    compile(udp_source.split(neg_setup_marker, 1)[0], str(udp_path), "exec"), globals()
)
report["scope"] = negotiation_scope
report["module_events"] = []
report["settings_reads"] = []


class NegotiationObserver(gdb.Breakpoint):
    def __init__(self, pc, name):
        super().__init__("*" + str(base + pc), internal=True)
        self.name = name

    def stop(self):
        name = self.name
        if name.startswith("module_"):
            item = dict(
                name=name,
                value=u32(base + 0x13BD468),
                phase="original_exit" if report.get("cleanup_complete") else "probe",
            )
            if name == "module_init":
                item["return_pc"] = u64(int(gdb.parse_and_eval("$rsp"))) - base
            if name == "module_force_enter":
                item["stack"] = gdb.execute("bt 6", to_string=True)
            report["module_events"].append(item)
            return False
        if name == "settings_read_return":
            buffer = int(gdb.parse_and_eval("$rsp"))
            loaded = bool(int(gdb.parse_and_eval("$al")) & 255)
            report["settings_reads"].append(
                dict(
                    loaded=loaded,
                    bytes=read(u64(buffer), u32(buffer + 20)).hex() if loaded else None,
                )
            )
        report["trace"].append(
            [
                name,
                gdb.selected_thread().global_num,
                u32(client + 256),
                u64(client + 136),
            ]
        )
        return False


for pc, name in (
    (0x3179E0, "settings_file"),
    (0x317920, "load_settings"),
    (0x31795C, "settings_read_return"),
    (0x173B10, "module_init"),
    (0x173C60, "module_force_enter"),
    (0x173C83, "module_force_return"),
    (0x3207D0, "authentication_response"),
    (0x194E60, "decrypt_control"),
):
    NegotiationObserver(pc, name)
call(
    "void(*)(void*,void*)",
    base + 0x3179E0,
    client,
    string(config["settings_file"].encode()),
)
# Continue the original UDP helper's address parser/Init setup, stopping before
# its handshake-only poll. All runtime setup instructions remain unchanged.
setup = (
    neg_setup_marker
    + udp_source.split(neg_setup_marker, 1)[1].split("for attempt in range(1500):", 1)[
        0
    ]
)
exec(compile(setup, str(udp_path), "exec"), globals())
for attempt in range(1500):
    call("void(*)(void*)", base + 0x3230A0, client)
    if (
        u32(client + 256) == 6
        and sum(e[0] == "frame_send" for e in report["trace"]) >= 4
    ):
        break
    call("int(*)(unsigned int)", symbol("usleep"), 1000)
else:
    raise AssertionError(("Original client did not reach Streaming", report))
report["connected_state"] = dict(
    client_phase=u32(client + 256),
    transport_state=u32(connection + 16),
    crc=read(connection + 10, 1)[0],
    outgoing_fec=read(connection + 11, 1)[0],
    receive_sequence=u64(client + 136),
    send_sequence=u64(client + 128),
)
cleanup = 'call("void(*)(void*)", base + 0x31AA60, client)'
tail = cleanup + udp_source.split(cleanup, 1)[1]
assert tail.count('assert report["module_refs"][0] == report["module_refs"][1]') == 1
# This is the helper's former pre-main assumption, not an original instruction.
# Capability lookup legitimately retains refs until the original atexit owner.
tail = tail.replace(
    'assert report["module_refs"][0] == report["module_refs"][1]',
    'report["module_refs_before_original_main"] = report["module_refs"][1]',
)
exec(compile(tail, str(udp_path), "exec"), globals())
