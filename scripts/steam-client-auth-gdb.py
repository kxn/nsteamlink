"""Actual UDP ServerHandshake/AuthenticationResponse, original client and crypto.

Reuse the UDP helper's original initialization and cleanup (with their source
SHA recorded); extend its observer/poll interval only. No parsed frame, phase,
connection state, crypto result, function body or original return is supplied.
Fixture token and server messages are explicit inputs. This is not Steam host
identity/authentication, Qt/SDL startup or media/device validation.
"""
# ruff: noqa: F821

from pathlib import Path

auth_scope = __doc__
udp_helper = Path(config["udp_helper"])
udp_text = udp_helper.read_text()
marker = "for attempt in range(1500):"
assert udp_text.count(marker) == 2
exec(compile(udp_text.split(marker, 1)[0], str(udp_helper), "exec"), globals())
report["scope"] = auth_scope
report["control_inputs"] = []
report["authentication_frames"] = []


class AuthenticationObserver(gdb.Breakpoint):
    def __init__(self, address, name):
        super().__init__("*" + str(base + address), internal=True)
        self.name = name

    def stop(self):
        name = self.name
        event = [name, gdb.selected_thread().global_num, u32(client + 256)]
        if name in ("server_handshake", "authentication_response"):
            frame = int(gdb.parse_and_eval("$rsi"))
            packet = u64(frame + 8)
            data = read(u64(packet + 56) + 13, u32(packet + 52) - 13)
            report["control_inputs"].append(data.hex())
            event.append(data.hex())
        elif name == "authentication_frame":
            frame = int(gdb.parse_and_eval("$rdi"))
            if read(frame + 25, 1)[0] != 1:
                return False
            packet = u64(frame + 8)
            # Frame::Send has not populated its reserved tag byte yet.
            # Read the protobuf bytes and the frame's actual type separately;
            # only real UDP output is evidence of the committed full envelope.
            data = read(u64(packet + 56) + 14, u32(packet + 52) - 14)
            frame_value = dict(type=1, payload=data.hex())
            report["authentication_frames"].append(frame_value)
            event.append(frame_value)
        if name.endswith("_return"):
            event.append(u32(base + 0x1335930))
        report["trace"].append(event)
        return False


for pc, name in (
    (0x320720, "server_handshake"),
    (0x32079F, "server_handshake_return"),
    (0x31B060, "start_authentication"),
    (0x3207D0, "authentication_response"),
    (0x32086A, "authentication_response_return"),
    (0x1947A0, "authentication_frame"),
    (0x31AA00, "client_stop_connection"),
):
    AuthenticationObserver(pc, name)

finish = config["finish_event"]
for attempt in range(1500):
    call("void(*)(void*)", base + 0x3230A0, client)
    if any(event[0] == finish for event in report["trace"]):
        break
    call("int(*)(unsigned int)", symbol("usleep"), 1000)
else:
    raise AssertionError(("Missing original terminal", finish, report))
# Copy the live connection state before the original cleanup releases ownership.
current_connection = u64(client + 280)
report["connected_state"] = dict(
    client_phase=u32(client + 256),
    transport_state=u32(current_connection + 16) if current_connection else None,
    crc=read(current_connection + 10, 1)[0] if current_connection else None,
    outgoing_fec=read(current_connection + 11, 1)[0] if current_connection else None,
    mtu=u32(base + 0x1335930),
)
cleanup = 'call("void(*)(void*)", base + 0x31AA60, client)'
assert udp_text.count(cleanup) == 1
exec(
    compile(cleanup + udp_text.split(cleanup, 1)[1], str(udp_helper), "exec"), globals()
)
