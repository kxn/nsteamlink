"""Original client APIs -> encrypted microphone controls and actual UDP data.

Encoded payload/format are explicit caller inputs, not SDK capture/encoding.
Peer 107/108 passes the actual socket/decrypt/dispatcher; return and empty-FIFO
barriers observe consumption before API actions. No body/state/return replacement.
"""

# ruff: noqa: F821
from pathlib import Path

_mic_scope = __doc__
_mic_path = Path(config["negotiation_helper"])
_mic_source = _mic_path.read_text()
_mic_setup = "# Continue the original UDP helper"
_mic_cut = "cleanup = "
assert _mic_source.count(_mic_setup) == 1 and _mic_source.count(_mic_cut) == 1
exec(compile(_mic_source.split(_mic_setup, 1)[0], str(_mic_path), "exec"), globals())
report.update(
    scope=_mic_scope,
    mic_sends=[],
    mic_states=[],
    mic_priorities=[],
    mic_peer_returns=[],
)


class MicReturn(gdb.FinishBreakpoint):
    def __init__(self, item):
        super().__init__(gdb.newest_frame(), internal=True)
        self.item = item

    def stop(self):
        self.item["return"] = int(gdb.parse_and_eval("$rax"))
        return False


class MicPeerReturn(gdb.FinishBreakpoint):
    def __init__(self, packet_id):
        super().__init__(gdb.newest_frame(), internal=True)
        self.packet_id = packet_id

    def stop(self):
        report["mic_peer_returns"].append(self.packet_id)
        return False


class MicPeer(gdb.Breakpoint):
    def stop(self):
        packet = int(gdb.parse_and_eval("$rdx"))
        wire = read(u64(packet + 56), u32(packet + 52))
        packet_id = int.from_bytes(wire[7:9], "little")
        if wire[4] == 1 and packet_id in (4, 5, 6):
            MicPeerReturn(packet_id)
        return False


class MicSend(gdb.Breakpoint):
    def stop(self):
        size = int(gdb.parse_and_eval("$rdx"))
        if not 13 <= size <= 65536:
            return False
        wire = read(int(gdb.parse_and_eval("$rsi")), size)
        if not 3 <= wire[4] <= 5:
            return False
        stack, frame = [], gdb.newest_frame()
        boundary = None
        for _ in range(16):
            if frame is None:
                break
            if frame.type() == gdb.DUMMY_FRAME:
                boundary = dict(pc=int(frame.pc()), frame_type=frame.type())
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
            stack=stack,
            debugger_boundary=boundary,
        )
        report["mic_sends"].append(item)
        MicReturn(item)
        return False


class MicPriority(gdb.Breakpoint):
    def stop(self):
        channel = int(gdb.parse_and_eval("$esi"))
        if int(gdb.parse_and_eval("$rdi")) == connection and 3 <= channel <= 5:
            report["mic_priorities"].append([channel, int(gdb.parse_and_eval("$edx"))])
        return False


MicPeer("*" + str(base + 0x31BBD0), internal=True)
MicSend("*" + str(symbol("sendto")), internal=True)
MicPriority("*" + str(base + 0x19ED10), internal=True)
exec(
    compile(
        _mic_setup + _mic_source.split(_mic_setup, 1)[1].split(_mic_cut, 1)[0],
        str(_mic_path),
        "exec",
    ),
    globals(),
)


def mic_state(label):
    report["mic_states"].append(
        dict(
            label=label,
            phase=u32(client + 256),
            channel=read(client + 627, 1)[0],
            sequence=int.from_bytes(read(client + 0x1F6F4, 2), "little"),
            gate=read(connection + 11, 1)[0],
            rx=u64(client + 136),
            tx=u64(client + 128),
        )
    )


def mic_drain(target, required):
    for _ in range(1000):
        call("void(*)(void*)", base + 0x3230A0, client)
        if (
            u64(client + 136) >= target
            and set(required) <= set(report["mic_peer_returns"])
            and u32(client + 0x2D4) == 0xFFFFFFFF
        ):
            return
        call("int(*)(unsigned int)", symbol("usleep"), 1000)
    raise AssertionError(("actual peer RPC not consumed", report))


mic_drain(4, (4, 5))
mic_state("before")
call("void(*)(void*,int,int,int,void*)", base + 0x31B480, client, 3, 48000, 2, 0)
mic_state("start")
for _mic_index, _mic_payload in enumerate(
    (
        bytes.fromhex("11223344"),
        bytes.fromhex("55667788"),
        bytes(i & 255 for i in range(4000)),
    )
):
    _mic_raw = alloc(len(_mic_payload))
    inf.write_memory(_mic_raw, _mic_payload)
    call(
        "void(*)(void*,void*,unsigned long)",
        base + 0x31AE90,
        client,
        _mic_raw,
        len(_mic_payload),
    )
    mic_state("send" + str(_mic_index))
mic_drain(5, (4, 5, 6))
mic_state("before_local_stop")
call("void(*)(void*)", base + 0x31BD50, client)
mic_state("stop")
call("void(*)(void*,void*,unsigned long)", base + 0x31AE90, client, _mic_raw, 4)
mic_state("after_stop_send")
for _mic_label in ("restart", "replace"):
    call("void(*)(void*,int,int,int,void*)", base + 0x31B480, client, 3, 48000, 2, 0)
    mic_state(_mic_label)
    call("void(*)(void*,void*,unsigned long)", base + 0x31AE90, client, _mic_raw, 4)
    mic_state(_mic_label + "_send")
for _mic_attempt in range(1000):
    call("void(*)(void*)", base + 0x3230A0, client)
    if len(
        {
            (bytes.fromhex(e["wire"])[4], bytes.fromhex(e["wire"])[7:9])
            for e in report["mic_sends"]
        }
    ) == 7 and all(
        e.get("return") == len(bytes.fromhex(e["wire"])) for e in report["mic_sends"]
    ):
        break
    call("int(*)(unsigned int)", symbol("usleep"), 1000)
else:
    raise AssertionError(("mic data not sent", report))
call("void(*)(void*)", base + 0x31BD50, client)
mic_state("final_stop")
call("void(*)(void*)", base + 0x31BD50, client)
mic_state("duplicate_stop")
report["mapped_sdk"] = {}
_mic_table = [u64(base + 0x13BD3A0 + 8 * i) for i in range(25)]
for _mic_index, _mic_name in (
    (0, "libavcodec.so.61"),
    (10, "libavcodec.so.61"),
    (17, "libavutil.so.59"),
):
    _mic_mapped = Path(gdb.solib_name(_mic_table[_mic_index])).resolve()
    assert _mic_mapped == (Path(config["sdk_directory"]) / _mic_name).resolve()
    report["mapped_sdk"][str(_mic_index)] = dict(
        path=str(_mic_mapped),
        sha256=hashlib.sha256(_mic_mapped.read_bytes()).hexdigest(),
    )
exec(
    compile(_mic_cut + _mic_source.split(_mic_cut, 1)[1], str(_mic_path), "exec"),
    globals(),
)
