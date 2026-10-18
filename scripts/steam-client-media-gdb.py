"""Original real UDP negotiation, StartVideo/fragments/SDK/pixel/StopVideo.

Reuse the negotiation helper before its cleanup. No parsed media Frame, callback,
SDK status, state, decoder link or virtual method is supplied. Controlled socket
peer, auth token, settings and media bytes remain fixture inputs. Generic player
queue observation is not physical rendering, a genuine Steam host or Switch.
"""

# ruff: noqa: F821
from pathlib import Path

media_scope = __doc__
media_neg_path = Path(config["negotiation_helper"])
media_neg_source = media_neg_path.read_text()
media_setup_marker = "# Continue the original UDP helper"
media_cleanup_marker = "cleanup = "
exec(
    compile(
        media_neg_source.split(media_setup_marker, 1)[0], str(media_neg_path), "exec"
    ),
    globals(),
)
report["scope"] = media_scope
report["media_events"] = []
report["pictures"] = []


class MediaObserver(gdb.Breakpoint):
    def __init__(self, pc, name):
        super().__init__("*" + str(base + pc), internal=True)
        self.name = name

    def stop(self):
        name = self.name
        e = dict(name=name, thread=gdb.selected_thread().global_num)
        if name == "decoder_join":
            if int(gdb.parse_and_eval("$r12")) not in {
                d + 104 for d in report.get("decoder_addresses", [])
            }:
                return False
            e["result"] = int(gdb.parse_and_eval("$eax")) & 0xFFFFFFFF
        if name == "decoder_ctor":
            report.setdefault("decoder_addresses", []).append(
                int(gdb.parse_and_eval("$rdi"))
            )
        if name in ("sdk_send_return", "sdk_receive_return"):
            e["result"] = int(gdb.parse_and_eval("$eax")) & 0xFFFFFFFF
        if name == "packet_callback":
            packet = int(gdb.parse_and_eval("$rdx"))
            wire = read(u64(packet + 56), u32(packet + 52))
            if wire[4] == 3:
                e.update(
                    wire_size=len(wire),
                    packet_header=wire[:13].hex(),
                    body_prefix=wire[13:45].hex(),
                    body_sha256=hashlib.sha256(wire[13:]).hexdigest(),
                )
        if name == "sdk_send":
            pkt = int(gdb.parse_and_eval("$rsi"))
            data = read(u64(pkt + 24), u32(pkt + 32))
            e.update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
        if name == "player_put":
            f = int(gdb.parse_and_eval("$rsi"))
            af = u64(f + 48)
            e.update(
                id=u32(f + 40) & 65535, timestamp=u32(f + 44), pixels=bool(u64(af))
            )
            if u64(af):
                pixels = bytearray()
                shape = [u32(af + 104), u32(af + 108), u32(af + 116)]
                assert shape == [128, 72, 0], shape
                for plane, w, h in ((0, 128, 72), (1, 64, 36), (2, 64, 36)):
                    ptr, stride = u64(af + 8 * plane), u32(af + 64 + 4 * plane)
                    for row in range(h):
                        pixels += read(ptr + row * stride, w)
                report["pictures"].append(
                    dict(
                        id=e["id"],
                        timestamp=e["timestamp"],
                        shape=shape,
                        md5=hashlib.md5(pixels).hexdigest(),
                    )
                )
        report["media_events"].append(e)
        return False


for pc, name in (
    (0x3212E0, "start_video"),
    (0x3214D0, "stop_video"),
    (0x324610, "decoder_ctor"),
    (0x323FC0, "decoder_dtor"),
    (0x2ED830, "submit"),
    (0x2EDF70, "player_put"),
    (0x324365, "sdk_send_return"),
    (0x324381, "sdk_receive_return"),
    (0x31BBD0, "packet_callback"),
    (0x1AA2D5, "decoder_join"),
):
    MediaObserver(pc, name)
# SDK function-table producer is initialized by real negotiation capability calls.

exec(
    compile(
        media_setup_marker
        + media_neg_source.split(media_setup_marker, 1)[1].split(
            media_cleanup_marker, 1
        )[0],
        str(media_neg_path),
        "exec",
    ),
    globals(),
)
table = [u64(base + 0x13BD3A0 + 8 * i) for i in range(25)]
MediaObserver(table[10] - base, "sdk_send")
for attempt in range(3000):
    call("void(*)(void*)", base + 0x3230A0, client)
    if report["pictures"] or (
        not config.get("source_decode", True)
        and report.get("decoder_addresses")
        and not u64(client + 40)
    ):
        break
    call("int(*)(unsigned int)", symbol("usleep"), 1000)
else:
    gdb.write(json.dumps(report) + "\n")
    raise AssertionError("real UDP media did not decode")
slot = alloc(8)
for attempt in range(3000):
    if call("int(*)(void*,void*)", base + 0x2EF250, player + 0x40, slot) & 255:
        f = u64(slot)
        call("void(*)(void*)", base + 0x323FF0, f)
    call("void(*)(void*)", base + 0x3230A0, client)
    if not u64(client + 40):
        break
    call("int(*)(unsigned int)", symbol("usleep"), 1000)
else:
    raise AssertionError("peer did not stop video")
report["media_final"] = dict(
    phase=u32(client + 256),
    decoder=u64(client + 40),
    rx=u64(client + 136),
    tx=u64(client + 128),
)

exec(
    compile(
        media_cleanup_marker + media_neg_source.split(media_cleanup_marker, 1)[1],
        str(media_neg_path),
        "exec",
    ),
    globals(),
)
