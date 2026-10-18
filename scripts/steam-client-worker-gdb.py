#!/usr/bin/env python3
"""GDB-only extension of steam-client-sdk-gdb.py; uses its initialized scope.

Original worker, SDK callback, main format consumer and player execute. Media is
an explicit already-parsed Frame/carrier boundary. Connection/UDP transport are
constructed by original code and stay unconnected/unopened; no network or full
Client constructor is claimed in the default mode. Optional bootstrap constructs
the full client and can run UDP Init/OnThink against a loopback fixture; received
video and decoder owner link remain explicit boundaries. Breakpoints observe
entries/returns, never change policy/status/callbacks/async flag. Pixel MD5 comes
from the independent fixture.
"""

# The parent GDB helper supplies this module namespace and initialized SDK.
# ruff: noqa: F821


def exercise_worker(mode):
    assert mode in (
        "empty",
        "decode",
        "cancel",
        "restart",
        "reset_pending",
        "reset_ready",
        "reset_open_error",
    )
    bootstrap = config.get("client_bootstrap")
    fixed = bool(bootstrap)
    client = cpp_alloc(0x1F6F8 if bootstrap else 0x22000)
    player, dec = cpp_alloc(0x168), cpp_alloc(0x2E0)
    main_thread = gdb.selected_thread().global_num
    trace, breaks, roles = [], [], {}
    format_memory = None
    output = {
        "mode": mode,
        "trace": trace,
        "boundaries": __doc__,
        "client_bootstrap": bootstrap,
    }

    def role():
        tid = gdb.selected_thread().global_num
        if tid == main_thread:
            return "main"
        if tid not in roles:
            roles[tid] = "background" + str(len(roles) + 1)
        return roles[tid]

    class Returned(gdb.FinishBreakpoint):
        def __init__(self, name):
            super().__init__(gdb.newest_frame(), internal=True)
            self.name = name

        def stop(self):
            value = int(gdb.parse_and_eval("$eax")) & 0xFFFFFFFF
            if value & 0x80000000:
                value -= 1 << 32
            trace.append([self.name + "_return", role(), value])
            return False

    class Entered(gdb.Breakpoint):
        def __init__(self, name, address, returns=False):
            super().__init__("*" + str(address), internal=True)
            self.name, self.returns = name, returns

        def stop(self):
            if self.name.startswith("pthread_join_"):
                owner = int(gdb.parse_and_eval("$r12"))
                label = (
                    "manager"
                    if owner == base + 0x13BD6A0
                    else "decoder"
                    if owner == dec + 104
                    else None
                )
                if label:
                    event = [label + "_" + self.name, role()]
                    if self.name.endswith("completed"):
                        event.append(int(gdb.parse_and_eval("$eax")) & 0xFFFFFFFF)
                    trace.append(event)
                return False
            if (
                self.name == "manager_join"
                and int(gdb.parse_and_eval("$rdi")) != base + 0x13BD6A0
            ):
                return False
            trace.append([self.name, role()])
            if self.name == "final_decode" and format_memory:
                format_memory.start()
            if self.name == "sdk_get_format":
                offered = int(gdb.parse_and_eval("$rsi"))
                formats = []
                for i in range(64):
                    value = u32(offered + 4 * i)
                    if value == 0xFFFFFFFF:
                        break
                    formats.append(value)
                else:
                    raise AssertionError("unterminated SDK formats")
                output.setdefault("offered_formats", []).append(formats)
                if format_memory:
                    format_memory.borrow(offered, formats)
            if self.name == "main_format" and format_memory:
                format_memory.consume()
            if self.name == "player_put":
                frame = int(gdb.parse_and_eval("$rsi"))
                af = u64(frame + 48)
                output.setdefault("player_objects", []).append(
                    {
                        "id": u32(frame + 40) & 0xFFFF,
                        "shape": [u32(af + 104), u32(af + 108), u32(af + 116)],
                        "has_pixels": bool(u64(af)),
                    }
                )
            if self.name == "frame_send":
                frame = int(gdb.parse_and_eval("$rdi"))
                output.setdefault("control", []).append(
                    {"channel": read(frame + 24, 1)[0], "type": read(frame + 25, 1)[0]}
                )
            if self.returns and not fixed:
                Returned(self.name)
            return False

    for address, name, returns in (
        (0x2ED830, "submit", False),
        (0x3260D0, "decode_frame", False),
        (0x324190, "final_decode", False),
        (0x324D00, "sdk_get_format", True),
        (0x324C90, "format_dispatch", True),
        (0x324D10, "main_format", False),
        (0x324990, "format_selector", True),
        (0x31DD40, "decoder_info", False),
        (0x1947A0, "frame_send", True),
        (0x2EDF70, "player_put", False),
        (0x2EDBF0, "public_stop", False),
        (0x324840, "codec_stop", False),
        (0x2ED980, "public_start", False),
        (0x2EDC50, "restart", False),
        (0x319360, "request_reset", False),
        (0x31F7F0, "data_lost", False),
    ):
        breaks.append(Entered(name, base + address, returns))
    # Keep these observers through the original --version main/ELF destructors.
    # A normal process exit alone would not prove that the global worker joined.
    manager_observers = [
        Entered("manager_destructor", base + 0x1A00E0),
        Entered("manager_join", base + 0x1AA260, True),
        Entered("pthread_join_enter", base + 0x1AA2D0),
        Entered("pthread_join_completed", base + 0x1AA2D5),
    ]
    output["manager_observers"] = len(manager_observers)
    if fixed:
        # Observe actual instruction continuations instead of thread-bound
        # GDB FinishBreakpoints (GDB can fail internally on extra thread exits).
        class AtReturn(gdb.Breakpoint):
            def __init__(self, name, address):
                super().__init__("*" + str(base + address), internal=True)
                self.name = name

            def stop(self):
                value = int(gdb.parse_and_eval("$eax")) & 0xFFFFFFFF
                if value & 0x80000000:
                    value -= 1 << 32
                trace.append([self.name + "_return", role(), value])
                return False

        for address, name in (
            (0x32478F, "sdk_open"),
            (0x324365, "sdk_send"),
            (0x324381, "sdk_receive"),
            (0x324CEB, "sdk_get_format"),
            (0x324CFE, "sdk_get_format"),
            (0x324D35, "format_selector"),
            (0x31B000, "frame_send"),
            (0x31B040, "frame_send"),
        ):
            breaks.append(AtReturn(name, address))

        class AfterActorRestart(gdb.Breakpoint):
            def stop(self):
                output["after_actor_restart"] = dict(
                    pending=pending(),
                    request=u32(dec + 96),
                    codec_alive=bool(u64(dec + 0x268)),
                )
                trace.append(["actor_restart_completed", role()])
                return False

        breaks.append(AfterActorRestart("*" + str(base + 0x31FA35), internal=True))
        for address, name in (
            (0x3230A0, "client_think"),
            (0x31F9D0, "pending_resets"),
            (0x191F90, "network_poll"),
            (0x322B90, "control_dispatch"),
        ):
            breaks.append(Entered(name, base + address))
    for index, name in ((10, "sdk_send"), (6, "sdk_receive")):
        breaks.append(Entered(name, table[index], True))

    if mode == "reset_open_error":

        class InvalidOpenInput(gdb.Breakpoint):
            def stop(self):
                if pending():
                    context = u64(dec + 0x268)
                    output["sdk_open_input"] = {
                        "boundary": "Explicit invalid SDK extradata_size input; no natural protocol producer claimed.",
                        "original": u32(context + 0x50),
                        "injected": -1,
                    }
                    # Bundled open2@69fcc checks this signed size as unsigned.
                    # Only its input changes; the SDK and original error branch
                    # execute, without a return-value or method replacement.
                    w32(context + 0x50, 0xFFFFFFFF)
                return False

        breaks.append(InvalidOpenInput("*" + str(base + 0x32477E), internal=True))

    def pause_until(predicate, label):
        for _ in range(1000):
            if predicate():
                return
            # Resume all real inferior threads; this is an OS scheduling input,
            # not an SDK return/status terminal or Python replacement worker.
            call("int(*)(unsigned int)", symbol("usleep"), 1000)
        if format_memory:
            gdb.write(
                json.dumps(dict(trace=trace, memory=format_memory.snapshot())) + "\n"
            )
            gdb.write(gdb.execute("thread apply all bt 12", to_string=True))
        raise AssertionError(label)

    def pending():
        return bool(read(dec + 0x2CD, 1)[0])

    if config.get("format_memory"):
        scope = dict(globals())
        helper = Path(config["format_memory_helper"])
        exec(compile(helper.read_text(), str(helper), "exec"), scope, scope)
        format_memory = scope["observe_formats"](
            table, dec, output, role, u64, pending, symbol
        )

    def start():
        call("void(*)(void*,void*)", base + 0x2ED980, dec, dec + 32)
        assert u64(dec + 0x268) and u64(dec + 0x270)
        assert read(dec + 100, 1) == b"\1"  # observed, never overwritten

    def submit(fid):
        carrier = cpp_alloc(0x928)
        call("void(*)(void*)", base + 0x198AA0, carrier)
        body = struct.pack("<HBHH", 0, 24, 0, 0) + fixture.read_bytes()[:2204]
        assert len(body) + 13 <= 0x8E0
        inf.write_memory(u64(carrier + 56) + 13, body)
        w32(carrier + 52, len(body) + 13)
        frame = cpp_alloc(0x38)
        call("void(*)(void*)", base + 0x1942F0, frame)
        # Transfer the constructor's initial carrier ref to this descriptor.
        # Original submit copies it and performs its own atomic retain/release.
        inf.write_memory(frame + 8, struct.pack("<Q", carrier))
        inf.write_memory(frame + 26, struct.pack("<H", fid))
        w32(frame + 28, 1000000)
        call("void(*)(void*,void*)", base + 0x2ED830, dec, frame)
        call("void(*)(void*)", u64(u64(frame) + 8), frame)
        pause_until(pending, "worker did not publish format request")
        trace.append(["pending_observed", "main"])

    def hash_frame(frame):
        af = u64(frame + 48)
        assert [u32(af + 104), u32(af + 108), u32(af + 116)] == [128, 72, 0]
        pixels = bytearray()
        for plane, width, height in ((0, 128, 72), (1, 64, 36), (2, 64, 36)):
            address, stride = u64(af + 8 * plane), u32(af + 64 + 4 * plane)
            assert address and width <= stride < 65536
            for row in range(height):
                pixels += read(address + row * stride, width)
        digest = hashlib.md5(pixels).hexdigest()
        assert digest == expected
        return digest

    def finish_picture(fid):
        assert pending()
        if bootstrap == "udp":
            call("void(*)(void*)", base + 0x3230A0, client)
        else:
            call("void(*)(void*)", base + 0x324D10, dec)
        assert not pending()
        trace.append(["main_format_completed", "main"])
        pause_until(lambda: u32(player + 0xEC) != 0xFFFFFFFF, "no player output")
        slot = alloc(8)
        assert call("int(*)(void*,void*)", base + 0x2EF250, player + 0x40, slot) & 255
        frame = u64(slot)
        assert u32(frame + 40) & 0xFFFF == fid and u32(frame + 44) == 1000000
        assert u64(frame + 32) == dec + 0x278
        output["picture"] = {
            "id": fid,
            "timestamp": 1000000,
            "md5_before_stop": hash_frame(frame),
        }
        return frame

    output["threads_before"] = len(inf.threads())
    # Actual config constructor/parser, with explicit software preference false.
    if bootstrap:
        call("void(*)(void*)", base + 0x31A6F0, client)
        assert u64(client) == base + 0x10FF908
        output["constructed_client"] = dict(
            vptr_offset=u64(client) - base,
            phase=u32(client + 256),
            hardware_preference=read(client + 612, 1)[0],
        )
    else:
        call("void(*)(void*)", base + 0x45A330, client + 456)
    wire = alloc(2)
    inf.write_memory(wire, bytes.fromhex("3800"))
    assert call("int(*)(void*,void*,int)", base + 0x7C9920, client + 456, wire, 2) == 1
    transport = connection = 0
    if bootstrap == "udp":
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
        text = alloc(128)
        call("void(*)(void*,void*,int,int)", base + 0x2AEF30, address, text, 128, 0)
        assert cstring(text).decode() == config["endpoint"]
        status = (
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
        assert status == 1
        output["transport_init_return"] = status
        output["client_phase"] = u32(client + 256)
        connection, transport = u64(client + 280), u64(client + 272)
        assert connection and transport and u64(client + 264)
        output["connection_state"] = u32(connection + 16)
        output["transport_fd"] = u32(transport + 20)
        assert output["client_phase"] == 1 and output["connection_state"] == 0
        assert output["transport_fd"] != 0xFFFFFFFF
    elif mode != "empty":
        transport = cpp_alloc(0x48)
        call("void(*)(void*)", base + 0x1A4210, transport)
        connection = call("void*(*)(void*)", base + 0x19BD00, transport)
        inf.write_memory(client + 280, struct.pack("<Q", connection))
        output["connection_state"] = u32(connection + 16)
        assert output["connection_state"] == 3
        output["transport_fd"] = u32(transport + 20)
        assert output["transport_fd"] == 0xFFFFFFFF
    output["threads_before_start"] = len(inf.threads())
    output["thread_ids_before_start"] = sorted(t.global_num for t in inf.threads())
    call("void(*)(void*,void*)", base + 0x2EE0F0, player, client)
    call("void(*)(void*,void*,void*,int)", base + 0x324610, dec, client, player, 4)
    # Declared partial-client owner link, also read by original RequestReset.
    # The full control StartVideo handler/Client ctor is outside this probe.
    inf.write_memory(client + 40, struct.pack("<Q", dec))
    output["configured_decoder_owner_link"] = True
    inf.write_memory(dec + 0x184, struct.pack("<II", 128, 72))
    start()
    ctx = u64(dec + 0x268)
    output.update(
        scope=(
            "Original complete client ctor"
            + (
                "/UDP Init/OnThink; loopback peer without handshake"
                if bootstrap == "udp"
                else "; no Init"
            )
            + "; explicit video owner/admission boundary; no full Qt/Steam startup."
        )
        if bootstrap
        else "Original worker with partial configured client; no full Client/Qt/network startup.",
        callback_deferred=True,
        decoder_active=bool(read(dec + 24, 1)[0]),
        context_created=True,
        parser_created=True,
        source_callback_installed=u64(ctx + 0xC0) == base + 0x324D00,
        sdk_threads=u32(ctx + 0x290),
        sdk_thread_type=u32(ctx + 0x294),
        codec_capabilities=u32(selected + 24),
        threads_started=len(inf.threads()),
    )
    assert output["source_callback_installed"]
    held = []
    if mode == "empty" and bootstrap == "udp":
        call("void(*)(void*)", base + 0x3230A0, client)
    if mode != "empty":
        submit(23)
        output["pending_stack"] = gdb.execute("thread apply all bt", to_string=True)
        if mode in ("reset_pending", "reset_open_error"):
            trace.append(["reset_while_pending", "main"])
            call("void(*)(void*,int)", base + 0x319360, client, 0)
            output["request_before_think"] = u32(dec + 96)
            call("void(*)(void*)", base + 0x3230A0, client)
            output["pending_after_reset_think"] = pending()
            output["request_after_reset_think"] = u32(dec + 96)
            if mode == "reset_open_error":
                context = u64(dec + 0x268)
                output["failed_open_state"] = dict(
                    codec_alive=bool(context),
                    parser_alive=bool(u64(dec + 0x270)),
                    active=bool(read(dec + 24, 1)[0]),
                    guard=bool(read(dec + 0x2CC, 1)[0]),
                    pending=pending(),
                    threads=u32(context + 0x290),
                )
            else:
                submit(24)
        if mode == "reset_open_error":
            pass  # No further media is submitted to the failed backend.
        elif mode in ("decode", "restart", "reset_pending", "reset_ready"):
            held.append(finish_picture(24 if mode == "reset_pending" else 23))
            if mode in ("restart", "reset_ready"):
                output["picture_before_restart"] = output.pop("picture")
                if mode == "reset_ready":
                    trace.append(["reset_after_picture", "main"])
                    call("void(*)(void*,int)", base + 0x319360, client, 0)
                    call("void(*)(void*)", base + 0x3230A0, client)
                else:
                    call("void(*)(void*)", base + 0x2EDC50, dec)
                output["pending_after_restart"] = pending()
                assert not pending()
                assert hash_frame(held[0]) == expected
                submit(24)
                held.append(finish_picture(24))
        else:
            call("void(*)(void*)", base + 0x2EDBF0, dec)
            output["pending_after_cancel"] = pending()
            output["cancel_cleared_codec"] = not u64(dec + 0x268) and not u64(
                dec + 0x270
            )
            assert output["cancel_cleared_codec"]
    call("void(*)(void*)", base + 0x2EDBF0, dec)
    output["context_cleared_after_stop"] = u64(dec + 0x268) == 0
    output["parser_cleared_after_stop"] = u64(dec + 0x270) == 0
    output["threads_after_stop"] = len(inf.threads())
    output["thread_ids_after_stop"] = sorted(t.global_num for t in inf.threads())
    output["reset_request_after_stop"] = u32(dec + 96)
    output["cached_info_after_stop"] = (
        cstring(u64(client + 648)).decode() if u64(client + 648) else None
    )
    assert output["context_cleared_after_stop"] and output["parser_cleared_after_stop"]
    if bootstrap == "udp":
        output["client_phase_after_stop"] = u32(client + 256)
        output["connection_state_after_stop"] = u32(connection + 16)
    if held:
        output["picture"]["md5_after_stop"] = hash_frame(held[-1])
        if len(held) > 1:
            output["picture_before_restart"]["md5_after_stop"] = hash_frame(held[0])
        for frame in held:
            call("void(*)(void*)", base + 0x323FF0, frame)
        assert u32(dec + 0x2AC) != 0xFFFFFFFF
        output["late_frame_returned_to_pool"] = True
        call("void(*)(void*)", base + 0x2EDBF0, dec)
        assert u32(dec + 0x2AC) == 0xFFFFFFFF
    if format_memory:
        format_memory.close()
    for bp in breaks:
        bp.delete()
    inf.write_memory(client + 40, struct.pack("<Q", 0))
    call("void(*)(void*)", u64(u64(dec) + 8), dec)
    call("void(*)(void*)", base + 0x2EE370, player)
    if bootstrap == "udp":
        call("void(*)(void*)", u64(u64(client) + 8), client)
        output["full_client_deleting_dtor_returned"] = True
        call("unsigned int(*)(void*)", base + 0x1A0C10, base + 0x13BD6A0)
        assert u32(base + 0x13BD6A0 + 0x88) == 0 and u32(base + 0x13BD6A0 + 0xA0) == 0
        output["connection_retired"] = True
    else:
        call("void(*)(void*,void*)", base + 0x2B5C80, client + 648, 0)
        if connection:
            call("void(*)(void*)", base + 0x19A860, connection)
            call("unsigned int(*)(void*)", base + 0x1A0C10, base + 0x13BD6A0)
            assert u32(base + 0x13BD6A0 + 0x88) == 0
            assert u32(base + 0x13BD6A0 + 0xA0) == 0
            assert u32(transport + 8) == 1
            assert call("int(*)(void*)", base + 0x1A41B0, transport) == 0
            output["connection_retired"] = True
        if bootstrap:
            call("void(*)(void*)", u64(u64(client) + 8), client)
            output["full_client_deleting_dtor_returned"] = True
        else:
            call("void(*)(void*)", u64(u64(client + 456)), client + 456)
            call("void(*)(void*,unsigned long)", base + 0xE3310, client, 0x22000)
    output["threads_after_resources"] = len(inf.threads())
    output["thread_ids_after_resources"] = sorted(t.global_num for t in inf.threads())
    return output
