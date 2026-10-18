"""GDB-only original control StartVideo/StopVideo and real SDK experiment.

Full Client and CStreamPlayer constructors, public UseThreads/AuthToken APIs and
UDP Init execute. Encoded control uses original encryption, original packet
callback/decryption/FIFO and OnThink handlers/factory; no decoder owner link is
written. Carrier header admission, deterministic auth token and parsed media
Frame remain explicit inputs; there is no Steam handshake, SDL init or renderer.
"""

# The parent SDK helper supplies the initialized official process namespace.
# ruff: noqa: F821


def exercise_start(mode):
    assert mode in ("decode", "replace_pending", "stop_pending", "reset_ready")
    client, player = cpp_alloc(0x1F6F8), cpp_alloc(0x10000)
    main = gdb.selected_thread().global_num
    trace, breaks, roles, decoders = [], [], {}, []
    output = dict(
        mode=mode, scope=__doc__, trace=trace, assertions=[], control_inputs=[]
    )

    def role():
        tid = gdb.selected_thread().global_num
        if tid == main:
            return "main"
        if tid not in roles:
            roles[tid] = "background" + str(len(roles) + 1)
        return roles[tid]

    class Entered(gdb.Breakpoint):
        def __init__(self, address, name):
            super().__init__("*" + str(base + address), internal=True)
            self.name = name

        def stop(self):
            name = self.name
            if name == "avcodec_constructor":
                decoders.append(int(gdb.parse_and_eval("$rdi")))
            if name.startswith("pthread_join"):
                owner = int(gdb.parse_and_eval("$r12"))
                if owner == base + 0x13BD6A0:
                    name = "manager_" + name
                elif owner in {d + 104 for d in decoders}:
                    name = "decoder_" + name
                else:
                    return False
            event = [name, role()]
            if name.endswith("completed"):
                event.append(int(gdb.parse_and_eval("$eax")) & 0xFFFFFFFF)
            trace.append(event)
            if name == "assertion":
                output["assertions"].append(
                    [
                        cstring(int(gdb.parse_and_eval("$rdi"))).decode(),
                        int(gdb.parse_and_eval("$esi")),
                        cstring(int(gdb.parse_and_eval("$rdx"))).decode(),
                    ]
                )
            elif name == "player_put":
                frame = int(gdb.parse_and_eval("$rsi"))
                af = u64(frame + 48)
                output.setdefault("player_objects", []).append(
                    dict(
                        id=u32(frame + 40) & 0xFFFF,
                        has_pixels=bool(u64(af)),
                        shape=[u32(af + 104), u32(af + 108), u32(af + 116)],
                    )
                )
            elif (
                name in ("codec_open_input", "sdk_send")
                and config.get("video_codec_data_hex") is not None
            ):
                context = (
                    u64(int(gdb.parse_and_eval("$rbx")) + 0x268)
                    if name == "codec_open_input"
                    else int(gdb.parse_and_eval("$rdi"))
                )
                if name == "codec_open_input":
                    owner = int(gdb.parse_and_eval("$rbx"))
                    output.setdefault("codec_data_states", []).append(
                        dict(
                            stored=read(u64(owner + 32), u32(owner + 52)).hex()
                            if u32(owner + 52)
                            else "",
                            sdk_size=u32(context + 0x50),
                            sdk_has_pointer=bool(u64(context + 0x48)),
                        )
                    )
                else:
                    packet = int(gdb.parse_and_eval("$rsi"))
                    assert packet and 0 <= u32(packet + 32) <= 2 * 1024 * 1024
                    data = read(u64(packet + 24), u32(packet + 32))
                    output.setdefault("codec_packets", []).append(
                        dict(
                            size=len(data),
                            sha256=hashlib.sha256(data).hexdigest(),
                            sdk_size=u32(context + 0x50),
                        )
                    )
            elif name == "frame_send":
                frame = int(gdb.parse_and_eval("$rdi"))
                output.setdefault("control", []).append(
                    dict(channel=read(frame + 24, 1)[0], type=read(frame + 25, 1)[0])
                )
            return False

    entries = {
        0x1A5610: "assertion",
        0x337610: "player_constructor",
        0x327D50: "player_prepare",
        0x317A10: "set_use_threads",
        0x317B30: "set_auth_token",
        0x31BBD0: "packet_callback",
        0x194B60: "encrypt_control",
        0x194E60: "decrypt_control",
        0x3230A0: "client_think",
        0x31F9D0: "pending_resets",
        0x191F90: "network_poll",
        0x322B90: "control_dispatch",
        0x3212E0: "start_video_handler",
        0x3214D0: "stop_video_handler",
        0x318640: "start_video_factory",
        0x318910: "stop_video_owner",
        0x32477E: "codec_open_input",
        0x319360: "request_reset",
        0x324610: "avcodec_constructor",
        0x323FC0: "avcodec_deleting_destructor",
        0x2ED980: "public_start",
        0x2EDBF0: "public_stop",
        0x324840: "codec_stop",
        0x2ED830: "submit",
        0x3260D0: "decode_frame",
        0x324190: "final_decode",
        0x324D00: "sdk_get_format",
        0x324C90: "format_dispatch",
        0x324D10: "main_format",
        0x324990: "format_selector",
        0x31DD40: "decoder_info",
        0x1947A0: "frame_send",
        0x2EDF70: "player_put",
        0x31F7F0: "data_lost",
        0x1AA2D0: "pthread_join_enter",
        0x1AA2D5: "pthread_join_completed",
        0x1A00E0: "manager_destructor",
    }
    for address, name in entries.items():
        bp = Entered(address, name)
        # Keep manager/join observers through original ELF destructors.
        if name not in (
            "manager_destructor",
            "pthread_join_enter",
            "pthread_join_completed",
        ):
            breaks.append(bp)

    class AtReturn(gdb.Breakpoint):
        def __init__(self, address, name):
            super().__init__("*" + str(base + address), internal=True)
            self.name = name

        def stop(self):
            value = int(gdb.parse_and_eval("$eax")) & 0xFFFFFFFF
            if value & 0x80000000:
                value -= 1 << 32
            trace.append([self.name + "_return", role(), value])
            return False

    for address, name in {
        0x32478F: "sdk_open",
        0x324365: "sdk_send",
        0x324381: "sdk_receive",
        0x324CEB: "sdk_get_format",
        0x324CFE: "sdk_get_format",
        0x324D35: "format_selector",
        0x31B000: "frame_send",
        0x31B040: "frame_send",
        0x31BD13: "decrypt_control",
    }.items():
        breaks.append(AtReturn(address, name))
    # SDK entries are observed at genuine resolved table addresses.
    for index, name in ((10, "sdk_send"), (6, "sdk_receive")):
        breaks.append(Entered(table[index] - base, name))

    def decoder():
        return u64(client + 40)

    def pending():
        d = decoder()
        return bool(d and read(d + 0x2CD, 1)[0])

    def pause_until(predicate, label):
        for _ in range(1000):
            if predicate():
                return
            call("int(*)(unsigned int)", symbol("usleep"), 1000)
        gdb.write(json.dumps(output) + "\n")
        gdb.write(gdb.execute("thread apply all bt 12", to_string=True))
        raise AssertionError(label)

    call("void(*)(void*)", base + 0x31A6F0, client)
    assert u64(client) == base + 0x10FF908 and u32(client + 256) == 0
    call("void(*)(void*,void*,int,int)", base + 0x337610, player, client, 0, 0)
    assert u64(player) == base + 0x11001A0 and u64(client + 48) == player
    assert u64(u64(player) + 32) == base + 0x327D50
    assert call("int(*)(void*,int)", base + 0x317A10, client, 1) == 1
    auth = alloc(32)
    inf.write_memory(auth, bytes(range(32)))
    call("void(*)(void*,void*,int)", base + 0x317B30, client, auth, 32)
    assert u32(client + 84) == 32 and read(u64(client + 64), 32) == bytes(range(32))
    wire = alloc(2)
    inf.write_memory(wire, bytes.fromhex("3800"))
    assert call("int(*)(void*,void*,int)", base + 0x7C9920, client + 456, wire, 2) == 1
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
    assert u32(client + 256) == 1 and u32(connection + 16) == 0
    before = {t.global_num for t in inf.threads()}
    output["thread_ids_before_start"] = sorted(before)
    output["client_phase"] = 1
    output["auth_token_input"] = (
        "deterministic 32-byte fixture via original API, not authenticated Steam"
    )
    sequence = 0

    def control(kind, body):
        nonlocal sequence
        frame = cpp_alloc(0x38)
        call("void(*)(void*,int,int)", base + 0x1945E0, frame, 1, kind)
        dest = call("void*(*)(void*,int)", base + 0x194730, frame, len(body))
        if body:
            inf.write_memory(dest, body)
        carrier = u64(frame + 8)
        # Incoming transport descriptor is the explicit parsed carrier boundary.
        # The original send cannot create it on an unconnected connection.
        inf.write_memory(u64(carrier + 56) + 13, bytes([kind]))
        assert (
            call(
                "int(*)(void*,unsigned long,void*,int)",
                base + 0x194B60,
                frame,
                sequence,
                auth,
                32,
            )
            & 255
        )
        encoded = read(u64(carrier + 56) + 13, u32(carrier + 52) - 13)
        inf.write_memory(u64(carrier + 40), bytes.fromhex("0330000001"))
        previous = u64(client + 136)
        call("void(*)(void*,void*,void*)", base + 0x31BBD0, client, connection, carrier)
        assert u64(client + 136) == previous + 1 == sequence + 1
        assert u32(client + 0x2D4) != 0xFFFFFFFF
        # Original callback retains the carrier. The fixture's ref retires here.
        call("void(*)(void*)", u64(u64(frame) + 8), frame)
        output["control_inputs"].append(
            dict(
                type=kind, plain=body.hex(), encrypted=encoded.hex(), sequence=sequence
            )
        )
        sequence += 1

    start_body = bytes.fromhex("080310042080012848")
    codec_hex = config.get("video_codec_data_hex")
    if codec_hex is not None:
        codec_bytes = bytes.fromhex(codec_hex)
        assert len(codec_bytes) < 128  # This fixture input, not a protocol limit.
        start_body += bytes([26, len(codec_bytes)]) + codec_bytes
        output["codec_data_input"] = codec_hex
    control(52, start_body)
    assert not decoder()  # Receive/FIFO must not eagerly execute the handler.
    call("void(*)(void*)", base + 0x3230A0, client)
    d = decoder()
    assert d and decoders == [d] and u32(client + 0x2D4) == 0xFFFFFFFF
    assert read(d + 100, 1) == b"\1" and read(d + 24, 1) == b"\1"
    ctx = u64(d + 0x268)
    assert ctx and u64(d + 0x270)
    output.update(
        codec_capabilities=u32(selected + 24),
        sdk_threads=u32(ctx + 0x290),
        sdk_thread_type=u32(ctx + 0x294),
        source_callback_installed=u64(ctx + 0xC0) == base + 0x324D00,
    )

    def submit(fid):
        carrier = cpp_alloc(0x928)
        call("void(*)(void*)", base + 0x198AA0, carrier)
        body = struct.pack("<HBHH", 0, 24, 0, 0) + fixture.read_bytes()[:2204]
        inf.write_memory(u64(carrier + 56) + 13, body)
        w32(carrier + 52, len(body) + 13)
        frame = cpp_alloc(0x38)
        call("void(*)(void*)", base + 0x1942F0, frame)
        inf.write_memory(frame + 8, struct.pack("<Q", carrier))
        inf.write_memory(frame + 26, struct.pack("<H", fid))
        w32(frame + 28, 1000000)
        call("void(*)(void*,void*)", base + 0x2ED830, decoder(), frame)
        call("void(*)(void*)", u64(u64(frame) + 8), frame)
        pause_until(pending, "original worker did not publish formats")
        trace.append(["pending_observed", "main"])

    def picture(fid):
        call("void(*)(void*)", base + 0x3230A0, client)
        assert not pending()
        pause_until(
            lambda: u32(player + 0xEC) != 0xFFFFFFFF, "original player queue empty"
        )
        slot = alloc(8)
        assert call("int(*)(void*,void*)", base + 0x2EF250, player + 0x40, slot) & 255
        frame = u64(slot)
        assert u32(frame + 40) & 0xFFFF == fid and u32(frame + 44) == 1000000
        af = u64(frame + 48)
        assert [u32(af + 104), u32(af + 108), u32(af + 116)] == [128, 72, 0]
        pixels = bytearray()
        for plane, width, height in ((0, 128, 72), (1, 64, 36), (2, 64, 36)):
            ptr, stride = u64(af + 8 * plane), u32(af + 64 + 4 * plane)
            assert ptr and width <= stride < 65536
            for row in range(height):
                pixels += read(ptr + row * stride, width)
        digest = hashlib.md5(pixels).hexdigest()
        assert digest == expected
        output["picture"] = dict(id=fid, timestamp=1000000, md5=digest)
        output.setdefault("pictures", []).append(output["picture"])
        # Full owner deletion has a separate external-frame lifetime contract.
        # Return this explicit external pop before control Stop deletes its pool.
        call("void(*)(void*)", base + 0x323FF0, frame)

    submit(23)
    if mode in ("decode", "reset_ready"):
        picture(23)
        if mode == "reset_ready":
            call("void(*)(void*,int)", base + 0x319360, client, 0)
            call("void(*)(void*)", base + 0x3230A0, client)
            assert decoder() == d and not pending()
            submit(24)
            picture(24)
    else:
        trace.append([mode, "main"])
        old = decoder()
        control(
            52 if mode == "replace_pending" else 53,
            start_body if mode == "replace_pending" else b"",
        )
        assert decoder() == old and pending()
        call("void(*)(void*)", base + 0x3230A0, client)
        assert not pending()
        if mode == "replace_pending":
            assert decoder() and len(decoders) == 2
            submit(24)
            picture(24)
        else:
            assert not decoder()
    output["cached_info_before_stop"] = (
        cstring(u64(client + 648)).decode() if u64(client + 648) else None
    )
    if decoder():
        control(53, b"")
        call("void(*)(void*)", base + 0x3230A0, client)
    assert not decoder() and read(client + 626, 1) == b"\0"
    output["thread_ids_after_stop"] = sorted(t.global_num for t in inf.threads())
    assert set(output["thread_ids_after_stop"]) <= before
    call("void(*)(void*)", base + 0x31AA60, client)
    assert u32(client + 256) == 0
    call("void(*)(void*,void*)", base + 0x317AB0, client, 0)
    assert not u64(client + 48)
    call("void(*)(void*)", u64(u64(player) + 8), player)
    call("void(*)(void*)", u64(u64(client) + 8), client)
    call("unsigned int(*)(void*)", base + 0x1A0C10, base + 0x13BD6A0)
    assert u32(base + 0x13BD6A0 + 0x88) == u32(base + 0x13BD6A0 + 0xA0) == 0
    output["thread_ids_after_resources"] = sorted(t.global_num for t in inf.threads())
    assert set(output["thread_ids_after_resources"]) <= before
    # Public shutdown joins before the original --version ELF TLS teardown.
    call("void(*)()", base + 0x1A0170)
    output["network_shutdown_before_main"] = True
    output["decoder_generations"] = len(decoders)
    output["cleanup_complete"] = True
    assert not output["assertions"], output["assertions"]
    for bp in breaks:
        bp.delete()
    return output
