#!/usr/bin/env python3
"""Execute official standalone video reset and resource retirement instructions.

Original player/standalone/Android-accel constructors, reset request/drain, real
virtual stop/flush/start, queue/frame/packet release and retained H264 buffers
execute. Whole Client::OnThink also executes its inline reset and order gates;
network/transport/control-drain/state/log endpoints are adapters. CPU/system,
JNI/SDK, allocator/string/atomic primitives and worker scheduling are explicit
adapters. New BCreateDecoder is either its real missing-JNI failure path or a
labelled initialization-result terminal; a true terminal is not a working codec.
Held frame slots are controlled, using real CAndroidFrame shape/constructor and
accessors; pixels/GPU/render ownership and Java semantics do not execute. No
Native reset/error mapping, real OS concurrency, Steam/FEC enable or device proof
is claimed. Source free records retirement without unmapping the emulated heap.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "events", ROOT / "scripts/audit-steam-decoder-events.py"
)
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)
c = d.c


class Reset(d.Decoder):
    def __init__(self, binary, scenario):
        self.trace, self.tracing = [], False
        self.backend_generation = 0
        self.late_request_done = False
        self.refs, self.labels, self.allocations = {}, {}, {}
        self.last_refs = {}
        super().__init__(binary, scenario)
        for address, name in self.plts.items():
            if name.startswith("SDL_Has"):
                self.callbacks[address] = lambda: self.ret(0)
            elif name == "SDL_GetCPUCount":
                self.callbacks[address] = lambda: self.ret(4)
        self.wi(c.CLIENT + 256, 0)
        self.wq(c.CLIENT + 40, 0)
        self.call(0x7676A8, self.player, c.CLIENT)
        self.wq(self.player, self.vt)
        # Flush/player queue internals use the original player implementation;
        # delivery isn't replaced with the decoder-event audit's recorder.
        self.wq(self.vt + 72, 0x767D9C)
        self.video = self.alloc(800)
        self.call(
            0x7B0E0C, self.video, c.CLIENT, self.player, scenario.get("video_codec", 4)
        )
        self.wq(c.CLIENT + 40, self.video)
        self.wi(self.video + 396, 1280)
        self.wi(self.video + 400, 720)
        self.b(self.video + 100, int(scenario.get("threads", True)))
        self.b(self.video + 24, 1)
        self.wi(c.CLIENT + 256, 6)
        self.callbacks[0xC0E5D0] = self.decoder_info
        # Actual frame destructors, not the control parser's borrowed-frame IO
        # adapter. Its body still treats libc storage/free as a platform boundary.
        self.callbacks.pop(0xC0E120, None)
        self.old = 0
        if scenario.get("old_backend", False):
            self.old = self.accel("old_backend")
            self.wq(self.video + 624, self.old)
            adc = self.old + 24
            self.old_codec = self.alloc(64)
            self.labels[self.old_codec] = "old_codec"
            self.wq(adc + 88, self.old_codec)
            self.wq(adc + 96, 0 if scenario.get("surface") else 1001)
            self.wq(adc + 104, 2001)
            if scenario.get("jni"):
                env, methods = self.alloc(8), self.alloc(1536)
                self.wq(env, methods)
                self.wq(methods + 176, c.STOP + 0x900)
                self.wq(adc, env)
                self.wq(adc + 8, 41)
                self.wq(adc + 24, 101)
                self.wq(adc + 56, 102)
                self.b(adc + 200, int(scenario.get("surface", False)))
                self.callbacks[c.STOP + 0x900] = self.delete_global_ref
        self.wq(c.CLIENT + 264, self.alloc(16))
        self.b(c.CLIENT + 16, 0)
        self.b(c.CLIENT + 18, int(scenario.get("threads", True)))
        self.b(c.CLIENT + 128692, 0)
        self.assertions.clear()

    def alloc(self, size):
        pointer = super().alloc(size)
        self.allocations[pointer] = size
        return pointer

    def event(self, name, *values):
        if self.tracing:
            self.trace.append([name, *values])

    def accel(self, label):
        obj = self.alloc(392)
        self.labels[obj] = label
        self.call(
            0x906488, obj, c.CLIENT, 1280, 720, self.scenario.get("video_codec", 4)
        )
        return obj

    def delete_global_ref(self):
        assert self.r(1) == 41
        self.event("delete_global_ref")
        self.ret()

    def decoder_info(self):
        self.event("decoder_info", self.cstring(self.r(1)), self.r(2))
        self.ret()

    def hook(self, u, address, size, data):
        named = {
            0x7671E4: "reset",
            0x76743C: "input_queue_purge",
            0x7B103C: "standalone_stop",
            0x7681EC: "player_flush",
            0x7B2A68: "pending_flush",
            0x7B0E70: "standalone_start",
            0x906488: "accel_ctor",
            0x9064AC: "accel_dtor",
            0x906F38: "accel_flush",
            0x906FC8: "accel_quit",
            0x9074A4: "android_destroy",
            0x907550: "create_decoder",
        }
        if address == 0x906488 and self.tracing:
            self.backend_generation += 1
            self.labels[self.r(0)] = f"new_backend_{self.backend_generation}"
        if address in named:
            self.event(named[address])
        name = self.plts.get(address, "")
        if name in (
            "_Z20StreamProcessNetworkv",
            "_ZN22CStreamTransportClient6UpdateEv",
            "_ZN13CStreamClient21HandleIncomingPacketsEv",
            "_ZN13CStreamClient15HandleStreamingEv",
            "_ZN13CStreamClient22SendPendingLogMessagesEv",
        ):
            label = {
                "_Z20StreamProcessNetworkv": "network",
                "_ZN22CStreamTransportClient6UpdateEv": "transport_update",
                "_ZN13CStreamClient21HandleIncomingPacketsEv": "control_drain",
                "_ZN13CStreamClient15HandleStreamingEv": "streaming",
                "_ZN13CStreamClient22SendPendingLogMessagesEv": "log_drain",
            }[name]
            self.event(label)
            if (
                label == "control_drain"
                and self.scenario.get("late_request")
                and not self.late_request_done
            ):
                self.late_request_done = True
                # Controlled input at the declared drain terminal; tail-call
                # original request function, preserving the caller stack/LR.
                self.u.reg_write(c.X0, c.CLIENT)
                self.u.reg_write(c.X0 + 1, 0)
                self.jump(0x7AD394)
            else:
                self.ret()
        elif name == "__system_property_get":
            key = self.cstring(self.r(0))
            value = self.manufacturer if key == "ro.product.manufacturer" else ""
            self.u.mem_write(self.r(1), value.encode() + b"\0")
            self.ret(len(value))
        elif name == "__strncpy_chk2":
            dest, src, count, capacity, source_capacity = [self.r(i) for i in range(5)]
            assert count <= capacity
            value = self.cstring(src).encode()
            assert min(len(value) + 1, count) <= source_capacity
            self.u.mem_write(dest, (value[:count] + bytes(count))[:count])
            self.ret(dest)
        elif name == "vasprintf":
            dest, fmt, args = self.r(0), self.r(1), self.r(2)
            pattern = self.cstring(fmt)
            assert (
                pattern.count("%s") == 1 and pattern.replace("%s", "").count("%") == 0
            )
            offset = struct.unpack("<i", self.u.mem_read(args + 24, 4))[0]
            location = self.q(args + 8) + offset if offset < 0 else self.q(args)
            text = (pattern % self.cstring(self.q(location))).encode()
            storage = self.alloc(len(text) + 1)
            self.u.mem_write(storage, text + b"\0")
            self.wq(dest, storage)
            self.ret(len(text))
        elif name == "realloc":
            old, count = self.r(0), self.r(1)
            assert count > 0 and (not old or old in self.allocations)
            memory = self.alloc(count)
            if old:
                size = min(count, self.allocations[old])
                self.u.mem_write(memory, bytes(self.u.mem_read(old, size)))
            self.ret(memory)
        elif (
            name == "_ZN20CAndroidVideoDecoder14BCreateDecoderEii17EStreamVideoCodec"
            and "init_success" in self.scenario
        ):
            self.event("init_terminal", bool(self.scenario["init_success"]))
            self.ret(int(self.scenario["init_success"]))
        elif name == "_ZN7_JNIEnv14CallVoidMethodEP8_jobjectP10_jmethodIDz":
            assert self.r(1) == 41 and self.r(2) in (101, 102)
            self.event("jni_close", "surface" if self.r(2) == 101 else "texture")
            self.ret()
        elif name == "AMediaCodec_flush":
            self.event("codec_flush", self.labels.get(self.r(0), "unknown"))
            self.ret(self.scenario.get("flush_result", 0) & 0xFFFFFFFF)
        elif name == "AMediaCodec_delete":
            self.event("codec_delete", self.labels.get(self.r(0), "unknown"))
            self.ret(self.scenario.get("delete_result", 0) & 0xFFFFFFFF)
        elif name == "ANativeWindow_release":
            self.event("window_release", self.r(0))
            self.ret()
        elif name == "SDL_DestroyTexture":
            self.event("texture_destroy", self.r(0))
            self.ret()
        elif name in ("ThreadInterlockedIncrement", "ThreadInterlockedDecrement"):
            ptr = self.r(0)
            value = (self.i(ptr) + (1 if "Increment" in name else -1)) & 0xFFFFFFFF
            self.wi(ptr, value)
            self.last_refs[ptr] = value
            self.ret(value)
        elif name == "_ZN16SteamThreadTools7CThread4JoinEj":
            self.event("join", self.r(1) & 0xFFFFFFFF)
            super().hook(u, address, size, data)
        elif name == "_ZN16SteamThreadTools7CThread5StartEm":
            self.event("thread_start")
            super().hook(u, address, size, data)
        elif (
            name
            == "_ZN13CStreamClient12SendDataLostE18EStreamingDataTypeRK10CUtlVectorIt10CUtlMemoryItEE"
        ):
            self.event("data_lost", self.r(1))
            super().hook(u, address, size, data)
        elif name in ("free", "_ZdlPv"):
            ptr = self.r(0)
            if ptr in self.labels:
                self.event("free", self.labels[ptr])
            super().hook(u, address, size, data)
        else:
            super().hook(u, address, size, data)

    def partial(self, sequence, fid):
        body = b"\x01" + struct.pack("<HIHI", fid, 1000000, 0, 0)
        body += (
            struct.pack(
                "<HBHH", sequence, 2 if self.scenario.get("escape") else 0, 0, 0
            )
            + b"partial-packet"
        )
        packet = self.packet(5, 3, False, 12, 34, len(body))
        self.labels[packet] = f"partial_packet_{fid}_{sequence}"
        self.u.mem_write(self.q(packet + 40) + 13, body)
        frame = self.alloc(64)
        self.call(self.symbols["_ZN12CStreamFrameC1EP13CStreamPacket"], frame, packet)
        self.call(0x7B2000, self.video, frame)
        self.call(self.symbols["_ZN12CStreamFrameD1Ev"], frame)
        self.refs[f"partial_packet_{fid}_{sequence}"] = packet

    def queue_input(self, fid):
        body = b"\x01" + struct.pack("<HIHI", fid, 1000000, 0, 0)
        body += struct.pack("<HBHH", fid, 0, 0, 0) + b"stream-queue"
        packet = self.packet(5, 3, False, 12, 34, len(body))
        self.labels[packet] = f"input_packet_{fid}"
        self.u.mem_write(self.q(packet + 40) + 13, body)
        frame = self.alloc(64)
        self.call(self.symbols["_ZN12CStreamFrameC1EP13CStreamPacket"], frame, packet)
        self.call(0x76727C, self.video, frame)
        self.call(self.symbols["_ZN12CStreamFrameD1Ev"], frame)
        self.refs[f"input_packet_{fid}"] = packet

    def picture(self, fid):
        obj = self.alloc(48)
        self.labels[obj] = f"picture_{fid}"
        self.call(0x767650, obj, self.old)
        self.wq(obj, self.symbols["_ZTV13CAndroidFrame"] + 16)
        self.wq(obj + 40, 0)
        self.call(0x76769C, obj, fid, 1000000)
        self.call(
            self.symbols["_ZN11IVideoFrame9SetFormatE12EVideoFormatjj"],
            obj,
            2,
            1280,
            720,
        )
        return obj

    def queue_picture(self, fid):
        self.call(0x767D9C, self.player, self.picture(fid))

    def queue_ids(self, head, tail, mask, storage, offset):
        if head == 0xFFFFFFFF:
            return []
        assert tail >= head and tail - head < 128
        return [
            struct.unpack(
                "<H", self.u.mem_read(self.q(storage + ((n & mask) * 8)) + offset, 2)
            )[0]
            for n in range(head, tail + 1)
        ]

    def snapshot(self):
        input_head, input_tail = self.i(self.video + 364), self.i(self.video + 368)
        player_head, player_tail = self.i(self.player + 244), self.i(self.player + 248)
        size = self.i(self.video + 500)
        assert size < 2 * 1024 * 1024
        return dict(
            active=self.u.mem_read(self.video + 24, 1)[0],
            request=self.i(self.video + 96),
            strict=self.u.mem_read(self.video + 404, 1)[0],
            soft=self.u.mem_read(self.video + 405, 1)[0],
            last_request=self.i(self.video + 408),
            backend=self.labels.get(self.q(self.video + 624), "unknown")
            if self.q(self.video + 624)
            else None,
            input_queue=dict(
                head=input_head,
                tail=input_tail,
                ids=self.queue_ids(
                    input_head,
                    input_tail,
                    self.i(self.video + 360),
                    self.q(self.video + 376),
                    26,
                ),
            ),
            player_queue=dict(
                head=player_head,
                tail=player_tail,
                ids=self.queue_ids(
                    player_head,
                    player_tail,
                    self.i(self.player + 240),
                    self.q(self.player + 256),
                    28,
                ),
            ),
            held=[
                struct.unpack("<H", self.u.mem_read(self.q(self.player + off) + 28, 2))[
                    0
                ]
                if self.q(self.player + off)
                else None
                for off in (272, 280, 288)
            ],
            refs={name: self.last_refs[ptr] for name, ptr in self.refs.items()},
            pending=[self.i(self.video + off) for off in (440, 444, 448, 452, 456)],
            encoded=bytes(self.u.mem_read(self.q(self.video + 480), size)).hex()
            if size
            else "",
            packet_buffers=self.i(self.video + 560),
            buffer_fields=[self.i(self.video + off) for off in (584, 592, 596, 600)],
            trace=list(self.trace),
            assertions=list(self.assertions),
        )


def run_case(binary, inp):
    r = Reset(binary, inp)
    r.thread_ok = inp.get("thread_start_ok", True)
    if inp.get("partial", "none") != "none":
        r.partial(0, 30)
        r.partial(1, 30)
        if inp["partial"] != "linked":
            r.call(0x7B24DC, r.video)
    for n in range(inp.get("inputs", 0)):
        r.queue_input(n + 1)
    for n in range(inp.get("pictures", 0)):
        r.queue_picture(n + 10)
    for off, fid in list(zip((272, 280, 288), (20, 21, 22)))[: inp.get("held", 0)]:
        r.wq(r.player + off, r.picture(fid))
    r.trace.clear()
    r.effects.clear()
    r.tracing = True
    stages = [r.snapshot()]
    for _ in range(inp.get("requests", 1)):
        r.call(0x7AD394, c.CLIENT, int(inp.get("synchronous", False)))
    stages.append(r.snapshot())
    drain = 0x7A5FF8 if inp.get("main") else 0x7A6198
    r.call(drain, c.CLIENT)
    stages.append(r.snapshot())
    r.call(drain, c.CLIENT)
    stages.append(r.snapshot())
    if not inp.get("late_request"):
        left, right = (dict(x) for x in stages[2:4])
        left.pop("trace")
        right.pop("trace")
        assert left == right, (inp, "repeat drain changed state")
    r.call(0x767160, r.video)
    stages.append(r.snapshot())
    assert not r.assertions, (inp, r.assertions)
    assert stages[0]["input_queue"]["ids"] == list(range(1, inp.get("inputs", 0) + 1))
    assert stages[0]["player_queue"]["ids"] == list(
        range(10, 10 + inp.get("pictures", 0))
    )
    assert not stages[4]["input_queue"]["ids"] and not stages[4]["player_queue"]["ids"]
    assert stages[4]["held"] == [None, None, None] and not stages[4]["encoded"]
    assert not stages[4]["backend"] and stages[4]["active"] == 0
    assert all(value == 0 for value in stages[4]["refs"].values())
    if inp.get("requests", 1) or inp.get("late_request"):
        final = stages[3]
        assert final["request"] == 0 and final["active"] == 1 and final["strict"] == 1
        assert not final["input_queue"]["ids"] and not final["player_queue"]["ids"]
        assert final["held"] == [None, None, None] and not final["encoded"]
        assert final["packet_buffers"] == 0
        assert all(value == 0 for value in final["refs"].values())
        assert bool(final["backend"]) == bool(inp.get("init_success", False))
        assert ["data_lost", 1] in final["trace"]
    return dict(input=inp, states=stages)


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == c.SHA
    cases = []
    for threads in (False, True):
        for old in (False, True):
            for init in (None, False, True):
                for state in ("empty", "linked", "refs", "copy", "all"):
                    inp = dict(
                        threads=threads,
                        old_backend=old,
                        partial=("linked" if state == "all" else state)
                        if state != "empty"
                        else "none",
                    )
                    inp["escape"] = state == "copy"
                    if init is not None:
                        inp["init_success"] = init
                    if state == "all":
                        inp.update(
                            inputs=2 if threads else 0,
                            pictures=2 if old else 0,
                            held=3 if old else 0,
                        )
                    cases.append(run_case(binary, inp))
    for threads in (False, True):
        for sync in (False, True):
            for count in (0, 1, 2):
                inp = dict(
                    threads=threads,
                    old_backend=True,
                    init_success=True,
                    inputs=3 if threads else 0,
                    pictures=3,
                    held=3,
                    partial="copy",
                    escape=True,
                    synchronous=sync,
                    requests=count,
                )
                cases.append(run_case(binary, inp))
    for option in ("thread_start_ok", "flush_result", "delete_result"):
        inp = dict(
            threads=True,
            old_backend=True,
            init_success=True,
            inputs=2,
            pictures=2,
            held=3,
            partial="refs",
        )
        inp[option] = False if option == "thread_start_ok" else -10000
        cases.append(run_case(binary, inp))
    for threads in (False, True):
        for late in (False, True):
            for init in (False, True):
                cases.append(
                    run_case(
                        binary,
                        dict(
                            threads=threads,
                            old_backend=True,
                            main=True,
                            late_request=late,
                            requests=0 if late else 1,
                            init_success=init,
                            inputs=2 if threads else 0,
                            pictures=2,
                            held=3,
                            partial="copy",
                            escape=True,
                        ),
                    )
                )
    for surface in (False, True):
        for threads in (False, True):
            for init in (False, True):
                cases.append(
                    run_case(
                        binary,
                        dict(
                            surface=surface,
                            jni=True,
                            threads=threads,
                            old_backend=True,
                            init_success=init,
                            inputs=2 if threads else 0,
                            pictures=2,
                            held=3,
                            partial="linked",
                        ),
                    )
                )
    spec = importlib.util.spec_from_file_location(
        "entries", ROOT / "scripts/audit-steam-client-fec-entry.py"
    )
    entries = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(entries)
    entries.TARGETS = (
        "_ZN13CStreamClient17ResetVideoDecoderEb",
        "_ZN13CStreamClient19HandlePendingResetsEv",
        "_ZN13CStreamClient7OnThinkEv",
    )
    r = Reset(binary, {})
    vtables = {
        name: {
            str(off): hex(r.q(r.symbols[name] + 16 + off))
            for off in (24, 32, 64, 80, 120)
        }
        for name in ("_ZTV19CStreamDecoderVideo", "_ZTV28CStreamDecoderH264Standalone")
    }
    anchors = {
        hex(pc): bytes(r.u.mem_read(pc, 4)).hex()
        for pc in (
            0x7AD3B8,
            0x7AD3CC,
            0x7A6058,
            0x7A6070,
            0x7A6084,
            0x7A609C,
            0x7A60C0,
            0x7A60C8,
            0x7A60D0,
            0x767210,
            0x767218,
            0x7B1074,
        )
    }
    return dict(
        binary_sha256=c.SHA,
        boundary=__doc__,
        cases=cases,
        static=entries.static(binary),
        vtables=vtables,
        anchors=anchors,
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--write", type=Path)
    p.add_argument("--check", type=Path)
    args = p.parse_args()
    result = audit(args.binary.read_bytes())
    if args.write:
        args.write.write_text(json.dumps(result, indent=2) + "\n")
    if args.check:
        assert result == json.loads(args.check.read_text())
    print(
        f"Official standalone reset: {len(result['cases'])} cases, {sum(len(x['states']) for x in result['cases'])} lifecycle states"
    )


if __name__ == "__main__":
    main()
