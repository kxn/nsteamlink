#!/usr/bin/env python3
"""Execute official Android decoder failure producers and player event consumption.

Pinned BUpdateDecoder + real low-latency helper, BUpdateParams, and FinalDecode ->
CAndroidAccel::BDecodeFrame -> BSubmitFrame execute. SDK returns, manufacturer,
JNI initialization, NAL scanning/parameter parser results, stream data storage,
OS signals/locks, frame IO/statistics, Disconnect/DataLost and file/network IO are
explicit adapters. Notify functions, event dispatch, ReduceVideoResolution and
real C++ config copy/mutation/setter/protobuf serialization execute. Events are
consumed only at explicit action boundaries, not a real SDL/UI/thread schedule.
No real MediaCodec decode, all factory/Java reachability, FFmpeg error mapping,
Native reset/geometry transitions, Steam/FEC activation or device proof is claimed.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "owner", ROOT / "scripts/audit-steam-player-owner.py"
)
o = importlib.util.module_from_spec(spec)
spec.loader.exec_module(o)
c = o.c


class Decoder(o.Owner):
    def __init__(self, binary, scenario):
        self.scenario = scenario
        self.sdk, self.queued, self.effects = [], [], []
        self.configure_results = list(scenario.get("configure", [0]))
        self.nal_calls = 0
        self.sdk_version = scenario.get("sdk", 30)
        self.manufacturer = scenario.get("manufacturer", "Generic")
        super().__init__(binary)
        # Imported NDK data variables are char* objects supplied by the dynamic
        # loader, not bytes in this ELF. Symbolic labels keep this SDK boundary
        # explicit; only direct SDK setter arguments consume the labels.
        for got, label in (
            (0xC81008, "AMEDIAFORMAT_KEY_MIME"),
            (0xC80FF8, "AMEDIAFORMAT_KEY_WIDTH"),
            (0xC81000, "AMEDIAFORMAT_KEY_HEIGHT"),
        ):
            pointer = self.alloc(8)
            value = self.alloc(len(label) + 1)
            self.u.mem_write(value, label.encode() + b"\0")
            self.wq(pointer, value)
            self.wq(got, pointer)
        self.decoder = self.alloc(512)
        self.callbacks[0xC15C70] = lambda: self.ret(1)  # JNI initialization terminal.
        self.call(0x906FD4, self.decoder, c.CLIENT)
        self.b(self.decoder + 202, int(scenario.get("low_latency", False)))
        self.wi(self.decoder + 176, scenario.get("codec", 4))
        self.wq(self.decoder + 104, 1234)
        self.codec = self.alloc(64)
        self.wq(self.decoder + 88, self.codec)
        self.wq(self.decoder + 184, 5678)
        self.input = self.alloc(4096)
        self.last_width, self.last_height = self.q(0xC80FE8), self.q(0xC80FF0)
        self.size(*scenario.get("size", [1920, 1080]))
        self.b(self.hard, int(scenario.get("hard", False)))
        self.b(self.background, 0)
        self.vdecoder = self.alloc(800)
        self.wq(self.vdecoder + 8, c.CLIENT)
        self.wq(self.vdecoder + 16, self.player)
        self.wq(c.CLIENT + 40, self.vdecoder)
        self.wq(c.CLIENT + 32, 0)
        self.wi(self.vdecoder + 396, scenario.get("size", [1920, 1080])[0])
        self.wi(self.vdecoder + 400, scenario.get("size", [1920, 1080])[1])
        self.wi(self.player + 1336, scenario.get("size", [1920, 1080])[0])
        self.wi(self.player + 1340, scenario.get("size", [1920, 1080])[1])
        self.b(self.player + 1785, 1)
        self.wq(self.vt + 128, c.STOP + 0x810)
        self.wq(self.vt + 72, c.STOP + 0x814)
        self.callbacks.update(
            {
                c.STOP + 0x810: self.config_notify,
                c.STOP + 0x814: self.put_frame,
                0xC0E110: self.config_send,
                0xC0A7A0: self.config_save,
                0xC0E090: self.data_lost,
                0xC0BAA0: self.frame_complete,
            }
        )
        if scenario.get("config") is not None:
            assert self.parse(c.INPUT, bytes.fromhex(scenario["config"]))
            self.call(
                self.symbols["_ZN22CStreamingClientConfig8CopyFromERKS_"],
                c.CLIENT + 456,
                c.INPUT,
            )
        self.wi(c.CLIENT + 256, scenario.get("phase", 6))
        self.actions.clear()
        self.assertions.clear()

    def size(self, width, height):
        self.wi(self.last_width, width)
        self.wi(self.last_height, height)

    def config_notify(self):
        self.actions.append(
            {"notify": self.freeze(self.r(1)), "local_only": bool(self.r(2))}
        )
        self.effects.append(["config_notify", bool(self.r(2))])
        self.ret()

    def config_save(self):
        self.actions.append({"save": self.freeze(c.CLIENT + 456)})
        self.effects.append(["config_save"])
        self.ret()

    def config_send(self):
        assert self.r(1) == 99
        self.actions.append({"send": self.freeze(self.r(2), 40)})
        self.effects.append(["config_send", 99])
        self.ret()

    def data_lost(self):
        assert self.r(0) == c.CLIENT and self.i(self.r(2) + 16) == 0
        self.effects.append(["data_lost", self.r(1)])
        self.ret()

    def frame_complete(self):
        self.effects.append(["frame_complete", self.r(1), self.r(2), self.r(3)])
        self.ret()

    def put_frame(self):
        f = self.r(1)
        self.effects.append(["put_frame", self.i(f + 20), self.i(f + 24)])
        self.ret()

    def hook(self, uc, address, size, data):
        name = self.plts.get(address, "")
        if name == "AMediaCodec_stop":
            self.sdk.append(["stop"])
            self.ret(self.scenario.get("stop", 0) & 0xFFFFFFFF)
        elif name == "AMediaFormat_new":
            self.sdk.append(["format_new"])
            self.ret(0 if self.scenario.get("format_fail") else self.alloc(128))
        elif name == "AMediaFormat_setString":
            self.sdk.append(
                ["setString", self.cstring(self.r(1)), self.cstring(self.r(2))]
            )
            self.ret()
        elif name == "AMediaFormat_setInt32":
            self.sdk.append(
                ["setInt32", self.cstring(self.r(1)), self.r(2) & 0xFFFFFFFF]
            )
            self.ret()
        elif name == "AMediaFormat_delete":
            self.sdk.append(["format_delete"])
            self.ret()
        elif name == "AMediaCodec_configure":
            assert self.configure_results
            result = self.configure_results.pop(0)
            self.sdk.append(["configure", result])
            self.ret(result & 0xFFFFFFFF)
        elif name == "AMediaCodec_start":
            self.sdk.append(["start"])
            self.ret(self.scenario.get("start", 0) & 0xFFFFFFFF)
        elif name == "SDL_GetAndroidSDKVersion":
            self.ret(self.sdk_version)
        elif name == "__system_property_get":
            key = self.cstring(self.r(0))
            assert key == "ro.product.manufacturer"
            self.sdk.append(["property", key, self.manufacturer])
            self.u.mem_write(self.r(1), self.manufacturer.encode() + b"\0")
            self.ret(len(self.manufacturer))
        elif name == "__cxa_guard_acquire":
            self.ret(1)
        elif name == "__cxa_guard_release":
            self.b(self.r(0), 1)
            self.ret()
        elif name == "__cxa_atexit":
            self.ret()
        elif name == "_ZN10CUtlString8SetValueEPKc":
            value = self.cstring(self.r(1)).encode() + b"\0"
            memory = self.alloc(len(value))
            self.u.mem_write(memory, value)
            self.wq(self.r(0), memory)
            self.ret()
        elif "basic_string" in name and "aSERKS" in name:
            source, dest = self.r(1), self.r(0)
            tag = self.u.mem_read(source, 1)[0]
            length = self.q(source + 8) if tag & 1 else tag >> 1
            pointer = self.q(source + 16) if tag & 1 else source + 1
            value = bytes(self.u.mem_read(pointer, length)) if length else b""
            storage = self.alloc(length + 1)
            self.u.mem_write(storage, value + b"\0")
            self.wq(dest, (length + 1) | 1)
            self.wq(dest + 8, length)
            self.wq(dest + 16, storage)
            self.ret(dest)
        elif name == "strcmp":
            left, right = self.cstring(self.r(0)), self.cstring(self.r(1))
            self.ret(((left > right) - (left < right)) & 0xFFFFFFFF)
        elif name == "__android_log_print":
            self.sdk.append(["log"])
            self.ret()
        elif name == "SDL_PushEvent":
            self.queued.append(
                {"type": self.i(self.r(0)), "code": self.i(self.r(0) + 20)}
            )
            self.ret(int(self.scenario.get("deliver_events", True)))
        elif name == "AMediaCodec_dequeueInputBuffer":
            self.sdk.append(["dequeue", self.r(1)])
            self.ret(self.scenario.get("dequeue", 2) & 0xFFFFFFFFFFFFFFFF)
        elif name == "AMediaCodec_getInputBuffer":
            self.sdk.append(["getInputBuffer", self.r(1)])
            self.wq(self.r(2), self.scenario.get("capacity", 4096))
            self.ret(0 if self.scenario.get("null_buffer") else self.input)
        elif name == "AMediaCodec_queueInputBuffer":
            self.sdk.append(["queueInputBuffer", *[self.r(i) for i in range(1, 6)]])
            self.ret(self.scenario.get("queue", 0) & 0xFFFFFFFF)
        elif name == "_Z22BShouldUseVideoSurfacev":
            self.ret(int(self.scenario.get("surface", False)))
        elif name == "find_nal_unit":
            # Controlled NAL metadata only. The original PPS parameter assembly
            # and BUpdateParams execute; no parser/reference analysis is claimed.
            self.nal_calls += 1
            if self.scenario.get("pps") and self.nal_calls == 1:
                assert self.r(1) == 8
                assert bytes(self.u.mem_read(self.r(0), 8)) == bytes.fromhex(
                    "0000000168ce06e2"
                )
                self.wi(self.r(2), 4)
                self.wi(self.r(3), 8)
                self.ret(1)
            else:
                self.ret(0)
        elif name == "_ZN13CStreamClient10DisconnectEv":
            assert self.u.mem_read(self.hard, 1)[0] == 1
            self.effects.append(["disconnect"])
            self.ret()
        else:
            super().hook(uc, address, size, data)

    def consume(self):
        for event in self.queued:
            if not self.scenario.get("deliver_events", True):
                continue
            storage = self.alloc(128)
            self.wi(storage, event["type"])
            self.wi(storage + 20, event["code"])
            self.call(0x7B8110, self.player, storage)

    def update(self):
        return self.call(
            0x9079A0,
            self.decoder,
            self.codec,
            *self.scenario.get("requested", [1920, 1080]),
        )

    def params(self):
        params = self.alloc(64)
        body = bytes.fromhex(self.scenario.get("payload", "11223344"))
        memory = self.alloc(len(body) + 16)
        if body:
            self.u.mem_write(memory, body)
        self.wq(params, memory)
        self.wi(params + 20, len(body))
        return self.call(0x907E80, self.decoder, params)

    def notify_reset(self):
        self.call(0x7C9D44)
        return None

    def submit(self):
        # Full FinalDecode -> actual Android accel -> actual BSubmitFrame.
        accel = self.alloc(24 + 512)
        vt, buffers, bvt = (self.alloc(512) for _ in range(3))
        self.u.mem_write(accel + 24, bytes(self.u.mem_read(self.decoder, 512)))
        self.decoder = accel + 24
        self.wq(accel, vt)
        self.wq(vt + 48, 0x906570)
        self.wq(self.vdecoder + 624, 0 if self.scenario.get("no_backend") else accel)
        self.wq(buffers, bvt)
        self.wq(bvt + 24, c.STOP + 0x820)
        self.wq(bvt + 16, c.STOP + 0x824)
        self.callbacks[c.STOP + 0x820] = lambda: self.ret(1)
        body = bytes.fromhex(self.scenario.get("payload", "11223344"))
        storage = self.alloc(len(body) + 16)
        if body:
            self.u.mem_write(storage, body)

        def get_data():
            assert self.r(1) == 0
            self.wi(self.r(2), len(body))
            self.ret(storage)

        self.callbacks[c.STOP + 0x824] = get_data
        if self.scenario.get("surface_changed"):
            self.wq(0xF4D380, 2345)
        if self.scenario.get("stopped"):
            self.b(0xF4D388, 1)
        self.call(0x7B1088, self.vdecoder, 10, 1000000, buffers)
        return None  # FinalDecode returns void.

    def snapshot(self):
        return dict(
            size=[self.i(self.last_width), self.i(self.last_height)],
            copied_timestamp=self.q(self.decoder + 192),
            cached_params=self.i(self.decoder + 132),
            pending_reset=self.i(self.vdecoder + 96),
            hard=bool(self.u.mem_read(self.hard, 1)[0]),
            queued=list(self.queued),
            effects=list(self.effects),
            sdk=list(self.sdk),
            assertions=list(self.assertions),
            configuration=c.Core.result(self),
        )


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == c.SHA
    cases = []
    scenarios = [
        ("update", "success", {}),
        ("update", "stop_fail", {"stop": -1}),
        ("update", "format_fail", {"format_fail": True}),
        ("update", "configure_fail", {"configure": [-1] * 8}),
        ("update", "configure_retry_success", {"configure": [-1, 0]}),
        ("update", "start_fail", {"start": -1}),
        ("params", "success", {}),
        ("params", "negative_index", {"dequeue": -1}),
        ("params", "null_buffer", {"null_buffer": True}),
        ("params", "undersized", {"capacity": 2}),
        ("params", "queue_fail", {"queue": -10000}),
        ("submit", "success", {}),
        ("submit", "negative_index", {"dequeue": -1}),
        ("submit", "null_buffer", {"null_buffer": True}),
        ("submit", "undersized", {"capacity": 2}),
        ("submit", "queue_fail", {"queue": -10000}),
        ("submit", "surface_changed", {"surface": True, "surface_changed": True}),
        ("submit", "stopped", {"stopped": True}),
        ("submit", "no_backend", {"no_backend": True}),
        ("notify_reset", "explicit_reset_notification", {}),
        (
            "update",
            "configure_fails_before_connected",
            {"phase": 5, "configure": [-1] * 8},
        ),
        ("update", "start_fails_already_hard", {"hard": True, "start": -1}),
    ]
    schema = o.audio.schema(binary)
    rich = schema(
        "CStreamingClientConfig",
        enable_unreliable_fec=True,
        controller_overlay_hotkey="keep-decoder-event",
        decoder_limit=[{"codec": 1, "mode": {"width": 1920, "height": 1080}}],
    )
    rich_wire = rich.SerializeToString() + b"\xb0\x09\x07"
    for suffix, inputs in (
        ("success", {}),
        ("negative_index", {"dequeue": -1}),
        ("null_buffer", {"null_buffer": True}),
        ("undersized", {"capacity": 2}),
        ("queue_fail", {"queue": -10000}),
    ):
        scenarios.append(
            (
                "submit",
                "pps_" + suffix,
                dict(inputs, pps=True, payload="0000000168ce06e2"),
            )
        )
    for enabled in (False, True):
        for sdk in (23, 24, 25, 26, 27, 28, 29, 30, 35):
            for manufacturer in ("Generic", "Oculus", "Pico", "xiaomi", "Xiaomi"):
                scenarios.append(
                    (
                        "update",
                        f"retry_{int(enabled)}_{sdk}_{manufacturer}",
                        dict(
                            low_latency=enabled,
                            sdk=sdk,
                            manufacturer=manufacturer,
                            configure=[-1] * 8,
                        ),
                    )
                )
    for size in (
        [3840, 2160],
        [1920, 1081],
        [1920, 1080],
        [1280, 721],
        [1280, 720],
        [640, 480],
        [2560, 360],
    ):
        for previous in ([0, 0], [1280, 720], [1920, 1080]):
            for hard in (False, True):
                for fec in (None, False, True):
                    config = schema("CStreamingClientConfig")
                    config.ParseFromString(rich_wire)
                    (
                        config.runtime_limit.mode.width,
                        config.runtime_limit.mode.height,
                    ) = previous
                    if fec is None:
                        config.ClearField("enable_unreliable_fec")
                    else:
                        config.enable_unreliable_fec = fec
                    scenarios.append(
                        (
                            "update",
                            f"reduce_{size}_{previous}_{int(hard)}_{fec}",
                            dict(
                                size=size,
                                config=config.SerializeToString().hex(),
                                hard=hard,
                                configure=[-1] * 8,
                            ),
                        )
                    )
    for stage, name, scenario in list(scenarios[:19]):
        if name in ("start_fail", "null_buffer", "configure_fail"):
            scenarios.append(
                (stage, name + "_undelivered", dict(scenario, deliver_events=False))
            )
    for stage, name, scenario in scenarios:
        r = Decoder(binary, scenario)
        before = r.snapshot()
        try:
            value = getattr(r, stage)()
            produced = r.snapshot()
            r.consume()
        except Exception as error:
            raise AssertionError((stage, name, r.snapshot())) from error
        after = r.snapshot()
        assert not r.assertions, (stage, name, r.assertions)
        assert all(v[1] == 250000 for v in produced["sdk"] if v[0] == "dequeue")
        if "config" in scenario:
            previous = schema("CStreamingClientConfig")
            updated = schema("CStreamingClientConfig")
            previous.ParseFromString(bytes.fromhex(scenario["config"]))
            updated.ParseFromString(bytes.fromhex(after["configuration"]["config"]))
            previous.ClearField("runtime_limit")
            updated.ClearField("runtime_limit")
            assert previous.SerializeToString() == updated.SerializeToString(), name
        cases.append(
            dict(
                stage=stage,
                name=name,
                input=scenario,
                result=value,
                before=before,
                produced=produced,
                after=after,
            )
        )
    static_spec = importlib.util.spec_from_file_location(
        "entries", ROOT / "scripts/audit-steam-client-fec-entry.py"
    )
    entries = importlib.util.module_from_spec(static_spec)
    static_spec.loader.exec_module(entries)
    entries.TARGETS = (
        "_Z23NotifyFatalDecoderErrorv",
        "_Z22NotifyResetVideoStreamv",
        "_Z22NotifyReduceResolutionv",
        "_ZN13CStreamPlayer16TerminateSessionEv",
        "_ZN13CStreamPlayer21ReduceVideoResolutionEv",
        "_ZN20CAndroidVideoDecoder12BSubmitFrameEP18IStreamDataBuffersP13CAndroidFrame",
        "_ZN20CAndroidVideoDecoder14BUpdateDecoderEP11AMediaCodecii",
        "_ZN20CAndroidVideoDecoder13BUpdateParamsER10CUtlBuffer",
        "_ZN20CAndroidVideoDecoder21BGetLowLatencyOptionsEP11AMediaCodecP12AMediaFormati",
        "_ZN13CStreamClient17ResetVideoDecoderEb",
    )
    # Direct-call/relocation provenance is bounded; no absence-of-indirect-call
    # claim follows. Record real bytes for constants and Java producer anchors.
    r = Decoder(binary, {})
    anchors = {
        hex(pc): bytes(r.u.mem_read(pc, 4)).hex()
        for pc in (
            0x9069E0,
            0x9069E4,
            0x9069E8,
            0x907EC4,
            0x907EC8,
            0x907ECC,
            0x9075CC,
            0x907700,
            0x907704,
            0x907710,
            0x907240,
            0x907250,
            0x907258,
        )
    }
    elf = entries.ELFFile(entries.io.BytesIO(binary))
    symbols = list(elf.get_section_by_name(".dynsym").iter_symbols())
    binding = {
        hex(rel["r_offset"]): symbols[rel["r_info_sym"]].name
        for rel in elf.get_section_by_name(".rela.dyn").iter_relocations()
        if rel["r_offset"] in (0xC81008, 0xC80FF8, 0xC81000)
    }
    assert binding == {
        "0xc81008": "AMEDIAFORMAT_KEY_MIME",
        "0xc80ff8": "AMEDIAFORMAT_KEY_WIDTH",
        "0xc81000": "AMEDIAFORMAT_KEY_HEIGHT",
    }
    return dict(
        binary_sha256=c.SHA,
        boundary=__doc__,
        cases=cases,
        static=entries.static(binary),
        imported_ndk_keys=binding,
        anchors=anchors,
        java_flag_binding={
            "method": r.cstring(0x39F987),
            "signature": r.cstring(0x393D00),
        },
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
    print(f"Official decoder events: {len(result['cases'])} combined cases")


if __name__ == "__main__":
    main()
