#!/usr/bin/env python3
"""Execute original peer SetConfig and explicit StreamStarting entry points.

Real C++ constructors, Frame Get/parser, negotiated-config CopyFrom/serializer,
state branches and Complete Frame Put/Send execute. Input is post-decryption.
Non-debug assertions are recorded. Allocation, hardware-independent seed state,
network lock, priority setter, timestamp, stats/player callbacks, GetChannel,
encryption and final Connection send are adapters. Calling StreamStarting here
is explicit, not proof of the complete application's dispatch/loop ordering.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "config", ROOT / "scripts/audit-steam-client-config.py"
)
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == config.SHA
    schema = config.descriptor_pb2.FileDescriptorProto.FromString(
        binary[0x3E5474 : 0x3E5474 + 21560]
    )
    pool = config.descriptor_pool.DescriptorPool()
    pool.Add(schema)

    def message(name, **fields):
        return config.message_factory.GetMessageClass(pool.FindMessageTypeByName(name))(
            **fields
        )

    cases = []
    initial = dict(
        reliable_data=True,
        selected_audio_codec=3,
        selected_video_codec=4,
        enable_remote_hid=True,
        enable_touch_input=True,
    )
    inputs = [("empty", b"")]
    for reliable in (None, False, True):
        for audio, video in ((3, 4), (0, 4), (3, 0), (1, 5), (0, 0)):
            fields = dict(selected_audio_codec=audio, selected_video_codec=video)
            if reliable is not None:
                fields["reliable_data"] = reliable
            body = message(
                "CNegotiationSetConfigMsg", config=fields
            ).SerializeToString()
            inputs.append((f"config_{reliable}_{audio}_{video}", body))
    inputs += [("bad_ff", b"\xff"), ("bad_0f", b"\x0f")]
    fields = dict(initial, enable_remote_hid=False, enable_touch_input=False)
    inputs.append(
        (
            "all_flags_cleared",
            message("CNegotiationSetConfigMsg", config=fields).SerializeToString(),
        )
    )
    inputs.append(
        (
            "ignored_client_config_and_caps",
            message(
                "CNegotiationSetConfigMsg",
                config=initial,
                streaming_client_config=dict(enable_unreliable_fec=True),
                streaming_client_caps=dict(supported_video_codecs=[5]),
            ).SerializeToString(),
        )
    )
    # Unknown negotiated-config tag100 varint7 retained by original CopyFrom.
    nested = (
        message("CNegotiatedConfig", **initial).SerializeToString() + b"\xa0\x06\x07"
    )
    assert len(nested) < 128
    inputs.append(("unknown_config", bytes([10, len(nested)]) + nested))
    scenarios = [(state, name, body) for state in (4, 5, 6) for name, body in inputs]
    scenarios += [(state, "empty_required_config", b"\x0a\x00") for state in (4, 5, 6)]
    for state, name, body in scenarios:
        r = config.Core(binary)
        assert r.parse(
            config.CLIENT + 288,
            message("CNegotiatedConfig", **initial).SerializeToString(),
            "CNegotiatedConfig",
        )
        channel, connection, packet, frame, raw = (r.alloc(4096) for _ in range(5))
        r.wq(config.CLIENT + 280, connection)
        r.wi(config.CLIENT + 256, state)
        r.wq(config.VTABLE + 96, config.STOP + 0x300)
        events, frames, asserts = [], [], []

        def final_send():
            p = r.r(1)
            frames.append(bytes(r.u.mem_read(r.q(p + 56) + 13, r.i(p + 52) - 13)).hex())
            r.ret(0)

        def assertion():
            asserts.append(r.r(1))
            r.ret(0)

        def priority():
            value = r.r(2) & 0xFFFFFFFF
            if value & 0x80000000:
                value -= 1 << 32
            events.append(dict(priority=[r.r(1), value]))
            r.ret()

        def event(name):
            events.append(name)
            r.ret()

        r.callbacks.update(
            {
                0xC097E0: assertion,
                0xC097F0: lambda: r.ret(0),
                0xC0E290: lambda: event("lock"),
                0xC0E2B0: lambda: event("unlock"),
                0xC0E2A0: priority,
                0xC0A950: lambda: r.ret(123456),
                0xC0C220: lambda: event("stats_start"),
                config.STOP + 0x300: lambda: event("player_started"),
                0xC0E110: lambda: r.jump(0x7A7D90),
                0xC0E390: lambda: r.ret(channel),
                0xC0E3A0: lambda: r.ret(1),
                0xC0E2F0: lambda: r.jump(0x7F3078),
                0xC10FF0: final_send,
            }
        )
        data = bytes(13) + b"\x04" + body
        r.u.mem_write(raw, data)
        r.wq(frame + 8, packet)
        r.b(frame + 16, 1)
        r.wq(packet + 40, raw)
        r.wq(packet + 56, raw)
        r.wi(packet + 48, 4096)
        r.wi(packet + 52, len(data))
        returned = r.call(0x7ADB28, config.CLIENT, frame)
        after = dict(
            state=r.i(config.CLIENT + 256),
            config=r.serialize(config.CLIENT + 288, "CNegotiatedConfig").hex(),
            frames=list(frames),
            events=list(events),
            asserts=list(asserts),
            returned=returned,
            client_config=r.serialize(config.CLIENT + 456).hex(),
        )
        if r.i(config.CLIENT + 256) == 5:
            r.call(0x7A6F9C, config.CLIENT)
        cases.append(
            dict(
                case=name,
                input=dict(state=state, body=body.hex()),
                after_peer=after,
                after_start=dict(
                    state=r.i(config.CLIENT + 256),
                    frames=frames,
                    events=events,
                    asserts=asserts,
                    sequence=r.q(config.CLIENT + 128),
                    timestamp1=r.i(config.CLIENT + 0x1C678),
                    timestamp2=r.i(config.CLIENT + 0x1F6F0),
                ),
            )
        )
    return cases


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    report = dict(
        binary_sha256=config.SHA, scope=__doc__, cases=audit(a.binary.read_bytes())
    )
    ref = ROOT / "scripts/fixtures/steam-peer-negotiation-reference.json"
    if a.refresh_reference:
        if ref.exists():
            old = json.loads(ref.read_text())
            assert old["binary_sha256"] == report["binary_sha256"]
            assert old["cases"] == report["cases"][: len(old["cases"])]
        ref.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert json.loads(ref.read_text()) == report
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"Official peer SetConfig/explicit Start: {len(report['cases'])} cases passed"
    )


if __name__ == "__main__":
    main()
