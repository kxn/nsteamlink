#!/usr/bin/env python3
"""Execute official OnThink -> incoming dispatch -> peer SetConfig/Start/Streaming.

Real queue dequeue, Frame construction/parser, C++ config copy/serialization,
OnThink stage selection, Start and Streaming/KeepAlive branches and control frame
production run. Input packets are seeded post-decryption. Network process and
Transport Update, decoder-free platform state, locks/refcounts/destruction,
priority setter, clock, stats/player/log callbacks, GetChannel, encryption and
final Connection send are explicit adapters. Connection feedback/TX internals,
actual authentication, device decoders and OS scheduling are not exercised.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

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

    initial = message(
        "CNegotiatedConfig",
        reliable_data=True,
        selected_audio_codec=3,
        selected_video_codec=4,
    )
    valid = message(
        "CNegotiationSetConfigMsg",
        config=dict(
            reliable_data=False, selected_audio_codec=3, selected_video_codec=4
        ),
    ).SerializeToString()
    other = message(
        "CNegotiationSetConfigMsg",
        config=dict(reliable_data=True, selected_audio_codec=1, selected_video_codec=5),
    ).SerializeToString()
    cases = []
    scenarios = [
        (state, own, packets, None)
        for state in (4, 5, 6)
        for own in (False, True)
        for packets in ([], [valid], [b"\xff"], [valid, other], [b"\xff", valid])
    ]
    scenarios += [(4, False, [valid], [0, 1, 0xA0001, 0xA0002])]
    start = 0xFFFF0000
    scenarios += [
        (
            4,
            False,
            [valid],
            [
                (start + d) & 0xFFFFFFFF
                for d in (0, 1, 0xA0000, 0xA0001, 0x140001, 0x140002)
            ],
        )
    ]
    scenarios += [(4, False, [valid], [1000000, 999999, 1655360, 1655361])]
    for delta in (
        0x7FFFFFFF,
        0x80000000,
        0x8009FFFF,
        0x800A0000,
        0x800A0001,
        0xFFFFFFFF,
    ):
        scenarios.append((4, False, [valid], [1000000, (1000000 + delta) & 0xFFFFFFFF]))
    for state, own_network, packets, ticks in scenarios:
        r = config.Core(binary)
        assert r.parse(
            config.CLIENT + 288,
            initial.SerializeToString(),
            "CNegotiatedConfig",
        )
        channel, connection, transport, queue = (r.alloc(4096) for _ in range(4))
        r.wq(config.CLIENT + 264, transport)
        r.wq(config.CLIENT + 280, connection)
        r.wi(config.CLIENT + 256, state)
        r.b(config.CLIENT + 16, int(own_network))
        r.wq(config.VTABLE + 96, config.STOP + 0x300)
        r.wq(config.CLIENT + 736, queue)
        r.wi(config.CLIENT + 720, 3)
        r.wi(config.CLIENT + 724, 0 if packets else -1)
        r.wi(config.CLIENT + 728, len(packets) - 1)
        for index, body in enumerate(packets):
            data = (
                struct.pack("<BBBBBHHI", 5, 0, 34, 12, 1, index, 0, 900000)
                + b"\x04"
                + body
            )
            packet = r.alloc(4096)
            r.wq(packet + 40, packet + 64)
            r.wq(packet + 56, packet + 64)
            r.wi(packet + 52, len(data))
            r.u.mem_write(packet + 64, data)
            r.wq(queue + index * 8, packet)
        events, frames, asserts = [], [], []
        now = [ticks[0] if ticks else 1000000]

        def event(value):
            events.append(value)
            r.ret()

        def assertion():
            asserts.append(r.r(1))
            r.ret(0)

        def final_send():
            p = r.r(1)
            frames.append(bytes(r.u.mem_read(r.q(p + 56) + 13, r.i(p + 52) - 13)).hex())
            r.ret(0)

        def priority():
            v = r.r(2) & 0xFFFFFFFF
            events.append(
                dict(priority=[r.r(1), v if v < 0x80000000 else v - (1 << 32)])
            )
            r.ret()

        r.callbacks.update(
            {
                0xC097E0: assertion,
                0xC097F0: lambda: r.ret(0),
                0xC0E0B0: lambda: event("network_process"),
                0xC0E0C0: lambda: event("transport_update"),
                0xC0E100: lambda: event("pending_logs"),
                0xC0E290: lambda: event("lock"),
                0xC0E2B0: lambda: event("unlock"),
                0xC0E2A0: priority,
                0xC0A950: lambda: r.ret(now[0]),
                0xC0C220: lambda: event("stats_start"),
                0xC0E2C0: lambda: event(dict(frame_events=r.r(1))),
                config.STOP + 0x300: lambda: event("player_started"),
                0xC0E110: lambda: r.jump(0x7A7D90),
                0xC0E390: lambda: r.ret(channel),
                0xC0E3A0: lambda: r.ret(1),
                0xC0E2F0: lambda: r.jump(0x7F3078),
                0xC10FF0: final_send,
                0xC0A380: lambda: r.ret(2),
                0xC0A390: lambda: r.ret(1),
                0xC0E120: lambda: r.ret(),
            }
        )
        stages = []
        for tick in (
            ticks
            if ticks is not None
            else (1000000, 1000001, 1000000 + 0xA0000, 1000001 + 0xA0000)
        ):
            now[0] = tick
            r.call(0x7A5FF8, config.CLIENT)
            stages.append(
                dict(
                    tick=tick,
                    state=r.i(config.CLIENT + 256),
                    config=r.serialize(config.CLIENT + 288, "CNegotiatedConfig").hex(),
                    frames=list(frames),
                    events=list(events),
                    asserts=list(asserts),
                    sequence=r.q(config.CLIENT + 128),
                    frame_events_time=r.i(config.CLIENT + 0x1C678),
                    keepalive_time=r.i(config.CLIENT + 0x1F6F0),
                )
            )
            frames.clear()
            events.clear()
            asserts.clear()
        inp = dict(
            state=state, own_network=own_network, packets=[b.hex() for b in packets]
        )
        if ticks is not None:
            inp["ticks"] = ticks
        cases.append(
            dict(
                input=inp,
                observed=stages,
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
    ref = ROOT / "scripts/fixtures/steam-negotiation-loop-reference.json"
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
        f"Official OnThink negotiation/KeepAlive: {len(report['cases'])} cases passed"
    )


if __name__ == "__main__":
    main()
