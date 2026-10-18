#!/usr/bin/env python3
"""Execute official OnNegotiationInit through final SetConfig protobuf production.

Real C++ construction/parser/CopyFrom/serialization, codec-selection branches and
SendControlMessage/Frame::Put run the pinned Android instructions. Input Frame
is seeded after decryption. Hardware BAvailable, GetChannel, encryption and final
Connection send are explicit adapters; captured frame is plaintext, not a network wire.
No host or decoder runs, and no complete post-SetConfig handshake is claimed.
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

    def encoded(**fields):
        return message("CNegotiationInitMsg", **fields).SerializeToString().hex()

    inputs = []

    def case(name, packets, client=None, hevc=False, caps=None):
        if caps is None:
            caps = {"supports_video_hevc_OBSOLETE": True} if hevc else {}
        inputs.append(
            dict(
                case=name,
                input=dict(
                    packets=packets,
                    initial_config=message("CStreamingClientConfig", **(client or {}))
                    .SerializeToString()
                    .hex(),
                    initial_caps=message("CStreamingClientCaps", **caps)
                    .SerializeToString()
                    .hex(),
                    available=[4, 5] if hevc else [4],
                ),
            )
        )

    for reliable in (None, False, True):
        case(
            f"reliable_{reliable}",
            [encoded(**({} if reliable is None else {"reliable_data": reliable}))],
        )
    for audio in ([], [1], [3], [1, 3], [3, 1], [2, 1, 3], [2, 3, 1]):
        for raw in (False, True):
            case(
                f"audio_{audio}_raw_{raw}",
                [
                    encoded(
                        reliable_data=True,
                        supported_audio_codecs=audio,
                        supported_video_codecs=[4],
                    )
                ],
                dict(enable_audio_uncompressed=raw),
            )
    for video in ([], [4], [5], [5, 4], [4, 5], [2, 5, 4], [8, 5, 4], [9, 4]):
        for hevc in (False, True):
            for preference in (False, True):
                case(
                    f"video_{video}_available_{hevc}_preference_{preference}",
                    [
                        encoded(
                            reliable_data=True,
                            supported_audio_codecs=[3, 1],
                            supported_video_codecs=video,
                        )
                    ],
                    dict(enable_video_hevc=preference),
                    hevc,
                )
    for reliable in (None, False, True):
        for hid in (None, False, True):
            for touch in (None, False, True):
                fields = {
                    k: v
                    for k, v in dict(
                        reliable_data=reliable,
                        supports_remote_hid=hid,
                        supports_touch_input=touch,
                    ).items()
                    if v is not None
                }
                case(f"presence_{reliable}_{hid}_{touch}", [encoded(**fields)])
    case(
        "audio_disabled_is_not_decoder_unavailable",
        [
            encoded(
                reliable_data=True,
                supported_audio_codecs=[3, 1],
                supported_video_codecs=[4],
            )
        ],
        dict(enable_audio_streaming=False),
    )
    case(
        "repeated_flags_and_host_metadata",
        [
            encoded(
                reliable_data=True,
                supports_remote_hid=True,
                supports_touch_input=True,
                os_type=1,
                gaming_device_type=4,
                supported_audio_codecs=[3],
                supported_video_codecs=[4],
            ),
            encoded(
                reliable_data=False,
                supports_remote_hid=False,
                supports_touch_input=False,
            ),
            encoded(os_type=0),
        ],
    )
    for field in ("display_limit", "quality_limit", "runtime_limit"):
        case(
            field,
            [
                encoded(
                    reliable_data=True,
                    supported_audio_codecs=[3],
                    supported_video_codecs=[4],
                )
            ],
            {field: dict(codec=1, bitrate_kbps=9000)},
        )
    case(
        "unknown_config",
        [encoded(reliable_data=True)],
        dict(controller_overlay_hotkey="ctrl+f1"),
    )
    for body in ("ff", "0f", "0802"):
        case("parse_" + body, [body])
    case(
        "failed_parse_keeps_prior_config",
        [encoded(reliable_data=True, supports_remote_hid=True), "ff", encoded()],
    )

    video_enum = pool.FindEnumTypeByName("EStreamVideoCodec")
    assert {v.number: v.name for v in video_enum.values}[1] == "k_EStreamVideoCodecRaw"
    assert {v.number: v.name for v in video_enum.values}[4] == "k_EStreamVideoCodecH264"
    assert {v.number: v.name for v in video_enum.values}[5] == "k_EStreamVideoCodecHEVC"
    case(
        "source_raw_video_always_available",
        [encoded(reliable_data=True, supported_video_codecs=[1, 4])],
    )
    inputs[-1]["input"]["native_compatible"] = False
    for codec in (8, 9):
        case(
            f"source_codec_{codec}_available",
            [encoded(reliable_data=True, supported_video_codecs=[codec, 4])],
            hevc=True,
        )
        inputs[-1]["input"]["available"] = [4, 5, 8, 9]
        inputs[-1]["input"]["native_compatible"] = False
    for fec in (None, False, True):
        for reliable in (False, True):
            case(
                f"independent_fec_{fec}_reliable_{reliable}",
                [
                    encoded(
                        reliable_data=reliable,
                        supported_audio_codecs=[3],
                        supported_video_codecs=[4],
                    )
                ],
                {} if fec is None else dict(enable_unreliable_fec=fec),
            )
    case(
        "long_config_fragmentation",
        [
            encoded(
                reliable_data=True,
                supported_audio_codecs=[3],
                supported_video_codecs=[4],
            )
        ],
        dict(controller_overlay_hotkey="x" * 2000),
    )
    for name, caps in [
        ("legacy_hevc_absent_independent_of_decoder", {}),
        (
            "legacy_hevc_false_independent_of_decoder",
            {"supports_video_hevc_OBSOLETE": False},
        ),
    ]:
        case(
            name,
            [
                encoded(
                    reliable_data=True,
                    supported_audio_codecs=[3],
                    supported_video_codecs=[4],
                )
            ],
            hevc=True,
            caps=caps,
        )
    for entry in inputs:
        entry["input"].setdefault("native_compatible", True)
    cases = []
    for entry in inputs:
        entry["input"].setdefault("native_compatible", True)
        inp = entry["input"]
        r = config.Core(binary)
        r.call(r.symbols["_ZN17CNegotiatedConfigC1Ev"], config.CLIENT + 288)
        assert r.parse(
            config.CLIENT + 352,
            bytes.fromhex(inp["initial_caps"]),
            "CStreamingClientCaps",
        )
        assert r.parse(config.CLIENT + 456, bytes.fromhex(inp["initial_config"]))
        channel, connection = r.alloc(4096), r.alloc(4096)
        r.wq(config.CLIENT + 280, connection)
        r.wi(config.CLIENT + 256, 4)
        captured, availability = [], []

        def send():
            packet = r.r(1)
            captured.append(
                bytes(r.u.mem_read(r.q(packet + 56) + 13, r.i(packet + 52) - 13)).hex()
            )
            r.ret(0)

        def available():
            codec = r.r(0)
            availability.append(codec)
            r.ret(int(codec in inp["available"]))

        r.callbacks.update(
            {
                0xC0E3E0: available,
                0xC0E110: lambda: r.jump(0x7A7D90),
                0xC0E390: lambda: r.ret(channel),
                0xC0E3A0: lambda: r.ret(1),
                0xC0E2F0: lambda: r.jump(0x7F3078),
                0xC10FF0: send,
            }
        )
        stages = []
        for data_hex in inp["packets"]:
            payload = bytes.fromhex(data_hex)
            frame, packet, raw = (r.alloc(4096) for _ in range(3))
            data = bytes(13) + b"\x03" + payload
            r.u.mem_write(raw, data)
            r.wq(frame + 8, packet)
            r.b(frame + 16, 1)
            r.wq(packet + 40, raw)
            r.wq(packet + 56, raw)
            r.wi(packet + 48, 4096)
            r.wi(packet + 52, len(data))
            result = r.call(0x7AD698, config.CLIENT, frame)
            stages.append(
                dict(
                    frames=list(captured),
                    returned=result,
                    negotiated=r.serialize(
                        config.CLIENT + 288, "CNegotiatedConfig"
                    ).hex(),
                    caps=r.serialize(config.CLIENT + 352, "CStreamingClientCaps").hex(),
                    client_config=r.serialize(config.CLIENT + 456).hex(),
                    host_os=r.i(config.CLIENT + 8),
                    gaming_device=r.i(config.CLIENT + 12),
                    sequence=r.q(config.CLIENT + 128),
                    availability=list(availability),
                )
            )
            captured.clear()
            availability.clear()
        cases.append(dict(entry, observed=stages))
    return cases


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    args = p.parse_args()
    report = dict(
        binary_sha256=config.SHA, scope=__doc__, cases=audit(args.binary.read_bytes())
    )
    ref = ROOT / "scripts/fixtures/steam-negotiation-reference.json"
    if args.refresh_reference:
        if ref.exists():
            old = json.loads(ref.read_text())
            assert old["cases"] == report["cases"][: len(old["cases"])]
        ref.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert json.loads(ref.read_text()) == report
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Official negotiation producer: {len(report['cases'])} cases passed")


if __name__ == "__main__":
    main()
