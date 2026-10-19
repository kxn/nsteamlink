"""Declared decoder-boundary input plans and selected official function names.

Counts are expected observations for explicit IDs, not a replacement receiver.
No transport producer or automatic recovery/reconnect trigger is modeled.
"""

DESCRIPTOR = dict(frequency=48000, channels=2, player_format=2, channel=3)

FUNCTIONS = (
    "_ZN18CStreamDecoderOpus13StartDecodingER10CUtlBuffer",
    "_ZN18CStreamDecoderOpus11DecodeFrameER12CStreamFrame",
    "_ZN18CStreamDecoderOpus12StopDecodingEv",
    "_ZN13IStreamPlayer16CreateAudioFrameEtj",
    "_ZN12CStreamFrameC1Ev",
    "_ZN12CStreamFrame10SetMessageEhh",
    "_ZN12CStreamFrame8SetFrameEtj",
)


def plans():
    rows = [
        ("fresh_high", [40000], [1]),
        ("in_order", [0, 1], [1, 1]),
        ("gap3", [0, 4], [1, 4]),
        ("gap32767", [0, 32768], [1, 32768]),
        ("halfspace", [0, 32769], [1, 32769]),
        ("beyond_halfspace", [0, 32770, 1], [1, 0, 1]),
        ("wrap", [65534, 1], [1, 3]),
        ("old", [0, 65535, 1], [1, 0, 1]),
        ("restart", [0, "R", 32769], [1, 0, 1]),
    ]
    return [
        dict(
            name=name,
            counts=counts,
            actions=[
                ["R"] if fid == "R" else ["F", fid, 1100000 + index * 1000]
                for index, fid in enumerate(ids)
            ],
        )
        for name, ids, counts in rows
    ]
