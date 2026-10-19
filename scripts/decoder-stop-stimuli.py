"""Controlled audio worker/Stop interleavings; these do not model network loss."""

DESCRIPTOR = dict(frequency=48000, channels=2, codec=3, channel=3, clock_offset=0)
FUNCTIONS = (
    "_ZN14IStreamDecoder13RunDecodeLoopEv",
    "_ZN14IStreamDecoder15OnStreamStoppedEv",
    "_ZN14IStreamDecoder14OnReceiveFrameER12CStreamFrame",
    "_ZN14IStreamDecoder7OnThinkEv",
    "_ZN18CStreamDecoderOpus11DecodeFrameER12CStreamFrame",
    "_ZN18CStreamDecoderOpus12StopDecodingEv",
    "_ZN18CStreamDecoderOpus13StartDecodingER10CUtlBuffer",
    "_ZN17CStreamFrameQueueI22CReleasableStreamFrameE5PurgeEv",
    "_ZN22CReleasableStreamFrame7ReleaseEv",
)


def frame(fid, stamp):
    return dict(id=fid, timestamp=stamp, payload="f0fffe")


def plans():
    rows = [
        ("decode_empty", "decode", [0, 1], []),
        ("decode_pending", "decode", [0, 1], [2, 3, 4]),
        ("decode_gap", "decode", [0, 4], [5, 6]),
        ("decode_wrap", "decode", [65534, 0], [1, 2]),
        ("decode_duplicate", "decode", [0, 1], [1, 2]),
        ("think_empty", "think", [0], []),
        ("think_pending", "think", [0], [1, 2]),
        ("entry_empty", "entry", [], []),
        ("entry_pending", "entry", [], [0, 1, 2]),
    ]
    return [
        dict(
            name=name,
            stage=stage,
            initial=[frame(fid, 1100000 + i * 1000) for i, fid in enumerate(initial)],
            pending=[
                frame(fid, 1100000 + (len(initial) + i) * 1000)
                for i, fid in enumerate(pending)
            ],
            after_stop=frame(99, 1199000),
        )
        for name, stage, initial, pending in rows
    ]
