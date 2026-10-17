#!/usr/bin/env python3
"""Execute official OnThink/Starting/Streaming through real frame-stat production.

The pinned client runs its empty incoming queue, stage selection, both time
comparisons, receive/completion/ring retirement, accumulator, C++ protobuf and
Frame Send. Network process/update, locks, priority, player, Stats::Start,
encryption, clock, metric collectors and final Connection send are adapters.
No authentication, socket scheduling, decoder or live metric window is claimed.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "stats", ROOT / "scripts/audit-steam-frame-stats.py"
)
stats = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stats)
config = stats.config


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == config.SHA
    cases = []
    schedules = [
        ("strict", 5, [1000000 + d for d in (0, 65536, 65537, 131073, 131074)]),
        ("zero_start", 5, [0, 0, 1, 65537, 65538]),
        ("wrap", 5, [(0xFFFF0000 + d) & 0xFFFFFFFF for d in (0, 65536, 65537, 131074)]),
        ("simultaneous", 5, [1000000, 1655360, 1655361, 1655362]),
        ("already_streaming", 6, [1000000, 1065536, 1065537]),
        ("negotiating", 4, [1000000, 2000000]),
    ]
    for delta in (
        0x7FFFFFFF,
        0x80000000,
        0x8000FFFF,
        0x80010000,
        0x80010001,
        0xFFFFFFFF,
    ):
        schedules.append(
            (f"half_{delta:x}", 5, [1000000, (1000000 + delta) & 0xFFFFFFFF])
        )
    for full in (False, True):
        for name, state, ticks in schedules:
            for result in (0, 5):
                # Initial update establishes Starting timestamps. A second frame
                # after a send proves rejected data is retired rather than replayed.
                actions = [["UPDATE", ticks[0]], ["R", 1], ["C", 1, 1, 906000]]
                for tick in ticks[1:]:
                    actions.append(["UPDATE", tick])
                actions += [
                    ["R", 2],
                    ["C", 2, 1, 907000],
                    ["UPDATE", (ticks[-1] + 65537) & 0xFFFFFFFF],
                ]
                r = stats.Stats(binary, full)
                transport, queue, channel = (r.alloc(4096) for _ in range(3))
                r.wq(config.CLIENT + 264, transport)
                r.wq(config.CLIENT + 736, queue)
                r.wi(config.CLIENT + 724, -1)
                r.wi(config.CLIENT + 728, -1)
                r.wi(config.CLIENT + 256, state)
                r.wq(config.VTABLE + 96, config.STOP + 0x300)
                outputs = []
                calls = []

                def send():
                    p = r.r(1)
                    raw = bytes(r.u.mem_read(r.q(p + 56), r.i(p + 52)))
                    # Connection::Send(packet, channel) receives channel in w2;
                    # its packet header has not yet been populated by Connection.
                    channel_id = r.r(2)
                    outputs.append(dict(channel=channel_id, body=raw[13:].hex()))
                    r.ret(result if channel_id == 2 else 0)

                def report():
                    calls.append(r.r(1))
                    r.jump(0x7A82E8)

                r.callbacks.update(
                    {
                        0xC0E0B0: lambda: r.ret(),
                        0xC0E0C0: lambda: r.ret(),
                        0xC0E100: lambda: r.ret(),
                        0xC0E290: lambda: r.ret(),
                        0xC0E2B0: lambda: r.ret(),
                        0xC0E2A0: lambda: r.ret(),
                        0xC0C220: lambda: r.ret(),
                        config.STOP + 0x300: lambda: r.ret(),
                        0xC0E2C0: report,
                        0xC0E110: lambda: r.jump(0x7A7D90),
                        0xC0E390: lambda: r.ret(channel),
                        0xC0E3A0: lambda: r.ret(1),
                        0xC0A390: lambda: r.ret(1),
                        0xC0E120: lambda: r.ret(),
                        0xC10FF0: send,
                    }
                )
                observed = []
                for action in actions:
                    if action[0] == "R":
                        r.receive(action[1])
                    elif action[0] == "C":
                        _, fid, outcome, r.now = action
                        r.call(0x7AC3F8, config.CLIENT, 1, fid, outcome)
                    else:
                        r.now = action[1]
                        r.call(0x7A5FF8, config.CLIENT)
                        observed.append(
                            dict(
                                state=r.i(config.CLIENT + 256),
                                frames=list(outputs),
                                frame_events=list(calls),
                                frame_events_time=r.i(config.CLIENT + 0x1C678),
                                keepalive_time=r.i(config.CLIENT + 0x1F6F0),
                                sequence=r.q(config.CLIENT + 128),
                                reported=r.i(r.ring(1) + 8) >> 16,
                            )
                        )
                        outputs.clear()
                        calls.clear()
                assert not r.asserts, r.asserts
                cases.append(
                    dict(
                        input=dict(
                            name=name,
                            full=full,
                            state=state,
                            send_result=result,
                            actions=actions,
                        ),
                        observed=observed,
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
    ref = ROOT / "scripts/fixtures/steam-frame-events-loop-reference.json"
    if a.refresh_reference:
        if ref.exists():
            assert json.loads(ref.read_text()) == report
        ref.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert json.loads(ref.read_text()) == report
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Official OnThink/frame-event producer: {len(report['cases'])} cases passed")


if __name__ == "__main__":
    main()
