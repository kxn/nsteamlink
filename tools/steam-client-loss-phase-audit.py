#!/usr/bin/env python3
"""Compare original client DataLost phase gates with the production consumer.

Original SendDataLost/protobuf/Frame Put/Send execute in the pinned Linux client;
Connection delivery is a recording terminal. A second path enters the original
AVCodec OnThink/FinalDecode with an explicit SDK EAGAIN and client phase change
at receive return. It is not a natural thread race, decoder or authenticated
network. Native enters ApplyDecodeFeedback with the same ReportLost boundary;
the generic channel/transport sender is checked separately, not redefined as a
Client API. Queue admission is the Native observation terminal.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts/audit-steam-client-avcodec-player.py"
spec = importlib.util.spec_from_file_location("avcodec_player", SOURCE)
player = importlib.util.module_from_spec(spec)
spec.loader.exec_module(player)


class PhasePlayer(player.Player):
    def __init__(self, binary, mutation):
        self.phase_after_receive = None
        super().__init__(binary)
        if mutation:
            assert bytes(self.u.mem_read(0x31F81B, 2)) == b"\x74\x33"
            self.u.mem_write(0x31F81B, b"\xeb\x33")
            self.u.ctl_remove_cache(0x31F81B, 0x31F81D)

    def hook(self, u, address, size, context):
        if self.names.get(address) == "avcodec_receive_frame" and self.phase_after_receive is not None:
            self.wi(self.client + 0x100, self.phase_after_receive)
        super().hook(u, address, size, context)


def audit(args):
    binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == player.codec.SHA
    cases = []
    for phase in range(8):
        r = PhasePlayer(binary, args.mutation)
        r.wi(r.client + 0x100, phase)
        vector = r.alloc(32)  # Explicit empty CUtlVector boundary, no packet IDs.
        r.events = []
        # EStreamChannelVideo=1 selects client+0x272, seeded as channel3.
        r.call(0x31F7F0, r.client, 1, vector)
        feedback = [e[1:] for e in r.events if e[0] == "feedback"]
        expected = [[3, "02"]] if phase == 6 else []
        assert feedback == expected, (phase, "original Client send gate", feedback, expected)
        assert not r.assertions, (phase, r.assertions)
        cases.append(dict(phase=phase, feedback=feedback, events=list(r.events)))
    codec_cases = []
    for phase in (6, 7):
        for send in (0, -5):
            r = PhasePlayer(binary, args.mutation)
            r.phase_after_receive = phase
            state = r.submit(dict(send=send, receive=-11))
            feedback = [e[1:] for e in state["events"] if e[0] == "feedback"]
            assert feedback == ([[3, "02"]] if phase == 6 else []), (phase, send, "codec feedback", state)
            # All cases enter SendDataLost; only phase6 delivers a frame.
            assert any(e[0] == "lost" for e in state["events"]), (phase, send, "missing consumer")
            assert bool(state["reset_requested"]) == (send != 0), (phase, send, "reset retained", state)
            codec_cases.append(dict(phase_after_receive=phase, send=send, state=state))
    native = None
    if args.receiver:
        run = subprocess.run([str(args.receiver.resolve())], check=True, capture_output=True,
                             text=True, timeout=10)
        native = [json.loads(line) for line in run.stdout.splitlines()]
        expected = [dict(phase=c["phase"], client_feedback=len(c["feedback"]), transport_feedback=1)
                    for c in cases]
        assert native == expected, ("Native client/transport phase split", native, expected)
    return dict(
        scope=__doc__, binary_sha256=player.codec.SHA,
        audit_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        inherited_harness_sha256={str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                 for path in (SOURCE, player.ROOT / "scripts/audit-steam-client-avcodec.py")},
        original_send_range=dict(start="0x31f7f0", end="0x31f9a5",
                                 sha256=hashlib.sha256(bytes(r.u.mem_read(0x31F7F0, 0x1B5))).hexdigest()),
        native_receiver_sha256=hashlib.sha256(args.receiver.read_bytes()).hexdigest() if args.receiver else None,
        cases=cases, codec_cases=codec_cases, native=native,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--receiver", type=Path)
    parser.add_argument("--mutation", action="store_true", help="Bypass original Client phase gate")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    text = json.dumps(audit(args), indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
