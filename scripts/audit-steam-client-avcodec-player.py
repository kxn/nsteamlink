#!/usr/bin/env python3
"""Replay the pinned official Linux AVCodec caller, queue and video consumer.

Executes original OnThink/AppendBuffer/FinalDecode, IStreamPlayer construction,
PutVideoFrame/jitter/ring queue, newest-ready selection, BUpdateVideo, original
frame-event/stat completion gates and DataLost protobuf/Frame::Put/Send. Codec
APIs/status/elapsed ticks, OS services, input UI pump, overlay virtual call,
statistics UI consumers and SDL are declared terminals. The derived player
vptr, initialized render handles/mode and legal pending stats slots are explicit
boundary inputs, not a full CStreamPlayer/Qt/session startup. SDL calls describe
attempted operations only; there are no fabricated or physically decoded pixels,
screen/backbuffer claims, NVTEGRA mapping, live Steam or Switch validation.

The pinned binary/provenance and codec terminal definitions are shared with
audit-steam-client-avcodec.py. No host binary is used as client-policy evidence.
"""

import argparse
import gzip
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "official_avcodec", ROOT / "scripts/audit-steam-client-avcodec.py"
)
codec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(codec)
codec.FUNCTIONS.update(
    {
        0x2EE0F0: "player_base_constructor",
        0x317AB0: "register_player",
        0x2ED010: "jitter_constructor",
        0x2ED080: "jitter_update",
        0x2ED1D0: "jitter_ready",
        0x2EDF70: "put_video_frame",
        0x2EF250: "pop_video_frame",
        0x2EE9E0: "pop_ready_video_frame",
        0x2EEA50: "select_newest_ready_frame",
        0x2EEAA0: "get_next_video_frame",
        0x2EE7A0: "complete_video_frame",
        0x2EE8D0: "complete_current_video_frame",
        0x33B5B0: "complete_current_video_frame_derived",
        0x318DF0: "lookup_frame_stats",
        0x318A90: "record_frame_event_client",
        0x326F30: "decoder_on_think_vslot4",
        0x3236E0: "append_buffer_vslot13",
        0x326C00: "check_content_mode",
        0x326C60: "decoder_overflow_check",
        0x33D350: "update_video",
    }
)


class Player(codec.Client):
    def __init__(self, binary, *, budget=0, present_status=True):
        self.now = 1000000
        self.input_ticks = self.output_ticks = 0
        self.allocations = {}
        self.present_status = present_status
        super().__init__(binary)
        # Shared controlled fopen(/proc/cpuinfo)=NULL exercises original CPU
        # fallback/assert during setup, not a protocol/player assertion.
        assert self.assertions == [[2919, 0x8C88D0]], self.assertions
        self.bootstrap_assertions = list(self.assertions)
        self.assertions = []
        self.hooks.update(
            {
                0x1A4530: lambda: self.ret(self.now),
                0x1A8E50: lambda: self.ret(),  # OS event constructor
                0x1A92F0: lambda: self.ret(),  # OS wakeup
                0x133B30: lambda: self.ret(),  # bounded debug formatting
                0x32B9C0: lambda: self.ret(),  # external UI/input pump
                0x331630: lambda: self.ret(),  # stats UI consumer, after completion
                0x331E40: lambda: self.ret(),  # stats UI consumer, after completion
                0x177340: lambda: self.ret(0),  # optional external display service
                0x318A90: self.frame_event,  # observer; original executes
            }
        )
        self.wi(self.client + 0x100, 0)
        self.call(0x2EE0F0, self.player, self.client)
        assert not self.assertions
        self.wi(self.client + 0x100, 6)
        assert self.q(self.player) == 0x10FE988
        assert self.q(self.client + 0x30) == self.player
        # Configured original derived caller boundary, not its full UI factory.
        self.wq(self.player, 0x11001A0)
        assert self.q(0x11001A0 + 9 * 8) == 0x2EDF70
        assert self.q(0x11001A0 + 49 * 8) == 0x33B5B0
        self.u.mem_write(self.client + 0x265, b"\x01")
        self.wi(self.player + 0x52C, 1)
        self.wi(self.player + 0x530, 128)
        self.wi(self.player + 0x534, 72)
        self.wi(self.player + 0x120 + 0x40, budget)
        renderer = self.alloc(128)
        for offset in (0x5B0, 0x5B8):
            self.wq(self.player + offset, renderer)
        self.wq(self.player + 0x5C0, self.alloc(128))
        self.wq(self.player + 0x5C8, self.alloc(128))
        overlay, vt = self.alloc(256), self.alloc(256)
        self.wq(overlay, vt)
        self.wq(vt + 128, codec.STOP + 0xF100)
        self.wq(self.player + 0x5D8, overlay)
        self.hooks[codec.STOP + 0xF100] = lambda: self.ret()
        self.node = self.alloc(40)
        self.carrier = self.alloc(256)
        self.slots = {}
        self.events = []

    def alloc(self, size):
        address = super().alloc(size)
        self.allocations[address] = size
        return address

    def frame_event(self):
        self.events.append(["event", self.arg(2), self.arg(3), self.now])

    def hook(self, u, address, size, data):
        if address == 0x2EDF70:
            frame = self.arg(1)
            avframe = self.q(frame + 48)
            self.events.append(
                [
                    "queue_put",
                    self.i(frame + 40) & 65535,
                    self.i(frame + 44),
                    self.i(frame + 16),
                    self.i(frame + 20),
                    self.i(frame + 24),
                    self.i(avframe + 104),
                    self.i(avframe + 108),
                    self.now,
                ]
            )
        elif address == 0x2ED080:
            self.events.append(["sample", self.arg(1), self.arg(2)])
        name = self.names.get(address, "")
        if name == "malloc":
            self.ret(self.alloc(self.arg(0)))
        elif name == "realloc":
            previous, requested = self.arg(0), self.arg(1)
            replacement = self.alloc(requested)
            if previous:
                retained = min(requested, self.allocations[previous])
                self.u.mem_write(
                    replacement, bytes(self.u.mem_read(previous, retained))
                )
            self.ret(replacement)
        elif name == "strlen":
            pointer, length = self.arg(0), 0
            while self.u.mem_read(pointer + length, 1) != b"\0":
                length += 1
                assert length < 65536
            self.ret(length)
        elif name == "__cxa_guard_acquire":
            self.ret(not self.u.mem_read(self.arg(0), 1)[0])
        elif name == "__cxa_guard_release":
            self.u.mem_write(self.arg(0), b"\x01")
            self.ret()
        elif name in {
            "SDL_SetRenderDrawColor",
            "SDL_RenderFillRect",
            "SDL_SetTextureAlphaMod",
            "SDL_RenderTexture",
            "SDL_UpdateYUVTexture",
            "SDL_RenderPresent",
        }:
            self.events.append(["sdl", name])
            if name == "SDL_UpdateYUVTexture":
                self.events.append(["pixel_upload"])
            self.ret(self.present_status if name == "SDL_RenderPresent" else 1)
        else:
            super().hook(u, address, size, data)
            if name == "avcodec_send_packet":
                self.now = (self.now + self.input_ticks) & 0xFFFFFFFF
            elif name == "avcodec_receive_frame":
                self.now = (self.now + self.output_ticks) & 0xFFFFFFFF

    def picture_identity(self, pointer):
        if not pointer:
            return None
        return [self.i(pointer + 40) & 65535, self.i(pointer + 44)]

    def state(self):
        return dict(
            clock=self.now,
            events=list(self.events),
            stats={str(fid): self.i(slot + 88) for fid, slot in self.slots.items()},
            jitter_count=self.i(self.player + 0x128),
            jitter_budget=self.i(self.player + 0x160),
            current=self.picture_identity(self.q(self.player + 0x110)),
            previous=self.picture_identity(self.q(self.player + 0x118)),
            reset_requested=self.i(self.dec + 0x60),
            assertions=list(self.assertions),
        )

    def submit(self, inp):
        fid = inp.get("id", 23)
        stamp = inp.get("timestamp", self.now)
        self.now = inp.get("now", self.now)
        self.send_status = inp.get("send", 0)
        self.receive_status = inp.get("receive", 0)
        self.sdk_format = inp.get("format", 0)
        self.sdk_size = tuple(inp.get("dimensions", [128, 72]))
        self.sdk_pts = inp.get("output_pts", 123456)
        self.input_ticks = inp.get("input_ticks", 0)
        self.output_ticks = inp.get("output_ticks", 0)
        self.parse_delta = inp.get("parse_delta", 0)
        self.parsed_size = inp.get("parsed_size")
        self.slots[fid] = self.seed(fid)
        self.events = []
        self.assertions = []
        # Legal, unconsumed complete original carrier/list-node boundary. Original
        # AppendBuffer retains it in the AU scatter list and OnThink releases it.
        # Refcount 2 accounts for this fixture's one external carrier owner.
        self.wi(self.carrier, 2)
        self.wi(self.carrier + 0x34, 2204)
        self.wq(self.carrier + 0x38, self.raw)
        self.u.mem_write(self.node, bytes(40))
        self.u.mem_write(self.node + 2, fid.to_bytes(2, "little"))
        self.wi(self.node + 4, stamp)
        self.u.mem_write(self.node + 8, b"\x08")
        self.wq(self.node + 0x18, self.carrier)
        self.wi(self.node + 0x20, -1)
        self.wi(self.node + 0x24, -1)
        self.wq(self.dec + 0x1A0, self.node)
        for offset, value in ((0x1B0, 0), (0x1B4, 0), (0x1BC, 1), (0x1C0, 1)):
            self.wi(self.dec + offset, value)
        self.call(0x326F30, self.dec)
        assert not self.assertions, self.assertions
        assert self.i(self.dec + 0x1BC) == 0
        return self.state()

    def present(self, now=None):
        if now is not None:
            self.now = now
        self.events = []
        self.assertions = []
        returned = self.call(0x33D350, self.player)
        assert not self.assertions, self.assertions
        return dict(self.state(), returned=returned)


def scenarios():
    cases = []
    for name, values in (
        ("normal", {}),
        ("output_pts_does_not_change_task", dict(output_pts=987654321)),
        ("no_output", dict(receive=-11)),
        ("eof", dict(receive=-541478725)),
        ("invalid_data", dict(receive=-1094995529)),
        ("receive_eio", dict(receive=-5)),
        ("send_again_then_output", dict(send=-11)),
        ("send_again_no_output", dict(send=-11, receive=-11)),
        ("parser_partial", dict(parse_delta=-1)),
        ("invalid_width", dict(dimensions=[0, 72])),
        ("unknown_format", dict(format=44)),
        ("decoder_time", dict(input_ticks=100, output_ticks=200)),
        ("failed_present", {}),
    ):
        cases.append(
            dict(
                name=name,
                present_status=name != "failed_present",
                actions=[["submit", values], ["present", None]],
            )
        )
    cases += [
        dict(
            name="no_output_then_recovery",
            actions=[
                ["submit", dict(id=1, receive=-11)],
                ["present", None],
                ["submit", dict(id=2, timestamp=1001000, now=1001000)],
                ["present", None],
            ],
        ),
        dict(
            name="normal_then_no_output_then_recovery",
            actions=[
                ["submit", dict(id=1)],
                ["present", None],
                ["submit", dict(id=2, receive=-11)],
                ["present", None],
                ["submit", dict(id=3)],
                ["present", None],
            ],
        ),
        dict(
            name="newest_ready_skips_old_placeholder",
            actions=[
                ["submit", dict(id=1, receive=-11)],
                ["submit", dict(id=2)],
                ["present", None],
            ],
        ),
        dict(
            name="budget_delays_placeholder",
            budget=20,
            actions=[
                ["submit", dict(receive=-11)],
                ["present", 1000000],
                ["present", 1001311],
            ],
        ),
        dict(
            name="repeat_placeholder",
            actions=[
                ["submit", dict(receive=-11)],
                ["present", None],
                ["present", 1001000],
            ],
        ),
    ]
    return cases


def run(binary, case, patch=None):
    player = Player(
        binary,
        budget=case.get("budget", 0),
        present_status=case.get("present_status", True),
    )
    if patch:
        address, replacement = patch
        assert len(replacement) == 5 and binary[address] == 0xE8
        player.u.mem_write(address, replacement)
        player.u.ctl_remove_cache(address, address + len(replacement))
    states = []
    for op, inp in case["actions"]:
        states.append(player.submit(inp) if op == "submit" else player.present(inp))
    return dict(
        case,
        states=states,
        bootstrap_assertions=player.bootstrap_assertions,
        entries={codec.FUNCTIONS[a]: n for a, n in sorted(player.entered.items())},
    )


def audit(binary):
    cases = [run(binary, c) for c in scenarios()]
    by_name = {case["name"]: case for case in cases}
    empty = by_name["no_output"]["states"]
    assert empty[0]["stats"] == empty[1]["stats"] == {"23": 7}
    assert [row[3] for row in empty[0]["events"] if row[0] == "complete"] == [7, 5]
    assert [row[3] for row in empty[1]["events"] if row[0] == "complete"] == [1]
    assert ["feedback", 3, "02"] in empty[0]["events"]
    assert empty[1]["previous"] == [23, 1000000]
    assert not any(row[0] == "pixel_upload" for row in empty[1]["events"])
    assert ["sdl", "SDL_RenderPresent"] in empty[1]["events"]
    assert not empty[0]["reset_requested"]
    normal = by_name["normal"]["states"]
    assert normal[1]["stats"] == {"23": 1}
    assert ["pixel_upload"] in normal[1]["events"]
    timed = by_name["decoder_time"]["states"][0]["events"]
    assert [row for row in timed if row[0] == "event"] == [
        ["event", 23, 14, 1000000],
        ["event", 23, 15, 1000300],
    ]
    assert ["sample", 1000000, 1000300] in timed
    delayed = by_name["budget_delays_placeholder"]["states"]
    assert delayed[1]["previous"] is None and delayed[2]["previous"] == [23, 1000000]
    recovered = by_name["no_output_then_recovery"]["states"][-1]
    assert recovered["stats"] == {"1": 7, "2": 1}
    assert recovered["previous"] == [2, 1001000]
    assert by_name["failed_present"]["states"][-1]["stats"] == {"23": 1}
    repeated = by_name["repeat_placeholder"]["states"][-1]
    assert repeated["stats"] == {"23": 7}
    assert not any(row[0] in ("event", "complete") for row in repeated["events"])
    mutations = []
    for name, shape, pc in (
        ("omit_decode_end", "normal", 0x3270EF),
        ("omit_jitter_sample", "decoder_time", 0x2EDFAC),
        ("omit_completion_gate", "normal", 0x2EE832),
        ("omit_newest_ready_drop", "newest_ready_skips_old_placeholder", 0x2EEA83),
        ("omit_data_lost", "no_output", 0x3244A4),
    ):
        baseline = by_name[shape]
        changed = run(binary, baseline, (pc, b"\x90" * 5))
        assert baseline["states"] != changed["states"], name
        mutations.append(name)
    assert all(
        any(name in c["entries"] for c in cases) for name in codec.FUNCTIONS.values()
    )
    return dict(
        binary_sha256=codec.SHA,
        archive_sha256=codec.ARCHIVE_SHA,
        archive_url="https://repo.steampowered.com/steamlink/1.3.32.316/steamlink-1.3.32.316.tgz",
        scope=__doc__,
        functions=codec.inventory(binary),
        cases=cases,
        mutation_checks=mutations,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--refresh-reference", action="store_true")
    args = parser.parse_args()
    report = audit(args.binary.read_bytes())
    encoded = (json.dumps(report, indent=2) + "\n").encode()
    reference = ROOT / "scripts/fixtures/steam-client-avcodec-player-reference.json.gz"
    if args.refresh_reference:
        if reference.exists():
            assert json.loads(gzip.decompress(reference.read_bytes())) == report
        reference.write_bytes(gzip.compress(encoded, mtime=0))
    else:
        assert json.loads(gzip.decompress(reference.read_bytes())) == report
    args.output.write_bytes(encoded)
    print(
        "Official Linux AVCodec player:",
        len(report["cases"]),
        "cases,",
        sum(len(c["states"]) for c in report["cases"]),
        "states,",
        len(report["functions"]),
        "functions,",
        len(report["mutation_checks"]),
        "mutations",
    )


if __name__ == "__main__":
    main()
