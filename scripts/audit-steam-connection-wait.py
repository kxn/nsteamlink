#!/usr/bin/env python3
"""Execute official SDL connection wait, Client OnThink and empty video Update.

Pinned Android core: selected SDL_main loop instructions after BConnect, original
Client OnThink/HandleStreaming, Player Update/BUpdateVideo and IStreamPlayer
empty-queue pop execute. Phase, clock, empty queue and previous display timestamp
are explicit inputs. OS/network processing, transport Update, incoming packet/
log drains, input/platform rendering, error presentation and final Quit are
declared boundaries. Control cipher/final sends inherit the audio-player driver.
No actual Host, decoder output, natural concurrency, full main/cleanup or device.
"""

import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

from unicorn.arm64_const import UC_ARM64_REG_X21

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "player", ROOT / "scripts/audit-steam-audio-player.py"
)
p = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p)
c = p.a.c
REFERENCE = ROOT / "scripts/fixtures/steam-connection-wait-reference.json.gz"
SHA = "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"


class Wait(p.Player):
    def __init__(self, binary, inp, patch=False):
        self.wait_events, self.entered, self.patch_hits = [], set(), []
        self.clock_calls, self.stream_visits = 0, 0
        self.inp = inp
        self.enabled = False
        super().__init__(binary)
        self.main_sp = 0x300C0000
        self.main_client = self.main_sp + 0x238
        # The configured projection/real queue constructors are reused. Moving
        # it to SDL's stack offset lets the unchanged original loop read state.
        self.u.mem_write(self.main_client, bytes(self.u.mem_read(c.CLIENT, 0x1F800)))
        self.wi(self.main_client + 256, inp["phase"])
        self.wq(self.main_client + 264, self.transport)
        self.b(self.main_client + 0x265, 1)
        self.wq(self.player + 8, self.main_client)
        self.wi(self.player + 0x6FC, inp["previous_display"])
        self.wq(self.player_vt + 0x198, 0x7B76E8)
        self.wq(self.player_vt + 0x58, c.STOP + 0xB00)
        self.callbacks[c.STOP + 0xB00] = self.wait_error
        self.callbacks[0xC0A970] = self.quit
        self.callbacks[0xC0A950] = self.clock
        if patch:
            pc = 0x75CEC4
            original = struct.unpack("<I", self.u.mem_read(pc, 4))[0]
            assert (original >> 10) & 0xFFF == 0xA0
            self.u.mem_write(pc, struct.pack("<I", original - (0x50 << 10)))
        self.enabled = True

    def event(self, name):
        self.wait_events.append(name)

    def wait_error(self):
        self.wait_events.append(["error", self.r(1)])
        self.ret()

    def quit(self):
        self.event("quit_boundary")
        self.ret()

    def clock(self):
        value = self.inp["start"] if self.clock_calls == 0 else self.inp["now"]
        self.clock_calls += 1
        self.ret(value)

    def stop(self):
        self.jump(c.STOP)
        self.u.emu_stop()

    def hook(self, u, pc, size, data):
        if self.enabled:
            if pc == 0x75CEC4:
                self.patch_hits.append(hex(pc))
            if pc in (0x7A5FF8, 0x7A7140, 0x7B76E8, 0x7B782C, 0x76817C):
                self.entered.add(hex(pc))
            if pc == 0x75CEB0:
                self.event("connecting_continue")
                self.stop()
                return
            if pc == 0x75CF80:
                self.stream_visits += 1
                if self.stream_visits == 2:
                    self.event("session_continue")
                    self.stop()
                    return
            if pc == 0x75CF24:
                self.stop()
                return
        name = self.plts.get(pc, "")
        if self.enabled and name in (
            "_Z20StreamProcessNetworkv",
            "_ZN22CStreamTransportClient6UpdateEv",
            "_ZN13CStreamClient21HandleIncomingPacketsEv",
            "_ZN13CStreamClient22SendPendingLogMessagesEv",
            "_ZN13CStreamPlayer11UpdateInputEv",
            "_ZN13CStreamPlayer21RecreateRenderTargetsEv",
        ):
            self.ret()
            return
        if self.enabled and name == "ThreadSleep":
            self.wait_events.append(["sleep_ms", self.r(0)])
            self.ret()
            return
        if self.enabled and name in (
            "_ZN13CStreamClient7OnThinkEv",
            "_ZN13CStreamClient15HandleStreamingEv",
            "_ZN13CStreamPlayer12BUpdateVideoEv",
            "_ZN13IStreamPlayer18BGetNextVideoFrameEv",
        ):
            self.jump(self.symbols[name])
            return
        super().hook(u, pc, size, data)

    def run_loop(self):
        self.u.reg_write(c.SP, self.main_sp)
        self.u.reg_write(c.LR, c.STOP)
        self.u.reg_write(UC_ARM64_REG_X21, self.player)
        self.u.emu_start(0x75CE98, c.STOP + 4, count=10000000)
        assert self.u.reg_read(c.BASE["UC_ARM64_REG_PC"]) == c.STOP
        assert not self.assertions
        return dict(
            phase=self.i(self.main_client + 256),
            events=self.wait_events,
            entered=sorted(self.entered),
            clock_calls=self.clock_calls,
            source_assertions=self.assertions,
        )


def schedules():
    for start in (0, 1000000, 0xFFFFFFF0):
        for elapsed in (
            0,
            655359,
            655360,
            655361,
            45 * 65536,
            0x7FFFFFFF,
            0x80000000,
            0x8009FFFF,
            0x800A0000,
            0xFFFFFFFF,
        ):
            yield dict(
                phase=1,
                start=start,
                now=(start + elapsed) & 0xFFFFFFFF,
                previous_display=0,
            )
    for phase in (2, 3, 4, 6):
        for elapsed in (10, 45, 180):
            for previous in (0, 1000000):
                yield dict(
                    phase=phase,
                    start=1000000,
                    now=1000000 + elapsed * 65536,
                    previous_display=previous,
                )
    yield dict(phase=0, start=1000000, now=1000000, previous_display=0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--refresh-reference", action="store_true")
    args = parser.parse_args()
    binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == SHA
    cases = []
    for inp in schedules():
        result = Wait(binary, inp).run_loop()
        delta = (inp["now"] - inp["start"]) & 0xFFFFFFFF
        expired = inp["phase"] == 1 and ((delta - 655360) & 0xFFFFFFFF) < 0x80000000
        assert (["error", 4] in result["events"]) == expired, (inp, result)
        assert ("quit_boundary" in result["events"]) == (expired or inp["phase"] == 0)
        assert result["phase"] == inp["phase"]
        cases.append(dict(input=inp, observed=result))
    inp = dict(phase=1, start=1000000, now=1000000 + 655359, previous_display=0)
    original, changed = Wait(binary, inp), Wait(binary, inp, True)
    mutation = dict(original=original.run_loop(), mutant=changed.run_loop())
    assert mutation["original"] != mutation["mutant"]
    assert changed.patch_hits == ["0x75cec4"] and not changed.assertions
    mutation["hits"] = changed.patch_hits
    report = dict(binary_sha256=SHA, scope=__doc__, cases=cases, mutation=mutation)
    if args.refresh_reference:
        REFERENCE.write_bytes(
            gzip.compress((json.dumps(report, sort_keys=True) + "\n").encode(), mtime=0)
        )
    else:
        assert report == json.loads(gzip.decompress(REFERENCE.read_bytes()))
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"Official SDL wait/video: {len(cases)} loop cases; original 10-to-5-second counterfactual detected"
    )


if __name__ == "__main__":
    main()
