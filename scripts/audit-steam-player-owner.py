#!/usr/bin/env python3
"""Execute official focus producers and SDL_main owner teardown gates.

Original BOpenVideo flag-read block, complete BHandleEvent for focus events,
post-connect SDL_main loop/cleanup gates and the destructor's initial Quit call
execute. Client/Player update/Quit/destroy, sleep/network are explicit terminal
adapters. Resource cases replace player Quit/destroy with the real CloseAudio
slice, justified separately by the destructor/Quit prefix audits; they do not
execute full UI destruction. Receiver identity is pinned by real Main allocation
and constructor callsite instructions. Hard-flag producers execute with explicit
Disconnect and config-storage/wire terminals. No whole SDL_main/ctor/dtor, all flag-producer reachability, UI/OS
concurrency or Switch lifecycle proof is claimed.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_X19, UC_ARM64_REG_X21

ROOT = Path(__file__).resolve().parents[1]


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


audio = module("audio", "audit-steam-audio-start.py")
player = module("player", "audit-steam-audio-player.py")
c = audio.c


class OwnerOps:
    def setup_owner(self, physical=False):
        self.owner_active = False
        self.owner_actions = []
        self.physical = physical
        old = self.player
        self.player = self.alloc(4232)
        self.u.mem_write(self.player, bytes(self.u.mem_read(old, 4096)))
        self.vt = self.alloc(512)
        original = self.q(old) if physical else self.symbols["_ZTV13CStreamPlayer"] + 16
        self.u.mem_write(self.vt, bytes(self.u.mem_read(original, 512)))
        self.wq(self.player, self.vt)
        self.wq(self.player + 8, c.CLIENT)
        self.wq(c.CLIENT + 48, self.player)
        self.player_vt = self.vt
        self.wq(self.vt + 416, c.STOP + 0x710)
        self.wq(self.vt + 8, c.STOP + 0x714)
        self.wq(self.vt + 408, c.STOP + 0x718)
        self.callbacks.update(
            {
                c.STOP + 0x710: lambda: self.action("player_quit"),
                c.STOP + 0x714: lambda: self.action("destroy"),
                c.STOP + 0x718: lambda: self.action("player_update", self.busy),
            }
        )
        self.hard = self.symbols["g_bHardShutdown"]
        self.background = self.symbols["g_bBackgroundShutdown"]

    def action(self, name, value=0):
        self.owner_actions.append(name)
        if self.physical and name in ("player_quit", "destroy"):
            self.jump(
                0x7C0E00
            )  # Declared audio-slice adapter, not a whole Quit/dtor return.
        else:
            self.ret(value)

    def owner_hook(self):
        name = self.plts.get(self.u.reg_read(c.BASE["UC_ARM64_REG_PC"]), "")
        if name == "SDL_GetWindowFlags":
            self.ret(self.windowflags)
            return True
        if not getattr(self, "owner_active", False):
            return False
        if name == "_ZN13CStreamClient4QuitEv":
            self.action("client_quit")
        elif name == "_ZN13CStreamClient7OnThinkEv":
            self.owner_actions.append("client_update")
            assert self.phases
            self.wi(self.stack + 824, self.phases.pop(0))
            self.ret()
        elif name == "ThreadSleep":
            self.action("sleep")
        elif name == "_Z31StreamShutdownNetworkProcessingv":
            self.action("network_shutdown")
        elif name == "SteamDatagramClient_Kill":
            self.action("datagram_kill")
        elif name == "_ZN13CStreamPlayer4QuitEv":
            self.action("destructor_quit")
        else:
            return False
        return True

    def reset_owner(self):
        self.u.mem_write(self.player, bytes(4232))
        self.wq(self.player, self.vt)
        self.wq(self.player + 8, c.CLIENT)
        self.owner_actions = []
        self.audio_events = []
        self.assertions = []

    def focus_state(self):
        return dict(
            minimized=bool(self.u.mem_read(self.player + 1784, 1)[0]),
            focus=bool(self.u.mem_read(self.player + 1785, 1)[0]),
            mouse=bool(self.u.mem_read(self.player + 1786, 1)[0]),
            assertions=list(self.assertions),
        )

    def focus_event(self, value):
        event = self.alloc(128)
        self.wi(event, 0x20E if value else 0x20F)
        self.call(0x7B8110, self.player, event)

    def flags(self, value):
        self.windowflags = value
        self.u.reg_write(c.SP, 0x300FF000)
        self.u.reg_write(UC_ARM64_REG_X19, self.player)
        self.u.reg_write(c.X0, 123)
        self.u.emu_start(0x7B5E30, 0x7B5E6C, count=10000)
        assert self.u.reg_read(c.BASE["UC_ARM64_REG_PC"]) == 0x7B5E6C

    def cleanup(self, phase, hard, background, phases=(), busy=1):
        self.owner_actions = []
        self.phases = list(phases)
        self.busy = busy
        self.owner_active = True
        self.b(self.hard, int(hard))
        self.b(self.background, int(background))
        self.stack = 0x300E0000
        self.u.reg_write(c.SP, self.stack)
        self.u.reg_write(UC_ARM64_REG_X21, self.player)
        self.wi(self.stack + 824, phase)
        self.u.emu_start(0x75CF80, 0x75CFC8, count=1000000)
        assert self.u.reg_read(c.BASE["UC_ARM64_REG_PC"]) == 0x75CFC8
        assert not self.phases
        self.owner_active = False
        return dict(
            events=list(self.owner_actions),
            background=bool(self.u.mem_read(self.background, 1)[0]),
            focus=bool(self.u.mem_read(self.player + 1785, 1)[0]),
        )

    def hard_producer(self, kind, hard, size=None, previous=None):
        """Execute full methods; config copy/Destroy/Send are declared terminals."""
        self.reset_owner()
        self.b(self.hard, int(hard))
        effects = []

        def disconnect():
            assert self.r(0) == c.CLIENT
            assert self.u.mem_read(self.hard, 1)[0] == 1
            effects.append({"action": "disconnect"})
            self.ret()

        def config_copy():
            # Only storage for the original method's field decisions/writes;
            # no claim that a real protobuf config was constructed or sent.
            config = self.r(0)
            video = self.alloc(128)
            limit = self.alloc(64)
            self.u.mem_write(config, bytes(96))
            self.wq(config + 80, video)
            self.wq(video + 24, limit)
            self.wi(limit + 24, previous[0])
            self.wi(limit + 28, previous[1])
            self.ret(config)

        def set_config():
            assert self.r(0) == c.CLIENT and self.r(2) == 0
            limit = self.q(self.q(self.r(1) + 80) + 24)
            effects.append(
                {
                    "action": "set_config",
                    "width": self.i(limit + 24),
                    "height": self.i(limit + 28),
                }
            )
            self.ret()

        saved = dict(self.callbacks)
        self.callbacks.update(
            {
                0xC0B390: disconnect,
                0xC04770: config_copy,
                0xC04600: lambda: self.ret(),
                0xC0E7F0: set_config,
            }
        )
        try:
            if kind == "terminate":
                self.call(0x7B9A28, self.player)
            elif kind == "event":
                event = self.alloc(128)
                self.wi(event, 0x8000)
                self.wi(event + 20, 3)
                self.call(0x7B8110, self.player, event)
            else:
                assert kind == "reduce"
                self.wi(self.player + 1336, size[0])
                self.wi(self.player + 1340, size[1])
                self.call(0x7B9A4C, self.player)
            assert not self.assertions
            return dict(
                input=dict(
                    kind=kind,
                    hard=hard,
                    size=list(size) if size else None,
                    previous=list(previous) if previous else None,
                ),
                hard=bool(self.u.mem_read(self.hard, 1)[0]),
                effects=effects,
            )
        finally:
            self.callbacks = saved

    def destructor_prefix(self):
        self.reset_owner()
        self.owner_active = True
        self.u.reg_write(c.SP, 0x300E0000)
        self.u.reg_write(c.X0, self.player)
        self.u.emu_start(0x7B4944, 0x7B4980, count=100000)
        assert self.u.reg_read(c.BASE["UC_ARM64_REG_PC"]) == 0x7B4980
        self.owner_active = False
        assert self.owner_actions == ["destructor_quit"]
        return list(self.owner_actions)


class Owner(OwnerOps, audio.Audio):
    def __init__(self, binary):
        super().__init__(binary)
        self.setup_owner()

    def hook(self, uc, address, size, data):
        if self.owner_hook():
            return
        super().hook(uc, address, size, data)


class ResourceOwner(OwnerOps, player.Player):
    def __init__(self, binary):
        super().__init__(binary)
        self.setup_owner(True)

    def hook(self, uc, address, size, data):
        if self.owner_hook():
            return
        super().hook(uc, address, size, data)


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == c.SHA
    r = Owner(binary)
    cases = []
    for flags in (0, 0x40, 0x200, 0x400, 0x240, 0x440, 0x600, 0x640):
        for events in ([], [True], [False], [True, False], [False, True]):
            for hard in (False, True):
                for background in (False, True):
                    for phase, updates, busy in [
                        (0, [], 1),
                        (6, [5, 6, 7, 0], 1),
                        (6, [7, 0], 0),
                    ]:
                        r.reset_owner()
                        r.flags(flags)
                        observed = [r.focus_state()]
                        for focus in events:
                            r.focus_event(focus)
                            observed.append(r.focus_state())
                        assert not r.assertions
                        inp = dict(
                            flags=flags,
                            events=events,
                            hard=hard,
                            background=background,
                            phase=phase,
                            updates=updates,
                            busy=busy,
                        )
                        result = r.cleanup(phase, hard, background, updates, busy)
                        cases.append(
                            dict(input=inp, focus_states=observed, cleanup=result)
                        )
    anchors = {
        hex(pc): bytes(r.u.mem_read(pc, 4)).hex()
        for pc in (
            0x75CCE4,
            0x75CCE8,
            0x75CCF0,
            0x75CCF8,
            0x75CCFC,
            0x75CF1C,
            0x75CF20,
            0x75CF24,
            0x75CF50,
            0x75CF58,
            0x75CF74,
            0x75CF78,
            0x75CFC0,
        )
    }
    prefix = r.destructor_prefix()
    producers = [
        r.hard_producer(kind, hard)
        for kind in ("terminate", "event")
        for hard in (False, True)
    ]
    for size in (
        (3840, 2160),
        (1920, 1081),
        (1920, 1080),
        (1280, 721),
        (1280, 720),
        (640, 480),
        (2560, 360),
    ):
        for previous in ((0, 0), (1280, 720), (1920, 1080)):
            for hard in (False, True):
                producers.append(r.hard_producer("reduce", hard, size, previous))
    resources = []
    message = audio.schema(binary)
    for focus in (False, True):
        for hard in (False, True):
            for background in (False, True):
                r = ResourceOwner(binary)
                r.control(
                    50,
                    message(
                        "CStartAudioDataMsg",
                        channel=3,
                        codec=3,
                        frequency=48000,
                        channels=2,
                    ).SerializeToString(),
                )
                setup = [r.observe("setup_start")]
                r.media(3, 1, 1100001, 1100011, 1100021, "f0fffe")
                setup.append(r.observe("setup_media"))
                r.control(51, b"")
                r.flags(0x200 if focus else 0)
                before = r.observe("before_owner")
                decision = r.cleanup(0, hard, background)
                after = r.observe("after_owner")
                resources.append(
                    dict(
                        input=dict(focus=focus, hard=hard, background=background),
                        setup=setup,
                        before=before,
                        after=after,
                        decision=decision,
                    )
                )
    return dict(
        binary_sha256=c.SHA,
        boundary=__doc__,
        anchors=anchors,
        destructor_prefix=prefix,
        source_only_hard_producers=producers,
        cases=cases,
        resources=resources,
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
    print(
        f"Official player owner: {len(result['cases'])} gate/loop cases, {len(result['resources'])} actual audio resource cases, {len(result['source_only_hard_producers'])} hard-producer cases"
    )


if __name__ == "__main__":
    main()
