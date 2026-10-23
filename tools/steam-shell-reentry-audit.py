#!/usr/bin/env python3
"""Execute original shell startup/selection policy, not a guessed reconnect loop.

Full AdvanceState/SetState/Main ctor, status update and selected callbacks run.
Qt/base objects, settings IO, UI construction/painting/destruction, hardware
guards, discovery subscription and server-record lookup are providers. Original
main through app construction and a separate BInit argv scan run between real
boundaries; BInit, StartStreaming and processEvents are providers there.
No full BInit, real Qt loop, paired host,
Android restart, discovery packets or media are proved by this tool.
"""
import argparse
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
PROVIDER = ROOT / "scripts/audit-steam-client-fec-policy.py"
spec = importlib.util.spec_from_file_location("policy", PROVIDER)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
APP, PANEL = policy.APP, policy.PANEL
MAIN = "_ZN10CPanelMainC1EP17CShellApplication"
ADVANCE = "_ZN17CShellApplication12AdvanceStateEv"
STATE = "_ZN17CShellApplication8SetStateE17EApplicationStateb"
PUSH = "_ZN17CShellApplication9PushStateE17EApplicationState"
PLAY = "_ZN10CPanelMain12StartPlayingEv"
ONLINE = "_ZN10CPanelMain13OnSteamOnlineEv"
MUTATIONS = ("omit-saved-host-discovery", "online-starts-playing", "omit-active-host-set", "retain-old-streaming-flag",
             "ignore-autoconnect-gate")
CLIENT = 0x1122334455667788


def require(ok, reason):
    if not ok:
        raise AssertionError("policy difference: " + reason)


class Reentry(policy.Shell):
    def __init__(self, binary, settings, mutation=None):
        super().__init__(binary)
        self.settings = dict(settings)
        self.actions, self.timers, self.executed = [], [], set()
        self.variants = {}
        self.unmapped = self.unsupported = self.slow = False
        self.record_present = self.remote_online = False
        self.manager = 0x20040000
        self.wq(APP + 0x18, self.manager)
        self.wq(APP + 0x28, 0x20060000)
        self.wq(APP + 0x70, 0x20070000)
        self.wq(APP + 0x78, 0x20080000)
        self.wq(APP + 0x1000 + 0x10, 0x20090000)
        vector = self.alloc(512)
        self.wi(vector, 1)
        self.wi(vector + 8, 64)
        self.wq(vector + 16, 24)
        self.wq(APP + 0x68, vector)
        self.ui_vtable = self.alloc(256)
        self.dispose = self.alloc(16)
        self.wq(self.ui_vtable + 0x20, self.dispose)
        self.callbacks[self.dispose] = self.dispose_widget
        self.widget_visible = self.alloc(16)
        self.wq(self.ui_vtable + 0x68, self.widget_visible)
        self.callbacks[self.widget_visible] = lambda: self.visible_widget()
        self.address_names = {value: name for name, value in self.symbols.items()
                              if value and (name in (MAIN, ADVANCE, STATE, PUSH, PLAY, ONLINE) or
                              name.startswith("_ZN10CPanelMain"))}
        if mutation == "online-starts-playing":
            address = 0xc82e08
            target = self.symbols[PLAY]
            self.patch(address, 0x14000000 | (((target - address) // 4) & 0x3ffffff))
        elif mutation == "omit-saved-host-discovery":
            self.patch(0xc7f730, 0xd503201f)
        elif mutation == "omit-active-host-set":
            self.patch(0xc7f6e4, 0xd503201f)
        elif mutation == "retain-old-streaming-flag":
            self.patch(0xc98754, 0xd503201f)
        elif mutation == "ignore-autoconnect-gate":
            self.patch(0xc82068, 0xd503201f)

    def patch(self, address, value):
        self.u.mem_write(address, struct.pack("<I", value))

    def dispose_widget(self):
        self.actions.append(dict(kind="dispose-ui-provider"))
        self.ret()

    def visible_widget(self):
        self.actions.append(dict(kind="widget-visible-provider", visible=bool(self.r(1))))
        self.ret()

    def qs(self, reference):
        return self.qt_strings[self.q(reference)]

    def snapshot(self):
        return dict(state=self.i(APP + 0x60), selected=self.q(self.main + 0xd8) if hasattr(self, "main") else None,
                    settings=dict(self.settings), actions=self.actions[:], timers=self.timers[:],
                    scan_count=self.i(self.main + 0xf4) if hasattr(self, "main") else None,
                    play_available=bool(self.u.mem_read(self.main + 0x118, 1)[0]) if hasattr(self, "main") else None,
                    launch_game=self.q(self.manager + 0x1e8))

    def hook(self, u, pc, size, data):
        if pc in self.address_names:
            name = self.address_names[pc]
            self.executed.add(name)
            if name == MAIN:
                self.main = self.r(0)
                self.actions.append(dict(kind="construct-main-original"))
            elif name in (STATE, PUSH):
                self.actions.append(dict(kind="state" if name == STATE else "push", value=self.r(1)))
        if pc == self.symbols.get("_ZN10CPanelMainD0Ev"):
            return self.dispose_widget()
        name = self.plts.get(pc, "")
        if name in ("_ZN9QSettingsC1EP7QObject", "_ZN9QSettingsD1Ev", "_ZN8QVariantD1Ev"):
            return self.ret()
        if name in ("_ZN8QVariantC1Ey", "_ZN8QVariantC1Eb"):
            self.variants[self.r(0)] = self.r(1)
            return self.ret()
        if name == "_ZN8QVariantC1ERK7QString":
            self.variants[self.r(0)] = self.qs(self.r(1))
            return self.ret()
        if name == "_ZNK9QSettings5valueERK7QStringRK8QVariant":
            key = self.qs(self.r(1))
            value = self.settings.get(key, self.variants[self.r(2)])
            self.actions.append(dict(kind="settings-read", key=key, value=value))
            self.variants[self.r(8)] = value
            return self.ret()
        if name in ("_ZNK8QVariant11toULongLongEPb", "_ZNK8QVariant6toBoolEv"):
            return self.ret(int(self.variants[self.r(0)]))
        if name == "_ZNK8QVariant8toStringEv":
            self.wq(self.r(8), self.qstring(str(self.variants[self.r(0)])))
            return self.ret()
        if name == "_ZN9QSettings8setValueERK7QStringRK8QVariant":
            key, value = self.qs(self.r(1)), self.variants[self.r(2)]
            self.settings[key] = value
            self.actions.append(dict(kind="settings-write", key=key, value=value))
            return self.ret()
        if name == "_ZN7QString16fromAscii_helperEPKci":
            return self.ret(self.qstring(self.cstring(self.r(0))))
        if name == "_ZN7QString15fromUtf8_helperEPKci":
            self.wq(self.r(8), self.qstring(self.cstring(self.r(0))))
            return self.ret()
        if name == "_ZN7QString14compare_helperEPK5QChariPKciN2Qt15CaseSensitivityE":
            text = bytes(u.mem_read(self.r(0), self.r(1) * 2)).decode("utf-16le")
            other = self.cstring(self.r(2))
            return self.ret((text > other) - (text < other))
        if name == "_ZN7QStringD2Ev":
            return self.ret()
        if name == "strlen":
            return self.ret(len(self.cstring(self.r(0))))
        if name == "_ZN10CPanelBaseC2EP17CShellApplication":
            self.wq(self.r(0) + 0x30, self.r(1))
            self.wq(self.r(0), self.ui_vtable)
            return self.ret()
        if "CPanel" in name and "C1EP17CShellApplication" in name and name != MAIN:
            self.actions.append(dict(kind="construct-ui-provider", symbol=name, extra=self.r(2)))
            self.wq(self.r(0), self.ui_vtable)
            self.wq(self.r(0) + 0x30, self.r(1))
            return self.ret()
        if name == "_ZN10CPanelMain7SetupUIEv":
            self.actions.append(dict(kind="setup-ui-provider"))
            for offset in (0x100, 0x108, 0x110):
                widget = self.alloc(128)
                self.wq(widget, self.ui_vtable)
                self.wq(self.r(0) + offset, widget)
            return self.ret()
        if name == "_ZN10CPanelMain25OnApplicationStateChangedEN2Qt16ApplicationStateE":
            self.actions.append(dict(kind="application-state-provider", value=self.r(1)))
            return self.ret()
        if name == "_ZN14CServerManager18AddClientDiscoveryEy":
            self.actions.append(dict(kind="add-client-discovery-provider", client_id=self.r(1)))
            return self.ret()
        if name == "_ZN14CServerManager11AddDelegateEP22IServerManagerDelegate":
            self.actions.append(dict(kind="add-delegate-provider"))
            return self.ret()
        if name == "_ZN6QTimer10singleShotEiPK7QObjectPKc":
            self.timers.append(dict(milliseconds=self.r(0), slot=self.cstring(self.r(2))))
            return self.ret()
        if name == "_ZN10CPanelMain20UpdateComputerStatusEv":
            self.actions.append(dict(kind="update-computer-status-original"))
            return self.jump(self.symbols[name])
        if name == "_ZNK11CUtlHashMapIy11CServerInfo10CDefEqualsIyE11HashFunctorIyEyE4FindERKy":
            return self.ret(0 if self.record_present else 0xffffffff)
        if name == "_ZN14CServerManager26BRemoteClientSessionOnlineEv":
            return self.ret(int(self.remote_online))
        if name == "_ZN6QLabel7setTextERK7QString":
            self.actions.append(dict(kind="paint-label-provider", text=self.qs(self.r(1))))
            return self.ret()
        if name == "_ZN18CControllerManager23BHasUnmappedControllersEv":
            return self.ret(int(self.unmapped))
        if name == "_ZN10CPanelMain25BCheckUnsupportedHardwareEv":
            return self.ret(int(self.unsupported))
        if name == "_ZN10CPanelMain27BCheckAndroidSlowControllerEv":
            return self.ret(int(self.slow))
        if name in ("_ZN7QLayout12removeWidgetEP7QWidget", "_ZN7QObject11setPropertyEPKcRK8QVariant",
                    "_ZN7QObject11deleteLaterEv"):
            self.actions.append(dict(kind="ui-provider", symbol=name))
            return self.ret()
        if name in ("_ZN10CAppImagesC1EP18CWebRequestManager9EUniverse11ESteamRealm",
                    "_ZN10CAppImages11LoadAppListEv", "_ZN10CAppImagesD1Ev"):
            return self.ret()
        if name == "_ZN10CAppImages8AddAppIDEj":
            self.actions.append(dict(kind="cache-app-id-provider", app_id=self.r(1)))
            return self.ret()
        # Original block-only BInit argv scan providers.
        if name == "strstr":
            text, needle = self.cstring(self.r(0)), self.cstring(self.r(1))
            offset = text.find(needle)
            self.actions.append(dict(kind="argv-substring", argument=text, needle=needle))
            return self.ret(self.r(0) + offset if offset >= 0 else 0)
        if name == "_ZN17CShellApplication14StartStreamingERK11QStringList":
            self.actions.append(dict(kind="argv-launch-provider", empty=self.q(self.r(1)) == self.empty))
            self.b(self.symbols["_ZN17CShellApplication12s_bStreamingE"], int(self.launch_sets_flag))
            return self.ret()
        if name == "_ZN16QCoreApplication13processEventsE6QFlagsIN10QEventLoop17ProcessEventsFlagEE":
            self.actions.append(dict(kind="process-events-provider", flags=self.r(0),
                streaming_before=bool(u.mem_read(self.symbols["_ZN17CShellApplication12s_bStreamingE"], 1)[0])))
            if self.events_sets_flag:
                self.b(self.symbols["_ZN17CShellApplication12s_bStreamingE"], 1)
            return self.ret()
        if name == "_ZN5QListI7QStringED2Ev":
            return self.ret()
        if name in ("SDL_SetMainReady", "_ZN7QObjectC2EPS_"):
            return self.ret()
        if name == "SDL_GetPreferredLocales":
            return self.ret(0)
        if name == "strcmp":
            left, right = self.cstring(self.r(0)), self.cstring(self.r(1))
            return self.ret((left > right) - (left < right))
        if name == "_ZN17CShellApplication5BInitERiPPc":
            self.actions.append(dict(kind="main-binit-boundary", argc=self.i(self.r(1)),
                autoconnect=bool(u.mem_read(self.r(0) + 0x98, 1)[0]), initial_state=self.i(self.r(0) + 0x60)))
            return self.jump(policy.STOP)
        return super().hook(u, pc, size, data)

    def startup(self):
        # BInit's original store at c980e4 initializes state zero. This harness
        # begins at its AdvanceState boundary, not at full BInit or a real VM.
        self.call(self.symbols[ADVANCE], APP)
        self.call(self.symbols[ADVANCE], APP)
        if self.i(APP + 0x60) == 2:
            self.call(self.symbols[ADVANCE], APP)  # supplied welcome continuation
        return self.snapshot()

    def argv(self, words, stale, launch_flag, events_flag):
        self.launch_sets_flag, self.events_sets_flag = launch_flag, events_flag
        argc, argv = self.alloc(4), self.alloc(max(1, len(words)) * 8)
        self.wi(argc, len(words))
        for index, word in enumerate(words):
            text = self.alloc(len(word) + 1)
            self.u.mem_write(text, word.encode() + b"\0")
            self.wq(argv + 8 * index, text)
        for index, value in ((19, APP), (20, argv), (21, argc)):
            self.u.reg_write(policy.UC_ARM64_REG_X0 + index, value)
        self.b(self.symbols["_ZN17CShellApplication12s_bStreamingE"], int(stale))
        def stop(label):
            self.actions.append(dict(kind="argv-boundary", value=label))
            self.jump(policy.STOP)
        self.callbacks[0xc9881c] = lambda: stop("continue-ui")
        self.callbacks[0xc98c58] = lambda: stop("streaming-shortcut")
        self.call(0xc98744)
        return self.actions[:]

    def main_prefix(self, words):
        argv = self.alloc((len(words) + 1) * 8)
        for index, word in enumerate(words):
            text = self.alloc(len(word) + 1)
            self.u.mem_write(text, word.encode() + b"\0")
            self.wq(argv + 8 * index, text)
        self.call(self.symbols["main"], len(words), argv)
        return self.actions[:]

    def server_record(self, fields, present=True):
        self.record_present = present
        data = self.alloc(0x68)
        self.wq(self.manager + 0x90, data)
        self.wi(self.manager + 0xa8, 1 if present else 0)
        self.wq(data + 8, CLIENT)
        name = self.alloc(32)
        self.u.mem_write(name, b"Fixture PC\0")
        self.wq(data + 8 + 0x10, name)
        for offset, value in enumerate(fields, 0x31):
            self.b(data + 8 + offset, value)


def audit(binary, mutation):
    startup = []
    for client in (CLIENT, 0):
        for selected_once in (True, False):
            for welcome in (True, False):
                for action in ("none", "desktop", "game"):
                    settings = dict(activeHostClientID=client, activeHostSet=selected_once, welcomeShown=welcome)
                    vm = Reentry(binary, settings, mutation)
                    initial = vm.startup()
                    callbacks = []
                    if initial["state"] == 3:
                        for method in (ONLINE, ONLINE, "_ZN10CPanelMain27OnScanningComputersCompleteEv",
                                       "_ZN10CPanelMain27OnScanningComputersCompleteEv",
                                       "_ZN10CPanelMain19OnAdvancePanelStateEv",
                                       "_ZN10CPanelMain18OnCheckSystemStateEv"):
                            vm.call(vm.symbols[method], vm.main)
                            callbacks.append(dict(method=method, result=vm.snapshot()))
                            if vm.i(APP + 0x60) != 3:
                                break
                        if action != "none" and vm.i(APP + 0x60) == 3:
                            name = "_ZN10CPanelMain14OnStartPlayingEv" if action == "desktop" else "_ZN10CPanelMain14OnStartPlayingEj"
                            vm.call(vm.symbols[name], vm.main, *(() if action == "desktop" else (42,)))
                    startup.append(dict(input=settings, action=action, startup=initial, callbacks=callbacks,
                                        final=vm.snapshot(), executed=sorted(vm.executed)))
    guards = []
    for unsupported in (False, True):
        for slow in (False, True):
            for unmapped in (False, True):
                vm = Reentry(binary, dict(activeHostClientID=CLIENT, activeHostSet=True,
                                         welcomeShown=True), mutation)
                vm.startup()
                vm.unsupported, vm.slow, vm.unmapped = unsupported, slow, unmapped
                steps = []
                # Supplied continuations exercise each guard's resume point;
                # they are not a claimed natural timer/dialog event loop.
                for _ in range(4):
                    if vm.i(APP + 0x60) != 3:
                        break
                    vm.call(vm.symbols["_ZN10CPanelMain19OnAdvancePanelStateEv"], vm.main)
                    steps.append(vm.snapshot())
                    if vm.i(APP + 0x60) != 3:
                        break  # do not deliver UI callbacks after replacement
                if vm.i(APP + 0x60) == 3:
                    vm.call(vm.symbols["_ZN10CPanelMain18OnCheckSystemStateEv"], vm.main)
                guards.append(dict(unsupported=unsupported, slow=slow, unmapped=unmapped,
                                   steps=steps, final=vm.snapshot()))
    arg_cases = []
    for words in ([], ["shell"], ["scheme://in-argv0"], ["shell", "plain", "--flag"],
                  ["shell", "steamlink://fixture"], ["shell", "https://fixture"],
                  ["shell", "before", "prefix://fixture", "later://ignored"],
                  ["shell", "scheme:/missing-slash"]):
        for stale, launch_flag, events_flag in ((False, True, False), (True, True, False),
                                               (False, False, False), (False, True, True)):
            vm = Reentry(binary, {}, mutation)
            observed = vm.argv(words, stale, launch_flag, events_flag)
            arg_cases.append(dict(words=words, stale=stale, launch_sets_flag=launch_flag,
                                  events_sets_flag=events_flag, observed=observed))
    prefix = []
    for words in (["shell"], ["--autoconnect"], ["shell", "--autoconnect"],
                  ["shell", "--autoconnect", "--autoconnect"],
                  ["shell", "--autoconnect=true"], ["shell", "--skip-update"],
                  ["shell", "unknown", "--autoconnect"], ["shell", "https://fixture"]):
        vm = Reentry(binary, {}, mutation)
        prefix.append(dict(words=words, observed=vm.main_prefix(words)))
    statuses = []
    raw_statuses = [(True, [1, 1, 0, 0, 0, 0, 0]), (True, [0, 1, 0, 0, 0, 0, 0]),
                    (True, [1, 0, 0, 0, 0, 0, 0]), (True, [1, 1, 1, 0, 0, 0, 0]),
                    (True, [1, 1, 0, 1, 0, 0, 0]), (True, [1, 1, 0, 0, 0, 1, 0]),
                    (True, [1, 1, 0, 0, 0, 0, 1]), (False, [1, 1, 0, 0, 0, 0, 0])]
    for autoconnect in (False, True):
        for client in (0, CLIENT):
            for present, fields in raw_statuses:
                vm = Reentry(binary, dict(activeHostClientID=client, activeHostSet=True,
                                         welcomeShown=True), mutation)
                vm.startup()
                vm.server_record(fields, present)
                # This field's producer runs independently in main_prefix;
                # no guessed startup default or recovered old process state.
                vm.b(APP + 0x98, int(autoconnect))
                for _ in range(2):
                    vm.call(vm.symbols[ONLINE], vm.main)
                    if vm.i(APP + 0x60) != 3:
                        break
                observed = vm.snapshot()
                if any(timer["slot"] == "1OnStartPlaying()" for timer in vm.timers) and vm.i(APP + 0x60) == 3:
                    vm.call(vm.symbols["_ZN10CPanelMain14OnStartPlayingEv"], vm.main)
                statuses.append(dict(autoconnect=autoconnect, client_id=client, record_present=present,
                    bytes_31_through_37=fields, after_online=observed, after_one_delivery=vm.snapshot(), texts=vm.texts[:]))
    return dict(startup=startup, hardware_guards=guards, argv=arg_cases,
                main_prefix=prefix, server_status=statuses)


def verify(report):
    for case in report["startup"]:
        inputs, initial = case["input"], case["startup"]
        client, selected = inputs["activeHostClientID"], inputs["activeHostSet"]
        expected = 3 if client or selected else 5
        require(initial["state"] == expected, "saved host does not automatically play")
        require(initial["selected"] == client, "64-bit saved host selection")
        require(bool(initial["settings"]["activeHostSet"]) == bool(client or selected), "activeHostSet migration")
        discoveries = [a["client_id"] for a in initial["actions"] if a["kind"] == "add-client-discovery-provider"]
        require(discoveries == ([client] if client else []), "saved host resumes discovery only")
        ui = [a["symbol"] for a in initial["actions"] if a["kind"] == "construct-ui-provider"]
        require(ui[0] == "_ZN10CPanelLogoC1EP17CShellApplication", "initial logo")
        require(("_ZN13CPanelWelcomeC1EP17CShellApplication" in ui) == (not inputs["welcomeShown"]), "welcome preference")
        for step in case["callbacks"]:
            require(step["result"]["state"] == 3, "lifecycle callbacks do not enter connection panel")
        if case["callbacks"]:
            timers = case["callbacks"][-1]["result"]["timers"]
            require(timers == [dict(milliseconds=0, slot="1OnAdvancePanelState()"),
                              *[dict(milliseconds=10000, slot="1OnScanningComputersComplete()")]*2,
                              *[dict(milliseconds=3000, slot="1OnCheckSystemState()")]*2], "timers are scans/hardware checks")
            require(case["callbacks"][-1]["result"]["scan_count"] == 0, "balanced scan timer notifications")
            if case["action"] != "none":
                require(case["final"]["state"] == (4 if client else 5), "explicit user play routing")
                require(case["final"]["launch_game"] == (42 if case["action"] == "game" else 0), "game/desktop choice")
    for case in report["hardware_guards"]:
        require(case["final"]["state"] == (8 if case["unmapped"] else 3), "hardware guard resumes to UI/controller mapping")
        require(not any(action["kind"] == "state" and action["value"] == 4
                        for step in case["steps"] for action in step["actions"]),
                "hardware callbacks do not start playing")
    for case in report["argv"]:
        matched = any("://" in word for word in case["words"][1:])
        launches = [v for v in case["observed"] if v["kind"] == "argv-launch-provider"]
        require(len(launches) == int(matched) and all(v["empty"] for v in launches), "argv URL-like gate")
        before = next(v["streaming_before"] for v in case["observed"] if v["kind"] == "process-events-provider")
        require(before == bool(matched and case["launch_sets_flag"]), "BInit clears old streaming flag")
        shortcut = bool((matched and case["launch_sets_flag"]) or case["events_sets_flag"])
        require(case["observed"][-1]["value"] == ("streaming-shortcut" if shortcut else "continue-ui"), "processEvents/launch completion gate")
    for case in report["main_prefix"]:
        observed = case["observed"][-1]
        require(observed["kind"] == "main-binit-boundary" and observed["initial_state"] == 0,
                "actual main constructs a fresh shell")
        require(observed["autoconnect"] == ("--autoconnect" in case["words"][1:]), "exact main --autoconnect option")
    for case in report["server_status"]:
        fields = case["bytes_31_through_37"]
        ready = bool(case["client_id"] and case["record_present"] and fields[0] and fields[1]
                     and not fields[3])
        require(case["after_online"]["play_available"] == ready, "original server ready predicate")
        queued = [timer for timer in case["after_online"]["timers"] if timer["slot"] == "1OnStartPlaying()"]
        eligible = ready and case["autoconnect"]
        require(queued == [dict(milliseconds=0, slot="1OnStartPlaying()")]* (2 if eligible else 0),
                "ready server autoconnect requires explicit launch flag")
        require(case["after_one_delivery"]["state"] == (4 if eligible else 3), "queued autoconnect routes into connection panel")


def main():
    if not __debug__:
        raise RuntimeError("original-code provider assertions require Python without -O")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mutation", choices=MUTATIONS)
    parser.add_argument("--reference", type=Path, help="compare with the frozen gzip JSON observation")
    args = parser.parse_args()
    binary = args.binary.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == policy.SHA, "pinned shell identity"
    report = audit(binary, args.mutation)
    image, symbols, _, _ = policy.load_image(binary)
    elf = ELFFile(io.BytesIO(binary))
    sizes = {symbol.name:symbol["st_size"] for symbol in elf.get_section_by_name(".dynsym").iter_symbols()}
    names = [MAIN, ADVANCE, STATE, PUSH, PLAY, ONLINE, "_ZN17CShellApplicationC1Ev",
             "_ZN10CPanelMain20UpdateComputerStatusEv", "_ZN10CPanelMain14OnStartPlayingEv",
             "_ZN10CPanelMain14OnStartPlayingEj", "_ZN10CPanelMain18OnCheckSystemStateEv",
             "_ZN10CPanelMain19OnAdvancePanelStateEv", "_ZN10CPanelMain27OnScanningComputersCompleteEv",
             "_ZN10CPanelLogo8BEnabledEv", "_ZN13CPanelWelcome8BEnabledEv"]
    windows = {name:(symbols[name], sizes[name]) for name in names}
    windows.update(main_through_BInit_boundary=(0xc65514, 0xc65804-0xc65514),
                   BInit_argv_scan=(0xc98744, 0xc9881c-0xc98744),
                   BInit_initial_state_store=(0xc980e4, 4))
    report.update(shell_sha256=policy.SHA, tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  provider_sha256=hashlib.sha256(PROVIDER.read_bytes()).hexdigest(), mutation=args.mutation,
                  scope=__doc__, original_ranges={name:dict(address=address, size=size,
                      sha256=hashlib.sha256(image[address:address+size]).hexdigest())
                      for name,(address,size) in windows.items()})
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    verify(report)
    if args.reference:
        require(report == json.loads(gzip.decompress(args.reference.read_bytes())), "frozen original observations")
    print(json.dumps({key:len(report[key]) for key in ("startup", "hardware_guards", "argv", "main_prefix", "server_status")}))


if __name__ == "__main__":
    main()
