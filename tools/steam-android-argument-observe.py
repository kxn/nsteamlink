#!/usr/bin/env python3
"""Trace original Intent -> Qt -> native argv across controlled process exit.

Only an owned read-only AVD and fresh root Frida server are supported. The base
completion observer suppresses EVERY player's nativeRunMain. Spawn gating
attaches the restored process before execution; its original CLI/ctor run, then
BInit is held before network admission. This is not a natural media failure or
full restored BInit/UI/host recovery. No pairing or real media request is made.
Raw argv/logcat/task dumps remain private. Temporary gating is always disabled.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import queue
import subprocess
import threading
import time

import frida
import frida_tools

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "com.valvesoftware.steamlink"
BASE = Path(__file__).with_name("steam-android-completion-observer.js")
SOURCE = Path(__file__).with_name("steam-android-argument-observer.js")
INPUTS = {"launcher": None, "autoconnect-extra": "--autoconnect",
          "url-extra": "steamlink://fixture.invalid/opaque"}


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", default="emulator-5580")
    parser.add_argument("--readonly-qemu-pid", type=int, required=True)
    parser.add_argument("--frida-address", default="127.0.0.1:27045")
    parser.add_argument("--case", choices=INPUTS, default="launcher")
    parser.add_argument("--result", choices=(-1, 0), type=int, default=-1)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(__debug__, "read-only guard requires Python without -O")
    spec = importlib.util.spec_from_file_location("guard", BASE.with_name("steam-android-network-observe.py"))
    guard_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard_module)
    guard = guard_module.readonly_guard(args.readonly_qemu_pid, args.serial)

    def adb(*command):
        return subprocess.run(["adb", "-s", args.serial, *command], check=True,
            capture_output=True, text=True, timeout=15).stdout.strip()

    require(adb("shell", "getprop", "ro.kernel.qemu") == "1", "not an emulator")
    require(adb("shell", "id", "-u") == "0", "fresh root Frida server required")
    host, separator, port = args.frida_address.rpartition(":")
    require(separator and host == "127.0.0.1" and port.isdecimal(), "Frida must use an explicit local adb forward")
    forward = args.serial + " tcp:" + port + " tcp:27042"
    require(forward in adb("forward", "--list").splitlines(), "Frida forward does not belong to guarded AVD")
    apk = adb("shell", "pm", "path", PACKAGE).splitlines()[0].removeprefix("package:")
    require(adb("shell", "sha256sum", apk).split()[0] ==
            "7114b75e6fdd55e7bdcbad643cd1e7baf8cf5060da820120435adaefc6004dfc", "base APK identity")
    library = apk.rsplit("/", 1)[0] + "/lib/x86_64/"
    binaries = {**guard_module.PINNED,
        "libmain.so": "57e625cdecef4683e019109cea5bf26c67ab7d0e84bbe4c247377a0ba9a11a34"}
    for name, expected in binaries.items():
        require(adb("shell", "sha256sum", library + name).split()[0] == expected, name)
    frozen = json.loads((ROOT / "tools/fixtures/steam-android-completion-runtime-1.3.32.json").read_text())
    require(hashlib.sha256(BASE.read_bytes()).hexdigest() ==
            frozen["tools_sha256"]["tools/steam-android-completion-observer.js"], "base observer identity")
    adb("shell", "am", "force-stop", PACKAGE)
    require(adb("shell", "pm", "clear", PACKAGE) == "Success", "fresh unpaired overlay")
    adb("shell", "pm", "grant", PACKAGE, "android.permission.BLUETOOTH_CONNECT")
    args.output.mkdir(parents=True, mode=0o700, exist_ok=False)
    output = os.fdopen(os.open(args.output / "events.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w")
    lock = threading.RLock()
    condition = threading.Condition(lock)
    events, errors, sessions = [], [], {}
    detached_pids = set()
    stopping = threading.Event()
    work = queue.Queue()
    device = frida.get_device_manager().add_remote_device(args.frida_address)
    require(not device.enumerate_pending_spawn(), "fresh Frida server has pending spawns")
    bridge = Path(frida_tools.__file__).parent / "bridges/java.js"

    def record(event):
        encoded = json.dumps(event)
        with condition:
            events.append(event)
            output.write(encoded + "\n")
            output.flush()
            condition.notify_all()

    def message(value, data):
        if value["type"] == "send":
            record(value["payload"])
        else:
            errors.append(value)
            record(dict(kind="observer_error", value=value))

    def on_spawn(spawn):
        # Frida delivers this on its event dispatcher. Blocking attach/load RPC
        # here can deadlock that dispatcher, including cleanup RPC responses.
        # An owned, joinable worker handles RPC; this callback only queues.
        work.put(spawn)

    def detached_callback(pid):
        # Frida introspects callback arity; a default third argument would
        # request a sender Session argument and shift reason/crash incorrectly.
        def detached(reason, crash):
            record(dict(kind="argument_detached", pid=pid, reason=reason, crash=crash is not None))
            with condition:
                detached_pids.add(pid)
                condition.notify_all()
        return detached

    def attach_spawn(spawn):
        if spawn.identifier != PACKAGE:
            # This server belongs to the disposable AVD. Never stall its other
            # services or inspect them just because gating saw a process.
            device.resume(spawn.pid)
            return
        if stopping.is_set():
            device.kill(spawn.pid)
            return
        with lock:
            generation = len(sessions)
            sessions[spawn.pid] = dict(generation=generation)
        record(dict(kind="gated_target_spawn", pid=spawn.pid, generation=generation))
        try:
            require(generation < 2, "unexpected third target process")
            session = device.attach(spawn.pid)
            callback = detached_callback(spawn.pid)
            session.on("detached", callback)
            prefix = "globalThis.nslArgumentGeneration = %d; globalThis.nslArgumentResult = %d;\n" % (generation, args.result)
            script = session.create_script(bridge.read_text() + "\n" + prefix + BASE.read_text() + "\n" + SOURCE.read_text())
            script.on("message", message)
            script.load()
            with lock:
                sessions[spawn.pid].update(session=session, script=script, detached_callback=callback)
            device.resume(spawn.pid)
        except Exception as error:
            errors.append(str(error))
            record(dict(kind="attach_error", pid=spawn.pid, error=str(error)))
            # Do not resume an uninstrumented player, even in a fresh profile.
            try:
                device.kill(spawn.pid)
            except frida.ProcessNotFoundError:
                pass

    def spawn_worker():
        while True:
            spawn = work.get()
            try:
                if spawn is None:
                    return
                attach_spawn(spawn)
            except Exception as error:
                errors.append(str(error))
                record(dict(kind="spawn_worker_error", error=str(error)))
            finally:
                work.task_done()

    def wait_for(predicate, timeout):
        deadline = time.monotonic() + timeout
        with condition:
            while not predicate():
                require(not errors, "observer failure")
                remaining = deadline - time.monotonic()
                require(remaining > 0, "observation deadline")
                condition.wait(min(remaining, .25))

    def phase(name):
        record(dict(kind="argument_phase", name=name))

    record(dict(kind="argument_identity", guard=guard, frida_forward=forward, binaries=binaries, case=args.case,
        input=INPUTS[args.case], result=args.result, fresh_unpaired_overlay=True,
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        observer_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        base_observer_sha256=hashlib.sha256(BASE.read_bytes()).hexdigest(),
        bridge_sha256=hashlib.sha256(bridge.read_bytes()).hexdigest(),
        fingerprint=adb("shell", "getprop", "ro.build.fingerprint")))
    gating = False
    worker = threading.Thread(target=spawn_worker, name="argument-spawn-worker")
    worker.start()
    try:
        stamp = adb("shell", "date", r"+%m-%d\ %H:%M:%S.000")
        device.on("spawn-added", on_spawn)
        device.enable_spawn_gating()
        gating = True
        phase("launch")
        command = ["am", "start", "-a", "android.intent.action.MAIN", "-c",
                   "android.intent.category.LAUNCHER", "-n", PACKAGE + "/.SteamShellActivity"]
        if INPUTS[args.case] is not None:
            command.extend(["--es", "applicationArguments", INPUTS[args.case]])
        adb("shell", *command)
        if args.case != "url-extra":
            wait_for(lambda: any(e["kind"] == "native_shell_enter" and e.get("method") == "Run" for e in events), 35)
            with lock:
                first_pid, first = next(iter(sessions.items()))
                first_script = first["script"]
            require(first_script.exports_sync.snapshot()["ready"], "original shell not ready")
            phase("controlled-native-launch")
            first_script.exports_sync.launch(args.result)
        wait_for(lambda: any(e["kind"] == "restored_binit_held" for e in events), 45)
        phase("restored-before-admission")
        with lock:
            pids = list(sessions)
        require(len(pids) == 2 and pids[0] != pids[1], "two distinct process identities")
        before, after = pids
        for kind in ("native_shell_argv", "native_binit_arguments", "qt_loader_parameters",
                     "qt_native_parameters", "shell_argument_intent"):
            entries = [[e for e in events if e["kind"] == kind and e.get("pid") == pid] for pid in pids]
            require(all(len(values) == 1 for values in entries), "missing/duplicate " + kind)
        def one(kind, pid):
            return next(e for e in events if e["kind"] == kind and e.get("pid") == pid)
        require(one("native_shell_argv", before)["argv"] == one("native_shell_argv", after)["argv"], "restored argv changed")
        for kind in ("qt_loader_parameters", "qt_native_parameters"):
            require(one(kind, before)["parameters"] == one(kind, after)["parameters"], "restored Qt parameters changed")
        for pid in pids:
            intent = one("shell_argument_intent", pid)
            require(intent["applicationArguments"] == INPUTS[args.case] and "args" not in intent["extra_keys"], "player args copied into shell intent")
            native = one("native_binit_arguments", pid)
            require(native["initial_state"] == 0 and native["autoconnect"] == int(args.case == "autoconnect-extra"), "native CLI flag/ctor")
        require(one("shell_argument_intent", before)["task"] == one("shell_argument_intent", after)["task"], "task identity changed")
        require(any(e["kind"] == "system_exit" and e.get("pid") == before and e["code"] == 0 for e in events), "original System.exit not observed")
        wait_for(lambda: before in detached_pids, 5)
        require(any(e["kind"] == "argument_detached" and e.get("pid") == before and not e["crash"] for e in events), "old process did not exit cleanly")
        require(not errors, "observer error")
        for name, data in (("tasks.txt", adb("shell", "dumpsys", "activity", "activities")),
                           ("logcat.txt", adb("logcat", "-d", "-v", "threadtime", "-T", stamp))):
            path = args.output / name
            path.write_text(data)
            path.chmod(0o600)
        record(dict(kind="validated_arguments", old_pid=before, restored_pid=after,
                    restored_binit_executed=False, events=len(events)))
    finally:
        stopping.set()
        phase("cleanup-force-stop-held-process")
        try:
            adb("shell", "am", "force-stop", PACKAGE)
        finally:
            try:
                if gating:
                    device.disable_spawn_gating()
                    gating = False
                device.off("spawn-added", on_spawn)
                for spawn in device.enumerate_pending_spawn():
                    device.resume(spawn.pid)
            finally:
                work.put(None)
                worker.join(10)
                deadline = time.monotonic() + 5
                with condition:
                    attached = {pid for pid, value in sessions.items() if "session" in value}
                    while not attached.issubset(detached_pids) and time.monotonic() < deadline:
                        condition.wait(.1)
                for value in sessions.values():
                    if "session" in value:
                        value["session"].off("detached", value["detached_callback"])
                        value["script"].off("message", message)
                record(dict(kind="argument_cleanup", gating_disabled=not gating,
                            worker_joined=not worker.is_alive(), all_sessions_detached=attached.issubset(detached_pids)))
                output.close()
            require(not worker.is_alive(), "spawn RPC worker did not join")
            require(attached.issubset(detached_pids), "observed sessions did not detach")
    require(not errors, "observer/cleanup errors")
    print(json.dumps(dict(output=str(args.output), case=args.case, processes=len(sessions), errors=len(errors))))


if __name__ == "__main__":
    main()
