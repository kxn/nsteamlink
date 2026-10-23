#!/usr/bin/env python3
"""Observe real Android task recovery after a controlled player completion.

Requires a read-only, freshly cleared and unpaired AVD. The original Java
Activity start/completion and System.exit execute. Native StartStreaming takes
an empty QStringList on its Qt event thread; Run/Quit/manager retirement run.
Native player main alone is suppressed; no media connection is made. This does
NOT reproduce ticket admission or a natural transport failure. Artifacts are private; do not commit raw
logcat, task dumps, or app data. No physical device, pairing or UI taps.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time

import frida
import frida_tools

PACKAGE = "com.valvesoftware.steamlink"
APK_SHA = "7114b75e6fdd55e7bdcbad643cd1e7baf8cf5060da820120435adaefc6004dfc"
SOURCE = Path(__file__).with_suffix(".js").with_name("steam-android-completion-observer.js")


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", default="emulator-5580")
    parser.add_argument("--readonly-qemu-pid", type=int, required=True)
    parser.add_argument("--frida-address", default="127.0.0.1:27045")
    parser.add_argument("--result", type=int, choices=(-1, 0), default=-1)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location("network_guard",
        Path(__file__).with_name("steam-android-network-observe.py"))
    guard_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard_module)
    # Existing guard uses assertions; refuse optimized execution rather than
    # accidentally turning its userdata checks off.
    require(__debug__, "read-only guard requires Python without -O")
    guard = guard_module.readonly_guard(args.readonly_qemu_pid, args.serial)

    def adb(*command):
        return subprocess.run(["adb", "-s", args.serial, *command], check=True,
            capture_output=True, text=True, timeout=15).stdout.strip()

    require(adb("shell", "getprop", "ro.kernel.qemu") == "1", "not an emulator")
    require(adb("shell", "id", "-u") == "0", "Frida spawn requires rooted adb/server")
    base = adb("shell", "pm", "path", PACKAGE).splitlines()[0].removeprefix("package:")
    require(adb("shell", "sha256sum", base).split()[0] == APK_SHA, "APK identity mismatch")
    library = base.rsplit("/", 1)[0] + "/lib/x86_64/"
    binaries = {**guard_module.PINNED,
                "libmain.so": "57e625cdecef4683e019109cea5bf26c67ab7d0e84bbe4c247377a0ba9a11a34"}
    for name, expected in binaries.items():
        require(adb("shell", "sha256sum", library + name).split()[0] == expected, name)
    # Clearing only the ephemeral overlay ensures there is no trusted host or
    # authentication state. Guard must have succeeded before this operation.
    adb("shell", "am", "force-stop", PACKAGE)
    require(adb("shell", "pm", "clear", PACKAGE) == "Success", "fresh overlay failed")
    adb("shell", "pm", "grant", PACKAGE, "android.permission.BLUETOOTH_CONNECT")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    bridge = Path(frida_tools.__file__).parent / "bridges/java.js"
    source = SOURCE.read_text()
    events, errors = [], []
    detached = threading.Event()
    session = script = None
    output = os.fdopen(os.open(args.output / "events.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w")
    lock = threading.Lock()

    def record(value):
        with lock:
            events.append(value)
            output.write(json.dumps(value) + "\n")
            output.flush()

    def on_message(message, data):
        if message["type"] == "send":
            record(message["payload"])
        else:
            errors.append(message)
            record(dict(kind="frida_error", message=message))

    def on_detached(reason, crash):
        record(dict(kind="detached", reason=reason, crash=crash is not None))
        detached.set()

    def snapshot(label):
        data = adb("shell", "dumpsys", "activity", "activities")
        path = args.output / (label + ".tasks.txt")
        path.write_text(data)
        path.chmod(0o600)
        result = subprocess.run(["adb", "-s", args.serial, "shell", "pidof", PACKAGE],
                                capture_output=True, text=True, timeout=10)
        value = dict(kind="task_snapshot", label=label, pids=result.stdout.strip(),
                     sha256=hashlib.sha256(data.encode()).hexdigest())
        resumed = re.search(r"topResumedActivity=.*? (\S+/\S+) t(\d+)", data)
        value["top_resumed_activity"] = resumed[1] if resumed else None
        value["task_id"] = int(resumed[2]) if resumed else None
        record(value)
        return data, value

    record(dict(kind="identity", guard=guard, apk_sha256=APK_SHA,
        binaries=binaries, fresh_unpaired_overlay=True,
        bridge_sha256=hashlib.sha256(bridge.read_bytes()).hexdigest(),
        script_sha256=hashlib.sha256(source.encode()).hexdigest(),
        runner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        fingerprint=adb("shell", "getprop", "ro.build.fingerprint"),
        result=args.result, controlled_boundary="SDLActivity.nativeRunMain replaced"))
    device = frida.get_device_manager().add_remote_device(args.frida_address)
    try:
        # Timestamp-filtered logcat is collected afterwards; do not clear the
        # guest's global log buffer even though this is a disposable fixture.
        stamp = adb("shell", "date", r"+%m-%d\ %H:%M:%S.000")
        pid = device.spawn([PACKAGE])
        record(dict(kind="spawn", pid=pid))
        session = device.attach(pid)
        session.on("detached", on_detached)
        script = session.create_script(bridge.read_text() + "\n" + source)
        script.on("message", on_message)
        script.load()
        device.resume(pid)
        deadline = time.monotonic() + 25
        while not (any(event["kind"] == "lifecycle" and event.get("method") == "onResume"
                       and event.get("activity") == "shell" for event in events) and
                   any(event["kind"] == "native_shell_enter" and event.get("method") == "Run"
                       for event in events)):
            require(not detached.is_set() and not errors, "startup detached / observer error")
            require(time.monotonic() < deadline, "shell startup timeout")
            time.sleep(0.1)
        require(script.exports_sync.snapshot()["ready"], "shell reference missing")
        _, before = snapshot("before")
        script.exports_sync.launch(args.result)
        require(detached.wait(20), "completion did not terminate observed process")
        snapshot("after-exit")
        for index in range(1, 5):
            time.sleep(5)
            tasks, final = snapshot("after-%02ds" % (index * 5))
        logs = adb("logcat", "-d", "-v", "threadtime", "-T", stamp)
        path = args.output / "logcat.txt"
        path.write_text(logs)
        path.chmod(0o600)
        require(not errors, "Frida error invalidates observation")
        for kind in ("controlled_player_boundary", "invoke_original_completion",
                     "completion_result", "system_exit", "original_java_start_streaming"):
            require(any(e["kind"] == kind for e in events), "missing " + kind)
        def position(kind, **fields):
            return next(index for index, event in enumerate(events)
                        if event["kind"] == kind and
                        all(event.get(key) == value for key, value in fields.items()))
        order = [position("native_shell_leave", method="Run"),
                 position("native_shell_enter", method="Quit"),
                 position("native_shell_leave", method="manager-destructor"),
                 position("original_java_start_streaming"),
                 position("controlled_player_boundary"),
                 position("completion_call", method="streamingComplete", arguments=[args.result]),
                 position("completion_call", method="setLowLatencyAudio", arguments=[False]),
                 position("completion_call", method="disableWiFiLock"),
                 position("completion_result", code=args.result),
                 position("system_exit", code=0),
                 position("detached", reason="process-terminated", crash=False)]
        require(order == sorted(order) and len(set(order)) == len(order), "handoff/completion order")
        require(final["pids"] and str(pid) not in final["pids"].split(), "new process not observed")
        require(final["task_id"] == before["task_id"] and before["task_id"] is not None,
                "restored shell is not in the original task")
        require(any("topResumedActivity=" in line and
                    "com.valvesoftware.steamlink/.SteamShellActivity" in line
                    for line in tasks.splitlines()), "shell task not restored")
        require(not any(e["kind"].startswith("unexpected_") or e["kind"] == "experiment_error"
                        for e in events), "unexpected completion behavior")
        record(dict(kind="validated_observation", events=len(events)))
    finally:
        if not detached.is_set():
            if script:
                script.unload()
            if session:
                session.detach()
        adb("shell", "am", "force-stop", PACKAGE)
        record(dict(kind="cleanup", force_stopped=True))
        output.close()
    print(json.dumps(dict(output=str(args.output), events=len(events), errors=len(errors))))


if __name__ == "__main__":
    main()
