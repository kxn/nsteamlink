#!/usr/bin/env python3
"""Observe official Qt/JNI network changes in a disposable, read-only AVD.

Requires an already running emulator and Frida server/adb forward. Refuses a
physical device or writable base userdata. The caller prepares an unpaired
profile and grants Nearby Devices in the ephemeral overlay. This tool never
clears app data, pairs, taps UI, requests streaming, or changes the host network.
It temporarily toggles only guest Wi-Fi/data, restores their initial state,
and force-stops the observed app. JSONL is private and must not be committed.
No absence of an observed hook is promoted to absence of all indirect behavior.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

import frida

PACKAGE = "com.valvesoftware.steamlink"
SCRIPT = Path(__file__).with_name("steam-android-network-observer.js")
PINNED = {
    "libQt5Core_x86_64.so": "cd59df801f6ad5586e38bc720454f51d73df0c03dbed0db73bd9b592b25d4041",
    "libQt5Network_x86_64.so": "1dc3801a783b585393935216bdd17a8313d24b831f7814b4177dd5ffc6214a74",
    "libplugins_bearer_qandroidbearer_x86_64.so": "6e70b91e29b80eed18f025c3cc2395c89b860e204c2208ba489a91cf5f95ae50",
    "libshell_x86_64.so": "195025601c2b17194a4d8b3debd674aca3377290fe3851986656c49bc973f907",
}


def readonly_guard(pid, serial):
    process = Path("/proc") / str(pid)
    command = process.joinpath("cmdline").read_bytes().split(b"\0")
    assert b"-read-only" in command and b"-no-snapshot-save" in command, "not a read-only AVD"
    assert serial.startswith("emulator-") and serial[9:].isdigit(), "physical device refused"
    port = command.index(b"-port")
    assert command[port + 1].decode() == serial[9:], "emulator/adb serial mismatch"
    bases = []
    for descriptor in process.joinpath("fd").iterdir():
        try:
            name = str(descriptor.readlink())
            if "userdata" not in name:
                continue
            info = process.joinpath("fdinfo", descriptor.name).read_text()
            flags = int(next(line.split()[1] for line in info.splitlines() if line.startswith("flags:")), 8)
            assert flags & 3 == os.O_RDONLY, "writable userdata base refused"
            bases.append(name)
        except FileNotFoundError:
            continue
    assert bases, "base userdata descriptors not verified"
    return dict(pid=pid, serial=serial, readonly_userdata=sorted(set(bases)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", default="emulator-5580")
    parser.add_argument("--readonly-qemu-pid", type=int, required=True)
    parser.add_argument("--frida-address", default="127.0.0.1:27045")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    guard = readonly_guard(args.readonly_qemu_pid, args.serial)

    def adb(*command):
        result = subprocess.run(["adb", "-s", args.serial, *command], check=True,
                                capture_output=True, text=True, timeout=12)
        return result.stdout.strip()

    assert adb("shell", "getprop", "ro.kernel.qemu") == "1", "not an emulator"
    base = adb("shell", "pm", "path", PACKAGE).splitlines()[0].removeprefix("package:")
    library = base.rsplit("/", 1)[0] + "/lib/x86_64/"
    for name, expected in PINNED.items():
        assert adb("shell", "sha256sum", library + name).split()[0] == expected, name
    radios = {name: adb("shell", "settings", "get", "global", name)
              for name in ("wifi_on", "mobile_data")}
    assert set(radios.values()) == {"1"}, "fixture requires Wi-Fi and data initially enabled"
    device = frida.get_device_manager().add_remote_device(args.frida_address)
    output = os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w")
    errors, events = [], []
    session = script = None
    snapshot = None

    def record(value):
        events.append(value)
        output.write(json.dumps(value) + "\n")
        output.flush()

    def message(value, data):
        if value["type"] == "send":
            record(value["payload"])
            if value["payload"]["kind"] == "observer_error":
                errors.append(value)
        else:
            errors.append(value)
            record(dict(kind="frida_error", message=value))

    def phase(name, seconds, *command):
        record(dict(kind="experiment_phase", name=name, time_ms=int(time.time() * 1000)))
        if command:
            adb("shell", *command)
        for _ in range(seconds * 4):
            if errors:
                raise RuntimeError("observer error; trace remains partial")
            time.sleep(0.25)

    record(dict(kind="experiment_identity", guard=guard, binaries=PINNED,
                observer_sha256=hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
                runner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                fingerprint=adb("shell", "getprop", "ro.build.fingerprint")))
    try:
        adb("shell", "am", "force-stop", PACKAGE)
        pid = device.spawn([PACKAGE])
        session = device.attach(pid)
        script = session.create_script(SCRIPT.read_text())
        script.on("message", message)
        script.load()
        device.resume(pid)
        phase("startup", 10)
        phase("mobile-off", 5, "svc", "data", "disable")
        phase("offline", 8, "svc", "wifi", "disable")
        phase("wifi-on", 15, "svc", "wifi", "enable")
        phase("mobile-on", 8, "svc", "data", "enable")
        snapshot = script.exports_sync.snapshot()
        record(dict(kind="observer_snapshot", snapshot=snapshot))
        assert not errors and snapshot["dropped"] == 0, "partial observer trace"
        assert snapshot["arch"] == "x64", "unsupported Qt metadata layout"
        for kind in ("jni_registration", "native_network_notification", "qt_signal", "nam_slot", "server_manager_call"):
            assert snapshot["counts"].get(kind, 0), ("missing observation stage", kind)
        names = {event["module"] for event in events if event["kind"] == "qt_module_ready"}
        assert any("qandroidbearer" in name for name in names), "bearer not observed"
        values = [event["value"] for event in events if event["kind"] == "qt_signal"
                  and event["class"] == "QNetworkAccessManager" and event["method"] == "networkAccessibleChanged"]
        assert 0 in values and 1 in values, "missing offline/online observation"
        record(dict(kind="validated_trace", accessible_sequence=values))
    finally:
        # Unhook before restoration; neither callbacks nor workers remain in the
        # app once it is force-stopped. Cleanup failures invalidate the run.
        for label, action in (("unload", lambda: script.unload() if script else None),
                              ("detach", lambda: session.detach() if session else None),
                              ("force-stop", lambda: adb("shell", "am", "force-stop", PACKAGE)),
                              ("wifi", lambda: adb("shell", "svc", "wifi", "enable")),
                              ("data", lambda: adb("shell", "svc", "data", "enable"))):
            try:
                action()
            except Exception as error:
                errors.append(str(error))
                record(dict(kind="cleanup_error", stage=label, error=str(error)))
        record(dict(kind="experiment_end", errors=len(errors), radios_restored=not errors))
        output.close()
    assert not errors, "observation/cleanup failure"
    print(json.dumps(dict(output=str(args.output), snapshot=snapshot)))


if __name__ == "__main__":
    main()
