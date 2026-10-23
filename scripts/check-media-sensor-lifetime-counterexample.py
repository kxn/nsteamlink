#!/usr/bin/env python3
"""Replay the old expired sensor borrow using isolated production source copies.

Only the newly added sensor-scope lease is removed. Real binding/stop/join and
SessionDestroy remain intact. The receiver observes the expired pointer without
dereferencing it; a crash, assertion, compile failure or timeout is not evidence.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def require(value, reason):
    if not value:
        raise ValueError(reason)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    build, folder = args.build.resolve(), args.output.resolve()
    folder.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location("sensor_check", ROOT / "scripts/check-media-sensor-lifetime.py")
    check = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(check)
    check.verify(build / "app/nsl-sensor-lifetime-runtime")

    media = ROOT / "app/platforms/common/media.c"
    text = media.read_text()
    start = text.index("    /* A snapshot under state_lock is not a lifetime lease.")
    end = text.index("\n    pthread_mutex_lock(&state_lock);\n    if (rumble_reset_pending)", start)
    scope = text[start:end]
    for operation in ("lock", "unlock"):
        call = f"    pthread_mutex_{operation}(&hid_lifecycle_lock);\n"
        require(scope.count(call) == 1, "exactly one sensor-scope " + operation)
        scope = scope.replace(call, "")
    (folder / "media.c").write_text(text[:start] + scope + text[end:])
    driver = ROOT / "app/tests/test_sensor_lifetime.c"
    include = '#include "../platforms/common/media.c"'
    require(driver.read_text().count(include) == 1, "actual media fixture include")
    source = folder / driver.name
    source.write_text(driver.read_text().replace(include, '#include "media.c"'))
    entries = json.loads((build / "compile_commands.json").read_text())
    entry = next(row for row in entries if Path(row["file"]) == driver)
    obj, receiver = folder / "counterexample.o", folder / "receiver"
    command = [str(source) if value == str(driver) else value for value in shlex.split(entry["command"])]
    command[command.index("-o") + 1] = str(obj)
    command += ["-I", str(driver.parent)]
    compiled = subprocess.run(command, cwd=entry["directory"], capture_output=True, text=True, timeout=40)
    (folder / "compile.log").write_text(compiled.stdout + compiled.stderr)
    require(compiled.returncode == 0, "old borrow counterexample: compile failed")
    directory = build / "app"
    link = shlex.split((directory / "CMakeFiles/nsl-sensor-lifetime-runtime.dir/link.txt").read_text())
    command = ["-Wl,--dependency-file=" + str(folder / "link.d")
               if value.startswith("-Wl,--dependency-file=") else value for value in link]
    command = [str(obj) if value.endswith("nsl-sensor-lifetime-runtime.dir/tests/test_sensor_lifetime.c.o")
               else value for value in command]
    require(str(obj) in command, "isolated driver object injection")
    command[command.index("-o") + 1] = str(receiver)
    linked = subprocess.run(command, cwd=directory, capture_output=True, text=True, timeout=40)
    (folder / "link.log").write_text(linked.stdout + linked.stderr)
    require(linked.returncode == 0, "old borrow counterexample: link failed")
    observed = check.observe(receiver)
    for row in observed["rounds"]:
        require(row["destroy_before_poll_return"] is True and row["injected_into_live_session"] is False,
                "old borrow was not exposed safely")
    try:
        check.verify(receiver)
    except ValueError as error:
        require(str(error) == "session destroyed during sensor borrow", "unrelated rejection: " + str(error))
    else:
        raise ValueError("expired session borrow accepted")
    (folder / "result.json").write_text(json.dumps(dict(observed=observed,
        receiver_exit=0, reason="session destroyed during sensor borrow"), indent=2) + "\n")
    print("Sensor lifetime: runnable old expired-borrow regression rejected")


if __name__ == "__main__":
    main()
