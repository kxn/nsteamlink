#!/usr/bin/env python3
"""Run the old replacement-ACK ownership against the actual application loop.

Compile a private application.c copy with only its pending-replacement STOP
generation restored. The receiver must observe the wrong page and exit through
normal application shutdown. Crashes, timeouts or build failures are not proof.
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
    spec = importlib.util.spec_from_file_location("recovery", ROOT / "scripts/check-session-recovery-runtime.py")
    check = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(check)
    origin = ROOT / "app/platforms/common/application.c"
    old = "sl_command stop = {.type = SL_CMD_STOP, .generation = a->lifecycle.request_id};"
    text = origin.read_text()
    require(text.count(old) == 1, "one pending replacement cleanup owner")
    source, obj, receiver = folder / "application.c", folder / "application.o", folder / "receiver"
    source.write_text(text.replace(old, old.replace("a->lifecycle.request_id", "cmd->generation")))
    entries = json.loads((build / "compile_commands.json").read_text())
    entry = next(row for row in entries if Path(row["file"]) == origin)
    command = [str(source) if value == str(origin) else value for value in shlex.split(entry["command"])]
    command[command.index("-o")+1] = str(obj)
    if "-MF" in command: command[command.index("-MF")+1] = str(folder / "compile.d")
    command += ["-I", str(origin.parent)]
    compiled = subprocess.run(command, cwd=entry["directory"], capture_output=True, text=True, timeout=40)
    (folder / "compile.log").write_text(compiled.stdout+compiled.stderr)
    require(compiled.returncode == 0, "counterexample compile failed")
    directory = build / "app"
    link = shlex.split((directory / "CMakeFiles/nsl-application-recovery-runtime.dir/link.txt").read_text())
    command = ["-Wl,--dependency-file="+str(folder / "link.d")
               if value.startswith("-Wl,--dependency-file=") else value for value in link]
    command.insert(1, str(obj))
    command[command.index("-o")+1] = str(receiver)
    linked = subprocess.run(command, cwd=directory, capture_output=True, text=True, timeout=40)
    (folder / "link.log").write_text(linked.stdout+linked.stderr)
    require(linked.returncode == 0, "counterexample link failed")
    observed = check.observe(receiver, ROOT / "app/tests/fixtures/video/sequential.h264")
    for field in ("wrong_cleanup_owner", "deferred_replacement", "final_clean", "joins_clean", "peer_joined"):
        require(observed[field] is True, "counterexample incomplete: "+field)
    require(observed["application_exit"] == 0 and observed["audio_opens"] == observed["audio_closes"] == 2,
            "counterexample must complete actual application cleanup")
    require(observed["first_generation"] < observed["cleanup_generation"] == observed["replacement_generation"],
            "observed wrong cleanup generation")
    require(observed["rounds"][1]["displayed"] is True and observed["rounds"][1]["audio"] is True,
            "new media still runs behind the wrong UI page")
    reason = "replacement cleanup dismissed new connection"
    try:
        check.verify(observed, True)
    except ValueError as error:
        require(str(error) == reason, "unrelated rejection: "+str(error))
    else:
        raise ValueError("old replacement cleanup was accepted")
    (folder / "result.json").write_text(json.dumps(dict(receiver_exit=0, observed=observed, reason=reason), indent=2)+"\n")
    print("Application recovery: runnable old cleanup ACK dismissed live replacement and was rejected")


if __name__ == "__main__":
    main()
