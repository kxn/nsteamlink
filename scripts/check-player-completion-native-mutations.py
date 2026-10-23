#!/usr/bin/env python3
"""Reject runnable full-player cleanup regressions while keeping prefix evidence.

Compile isolated copies of the real runtime/media. Each candidate must execute
both session/audio rounds and finish root teardown normally; build failures,
signals, fixture assertions or unrelated rejections never count as evidence.
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
    build, output = args.build.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location("completion", ROOT / "scripts/check-steam-player-completion.py")
    check = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(check)
    check.source_contract()
    check.verify(build / "app/nsl-player-owner-runtime", False)
    entries = json.loads((build / "compile_commands.json").read_text())
    driver = ROOT / "app/tests/player_owner_runtime.c"
    runtime = ROOT / "app/platforms/common/runtime.c"
    media = ROOT / "app/platforms/common/media.c"
    runtime_before = "sl_media_complete_stream_player(atomic_load(&r->player_input_focus), false, false);"
    require(runtime.read_text().count(runtime_before) == 1, "one full runtime completion call")
    text = media.read_text()
    start = text.index("void sl_media_complete_stream_player(")
    end = text.index("\nstatic int media_audio_prepare", start)
    body = text[start:end]
    require(body.count("    stream_media_audio_close(NULL);") == 1, "one post-prefix audio retirement")
    variants = {
        "runtime-calls-prefix-only": runtime.read_text().replace(runtime_before,
            runtime_before.replace("sl_media_complete_stream_player", "sl_media_end_stream_player")),
        "completion-omits-retirement": text[:start] + body.replace("    stream_media_audio_close(NULL);", "    /* omitted final retirement */") + text[end:],
    }
    directory = build / "app"
    link = shlex.split((directory / "CMakeFiles/nsl-player-owner-runtime.dir/link.txt").read_text())
    rows = []
    for name, changed in variants.items():
        folder = output / name
        folder.mkdir(exist_ok=True)
        obj, receiver = folder / "mutant.o", folder / "receiver"
        if name.startswith("runtime"):
            origin, source = driver, folder / driver.name
            include = '#include "../platforms/common/runtime.c"'
            require(driver.read_text().count(include) == 1, "runtime fixture include")
            (folder / "runtime.c").write_text(changed)
            source.write_text(driver.read_text().replace(include, '#include "runtime.c"'))
        else:
            origin, source = media, folder / media.name
            source.write_text(changed)
        entry = next(row for row in entries if Path(row["file"]) == origin)
        command = [str(source) if value == str(origin) else value for value in shlex.split(entry["command"])]
        command[command.index("-o") + 1] = str(obj)
        command += ["-I", str(origin.parent)]
        compiled = subprocess.run(command, cwd=entry["directory"], capture_output=True, text=True, timeout=40)
        (folder / "compile.log").write_text(compiled.stdout + compiled.stderr)
        require(compiled.returncode == 0, name + ": compile failed")
        command = ["-Wl,--dependency-file=" + str(folder / "link.d") if value.startswith("-Wl,--dependency-file=") else value for value in link]
        if origin == driver:
            command = [str(obj) if value.endswith("nsl-player-owner-runtime.dir/tests/player_owner_runtime.c.o") else value for value in command]
        else:
            command.insert(1, str(obj))
        require(str(obj) in command, "isolated object injection")
        command[command.index("-o") + 1] = str(receiver)
        linked = subprocess.run(command, cwd=directory, capture_output=True, text=True, timeout=40)
        (folder / "link.log").write_text(linked.stdout + linked.stderr)
        require(linked.returncode == 0, name + ": link failed")
        process = subprocess.run([str(receiver), "0"], capture_output=True, text=True, timeout=15)
        require(process.returncode == 0, name + ": abnormal fixture: " + process.stderr)
        observed = json.loads(process.stdout)
        require(observed["final_clean"] and len(observed["rounds"]) == 2 and observed["rounds"][0]["retained"] is True,
                "normal observations of wrong stream retention")
        try:
            check.verify(receiver, False)
        except ValueError as error:
            require(str(error) == "stream player survived completed session", "unrelated mutation rejection: " + str(error))
        else:
            raise ValueError(name + ": incorrect retention accepted")
        rows.append(dict(mutation=name, receiver_exit=0, observed=observed, reason="stream player survived completed session"))
    (output / "result.json").write_text(json.dumps(rows, indent=2) + "\n")
    print("Player completion: two runnable runtime/media retention regressions rejected")


if __name__ == "__main__":
    main()
