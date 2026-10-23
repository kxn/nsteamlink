#!/usr/bin/env python3
"""Require original discovery vectors to reject runnable polled dispatch changes.

Compile copies of the actual SDK client module and relink the existing runtime
oracle. Never edit production source/build objects. Build errors, signals and
fixture assertions are not accepted as policy counterexamples.
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
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build, work = args.build.resolve(), args.output.resolve()
    work.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location("polled_check", ROOT / "scripts/check-steam-discovery-polled.py")
    check = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(check)
    reference = ROOT / "scripts/fixtures/steam-discovery-cycles-reference.json"
    check.check(build / "app/nsl-discovery-polled-runtime", reference)
    source = ROOT / "third_party/ihslib/src/client/client.c"
    original = source.read_text()
    before = """        ClientProcessPacket(&client->base, &client->pollPacket.address,
                             &client->pollPacket.buffer, false);"""
    require(original.count(before) == 1, "unique polled dispatch anchor")
    variants = {
        # The parser consumes the cursor. A second call with that spent cursor
        # is behaviorally equivalent, so it is not a counterexample. Replay a
        # copied pre-parse view to model actually publishing one packet twice.
        "duplicate-polled-dispatch": "        IHS_Buffer replay = client->pollPacket.buffer;\n" + before + "\n" +
            "        ClientProcessPacket(&client->base, &client->pollPacket.address, &replay, false);",
        "drop-alternate-polled-batches": "        if (!(client->receiveGeneration & 1))\n" + before,
    }
    commands = json.loads((build / "compile_commands.json").read_text())
    entry = next(row for row in commands if Path(row["file"]) == source)
    directory = build / "app"
    link = shlex.split((directory / "CMakeFiles/nsl-discovery-polled-runtime.dir/link.txt").read_text())
    rows = []
    for name, after in variants.items():
        folder = work / name
        folder.mkdir(exist_ok=True)
        copy, obj, receiver = folder / "client.c", folder / "client.o", folder / "receiver"
        copy.write_text(original.replace(before, after))
        command = [str(copy) if value == str(source) else value for value in shlex.split(entry["command"])]
        command[command.index("-o") + 1] = str(obj)
        command += ["-I", str(source.parent)]
        compiled = subprocess.run(command, cwd=entry["directory"], capture_output=True, text=True, timeout=30)
        (folder / "compile.log").write_text(compiled.stdout + compiled.stderr)
        require(compiled.returncode == 0, name + ": compile failed")
        command = ["-Wl,--dependency-file=" + str(folder / "link.d")
                   if value.startswith("-Wl,--dependency-file=") else value for value in link]
        command.insert(1, str(obj))  # Resolve SDK client symbols before the archive.
        command[command.index("-o") + 1] = str(receiver)
        linked = subprocess.run(command, cwd=directory, capture_output=True, text=True, timeout=30)
        (folder / "link.log").write_text(linked.stdout + linked.stderr)
        require(linked.returncode == 0, name + ": link failed")
        observed = subprocess.run([str(receiver), "100", "negative_then_recovery"], capture_output=True,
                                  text=True, timeout=7)
        require(observed.returncode == 0, name + ": fixture abnormal exit: " + observed.stderr)
        native = json.loads(observed.stdout)
        require(native["final_clean"] is True and native["reads"] == [-1,-1,-1,-1,-1,9,-1,7,0],
                name + ": must still perform real reads and cleanup")
        try:
            check.check(receiver, reference)
        except ValueError as error:
            reason = str(error)
            require(reason == "negative_then_recovery/100: original read/callback order",
                    name + ": rejected for unrelated reason: " + reason)
        else:
            raise ValueError(name + ": accepted wrong dispatch behavior")
        rows.append(dict(mutation=name, receiver_exit=observed.returncode, observed=native, reason=reason))
    (work / "result.json").write_text(json.dumps(rows, indent=2) + "\n")
    print("Polled discovery: two runnable actual-SDK dispatch mutations rejected by original callback order")


if __name__ == "__main__":
    main()
