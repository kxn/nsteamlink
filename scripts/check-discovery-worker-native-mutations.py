#!/usr/bin/env python3
"""Reject runnable initialization-order regressions in the real runtime worker.

Compile copies of runtime/oracle; never replace production source or objects.
Each variant must emit valid observations after normal public teardown. Compiler
errors, signals, fixture failures and unrelated comparator failures do not count.
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
    build, output = args.build.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location("worker_check", ROOT / "scripts/check-steam-discovery-worker.py")
    check = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(check)
    plan = next(plan for plan in check.plans() if plan["mode"] == "socket")
    check.verify(build / "app/nsl-discovery-worker-runtime", plan)
    runtime = (ROOT / "app/platforms/common/runtime.c").read_text()
    initial = """    if (!ensure_control(r))
        fail(r, sl_tr(SL_T_NETWORK_UNAVAILABLE));"""
    cloud = """    if (!r->remote)
        start_cloud(r);"""
    require(runtime.count(initial) == runtime.count(cloud) == 1, "unique initialization anchors")
    variants = {
        "cloud-created-after-local-failure": (runtime.replace(initial, """    if (!start_client(r))
        fail(r, sl_tr(SL_T_NETWORK_UNAVAILABLE));
    start_cloud(r);"""), "socket: cloud constructed after failed local initialization"),
        "cloud-not-created-on-explicit-retry": (runtime.replace(cloud, "    /* omitted retry cloud construction */")
            .replace(initial, initial + "\n    if (r->client) start_cloud(r);"),
            "socket: explicit startup did not construct exactly one cloud owner"),
    }
    driver = ROOT / "app/tests/discovery_worker_runtime.c"
    include = '#include "../platforms/common/runtime.c"'
    require(driver.read_text().count(include) == 1, "actual runtime include")
    entry = next(row for row in json.loads((build / "compile_commands.json").read_text()) if Path(row["file"]) == driver)
    directory = build / "app"
    link = shlex.split((directory / "CMakeFiles/nsl-discovery-worker-runtime.dir/link.txt").read_text())
    rows = []
    for name, (changed, reason) in variants.items():
        folder = output / name
        folder.mkdir(exist_ok=True)
        source, obj, receiver = folder / driver.name, folder / "receiver.o", folder / "receiver"
        (folder / "runtime.c").write_text(changed)
        source.write_text(driver.read_text().replace(include, '#include "runtime.c"'))
        command = [str(source) if value == str(driver) else value for value in shlex.split(entry["command"])]
        command[command.index("-o") + 1] = str(obj)
        command += ["-I", str(driver.parent)]
        compiled = subprocess.run(command, cwd=entry["directory"], capture_output=True, text=True, timeout=40)
        (folder / "compile.log").write_text(compiled.stdout + compiled.stderr)
        require(compiled.returncode == 0, name + ": compile failure")
        command = [str(obj) if value.endswith("nsl-discovery-worker-runtime.dir/tests/discovery_worker_runtime.c.o")
                   else "-Wl,--dependency-file=" + str(folder / "link.d") if value.startswith("-Wl,--dependency-file=")
                   else value for value in link]
        require(str(obj) in command, "replace actual test object")
        command[command.index("-o") + 1] = str(receiver)
        linked = subprocess.run(command, cwd=directory, capture_output=True, text=True, timeout=40)
        (folder / "link.log").write_text(linked.stdout + linked.stderr)
        require(linked.returncode == 0, name + ": link failure")
        observed = subprocess.run([str(receiver), plan["mode"], str(plan["error"]), plan["name"]],
                                  capture_output=True, text=True, timeout=10)
        require(observed.returncode == 0, name + ": abnormal fixture: " + observed.stderr)
        native = json.loads(observed.stdout)
        require(native["runtime_joins"] == 1 and native["opens"] == native["closes"] == 1 and
                native["callbacks"] == [[5,9],[6,7]], "normal receive/teardown despite wrong initialization")
        try:
            check.verify(receiver, plan)
        except ValueError as error:
            require(str(error) == reason, name + ": unrelated rejection: " + str(error))
        else:
            raise ValueError(name + ": accepted wrong initialization order")
        rows.append(dict(mutation=name, receiver_exit=0, observed=native, reason=reason))
    (output / "result.json").write_text(json.dumps(rows, indent=2) + "\n")
    print("Discovery worker: two runnable actual-runtime initialization regressions rejected")


if __name__ == "__main__":
    main()
