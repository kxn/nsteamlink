#!/usr/bin/env python3
"""Observe a real joined pthread still represented in Linux procfs, if scheduled.

This is a kernel observation experiment, not Steam policy or a device test.
No observed overlap is an explicit inconclusive result; no timing is forced.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

SOURCE = r"""
#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <assert.h>
static atomic_long tid;
static void *worker(void *unused) {
    (void)unused;atomic_store(&tid,syscall(SYS_gettid));return NULL;
}
int main(int argc,char **argv) {
    assert(argc==2);unsigned rounds=(unsigned)strtoul(argv[1],NULL,10);
    for(unsigned n=0;n<rounds;n++) {
        pthread_t thread;assert(!pthread_create(&thread,NULL,worker,NULL));
        int joined=pthread_join(thread,NULL);assert(!joined);
        char path[128],line[1024];
        snprintf(path,sizeof(path),"/proc/self/task/%ld/stat",atomic_load(&tid));
        FILE *file=fopen(path,"r");
        if(!file) continue;
        if(fgets(line,sizeof(line),file)) {
            printf("OBSERVED %u %ld %d\n%s",n+1,atomic_load(&tid),joined,line);
            assert(!fclose(file));return 0;
        }
        assert(!fclose(file));
    }
    printf("INCONCLUSIVE %u\n",rounds);return 0;
}
"""


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--rounds", type=int, default=100000)
    a = p.parse_args()
    assert os.uname().sysname == "Linux" and 0 < a.rounds <= 1000000
    with tempfile.TemporaryDirectory(prefix="joined-task-") as directory:
        directory = Path(directory)
        source, binary = directory / "probe.c", directory / "probe"
        source.write_text(SOURCE)
        compiler = shlex.split(os.environ.get("CC", "cc"))
        subprocess.run(
            [
                *compiler,
                "-Wall",
                "-Wextra",
                "-O2",
                "-pthread",
                str(source),
                "-o",
                str(binary),
            ],
            check=True,
            timeout=60,
        )
        result = subprocess.run(
            [str(binary), str(a.rounds)], capture_output=True, text=True, timeout=60
        )
        assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    header = lines[0].split()
    report = dict(
        scope=__doc__,
        kernel=os.uname().release,
        source_sha256=hashlib.sha256(SOURCE.encode()).hexdigest(),
        observed=header[0] == "OBSERVED",
        rounds=int(header[1]),
        raw_stdout=result.stdout,
    )
    if report["observed"]:
        tid, joined = map(int, header[2:])
        fields = lines[1].rsplit(")", 1)[1].split()
        assert int(lines[1].split()[0]) == tid and joined == 0
        assert int(fields[6]) & 4  # PF_EXITING, not an active user-space worker.
        report.update(
            tid=tid, join_return=joined, task_state=fields[0], task_flags=int(fields[6])
        )
    else:
        assert header[0] == "INCONCLUSIVE"
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        "Joined task overlap observed"
        if report["observed"]
        else "Inconclusive: no overlap observed"
    )


if __name__ == "__main__":
    main()
