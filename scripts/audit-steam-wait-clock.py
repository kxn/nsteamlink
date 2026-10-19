#!/usr/bin/env python3
"""Execute the official auto-reset event constructor and Wait deadline arithmetic.

Original CThreadEvent/anonymous initialization/Set/Wait execute. pthread attribute,
mutex/condition and clock_gettime are explicit OS terminals; controlled clock
values are not a real system time change. Spurious/EINTR returns do not alter the
event. No decoder, kernel latency, physical Switch or Steam host claim is made.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "overlap", ROOT / "scripts/audit-steam-decoder-overlap.py"
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Clock(m.Slow):
    def __init__(self, binary):
        self.clock_probe = False
        super().__init__(binary)
        self.clock_probe = True
        self.trace = []
        self.now = (15, 999500000)
        self.returns = []
        self.fail = ""
        self.event = self.alloc(256)

    def hook(self, u, pc, size, data):
        name = self.plts.get(pc, "")
        if self.clock_probe:
            if name == "strerror":
                self.ret(self.event)  # Diagnostic string terminal; zero-filled storage.
                return
            if name in (
                "pthread_mutexattr_init",
                "pthread_mutexattr_destroy",
                "pthread_condattr_init",
                "pthread_condattr_destroy",
                "pthread_mutex_init",
                "pthread_cond_init",
                "pthread_mutex_destroy",
                "pthread_mutex_lock",
                "pthread_mutex_unlock",
                "pthread_cond_signal",
            ):
                self.trace.append([name])
                self.ret(22 if name == self.fail else 0)
                return
            if name == "pthread_condattr_setclock":
                self.trace.append([name, self.r(1)])
                self.ret(22 if name == self.fail else 0)
                return
            if name == "clock_gettime":
                self.trace.append([name, self.r(0), *self.now])
                self.u.mem_write(self.r(1), struct.pack("<qq", *self.now))
                self.ret(0)
                return
            if name in ("pthread_cond_wait", "pthread_cond_timedwait"):
                deadline = (
                    list(struct.unpack("<qq", self.u.mem_read(self.r(2), 16)))
                    if name.endswith("timedwait")
                    else None
                )
                result = self.returns.pop(0)
                self.trace.append([name, deadline, result])
                self.ret(result)
                return
        super().hook(u, pc, size, data)


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == m.c.SHA
    cases = []
    for name, timeout, returns, signaled in [
        ("zero", 0, [], False),
        ("one_ms_carry", 1, [110], False),
        ("sixteen_ms", 16, [110], False),
        ("whole_second", 1000, [110], False),
        ("large_unsigned", 0xFFFFFFFE, [110], False),
        ("spurious", 1, [0, 0, 110], False),
        ("eintr", 1, [4, 110], False),
        ("ordinary_error", 1, [22], False),
        ("infinite_error", 0xFFFFFFFF, [22], False),
        ("early_signal", 1, [], True),
        ("early_signal_infinite", 0xFFFFFFFF, [], True),
    ]:
        x = Clock(binary)
        x.call(0x90D390, x.event, 0)
        initialized = x.u.mem_read(x.event + 108, 1)[0]
        if signaled:
            x.call(0x90D9EC, x.event)
        x.returns = returns.copy()
        result = x.call(0x90D124, x.event, timeout)
        assert not x.returns and initialized == 1 and not x.assertions
        cases.append(
            dict(
                name=name,
                timeout=timeout,
                now=list(x.now),
                returns=returns,
                signaled=signaled,
                result=result,
                trace=x.trace,
                signaled_after=x.u.mem_read(x.event + 110, 1)[0],
            )
        )
    failures = []
    for failure in (
        "pthread_mutexattr_init",
        "pthread_condattr_init",
        "pthread_condattr_setclock",
        "pthread_mutex_init",
        "pthread_cond_init",
    ):
        x = Clock(binary)
        x.fail = failure
        x.call(0x90D390, x.event, 0)
        failures.append(
            dict(
                failure=failure,
                initialized=x.u.mem_read(x.event + 108, 1)[0],
                trace=x.trace,
            )
        )
    from elftools.elf.elffile import ELFFile
    import io

    text = ELFFile(io.BytesIO(binary)).get_section_by_name(".text")
    code, base = text.data(), text["sh_addr"]
    functions = [
        dict(
            name=n,
            address=a,
            size=s,
            sha256=hashlib.sha256(code[a - base : a - base + s]).hexdigest(),
        )
        for n, a, s in [
            ("EventConstructor", 0x90D390, 80),
            ("AnonymousEvent", 0x90D3E0, 300),
            ("EventSet", 0x90D9EC, 180),
            ("SyncWait", 0x90D124, 400),
        ]
    ]
    return dict(
        binary_sha256=m.c.SHA,
        boundary=__doc__,
        functions=functions,
        cases=cases,
        failures=failures,
    )


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--write", type=Path)
    p.add_argument("--check", type=Path)
    a = p.parse_args()
    result = audit(a.binary.read_bytes())
    if a.write:
        a.write.write_text(json.dumps(result, indent=2) + "\n")
    if a.check:
        assert result == json.loads(a.check.read_text())
    print("Original wait clock: 11 waits, 5 constructor failures")
