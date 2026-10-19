"""Configured-decoder barrier and per-socket Linux drop snapshot for large AU.

Inherit read-only pressure observations. Transform only the Python fixture's
start/stop notifications, not original instructions, packets, state or results.
The stream still uses the real worker/OnThink/SDK. No rendering/device claim.
"""

# ruff: noqa: F821
import hashlib
from pathlib import Path

_large_load_path = Path(config["load_helper"])
_large_source = _large_load_path.read_text()
_large_begin = 'Path(config["stage_file"]).write_text("start")'
assert _large_source.count(_large_begin) == 1
_large_source = _large_source.replace(
    _large_begin,
    'Path(config["stage_file"]).write_text("prepare")\nlarge_ready = False',
)
_large_tick = '    call("void(*)(void*)", base + 0x3230A0, client)\n'
assert _large_source.count(_large_tick) == 1
_large_source = _large_source.replace(
    _large_tick,
    _large_tick
    + """    if not large_ready and u64(client + 40):
        large_ready = True
        decoder = u64(client + 40)
        report["large_ready"] = dict(active=read(decoder + 24, 1)[0], phase=u32(client + 256))
        Path(config["stage_file"]).write_text("start")
""",
)
_large_end = '        Path(config["stage_file"]).write_text("stop")'
assert _large_source.count(_large_end) == 1
_large_source = _large_source.replace(
    _large_end,
    """        port = int(Path(config["port_file"]).read_text())
        matches = []
        for family in ("udp", "udp6"):
            rows = Path("/proc/" + str(inf.pid) + "/net/" + family).read_text().splitlines()[1:]
            matches.extend((family, int(row.split()[-1])) for row in rows if int(row.split()[1].split(":")[-1], 16) == port)
        assert len(matches) == 1, (port, matches)
        report["large_socket"] = dict(port=port, family=matches[0][0], drops=matches[0][1])
"""
    + _large_end,
)
_large_pressure_path = Path(config["pressure_helper"])
_large_pressure = _large_pressure_path.read_text()
_large_assignment = "_pressure_source = _pressure_path.read_text()"
assert _large_pressure.count(_large_assignment) == 1
_large_pressure = _large_pressure.replace(
    _large_assignment, "_pressure_source = _large_source"
)
_large_marker = '_pressure_marker = \'Path(config["stage_file"]).write_text("start")\''
assert _large_pressure.count(_large_marker) == 1
_large_pressure = _large_pressure.replace(
    _large_marker, "_pressure_marker = 'slot = alloc(8)'"
)
_large_report = 'report["pressure_flow"] = []'
assert _large_pressure.count(_large_report) == 1
_large_pressure = _large_pressure.replace(
    _large_report, _large_report + '\nreport["large_derived_sha256"] = _large_derived'
)
# Hash the exact derived fixture programs, in addition to the immutable helpers.
_large_derived = [
    hashlib.sha256(s.encode()).hexdigest() for s in (_large_source, _large_pressure)
]
exec(compile(_large_pressure, str(_large_pressure_path), "exec"), globals())
