"""Inherit original live worker/SDK observations; add read-only recovery traces.

The existing GapDecode/GapSend breakpoints observe original state and sendto
returns. No decoder flags, packets, entry points, clocks or results are written.
Inherited headless driver, configured-start and zero-delay SDK forwarding are
explicit boundaries; breakpoint overhead prevents performance claims.
"""

# ruff: noqa: F821
import ast
import hashlib
from pathlib import Path

path = Path(config["gap_helper"])
source = path.read_text()
tree = ast.parse(source)
names = {"gap_state", "GapDecodeReturn", "GapDecode", "GapSendReturn", "GapSend"}
pieces = [
    ast.get_source_segment(source, n)
    for n in tree.body
    if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names
]
assert len(pieces) == len(names)
# Correlate actual socket requests with the current original decoder input;
# waiting-key retries need not coincide with entering strict mode.
send_piece = next(
    i for i, piece in enumerate(pieces) if piece.startswith("class GapSend(")
)
needle = "wire=wire.hex(),"
assert pieces[send_piece].count(needle) == 1
pieces[send_piece] = pieces[send_piece].replace(
    needle,
    needle
    + '\n            input_id=report["load_frames"][-1],'
    + "\n            consumed=pressure_consumed,",
)
observer = "report.update(gap_states=[], gap_sends=[])\n" + "\n\n".join(pieces)
observer += '\nGapDecode("*" + str(base + 0x3260D0), internal=True)\n'
observer += 'GapSend("*" + str(symbol("sendto")), internal=True)\n'
observer += 'report["reorder_derived_sha256"] = reorder_derived\n'
pressure_path = Path(config["pressure_helper"])
reorder_pressure = pressure_path.read_text()
marker = 'report["pressure_flow"] = []'
assert reorder_pressure.count(marker) == 1
reorder_pressure = reorder_pressure.replace(marker, marker + "\n" + observer)
large_path = Path(config["large_helper"])
large_source = large_path.read_text()
assignment = "_large_pressure = _large_pressure_path.read_text()"
assert large_source.count(assignment) == 1
large_source = large_source.replace(assignment, "_large_pressure = reorder_pressure")
reorder_derived = [
    hashlib.sha256(s.encode()).hexdigest()
    for s in (observer, reorder_pressure, large_source)
]
exec(compile(large_source, str(large_path), "exec"), globals())
