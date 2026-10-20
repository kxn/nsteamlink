"""Observe original UDP APIs with a bounded caller-controlled scheduling window.

The external DSO calls original APIs/clock/rate setter. scheduler-locking affects
OS scheduling only during the batch; Source instructions/data are not patched.
Breakpoints are temporarily disabled to avoid debugger latency between APIs;
original assertion observation remains enabled. Peer datagrams are primary wire
observations, rather than absent sendto breakpoints during that interval.
"""

# ruff: noqa: F821
from pathlib import Path

_path = Path(config["mic_helper"])
_source = _path.read_text()
_begin = _source.index('call("void(*)(void*)", base + 0x31BD50, client)')
_end = _source.index("for _mic_attempt in range(1000):", _begin)
_batch = """_handle=call('void*(*)(void*,int)',symbol('dlopen'),string(config['driver'].encode()),2)
assert _handle
_fn=call('void*(*)(void*,void*)',symbol('dlsym'),_handle,string(b'nsl_mic_reorder'))
assert _fn
_trace=alloc(160)
_breakpoints=[b for b in gdb.breakpoints() if b.enabled and not isinstance(b,gdb.FinishBreakpoint) and not (isinstance(b,Observe) and b.name=='assert')]
for _bp in _breakpoints:
    _bp.enabled=False
try:
    if config['lock_network_thread']:
        gdb.execute('set scheduler-locking on')
    _result=call('int(*)(void*,unsigned long,void*,void*)',_fn,client,base,_mic_raw,_trace)
finally:
    gdb.execute('set scheduler-locking off')
    for _bp in _breakpoints:
        _bp.enabled=True
assert _result==0
report['schedule_trace']=[[u32(_trace+20*i+4*j) for j in range(5)] for i in range(8)]
report['schedule_lock_network']=config['lock_network_thread']
mic_state('fast_batch')
call('int(*)(void*)',symbol('dlclose'),_handle)
"""
_source = _source[:_begin] + _batch + _source[_end:]
_wait = _source.index("for _mic_attempt in range(1000):", _begin)
_predicate = _source.index("    if ", _wait)
_break = _source.index("        break", _predicate)
_source = (
    _source[:_predicate]
    + "    if Path(config['schedule_done']).exists():\n"
    + _source[_break:]
)
exec(compile(_source, str(_path), "exec"), globals())
