"""Observe original media UDP feedback/sendto and resulting SDK recovery.

The shared media helper drives genuine constructors, UDP/crypto, OnThink and SDK.
Observers read real send buffers/returns, stacks and module paths; no function,
return, state or Packet/Frame is supplied. Peer withholding/retry is explicit.
"""

# ruff: noqa: F821
from pathlib import Path

retry_scope = __doc__
retry_path = Path(config["media_helper"])
retry_source = retry_path.read_text()
retry_marker = (
    "# SDK function-table producer is initialized by real negotiation capability calls."
)
assert retry_source.count(retry_marker) == 1
exec(
    compile(retry_source.split(retry_marker, 1)[0], str(retry_path), "exec"), globals()
)
report["scope"] = retry_scope
report["feedback_sends"] = []


class FeedbackReturn(gdb.FinishBreakpoint):
    def __init__(self, item):
        super().__init__(gdb.newest_frame(), internal=True)
        self.item = item

    def stop(self):
        self.item["return"] = int(gdb.parse_and_eval("$rax"))
        return False


class FeedbackSend(gdb.Breakpoint):
    def stop(self):
        size = int(gdb.parse_and_eval("$rdx"))
        if not 13 <= size <= 65536:
            return False
        wire = read(int(gdb.parse_and_eval("$rsi")), size)
        if wire[0] & 127 not in (8, 10) or wire[4] != 3:
            return False
        pcs = []
        frame = gdb.newest_frame()
        for _ in range(16):
            if frame is None:
                break
            pc = int(frame.pc())
            pcs.append(
                dict(
                    pc=pc,
                    source_relative=pc - base
                    if base <= pc < base + 0x1000000
                    else None,
                    name=frame.name(),
                )
            )
            frame = frame.older()
        item = dict(
            wire=wire.hex(),
            thread=gdb.selected_thread().global_num,
            phase=u32(client + 256),
            pictures=len(report["pictures"]),
            sdk_packets=sum(e["name"] == "sdk_send" for e in report["media_events"]),
            stack=pcs,
        )
        report["feedback_sends"].append(item)
        FeedbackReturn(item)
        return False


FeedbackSend("*" + str(symbol("sendto")), internal=True)
retry_table_marker = "exec(\n    compile(\n        media_cleanup_marker"
retry_tail = retry_marker + retry_source.split(retry_marker, 1)[1]
assert retry_tail.count(retry_table_marker) == 1
retry_tail = retry_tail.replace(
    retry_table_marker,
    """report['mapped_sdk']={}
for index,name in ((0,'libavcodec.so.61'),(10,'libavcodec.so.61'),(17,'libavutil.so.59')):
    mapped=Path(gdb.solib_name(table[index])).resolve()
    assert mapped==(Path(config['sdk_directory'])/name).resolve()
    report['mapped_sdk'][str(index)]=dict(path=str(mapped),sha256=hashlib.sha256(mapped.read_bytes()).hexdigest())
"""
    + retry_table_marker,
)
exec(compile(retry_tail, str(retry_path), "exec"), globals())
