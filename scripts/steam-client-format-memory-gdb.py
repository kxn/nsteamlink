"""Observe allocator generations of the original SDK's borrowed format array.

GDB-only helper. Ordinary return-PC observers never replace allocator bodies or
results. The process uses genuine libc allocators and the pinned SDK. This
records completed public allocator operations, not all internal libc objects.
"""

import gdb


def observe_formats(table, dec, output, role, u64, pending, symbol):
    records, watched, borrowed, events = {}, set(), {}, []
    entered, returns, calls = [], {}, {}
    serial = 0

    def complete(api, args, value):
        nonlocal serial
        if api == "free":
            address, generation = args
            record = records.get(address)
            if record and record["generation"] == generation:
                record["live"] = False
            if address in watched:
                events.append(["free_return", role(), address, generation])
            return
        if api == "posix_memalign":
            if value & 0xFFFFFFFF:
                return
            address = u64(args[0])
            size = args[2]
        elif api == "realloc":
            old, size, generation = args
            if value or not size:
                record = records.get(old)
                if record and record["generation"] == generation:
                    record["live"] = False
            address = value
        else:
            address = value
            size = args[0] * args[1] if api == "calloc" else args[-1]
        if not address:
            return
        serial += 1
        records[address] = dict(generation=serial, live=True, api=api, size=size)
        if address in watched:
            events.append(
                ["allocation_return", role(), address, dict(records[address])]
            )

    class Returned(gdb.Breakpoint):
        def stop(self):
            tid = gdb.selected_thread().global_num
            pc = int(gdb.parse_and_eval("$pc"))
            sp = int(gdb.parse_and_eval("$rsp"))
            stack = calls.get((tid, pc, sp))
            if stack:
                api, args = stack.pop()
                if not stack:
                    del calls[(tid, pc, sp)]
                complete(api, args, int(gdb.parse_and_eval("$rax")) & ((1 << 64) - 1))
            return False

    class Entered(gdb.Breakpoint):
        def __init__(self, api, address):
            super().__init__("*" + str(address), internal=True)
            self.api = api

        def stop(self):
            api = self.api
            caller = gdb.newest_frame().older()
            if caller and caller.type() == gdb.DUMMY_FRAME:
                return False  # Explicit fixture malloc, not a program caller.
            count = (
                3
                if api == "posix_memalign"
                else 2
                if api in ("calloc", "realloc", "aligned_alloc", "memalign")
                else 1
            )
            args = tuple(
                int(gdb.parse_and_eval("$" + r)) for r in ("rdi", "rsi", "rdx")[:count]
            )
            if api == "free":
                address = args[0]
                record = records.get(address)
                if not record:
                    return False
                if not record["live"]:
                    # A public-operation observer does not see every libc
                    # internal allocation. Do not attribute reuse to a dead
                    # generation merely because its address matches.
                    if address in watched:
                        events.append(["unattributed_free", role(), address])
                    return False
                args = (address, record["generation"])
                if address in watched:
                    events.append(["free_entry", role(), address, args[1], pending()])
            elif api == "realloc":
                args += (records.get(args[0], {}).get("generation"),)
            tid = gdb.selected_thread().global_num
            sp = int(gdb.parse_and_eval("$rsp"))
            pc = u64(sp)
            if pc not in returns:
                returns[pc] = Returned("*" + str(pc), internal=True)
            calls.setdefault((tid, pc, sp + 8), []).append((api, args))
            return False

    addresses = set()
    for api in (
        "malloc",
        "calloc",
        "realloc",
        "posix_memalign",
        "aligned_alloc",
        "memalign",
        "valloc",
        "free",
    ):
        address = symbol(api)
        if address not in addresses:
            bp = Entered(api, address)
            bp.enabled = False
            entered.append(bp)
            addresses.add(address)

    class Observer:
        def start(self):
            for bp in entered:
                bp.enabled = True

        def snapshot(self):
            return dict(events=events, active_return_observers=len(calls))

        def borrow(self, address, formats):
            record = records[address]
            assert record["live"], (
                "SDK array has no observed live allocation",
                address,
            )
            watched.add(address)
            borrowed[address] = record["generation"]
            events.append(["sdk_borrow", role(), address, dict(record), list(formats)])

        def consume(self):
            if not pending():
                return
            address = u64(dec + 0x2D0)
            events.append(
                [
                    "main_consume",
                    role(),
                    address,
                    borrowed[address],
                    dict(records[address]),
                ]
            )

        def close(self):
            for bp in [*entered, *returns.values()]:
                bp.delete()
            output["format_memory"] = dict(
                scope=__doc__,
                events=events,
                sdk_free_override=u64(table[17] - 0x32500 + 0x104AA8),
            )

    return Observer()
