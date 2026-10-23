#!/usr/bin/env python3
"""Execute core's common JNI completion and the pinned Java callback bytecode.

Original ARM64 flag selection, JNIActivity ctor and two JNI varargs wrappers
run. JNI class/object/method services are explicit providers.
The tiny DEX interpreter executes the original callback instructions; audio and
Wi-Fi helper bodies are terminals. System.exit records an exit request and
terminates this fixture, NOT a real Android process. OS task restoration, Qt
event-loop return, a new manager, streaming recovery and Switch are unproved.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts/audit-steam-client-fec-policy.py"
spec = importlib.util.spec_from_file_location("policy", SOURCE)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
CORE_SHA = "50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e"
DEX_SHA = "a5c315d683eac7c7f8f73ec096bd414406d80f9ef68180a1ef469f052cd39e44"
APK_SHA = "7114b75e6fdd55e7bdcbad643cd1e7baf8cf5060da820120435adaefc6004dfc"
LINK = "Lcom/valvesoftware/steamlink/SteamLink;"
SHELL = "Lcom/valvesoftware/steamlink/SteamShellActivity;"
MUTATIONS = ("omit-jni-callback", "callback-returns", "exit-uses-result", "omit-wifi-unlock")


class ExitRequest(Exception):
    pass


class Dex:
    def __init__(self, binary, mutation=None):
        assert hashlib.sha256(binary).hexdigest() == DEX_SHA, "DEX identity"
        self.raw = binary
        string_count, strings = struct.unpack_from("<II", binary, 56)
        self.strings = []
        for index in range(string_count):
            offset = struct.unpack_from("<I", binary, strings + 4 * index)[0]
            _, start = self.uleb(offset)
            self.strings.append(binary[start:binary.index(b"\0", start)].decode("utf-8", errors="strict"))
        type_count, types = struct.unpack_from("<II", binary, 64)
        self.types = [self.strings[struct.unpack_from("<I", binary, types + i * 4)[0]] for i in range(type_count)]
        proto_count, protos = struct.unpack_from("<II", binary, 72)
        signatures = []
        for i in range(proto_count):
            _, result, params = struct.unpack_from("<III", binary, protos + 12 * i)
            args = [] if not params else [self.types[t] for t in struct.unpack_from(
                "<" + "H" * struct.unpack_from("<I", binary, params)[0], binary, params + 4)]
            signatures.append("(" + "".join(args) + ")" + self.types[result])
        count, table = struct.unpack_from("<II", binary, 88)
        self.methods = []
        for i in range(count):
            cls, proto, name = struct.unpack_from("<HHI", binary, table + 8 * i)
            self.methods.append((self.types[cls], self.strings[name], signatures[proto]))
        self.code, self.supers = {}, {}
        count, table = struct.unpack_from("<II", binary, 96)
        for i in range(count):
            cls, _, parent, _, _, _, data, _ = struct.unpack_from("<8I", binary, table + 32 * i)
            self.supers[self.types[cls]] = self.types[parent] if parent != 0xFFFFFFFF else None
            if not data:
                continue
            sizes = []
            for _ in range(4):
                value, data = self.uleb(data)
                sizes.append(value)
            for _ in range(sizes[0] + sizes[1]):
                _, data = self.uleb(data)
                _, data = self.uleb(data)
            for number in sizes[2:]:
                index = 0
                for _ in range(number):
                    diff, data = self.uleb(data)
                    flags, data = self.uleb(data)
                    offset, data = self.uleb(data)
                    index += diff
                    if not offset:
                        continue
                    registers, ins, _, _, _, units = struct.unpack_from("<4H2I", binary, offset)
                    self.code[self.methods[index]] = dict(offset=offset, registers=registers, ins=ins,
                        flags=flags, bytes=bytearray(binary[offset + 16:offset + 16 + units * 2]))
        if mutation:
            if mutation in ("callback-returns", "exit-uses-result"):
                code = self.code[(SHELL, "onStreamingResult", "(I)V")]["bytes"]
                assert code.hex() == "12007110840400000e00", "callback mutation signature"
                if mutation == "callback-returns": code[2:8] = bytes(6)
                # This method has a single parameter/local register: the
                # original const overwrites its input. NOP that const to pass
                # the real result, rather than inventing an out-of-range reg.
                else: code[0:2] = bytes(2)
            if mutation == "omit-wifi-unlock":
                code = self.code[(LINK, "streamingComplete", "(I)V")]["bytes"]
                assert code[8:14].hex() == "70108c030100", "Wi-Fi mutation signature"
                code[8:14] = bytes(6)
        self.events = []

    def uleb(self, offset):
        value, shift = 0, 0
        for _ in range(5):
            byte = self.raw[offset]
            offset += 1
            value |= (byte & 127) << shift
            if byte < 128: return value, offset
            shift += 7
        raise AssertionError("DEX uleb limit")

    def run(self, method, arguments):
        entry = self.code[method]
        regs, code = [0] * entry["registers"], entry["bytes"]
        assert len(arguments) == entry["ins"], ("DEX argument count", method)
        if arguments: regs[-len(arguments):] = arguments
        pc = 0
        while pc < len(code):
            word = struct.unpack_from("<H", code, pc)[0]
            opcode = word & 255
            if opcode == 0: pc += 2; continue
            if opcode == 0x12:
                value = word >> 12
                regs[(word >> 8) & 15] = value - 16 if value & 8 else value
                pc += 2
                continue
            if opcode == 0x0E: return
            assert opcode in (0x70, 0x71), ("unsupported callback opcode", hex(opcode), method, pc)
            count, last = word >> 12, (word >> 8) & 15
            target, values = struct.unpack_from("<HH", code, pc + 2)
            indices = [(values >> (i * 4)) & 15 for i in range(4)] + [last]
            assert count <= 5
            args = [regs[index] for index in indices[:count]]
            name = self.methods[target]
            self.events.append(dict(method=list(name), args=args))
            if name in ((SHELL, "onStreamingResult", "(I)V"), (SHELL, "onShellComplete", "()V")):
                self.run(name, args)
            elif name == ("Ljava/lang/System;", "exit", "(I)V"):
                raise ExitRequest(args[0])
            else:
                assert name in ((LINK, "setLowLatencyAudio", "(Z)V"), (LINK, "disableWiFiLock", "()V")), ("undeclared Java terminal", name)
            pc += 6


class Completion(policy.Shell):
    def __init__(self, core, dex, background, hard, mutation):
        self.enabled = False
        super().__init__(core)
        self.dex, self.trace, self.exit_status = dex, [], None
        self.continued = False
        self.env, table = self.alloc(8), self.alloc(2048)
        self.wq(self.env, table)
        self.base_class, self.object_class, self.object, self.context_method, self.method = [self.alloc(8) for _ in range(5)]
        self.adapters = {}
        for offset, name in ((0x30, "FindClass"), (0x388, "GetStaticMethodID"),
                             (0x398, "CallStaticObjectMethodV"),
                             (0xF8, "GetObjectClass"), (0xB8, "DeleteLocalRef"),
                             (0x108, "GetMethodID"), (0x1F0, "CallVoidMethodV")):
            address = self.alloc(16)
            self.adapters[address] = name
            self.wq(table + offset, address)
        self.b(self.symbols["g_bBackgroundShutdown"], background)
        self.b(self.symbols["g_bHardShutdown"], hard)
        if mutation == "omit-jni-callback":
            assert bytes(self.u.mem_read(0x75D060, 4)).hex() == "5cb61294", "native mutation signature"
            self.u.mem_write(0x75D060, bytes.fromhex("1f2003d5"))
        self.enabled = True

    def hook(self, u, pc, size, context):
        if not self.enabled: return super().hook(u, pc, size, context)
        if pc == 0x75D064:
            self.continued = True
            return self.jump(policy.STOP)
        name = self.plts.get(pc, "")
        if name == "SDL_Quit":
            self.trace.append(dict(operation="SDL_Quit"))
            return self.ret()
        if name == "SDL_GetAndroidJNIEnv": return self.ret(self.env)
        if name in ("_ZN11JNIActivityC2EP7_JNIEnv", "_ZN7_JNIEnv14CallVoidMethodEP8_jobjectP10_jmethodIDz") or "CallStaticObjectMethod" in name:
            return self.jump(self.symbols[name])  # Run ctor and both varargs wrappers.
        if pc in self.adapters:
            operation = self.adapters[pc]
            event = dict(operation=operation)
            if operation == "FindClass":
                event["name"] = self.cstring(self.r(1))
                assert event["name"] == "org/libsdl/app/SDL"
                result = self.base_class
            elif operation == "GetStaticMethodID":
                event.update(name=self.cstring(self.r(2)), signature=self.cstring(self.r(3)))
                assert event["name"] == "getContext" and event["signature"] == "()Landroid/app/Activity;"
                result = self.context_method
            elif operation == "CallStaticObjectMethodV":
                assert [self.r(i) for i in range(3)] == [self.env, self.base_class, self.context_method]
                result = self.object
            elif operation == "GetObjectClass":
                assert self.r(1) == self.object
                result = self.object_class
            elif operation == "DeleteLocalRef":
                assert self.r(1) == self.base_class
                result = 0
            elif operation == "GetMethodID":
                event.update(name=self.cstring(self.r(2)), signature=self.cstring(self.r(3)))
                assert self.r(1) == self.object_class
                assert (event["name"], event["signature"]) == ("streamingComplete", "(I)V")
                result = self.method
            else:
                assert self.r(1) == self.object and self.r(2) == self.method
                va = self.r(3)
                offset = struct.unpack("<i", bytes(u.mem_read(va + 24, 4)))[0]
                assert offset < 0, "ARM64 register varargs input"
                argument = struct.unpack("<i", bytes(u.mem_read(self.q(va + 8) + offset, 4)))[0]
                event["argument"] = argument
                self.trace.append(event)
                try:
                    self.dex.run((LINK, "streamingComplete", "(I)V"), ["SteamLink-instance", argument])
                except ExitRequest as exit:
                    self.exit_status = exit.args[0]
                    return self.jump(policy.STOP)
                return self.ret()
            self.trace.append(event)
            return self.ret(result)
        return super().hook(u, pc, size, context)


def audit(args):
    core, dex = args.core.read_bytes(), args.dex.read_bytes()
    assert hashlib.sha256(core).hexdigest() == CORE_SHA
    with zipfile.ZipFile(args.apk) as apk:
        assert hashlib.sha256(args.apk.read_bytes()).hexdigest() == APK_SHA
        assert apk.read("classes.dex") == dex
        manifest = apk.read("AndroidManifest.xml")
    xml = subprocess.run([str(args.aapt), "dump", "xmltree", str(args.apk), "AndroidManifest.xml"],
                         check=True, capture_output=True, text=True, timeout=30).stdout
    assert 'android:process(' not in xml, "this manifest does not separate the activities"
    assert 'com.valvesoftware.steamlink.SteamShellActivity' in xml and 'com.valvesoftware.steamlink.SteamLink' in xml
    cases = []
    expected_methods = ["setLowLatencyAudio", "disableWiFiLock", "onStreamingResult", "exit"]
    for background in (0, 1):
        for hard in (0, 1):
            d = Dex(dex, args.mutation)
            m = Completion(core, d, background, hard, args.mutation)
            m.call(0x75CFD4)
            expected_argument = 0 if background or hard else -1
            assert m.exit_status == 0 and not m.continued, "Java completion requests exit instead of returning to native caller"
            assert [event["method"][1] for event in d.events] == expected_methods, "ordered Java cleanup/result dispatch"
            assert d.events[0]["args"][-1] == 0 and d.events[2]["args"] == [expected_argument], "native flag-derived result argument"
            assert sum(event["operation"] == "SDL_Quit" for event in m.trace) == (not background), "native background SDL policy"
            cases.append(dict(background=background, hard=hard, native=m.trace, java=d.events,
                              exit_request=m.exit_status, returned_to_native=m.continued))
    for result in (-2147483648, -1, 0, 1, 255, 2147483647):
        d = Dex(dex, args.mutation)
        try: d.run((SHELL, "onStreamingResult", "(I)V"), [result])
        except ExitRequest as exit: status = exit.args[0]
        else: status = None
        assert status == 0, "Java callback ignores result and requests status zero"
        cases.append(dict(result=result, java=d.events, exit_request=status))
    d = Dex(dex, args.mutation)
    try: d.run((SHELL, "onShellComplete", "()V"), [])
    except ExitRequest as exit: status = exit.args[0]
    else: status = None
    assert status == 0, "shell completion exit"
    cases.append(dict(method="onShellComplete", java=d.events, exit_request=status))
    selected = {(LINK, "streamingComplete", "(I)V"), (SHELL, "onStreamingResult", "(I)V"),
                (SHELL, "onShellComplete", "()V"), (SHELL, "startStreaming", "([Ljava/lang/String;I)V")}
    return dict(scope=__doc__, core_sha256=CORE_SHA, dex_sha256=DEX_SHA, apk_sha256=APK_SHA,
                manifest_sha256=hashlib.sha256(manifest).hexdigest(), manifest_process_attributes=[],
                native_entry="0x75cfd4", native_continuation="0x75d064",
                original_ranges={hex(start): dict(size=end-start,
                    sha256=hashlib.sha256(policy.load_image(core)[0][start:end]).hexdigest())
                    for start, end in ((0x75CFD4, 0x75D064), (0x75D768, 0x75D810),
                                       (0x75D838, 0x75D8D4), (0x75DA28, 0x75DAC4))},
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                provider_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                activity_super=d.supers[LINK], methods=[dict(identity=list(key), **{k: v.hex() if k == "bytes" else v
                    for k, v in d.code[key].items()}) for key in sorted(selected)], cases=cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("core", "dex", "apk", "aapt", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--mutation", choices=MUTATIONS)
    args = parser.parse_args()
    args.output.write_text(json.dumps(audit(args), indent=2) + "\n")


if __name__ == "__main__":
    main()
