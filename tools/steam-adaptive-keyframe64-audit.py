#!/usr/bin/env python3
"""Execute DataLost -> original host encoder -> NVENC FORCEIDR -> output latch.

This extends the loss and NVENC audits, using their declared fixtures/terminals.
The original shared encoder loop, pending query, NVENC input-ring operations,
parameter construction, bitstream retrieval, buffer copy, descriptor flag update
and actual session output callback run together. Driver API results/data are
explicit fixtures, NOT an NVENC device. Pixel copy, CRT strings, platform clock/
elapsed time and timer construction are additional terminals; no physical
encoding, CRC/authentication or network is exercised. The output fixture may
deliberately return P/I/zero-byte output despite FORCEIDR: request and result are
independent. No algorithm consumes a hand-cleared session pending flag.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

import pefile

ROOT = Path(__file__).resolve().parents[1]


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


loss = module("loss64", "tools/steam-adaptive-loss64-audit.py")
nvenc = module("nvenc64", "tools/steam-adaptive-nvenc64-audit.py")
loss.feedback.config.host.NODES.update({
    0x13A1B1610: "encoder_frame_wrapper",
    0x13A1B5490: "nvenc_prepare_entry",
    0x13A1B16D0: "shared_encode_loop",
    0x13A1B1230: "shared_encode_call",
    0x13A1B46C0: "nvenc_encode_picture",
    0x13A1B5980: "nvenc_retrieve_output",
    0x13A1B5AD0: "nvenc_picture_type_decode",
    0x13A1A4520: "stage_failure_latch",
})
PATCHES = {
    "pending-query": (0x13A18B2C8, "0f95c0", "0f94c0"),
    "pending-force": (0x13A1B18B2, "7505", "9090"),
    "force-idr": (0x13A1B4B5C, "838d7005000002", "90909090909090"),
    "idr-result": (0x13A1B5ADA, "0f94c0", "0f95c0"),
    "pending-clear": (0x13A18B87A, "8787940c0000", "909090909090"),
    "failure-latch": (0x13A1A4520, "c6411801", "90909090"),
}


def picture_layout(header):
    layout = nvenc.sdk_layout(header)
    # The pinned primary SDK header names the offsets actually observed at
    # original driver boundaries. It supplies ABI, not any emulated algorithm.
    fields = {
        "api_picture": "offsetof(NV_ENCODE_API_FUNCTION_LIST,nvEncEncodePicture)",
        "api_lock_input": "offsetof(NV_ENCODE_API_FUNCTION_LIST,nvEncLockInputBuffer)",
        "api_unlock_input": "offsetof(NV_ENCODE_API_FUNCTION_LIST,nvEncUnlockInputBuffer)",
        "api_lock_output": "offsetof(NV_ENCODE_API_FUNCTION_LIST,nvEncLockBitstream)",
        "api_unlock_output": "offsetof(NV_ENCODE_API_FUNCTION_LIST,nvEncUnlockBitstream)",
        "picture_size": "sizeof(NV_ENC_PIC_PARAMS)",
        "picture_flags": "offsetof(NV_ENC_PIC_PARAMS,encodePicFlags)",
        "picture_time": "offsetof(NV_ENC_PIC_PARAMS,inputTimeStamp)",
        "picture_input": "offsetof(NV_ENC_PIC_PARAMS,inputBuffer)",
        "picture_output": "offsetof(NV_ENC_PIC_PARAMS,outputBitstream)",
        "lock_input_data": "offsetof(NV_ENC_LOCK_INPUT_BUFFER,bufferDataPtr)",
        "lock_input_pitch": "offsetof(NV_ENC_LOCK_INPUT_BUFFER,pitch)",
        "output_size": "offsetof(NV_ENC_LOCK_BITSTREAM,bitstreamSizeInBytes)",
        "output_time": "offsetof(NV_ENC_LOCK_BITSTREAM,outputTimeStamp)",
        "output_data": "offsetof(NV_ENC_LOCK_BITSTREAM,bitstreamBufferPtr)",
        "output_type": "offsetof(NV_ENC_LOCK_BITSTREAM,pictureType)",
        "force_idr": "NV_ENC_PIC_FLAG_FORCEIDR",
        "type_p": "NV_ENC_PIC_TYPE_P", "type_i": "NV_ENC_PIC_TYPE_I",
        "type_idr": "NV_ENC_PIC_TYPE_IDR",
        "picture_version": "NV_ENC_PIC_PARAMS_VER",
        "input_version": "NV_ENC_LOCK_INPUT_BUFFER_VER",
        "output_version": "NV_ENC_LOCK_BITSTREAM_VER",
    }
    source = '#include <stddef.h>\n#include <stdio.h>\n#include "nvEncodeAPI.h"\nint main(void){puts("{");\n'
    for index, (key, expression) in enumerate(fields.items()):
        comma = "," if index + 1 < len(fields) else ""
        source += f'printf("\\\"{key}\\\":%llu{comma}\\n",(unsigned long long)({expression}));\n'
    source += 'puts("}");return 0;}\n'
    with tempfile.TemporaryDirectory(prefix="nsl-keyframe-layout-") as temporary:
        directory = Path(temporary)
        shutil.copyfile(header, directory / "nvEncodeAPI.h")
        (directory / "layout.c").write_text(source)
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "layout.c", "-o", "layout"],
                       cwd=directory, check=True, capture_output=True, timeout=30)
        result = subprocess.run([str(directory / "layout")], check=True, capture_output=True,
                                text=True, timeout=5)
    observed = json.loads(result.stdout)
    expected = dict(api_picture=0x88, api_lock_input=0xA0, api_unlock_input=0xA8,
                    api_lock_output=0x90, api_unlock_output=0x98, picture_flags=0x10,
                    picture_time=0x18, picture_input=0x28, picture_output=0x30,
                    lock_input_data=0x10, lock_input_pitch=0x18, output_size=0x24,
                    output_time=0x28, output_data=0x38, output_type=0x40,
                    force_idr=2, type_p=0, type_i=2, type_idr=3)
    assert {key: observed[key] for key in expected} == expected, observed
    layout.update(observed)
    return layout


class KeyframeHost(loss.LossHost):
    # Reuse the existing fixture/driver recorder without creating a second
    # independently mapped emulator. These methods do not replace host code.
    setup_backend = nvenc.NvencHost.setup_backend
    driver = nvenc.NvencHost.driver

    def __init__(self, pe, image, layout, mutation):
        super().__init__(pe, image, None)
        self.layout = layout
        self.driver_status = 0
        self.driver_calls = []
        self.picture_calls = []
        self.output_locks = []
        self.picture_status = 0
        self.lock_status = 0
        self.return_type = layout["type_p"]
        self.return_size = 4
        self.submissions = {}
        self.clock_pairs = []
        self.qw(0x13AC4B420, self.alloc(4))
        self.api = self.alloc(0x200)
        self.qw(0x13B17D8A8, self.api)
        for name, address, callback in (
            ("api_reconfigure", 0x4000E080, self.driver),
            ("api_lock_input", 0x4000E100, self.lock_input),
            ("api_unlock_input", 0x4000E110, lambda: self.ret()),
            ("api_picture", 0x4000E120, self.picture),
            ("api_lock_output", 0x4000E130, self.lock_output),
            ("api_unlock_output", 0x4000E140, lambda: self.ret()),
        ):
            self.qw(self.api + layout[name], address)
            self.hooks[address] = callback
        for slot, address, callback in (
            (0x13AC4B438, 0x4000E0B0, lambda: self.ret(1000000)),
            (0x13AC4B478, 0x4000E0C0, self.elapsed),
            (0x13AC4BCA8, 0x4000E0D0, self.copy_description),
        ):
            self.qw(slot, address)
            self.hooks[address] = callback
        self.hooks[0x13A841DF0] = self.copy_pixels
        self.hooks[0x13A8B9770] = lambda: self.ret()  # Platform timer constructor.
        # Win64 __chkstk must PRESERVE allocation size in RAX. The smaller
        # loss-only chunk path did not consume this return value.
        self.hooks[0x13AAB3380] = lambda: self.ret(self.r(loss.UC_X86_REG_RAX))
        if mutation:
            address, signature, replacement = PATCHES[mutation]
            assert bytes(self.u.mem_read(address, len(bytes.fromhex(signature)))) == bytes.fromhex(signature), (
                "mutation-signature", mutation, hex(address))
            self.u.mem_write(address, bytes.fromhex(replacement))

    def timestamp(self):
        self.ret(self.arg(0) * 65536 // 1000000)

    def elapsed(self):
        first, last = self.arg(0), self.arg(1)
        assert last >= first
        self.clock_pairs.append([first, last])
        self.ret(last - first)

    def copy_description(self):
        # Both sides have an explicitly empty descriptor string in this fixture.
        assert self.u.mem_read(self.arg(1), 1)[0] == 0
        assert self.arg(2) == 0x40
        self.u.mem_write(self.arg(0), b"\0")
        self.ret(self.arg(0))

    def copy_pixels(self):
        source, stride, destination, pitch, width, rows = [self.arg(i) for i in range(6)]
        assert source == self.pixels and destination == self.locked_pixels
        assert stride == pitch == width == 1280 and rows == 1080
        self.u.mem_write(destination, bytes(self.u.mem_read(source, stride * rows)))
        self.ret()

    def lock_input(self):
        request = self.arg(1)
        assert self.arg(0) == 0x12345678
        assert self.rd(request) == self.layout["input_version"]
        self.qw(request + self.layout["lock_input_data"], self.locked_pixels)
        self.w(request + self.layout["lock_input_pitch"], 1280)
        self.ret()

    def picture(self):
        request = self.arg(1)
        item = dict(version=self.rd(request), width=self.rd(request + 4),
                    height=self.rd(request + 8), flags=self.rd(request + self.layout["picture_flags"]),
                    timestamp=self.q(request + self.layout["picture_time"]),
                    input=self.q(request + self.layout["picture_input"]),
                    output=self.q(request + self.layout["picture_output"]),
                    status=self.picture_status)
        assert self.arg(0) == 0x12345678 and item["version"] == self.layout["picture_version"]
        assert (item["width"], item["height"]) == (1280, 720)
        self.picture_calls.append(item)
        item["parameters_sha256"] = hashlib.sha256(bytes(
            self.u.mem_read(request, self.layout["picture_size"]))).hexdigest()
        # Result supplied independently of requested flags. Deliberate P/I/zero
        # cases must NOT be turned into IDR by the observation boundary.
        self.submissions[item["output"]] = dict(type=self.return_type, size=self.return_size,
                                                timestamp=item["timestamp"])
        self.ret(self.picture_status)

    def lock_output(self):
        request = self.arg(1)
        assert self.arg(0) == 0x12345678 and self.rd(request) == self.layout["output_version"]
        result = self.submissions[self.q(request + 8)]
        self.output_locks.append(dict(**result, status=self.lock_status))
        if self.lock_status == 0:
            self.w(request + self.layout["output_size"], result["size"])
            self.qw(request + self.layout["output_time"], result["timestamp"])
            self.qw(request + self.layout["output_data"], self.payload)
            self.w(request + self.layout["output_type"], result["type"])
        self.ret(self.lock_status)

    def configure(self, desired):
        self.prepare(desired, bytes.fromhex("0a023000" if desired == 0 else "0a0330f02e"))
        self.output_fixture()
        self.setup_backend(0)
        self.w(self.backend + 0x68, 4)
        self.call(0x13A849010, self.backend + 0x30)  # Actual output-buffer constructor.
        self.w(self.frame + 0x44, 0x100)
        self.w(self.frame + 0x48, 1280)
        self.qw(self.backend + 0x118, self.alloc(1))
        self.locked_pixels = self.alloc(1280 * 1080)
        self.pixels = self.alloc(1280 * 1080)
        self.qw(self.frame + 0xC0, self.pixels)
        self.qw(self.backend + 0x70, 1000000)  # Declared existing timestamp origin.
        queue, entries = self.alloc(0x18), self.alloc(0x298 * 2)
        self.qw(queue, entries)
        self.w(queue + 0x10, 2)
        self.qw(self.backend + 0x16E0, queue)
        for index in range(2):
            self.qw(entries + 0x298 * index + 8, 0x1234 + index)
            self.qw(entries + 0x298 * index + 16, 0x2345 + index)
        self.w(self.backend + 0x848, 1)  # No B-frame reordering in this fixture.
        self.now = 8.0

    def step(self, index):
        self.visited.clear()
        self.qw(self.frame + 0x60, 1016667 + 16667 * index)
        target = self.encode_stage()
        return dict(encoder_kbps=target, pending=self.pending(),
                    failed=bool(self.u.mem_read(self.backend + 0x18, 1)[0]),
                    local_force=bool(self.u.mem_read(self.backend + 0x60, 1)[0]),
                    nvenc_force=bool(self.u.mem_read(self.backend + 0x1690, 1)[0]),
                    pictures=len(self.picture_calls), locks=len(self.output_locks),
                    output=len(self.output_frames), visited=sorted(self.visited))


def audit(args):
    raw = args.binary.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == loss.feedback.config.host.SHA256
    pe = pefile.PE(data=raw)
    image = pe.get_memory_mapped_image()
    base = pe.OPTIONAL_HEADER.ImageBase
    pointer = lambda address: struct.unpack_from("<Q", image, address - base)[0]
    for vtable, offset, target in (
        (0x13AC95920, 0x38, 0x13A1B1610), (0x13AC95920, 0x60, 0x13A1B46C0),
        (0x13AC91FA0, 0x50, 0x13A1A1580), (0x13AC91FA0, 0x68, 0x13A1A2930),
        (0x13AC91FA0, 0x78, 0x13A1A2810),
    ):
        assert pointer(vtable + offset) == target
    layout = picture_layout(args.nvenc_header)
    command = [args.python, str(ROOT / "tools/steam-client-loss-phase-audit.py"),
               "--binary", str(args.client_binary), "--receiver", str(args.client_oracle)]
    client = json.loads(subprocess.run(command, check=True, capture_output=True,
                                       text=True, timeout=120).stdout)
    channel, payload = client["cases"][6]["feedback"][0]
    assert channel == 3 and payload == "02"
    cases = []

    def run(name, *, lost=False, desired=0, returned=0, size=4, status=0, lock_status=0,
            initial_force=False, nvenc_force=False, origin=1000000, steps=3):
        h = KeyframeHost(pe, image, layout, args.mutation)
        h.configure(desired)
        h.return_type, h.return_size = returned, size
        h.picture_status, h.lock_status = status, lock_status
        h.qw(h.backend + 0x70, origin)
        h.u.mem_write(h.backend + 0x60, bytes([int(initial_force)]))
        h.u.mem_write(h.backend + 0x1690, bytes([int(nvenc_force)]))
        if lost:
            h.receive_loss(bytes.fromhex(payload))
            assert h.loss_parsed == [True] and h.pending() == 1
        states = []
        for index in range(steps):
            state = h.step(index)
            states.append(state)
            assert state["encoder_kbps"] == (6000 if desired == 6000 else 2500 if lost else 15000)
            # Picture return and bitstream lock failures latch the ORIGINAL
            # backend failure byte; subsequent frames never reach the driver.
            failed = status != 0 or (lock_status != 0 and index >= 1)
            expected_pictures = 1 if status != 0 else 2 if failed else index + 1
            assert state["pictures"] == expected_pictures, (name, index, "failure gate", state)
            assert state["failed"] == failed, (name, index, "failure byte", state)
            clears = returned == layout["type_idr"] and size != 0 and not failed and index >= 1
            assert state["pending"] == int(lost and not clears), (name, index, "loss latch", state)
            expected_output = index if status == lock_status == 0 and size != 0 else 0
            assert state["output"] == expected_output, (name, index, "output boundary", state)
            assert not state["local_force"] and not state["nvenc_force"]
            if index < expected_pictures:
                request = h.picture_calls[index]
                forced = ((lost and (index < 2 or returned != layout["type_idr"] or size == 0))
                          or (index == 0 and (initial_force or nvenc_force or origin == 0)))
                assert request["flags"] == (layout["force_idr"] if forced else 0), (
                    name, index, "FORCEIDR", request)
                assert {"encoder_frame_wrapper", "nvenc_prepare_entry", "shared_encode_loop",
                        "shared_encode_call", "nvenc_encode_picture"} <= h.visited
            if index == 1 and status == lock_status == 0:
                assert {"nvenc_retrieve_output", "nvenc_picture_type_decode", "session_buffer_output"} <= h.visited
        expected_flag = 0x5C if returned == layout["type_idr"] else 0x4C
        assert all(frame["flags"] == expected_flag for frame in h.output_frames), (
            name, "driver picture type -> wire key flag", h.output_frames)
        cases.append(dict(name=name, input=dict(lost=lost, desired=desired, returned_type=returned,
                          returned_size=size, picture_status=status, output_lock_status=lock_status,
                          local_force=initial_force, nvenc_force=nvenc_force, origin=origin),
                          states=states, pictures=h.picture_calls, locks=h.output_locks,
                          output=h.output_frames, reconfigurations=h.driver_calls))
        return h

    run("ordinary-no-loss")
    run("loss-request-returned-P", lost=True)
    run("loss-request-returned-I", lost=True, returned=layout["type_i"])
    run("loss-request-returned-IDR", lost=True, returned=layout["type_idr"])
    run("fixed6000-loss-IDR", lost=True, desired=6000, returned=layout["type_idr"])
    run("zero-byte-IDR-retains-loss", lost=True, returned=layout["type_idr"], size=0)
    run("picture-error-retains-loss", lost=True, status=8)
    run("output-lock-error-retains-loss", lost=True, lock_status=8)
    run("first-frame-independent-force", origin=0)
    run("local-independent-force", initial_force=True)
    run("nvenc-independent-force", nvenc_force=True)

    h = run("new-loss-after-IDR", lost=True, returned=layout["type_idr"], steps=2)
    h.now = 9.0
    h.receive_loss(bytes.fromhex(payload))
    state = h.step(2)
    assert h.picture_calls[-1]["flags"] == layout["force_idr"]
    assert h.estimator_state()["last_event"] == 9.0
    # The older, already queued IDR can consume this new latch too. There is no
    # new request-ID association in the original output callback under test.
    assert state["pending"] == 0
    cases[-1]["second_loss"] = dict(state=state, picture=h.picture_calls[-1])
    dependencies = [ROOT / relative for relative in (
        "tools/steam-adaptive-loss64-audit.py", "tools/steam-adaptive-nvenc64-audit.py",
        "tools/steam-adaptive-feedback64-audit.py", "tools/steam-adaptive-config64-audit.py",
        "scripts/audit-steam-host64-fec.py", "tools/steam-client-loss-phase-audit.py")]
    return dict(scope=__doc__, host_sha256=hashlib.sha256(raw).hexdigest(),
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                nvenc_header_sha256=hashlib.sha256(args.nvenc_header.read_bytes()).hexdigest(),
                layout=layout, client_basis=client, mutation=args.mutation,
                original_ranges={f"0x{address:x}": dict(size=size, sha256=hashlib.sha256(
                    image[address - base:address - base + size]).hexdigest())
                    for address, size in ((0x13A1B16D0, 0x29F), (0x13A1B1230, 0x1BA),
                                          (0x13A1B46C0, 0x88C), (0x13A1B5980, 0x31C))},
                dependencies={str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                              for p in dependencies}, cases=cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "client-binary", "client-oracle", "nvenc-header"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--python", default="python3")
    parser.add_argument("--mutation", choices=PATCHES)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    text = json.dumps(audit(args), indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
