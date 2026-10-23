#!/usr/bin/env python3
"""Execute original overflow/estimator/stage/owner-getter/NVENC reconfiguration.

The driver function is an explicit recording terminal returning a fixture status,
NOT a GPU. Existing allocation/locks/logging/thread/clock terminals are inherited.
The original next-stage dispatch and encoder wrapper execute; frame encoding
after successful preparation is a recording terminal. memcpy is byte-preserving.
The NVENC object/session, owner settings,
and preallocated parameter block are fixture inputs, not a full constructor.
The pinned NVIDIA-authored SDK header supplies ABI names/offsets only; compiling
it checks the pointer size, function-table slot and parameter layout actually
observed at the original call boundary. No actual driver validation, encoded
output, sockets or current Steam session is claimed.
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
SOURCE = ROOT / "tools/steam-adaptive-feedback64-audit.py"
spec = importlib.util.spec_from_file_location("feedback64", SOURCE)
feedback = importlib.util.module_from_spec(spec)
spec.loader.exec_module(feedback)
HEADER_SHA = "dbdaa8bcbc2b9325bd24bc68b36170a8432411518040e8d4c8421608cf217425"
HEADER_URL = (
    "https://raw.githubusercontent.com/FFmpeg/nv-codec-headers/"
    "n12.1.14.0/include/ffnvcodec/nvEncodeAPI.h"
)
feedback.config.host.NODES.update({
    0x13A1A2A10: "owner_bitrate_getter",
    0x13A1B5490: "nvenc_prepare_entry",
    0x13A1B5560: "nvenc_prepare_settings",
    0x13A1B3BE0: "nvenc_reconfigure",
    0x13A1B6670: "nvenc_rate_parameters",
    0x13A1B1610: "encoder_frame_wrapper",
    0x13A1A4520: "stage_failure_latch",
})
PATCHES = {
    "owner-getter": (0x13A1A2A10, "8b8168010000", "8b816c010000"),
    "kilobits-conversion": (0x13A1B6670, "69c2e8030000", "69c201000000"),
    "change-gate": (0x13A1B5896, "755c", "9090"),
    "driver-result": (0x13A1B3C68, "7419", "eb19"),
    "encoder-store": (0x13A1A3038, "87be68010000", "909090909090"),
}
LAYOUT_C = r'''
#include <stddef.h>
#include <stdio.h>
#include "nvEncodeAPI.h"
int main(void) {
 printf("{\"pointer_size\":%zu,\"api_reconfigure\":%zu,\"reconfigure_size\":%zu,"
        "\"reinit\":%zu,\"init_size\":%zu,\"config_ptr\":%zu,\"config_size\":%zu,"
        "\"rc\":%zu,\"average\":%zu,\"max\":%zu,\"vbv\":%zu,\"initial\":%zu,"
        "\"reconfigure_version\":%u,\"config_version\":%u,\"init_version\":%u}\n",
        sizeof(void *), offsetof(NV_ENCODE_API_FUNCTION_LIST,nvEncReconfigureEncoder),
        sizeof(NV_ENC_RECONFIGURE_PARAMS),offsetof(NV_ENC_RECONFIGURE_PARAMS,reInitEncodeParams),
        sizeof(NV_ENC_INITIALIZE_PARAMS),offsetof(NV_ENC_INITIALIZE_PARAMS,encodeConfig),
        sizeof(NV_ENC_CONFIG),offsetof(NV_ENC_CONFIG,rcParams),
        offsetof(NV_ENC_RC_PARAMS,averageBitRate),offsetof(NV_ENC_RC_PARAMS,maxBitRate),
        offsetof(NV_ENC_RC_PARAMS,vbvBufferSize),offsetof(NV_ENC_RC_PARAMS,vbvInitialDelay),
        NV_ENC_RECONFIGURE_PARAMS_VER,NV_ENC_CONFIG_VER,NV_ENC_INITIALIZE_PARAMS_VER);
}
'''


def sdk_layout(header):
    assert hashlib.sha256(header.read_bytes()).hexdigest() == HEADER_SHA
    with tempfile.TemporaryDirectory(prefix="nsl-nvenc-layout-") as temporary:
        directory = Path(temporary)
        shutil.copyfile(header, directory / "nvEncodeAPI.h")
        (directory / "layout.c").write_text(LAYOUT_C)
        subprocess.run(
            ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "layout.c", "-o", "layout"],
            cwd=directory, check=True, capture_output=True, timeout=30,
        )
        result = subprocess.run(
            [str(directory / "layout")], check=True, capture_output=True, text=True, timeout=5,
        )
    value = json.loads(result.stdout)
    assert {key: value[key] for key in (
        "pointer_size", "api_reconfigure", "reconfigure_size", "reinit", "init_size",
        "config_ptr", "config_size", "rc", "average", "max", "vbv", "initial"
    )} == dict(
        pointer_size=8, api_reconfigure=0x108, reconfigure_size=0x720,
        reinit=8, init_size=0x710, config_ptr=0x58, config_size=0xE00,
        rc=0x28, average=0x14, max=0x18, vbv=0x1C, initial=0x20,
    ), value
    return value


class NvencHost(feedback.FeedbackHost):
    def __init__(self, pe, image, layout, mutation):
        super().__init__(pe, image, None)
        self.layout = layout
        self.driver_status = 0
        self.driver_calls = []
        self.encoded_boundaries = 0
        self.hooks[0x13AC31090] = self.memcpy
        self.hooks[0x13A1B16D0] = self.encode_boundary
        # Disabled profiling global: the wrapper's original gate still executes.
        self.qw(0x13AC4B420, self.alloc(4))
        table = self.alloc(0x200)
        self.qw(0x13B17D8A8, table)
        self.qw(table + layout["api_reconfigure"], 0x4000E080)
        self.hooks[0x4000E080] = self.driver
        if mutation:
            address, expected, changed = PATCHES[mutation]
            expected = bytes.fromhex(expected)
            assert bytes(self.u.mem_read(address, len(expected))) == expected
            self.u.mem_write(address, bytes.fromhex(changed))

    def memcpy(self):
        destination, source, size = [self.arg(i) for i in range(3)]
        self.u.mem_write(destination, bytes(self.u.mem_read(source, size)))
        self.ret(destination)

    def encode_boundary(self):
        assert self.arg(0) == self.backend and self.arg(1) == self.frame
        self.encoded_boundaries += 1
        self.ret()

    def driver(self):
        request = self.arg(1)
        init = request + self.layout["reinit"]
        config = self.q(init + self.layout["config_ptr"])
        assert config == self.backend + 0x830, ("driver config pointer", hex(config))
        # Full ORIGINAL copied block and zeroed trailing flags/reserved bytes.
        assert bytes(self.u.mem_read(init, self.layout["init_size"])) == bytes(
            self.u.mem_read(self.backend + 0x120, self.layout["init_size"])
        ), "driver reinit copy"
        trailing = self.layout["reconfigure_size"] - 8 - self.layout["init_size"]
        assert bytes(self.u.mem_read(init + self.layout["init_size"], trailing)) == bytes(trailing)
        rc = config + self.layout["rc"]
        self.driver_calls.append(dict(
            handle=self.arg(0), version=self.rd(request),
            average_bps=self.rd(rc + self.layout["average"]),
            maximum_bps=self.rd(rc + self.layout["max"]),
            vbv_bits=self.rd(rc + self.layout["vbv"]),
            initial_bits=self.rd(rc + self.layout["initial"]),
            flags=self.rd(config + 0x4C),
            status=self.driver_status,
        ))
        self.ret(self.driver_status)

    def setup_backend(self, control_mode):
        self.frame = self.alloc(0x200)
        # Actual owner vtable from CGameStreamVideoEncoder constructor/RTTI.
        self.qw(self.encoder, 0x13AC91FA0)
        self.qw(self.encoder + 0x160, (60 << 32) | 1)
        self.w(self.encoder + 0x16C, 4)
        self.w(self.encoder + 0x178, control_mode)
        self.u.mem_write(self.encoder + 0x188, b"\x01")
        self.w(self.frame + 0x40, 512)
        self.w(self.frame + 0x4C, 1280)
        self.w(self.frame + 0x50, 720)
        self.backend = self.alloc(0x2000)
        self.qw(self.backend, 0x13AC95920)
        self.qw(self.backend + 8, self.encoder)
        self.qw(self.backend + 0xF8, 0x12345678)  # Opaque fixture handle, no driver.
        self.w(self.backend + 0x144, 1280)
        self.w(self.backend + 0x148, 720)
        self.w(self.backend + 0x86C, 6000000)
        self.qw(self.backend + 0x178, self.backend + 0x830)
        self.w(self.backend + 0x120, self.layout["init_version"])
        self.w(self.backend + 0x830, self.layout["config_version"])
        # Actual next-stage method → shared encoder wrapper → backend +0x50.
        self.qw(self.stage + 0x10, self.backend)


def audit(args):
    layout = sdk_layout(args.nvenc_header)
    raw = args.binary.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == feedback.config.host.SHA256
    pe = pefile.PE(data=raw)
    image = pe.get_memory_mapped_image()
    # Validate object/virtual binding, not just a plausible field displacement.
    base = pe.OPTIONAL_HEADER.ImageBase
    pointer = lambda address: struct.unpack_from("<Q", image, address - base)[0]
    def rtti_name(vtable):
        col = pointer(vtable - 8)
        td = struct.unpack_from("<I", image, col - base + 12)[0]
        return image[td + 16:td + 160].split(b"\0")[0].decode()
    name = rtti_name(0x13AC91FA0)
    assert name == ".?AVCGameStreamVideoEncoder@@", name
    assert rtti_name(0x13AC95920) == ".?AVCGameStreamVideoStageNVENC@@"
    assert pointer(0x13AC91FA0 + 0x10) == 0x13A1A2A10
    assert pointer(0x13AC95920 + 0x38) == 0x13A1B1610
    assert pointer(0x13AC95920 + 0x50) == 0x13A1B5490
    reference_path = ROOT / "scripts/fixtures/steam-video-overflow-reference.json"
    reference = json.loads(reference_path.read_text())
    assert reference["binary_sha256"] == (
        "95482ca6120f90bb90798b27206b7946ab732e079f008d7fc90ea58a8b0074e1"
    )
    case = next(c for c in reference["cases"] if c["name"] == "equal_range_repeats")
    states = feedback.native_client(args.client_receiver, case)
    payload = bytes.fromhex(states[0]["feedback"][0][1])
    assert payload == bytes.fromhex("9408641066")
    cases = []

    def run(name, desired=0, status=0, other_limit=0, control_mode=0):
        assert desired in (0, 6000), (name, "unsupported config fixture", desired)
        h = NvencHost(pe, image, layout, args.mutation)
        h.prepare(desired, bytes.fromhex("0a023000" if desired == 0 else "0a0330f02e"),
                  other_limit=other_limit)
        h.setup_backend(control_mode)
        h.driver_status = status
        steps = []
        def step(label, expected, *, feedback_now=None, recompute_now=None, changed=True):
            h.visited.clear()
            if feedback_now is not None:
                h.now = feedback_now
                h.control(payload[1:], kind=payload[0], state=7)
            if recompute_now is not None:
                h.now = recompute_now
                h.call(0x13A172500, h.estimator)
            start = len(h.driver_calls)
            encoded_start = h.encoded_boundaries
            already_failed = bool(h.u.mem_read(h.backend + 0x18, 1)[0])
            target = h.encode_stage()
            assert target == expected, (name, label, "stage", target, expected)
            ok = not bool(h.u.mem_read(h.backend + 0x18, 1)[0])
            calls = h.driver_calls[start:]
            assert len(calls) == int(changed), (name, label, "driver calls", calls)
            expected_ok = not already_failed and (status == 0 or not changed)
            assert ok == expected_ok, (name, label, "driver status", ok, status)
            assert h.encoded_boundaries - encoded_start == int(expected_ok), (name, label, "encode gate")
            assert "encoder_frame_wrapper" in h.visited, (name, label, "wrapper dispatch")
            if not already_failed:
                assert {"owner_bitrate_getter", "nvenc_prepare_entry", "nvenc_prepare_settings"} <= h.visited
            if changed:
                expected_driver = dict(
                    handle=0x12345678, version=layout["reconfigure_version"],
                    average_bps=expected * 1000,
                    maximum_bps=expected * (2000 if control_mode else 1200),
                    vbv_bits=expected * (2000 if control_mode else 20),
                    initial_bits=0 if control_mode else expected * 20,
                    flags=8 if control_mode else 0x400, status=status,
                )
                assert calls == [expected_driver], (name, label, "driver parameters", calls, expected_driver)
                assert {"nvenc_reconfigure", "nvenc_rate_parameters"} <= h.visited
            steps.append(dict(name=label, stage_kbps=target, ok=ok, driver_calls=calls,
                              encode_boundary_calls=h.encoded_boundaries - encoded_start,
                              configured_bps=h.rd(h.backend + 0x86C), visited=sorted(h.visited)))
        ceiling = min(15000 if desired == 0 else desired, other_limit or 0xFFFFFFFF)
        step("initial", ceiling, changed=ceiling != 6000)
        step("unchanged", ceiling, changed=False)
        if desired == 0 and status == 0:
            step("overflow", min(2500, other_limit or 0xFFFFFFFF), feedback_now=8)
            for clock, target in [(8.125, 3750), (8.25, 7500), (8.5, 15000)]:
                limited = min(target, other_limit or 0xFFFFFFFF)
                old = steps[-1]["stage_kbps"]
                step("recovery-" + str(clock), limited, recompute_now=clock, changed=limited != old)
        cases.append(dict(name=name, desired=desired, driver_status=status,
                          independent_limit=other_limit, control_mode=control_mode, steps=steps))
    run("native-overflow-to-driver")
    run("independent-cap-to-driver", other_limit=8000)
    run("fixed-6000-no-reconfigure", desired=6000)
    run("driver-rejects", status=8)
    run("nonzero-control-mode", control_mode=1)
    ranges = [
        (0x13A1A2A10, 0x13A1A2A17), (0x13A1A2FE0, 0x13A1A3058),
        (0x13A1B5490, 0x13A1B597C), (0x13A1B3BE0, 0x13A1B3C8E),
        (0x13A1B6670, 0x13A1B66F5),
        (0x13A1A4510, 0x13A1A4525), (0x13A1B1610, 0x13A1B16D0),
    ]
    return dict(
        binary_sha256=feedback.config.host.SHA256,
        audit_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        inherited_harness_sha256={str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                 for path in [SOURCE, feedback.SOURCE, feedback.config.source]},
        native_receiver_sha256=hashlib.sha256(args.client_receiver.read_bytes()).hexdigest(),
        client_reference_sha256=hashlib.sha256(reference_path.read_bytes()).hexdigest(),
        client=dict(input=case["input"], states=states, payload=payload.hex()),
        sdk=dict(url=HEADER_URL, sha256=HEADER_SHA, layout=layout),
        binding=dict(class_name=name, vtable="0x13ac91fa0", getter="0x13a1a2a10",
                     backend_class=rtti_name(0x13AC95920), backend_vtable="0x13ac95920",
                     wrapper="0x13a1b1610", prepare="0x13a1b5490"),
        original_ranges=[dict(start=hex(a), end=hex(b), sha256=hashlib.sha256(image[a-base:b-base]).hexdigest())
                         for a, b in ranges],
        boundary=__doc__, cases=cases,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--nvenc-header", type=Path, required=True)
    parser.add_argument("--client-receiver", type=Path, required=True)
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
